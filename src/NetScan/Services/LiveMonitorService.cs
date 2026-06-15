using System.Collections.Concurrent;
using System.Text;

using Microsoft.Extensions.Logging;
using NetScan.Abstractions;
using NetScan.Configuration;
using NetScan.Models;
using NetScan.Platform.Linux.Ebpf;

namespace NetScan.Services;

/// <summary>
/// Real-time network monitoring service.
/// Consumes events from <see cref="INetworkEventSource"/> and renders a live dashboard
/// with connection table + event feed. Only re-renders when state actually changes.
/// </summary>
internal sealed class LiveMonitorService
{
    private readonly INetworkScanner _scanner;
    private readonly INetworkEventSource _eventSource;
    private readonly IConnectionExporter? _exporter;
    private readonly MonitoringOptions _options;
    private readonly ILogger<LiveMonitorService> _logger;
    private readonly DnsAddressResolver _dnsResolver;

    // Live state
    private readonly ConcurrentDictionary<string, NetworkConnection> _liveConnections = new();
    private readonly object _renderLock = new();
    private int _totalNewEvents;

    private DateTime _monitoringStartedUtc;
    private bool _hasExported;
    private bool _isFirstRender = true;

    private static readonly ConcurrentDictionary<int, (int Ppid, string Name)> PidParentCache = new();

    public LiveMonitorService(
        INetworkScanner scanner,
        INetworkEventSource eventSource,
        IServiceProvider serviceProvider,
        MonitoringOptions options,
        DnsAddressResolver dnsResolver,
        ILogger<LiveMonitorService> logger)
    {
        _scanner = scanner;
        _eventSource = eventSource;
        _exporter = serviceProvider.GetService(typeof(IConnectionExporter)) as IConnectionExporter;
        _options = options;
        _dnsResolver = dnsResolver;
        _logger = logger;
    }

    public async Task RunAsync(CancellationToken stoppingToken)
    {
        _logger.LogInformation("NetScan Real-Time Monitor starting...");
        _logger.LogInformation("Platform: {OS}", System.Runtime.InteropServices.RuntimeInformation.OSDescription);
        _logger.LogInformation("Mode: {Mode}", _options.LiveMode ? "REAL-TIME EVENT-DRIVEN" : "SNAPSHOT");
        _logger.LogInformation("Scan interval: {Interval}ms", _options.EventScanIntervalMs);

        if (!string.IsNullOrEmpty(_options.FilterByUser))
            _logger.LogInformation("Filtering by user: {User}", _options.FilterByUser);
        if (!string.IsNullOrEmpty(_options.FilterByProtocol))
            _logger.LogInformation("Filtering by protocol: {Protocol}", _options.FilterByProtocol);
        if (!string.IsNullOrEmpty(_options.FilterByProcess))
            _logger.LogInformation("Filtering by process: {Process}", _options.FilterByProcess);

        try
        {
            if (_options.LiveMode)
            {
                await RunRealTimeModeAsync(stoppingToken);
            }
            else
            {
                await RunSnapshotModeAsync(stoppingToken);
            }
        }
        catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
        {
            _logger.LogInformation("NetScan shutting down gracefully...");
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "NetScan encountered a fatal error");
            throw;
        }
    }

    /// <summary>
    /// Runs real-time event-driven monitoring. Only re-renders when connections change.
    /// </summary>
    private async Task RunRealTimeModeAsync(CancellationToken ct)
    {
        Console.Clear();
        _monitoringStartedUtc = DateTime.UtcNow;
        bool needsRender = false;
        int eventBatchCount = 0;
        DateTime lastRenderTime = DateTime.MinValue;
        const int MinRenderIntervalMs = 80; // Cap render rate to ~12 FPS to avoid flicker

        // Background UI heartbeat to update the Uptime counter and clean up dead/inactive connections
        using var uiTimer = new PeriodicTimer(TimeSpan.FromSeconds(1));
        var timerTask = Task.Run(async () =>
        {
            try
            {
                while (await uiTimer.WaitForNextTickAsync(ct))
                {
                    bool cleanedAny = false;
                    var now = DateTime.UtcNow;

                    foreach (var kvp in _liveConnections)
                    {
                        var conn = kvp.Value;

                        // 1. Clean up connection if its owning process has exited
                        if (conn.ProcessId > 0 && !IsPidAlive(conn.ProcessId))
                        {
                            if (_liveConnections.TryRemove(kvp.Key, out _))
                            {
                                cleanedAny = true;
                            }
                            continue;
                        }

                        // 2. Time out UDP/QUIC flows after 15 seconds of inactivity (since UDP is stateless)
                        if (conn.Protocol.Equals("UDP", StringComparison.OrdinalIgnoreCase))
                        {
                            if ((now - conn.CapturedAtUtc).TotalSeconds > 15)
                            {
                                if (_liveConnections.TryRemove(kvp.Key, out _))
                                {
                                    cleanedAny = true;
                                }
                            }
                        }
                    }

                    // Render if we cleaned up dead connections or if 1 second has elapsed since last render
                    if (cleanedAny || (DateTime.UtcNow - lastRenderTime).TotalMilliseconds >= 1000)
                    {
                        RenderRealTimeView();
                        lastRenderTime = DateTime.UtcNow;
                    }
                }
            }
            catch (OperationCanceledException) { }
        }, ct);

        await foreach (var evt in _eventSource.MonitorAsync(ct))
        {
            var connection = evt.Connection;
            if (connection.LocalAddress == "0.0.0.0" || connection.LocalAddress == "::")
            {
                string resolvedLocal = ResolveLocalIpForRemote(connection.RemoteAddress, connection.RemotePort);
                connection = connection with { LocalAddress = resolvedLocal };
            }

            var key = GetConnectionKey(connection);

            // Clean up connection immediately if it was closed or transitioned to an inactive state (like TIME_WAIT / CLOSE_WAIT)
            // UDP connections do not have active/inactive states and should only be cleaned up via the background timer.
            bool isClosedOrInactive = evt.EventType == NetworkEventType.ConnectionClosed ||
                (!connection.Protocol.Equals("UDP", StringComparison.OrdinalIgnoreCase) && !IsRelevantExternalConnection(connection));

            if (isClosedOrInactive)
            {
                if (_liveConnections.TryRemove(key, out _))
                {
                    needsRender = true;
                }
                continue;
            }

            // Apply filters — skip events that don't match
            if (!MatchesFilters(connection))
            {
                // SPECIAL CASE: If this connection is already in our live list,
                // and the new event is just a state update (like ESTABLISHED) but has a different/unknown process name
                // (which happens in softirq contexts), we still want to update its state!
                if (_liveConnections.TryGetValue(key, out var existingConn))
                {
                    existingConn.State = connection.State;
                    existingConn.CapturedAtUtc = connection.CapturedAtUtc;
                    needsRender = true;
                }
                continue;
            }

            // Update live state
            _liveConnections[key] = connection;
            _totalNewEvents++;

            // Trigger async DNS resolution to discover both IPv4 and IPv6 addresses
            _dnsResolver.GetOrStartResolve(connection.RemoteAddress);

            eventBatchCount++;
            needsRender = true;

            // Throttle rendering — batch rapid events
            var now = DateTime.UtcNow;
            var msSinceRender = (now - lastRenderTime).TotalMilliseconds;

            if (needsRender && msSinceRender >= MinRenderIntervalMs)
            {
                RenderRealTimeView();
                lastRenderTime = now;
                needsRender = false;
                eventBatchCount = 0;

                // Export on first render if configured
                if (_exporter != null && !_hasExported)
                {
                    await ExportCurrentStateAsync(ct);
                    _hasExported = true;
                }
            }
        }
        
        await timerTask;
    }

    /// <summary>
    /// Runs a single snapshot scan, displays results, and optionally exports.
    /// </summary>
    private async Task RunSnapshotModeAsync(CancellationToken ct)
    {
        Console.Clear();
        _logger.LogInformation("Running single snapshot scan...");
        _monitoringStartedUtc = DateTime.UtcNow;

        var connections = await _scanner.ScanAsync(ct);
        
        // Resolve 0.0.0.0 / :: local addresses virtually before filtering
        var resolvedConnections = new List<NetworkConnection>();
        foreach (var conn in connections)
        {
            if (conn.LocalAddress == "0.0.0.0" || conn.LocalAddress == "::")
            {
                string resolvedLocal = ResolveLocalIpForRemote(conn.RemoteAddress, conn.RemotePort);
                resolvedConnections.Add(conn with { LocalAddress = resolvedLocal });
            }
            else
            {
                resolvedConnections.Add(conn);
            }
        }

        var filtered = ApplyFilters(resolvedConnections);

        foreach (var conn in filtered)
        {
            var key = GetConnectionKey(conn);
            _liveConnections[key] = conn;
            _totalNewEvents++;
        }

        RenderRealTimeView();

        if (_exporter != null)
        {
            await ExportCurrentStateAsync(ct);
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    //  Filtering
    // ─────────────────────────────────────────────────────────────────────────

    private static bool IsRelevantExternalConnection(NetworkConnection conn)
    {
        // 1. Must be TCP or UDP (or SCTP, MPTCP)
        string proto = conn.Protocol.ToUpperInvariant();
        if (proto != "TCP" && proto != "UDP" && proto != "SCTP" && proto != "MPTCP")
            return false;

        // 2. Remote address must be specified (not listening)
        string remote = conn.RemoteAddress;
        if (string.IsNullOrWhiteSpace(remote) || 
            remote == "0.0.0.0" || 
            remote == "::" || 
            remote == "*" || 
            conn.RemotePort <= 0)
            return false;

        // 3. Exclude loopback
        if (remote.StartsWith("127.") || remote == "::1" || 
            conn.LocalAddress.StartsWith("127.") || conn.LocalAddress == "::1")
            return false;

        // 4. Exclude multicast/broadcast
        if (remote.StartsWith("224.") || remote.StartsWith("225.") || 
            remote.StartsWith("226.") || remote.StartsWith("227.") || 
            remote.StartsWith("228.") || remote.StartsWith("229.") || 
            remote.StartsWith("230.") || remote.StartsWith("231.") || 
            remote.StartsWith("232.") || remote.StartsWith("233.") || 
            remote.StartsWith("234.") || remote.StartsWith("235.") || 
            remote.StartsWith("236.") || remote.StartsWith("237.") || 
            remote.StartsWith("238.") || remote.StartsWith("239.") || 
            remote == "255.255.255.255" || 
            remote.StartsWith("ff", StringComparison.OrdinalIgnoreCase))
            return false;

        // 5. Exclude link-local
        if (remote.StartsWith("169.254.") || 
            remote.StartsWith("fe80:", StringComparison.OrdinalIgnoreCase))
            return false;

        // 6. Exclude infrastructure and local discovery noise (DNS: 53, DHCP: 67/68, mDNS: 5353, LLMNR: 5355, SSDP: 1900, WS-Discovery: 3702, NetBIOS: 137/138)
        if (conn.LocalPort == 53 || conn.RemotePort == 53 ||
            conn.LocalPort == 67 || conn.RemotePort == 67 ||
            conn.LocalPort == 68 || conn.RemotePort == 68 ||
            conn.LocalPort == 5353 || conn.RemotePort == 5353 ||
            conn.LocalPort == 5355 || conn.RemotePort == 5355 ||
            conn.LocalPort == 1900 || conn.RemotePort == 1900 ||
            conn.LocalPort == 3702 || conn.RemotePort == 3702 ||
            conn.LocalPort == 137 || conn.RemotePort == 137 ||
            conn.LocalPort == 138 || conn.RemotePort == 138)
            return false;

        // 7. Require a known process (exclude Unknown / PID 0 noise), EXCEPT for TCP/UDP connections to external addresses
        if (proto != "TCP" && proto != "UDP" && (conn.ProcessName == "Unknown" || conn.ProcessId <= 0))
            return false;

        // 8. If TCP, require active states (exclude TIME_WAIT, CLOSE_WAIT, etc.)
        if (proto == "TCP")
        {
            string state = conn.State.ToUpperInvariant();
            if (state != "ESTABLISHED" && 
                state != "SYN_SENT" && 
                state != "SYN_RECV" && 
                state != "NEW_SYN_RECV")
                return false;
        }

        // 9. Exclude infrastructure services/daemons and system/background noise
        if (IsUselessBackgroundProcess(conn))
            return false;

        return true;
    }

    private static bool IsUselessBackgroundProcess(NetworkConnection conn)
    {
        string name = conn.ProcessName;
        if (string.IsNullOrWhiteSpace(name))
            return true;

        string lowerName = name.ToLowerInvariant();

        // 1. Kernel threads and system base processes
        if (conn.ProcessId <= 100 || 
            lowerName.StartsWith("kworker/") || 
            lowerName.StartsWith("ksoftirqd/") || 
            lowerName.StartsWith("migration/") || 
            lowerName.StartsWith("idle_inject/") || 
            lowerName.StartsWith("cpuhp/") || 
            lowerName.StartsWith("rcu_") || 
            lowerName.StartsWith("swapper") || 
            lowerName == "kthreadd" || 
            lowerName == "kauditd")
        {
            return true;
        }

        // 2. Desktop Environment & GUI Infrastructure (GNOME, etc.)
        if (lowerName == "gnome-shell" || 
            lowerName.StartsWith("gnome-terminal") || 
            lowerName == "gnome-session-binary" || 
            lowerName.StartsWith("gsd-") || 
            lowerName.StartsWith("gvfsd-") || 
            lowerName == "dconf-service" || 
            lowerName == "at-spi-bus-laun" || 
            lowerName == "at-spi2-registr" || 
            lowerName == "goa-daemon" || 
            lowerName.StartsWith("evolution-") || 
            lowerName == "pipewire" || 
            lowerName == "wireplumber" || 
            lowerName == "pulseaudio" || 
            lowerName == "gdm" || 
            lowerName == "gdm3" || 
            lowerName == "gdm-session-wor" || 
            lowerName == "lightdm" || 
            lowerName == "sddm" || 
            lowerName == "xorg" || 
            lowerName == "x" || 
            lowerName == "wayland")
        {
            return true;
        }

        // 3. System Services, Daemons, and background agents
        if (lowerName == "systemd" || 
            lowerName.StartsWith("systemd-") || 
            lowerName == "dbus-daemon" || 
            lowerName == "dbus-broker" || 
            lowerName == "avahi-daemon" || 
            lowerName == "wpa_supplicant" || 
            lowerName == "networkmanager" || 
            lowerName == "dhclient" || 
            lowerName == "udisksd" || 
            lowerName == "upowerd" || 
            lowerName == "colord" || 
            lowerName == "accounts-daemon" || 
            lowerName == "polkitd" || 
            lowerName == "rtkit-daemon" || 
            lowerName == "snapd" || 
            lowerName == "packagekitd" || 
            lowerName == "fwupd" || 
            lowerName == "thermald" || 
            lowerName == "irqbalance" || 
            lowerName == "acpid" || 
            lowerName == "cron" || 
            lowerName == "atd" || 
            lowerName == "smartd" || 
            lowerName == "multipathd" || 
            lowerName == "lvmetad" || 
            lowerName == "dnsmasq" || 
            lowerName == "sshd" || 
            lowerName == "cupsd" ||
            lowerName == "chronyd" || 
            lowerName == "auditd" || 
            lowerName == "sssd" || 
            lowerName == "gssproxy" || 
            lowerName == "rpcbind" || 
            lowerName == "nscd")
        {
            return true;
        }

        // 4. Input method/IME infrastructure
        if (lowerName.StartsWith("ibus-") || 
            lowerName == "ibus-daemon")
        {
            return true;
        }

        // 5. Security/Keyring managers
        if (lowerName == "ssh-agent" || 
            lowerName == "gpg-agent" || 
            lowerName == "keyring" || 
            lowerName.Contains("keyring-daemon"))
        {
            return true;
        }

        // 6. Standard shell/terminal shells (unless they are explicitly running something,
        // but typically we want to show the program itself like curl/wget/ssh, not the shell process)
        if (lowerName == "bash" || 
            lowerName == "zsh" || 
            lowerName == "fish" || 
            lowerName == "sh" || 
            lowerName == "tmux" || 
            lowerName == "screen")
        {
            return true;
        }

        return false;
    }

    private bool MatchesFilters(NetworkConnection conn)
    {
        if (!IsRelevantExternalConnection(conn))
            return false;

        // Filter out IPv6 connections if not enabled
        if (!_options.IncludeIPv6 && conn.RemoteAddress.Contains(':'))
            return false;

        if (!string.IsNullOrEmpty(_options.FilterByUser) &&
            !conn.UserName.Contains(_options.FilterByUser, StringComparison.OrdinalIgnoreCase))
            return false;

        if (!string.IsNullOrEmpty(_options.FilterByProtocol) &&
            !conn.Protocol.Equals(_options.FilterByProtocol, StringComparison.OrdinalIgnoreCase))
            return false;

        if (!string.IsNullOrEmpty(_options.FilterByProcess) &&
            !ProcessMatchesFilter(conn.ProcessId, conn.ProcessName, conn.CommandLine, _options.FilterByProcess))
            return false;

        return true;
    }

    private static bool ProcessMatchesFilter(int pid, string processName, string commandLine, string filter)
    {
        if (string.IsNullOrEmpty(processName))
            return false;

        // Direct checks
        if (processName.Contains(filter, StringComparison.OrdinalIgnoreCase))
            return true;

        if (!string.IsNullOrEmpty(commandLine) && commandLine.Contains(filter, StringComparison.OrdinalIgnoreCase))
            return true;

        // Special browser child/content process matching
        if (filter.Equals("firefox", StringComparison.OrdinalIgnoreCase))
        {
            if (processName.Equals("isolated web co", StringComparison.OrdinalIgnoreCase) ||
                processName.Equals("Web Content", StringComparison.OrdinalIgnoreCase) ||
                processName.Equals("WebExtensions", StringComparison.OrdinalIgnoreCase) ||
                processName.Equals("Privileged Cont", StringComparison.OrdinalIgnoreCase) ||
                processName.Equals("Socket Process", StringComparison.OrdinalIgnoreCase) ||
                processName.Equals("GeckoMain", StringComparison.OrdinalIgnoreCase) ||
                processName.Equals("RDD Process", StringComparison.OrdinalIgnoreCase) ||
                processName.Equals("Utility Process", StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }
        }
        else if (filter.Equals("chrome", StringComparison.OrdinalIgnoreCase) || filter.Equals("google-chrome", StringComparison.OrdinalIgnoreCase))
        {
            if (processName.Equals("chrome", StringComparison.OrdinalIgnoreCase) ||
                processName.Equals("chrome-sandbox", StringComparison.OrdinalIgnoreCase) ||
                processName.Equals("nacl_helper", StringComparison.OrdinalIgnoreCase) ||
                processName.Equals("google-chrome", StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }
        }

        // Parent process check
        if (pid > 0)
        {
            string parentName = GetParentProcessName(pid);
            if (parentName.Contains(filter, StringComparison.OrdinalIgnoreCase))
                return true;

            // Grandparent process check
            int ppid = PidParentCache.TryGetValue(pid, out var cached) ? cached.Ppid : -1;
            if (ppid > 0)
            {
                string grandparentName = GetParentProcessName(ppid);
                if (grandparentName.Contains(filter, StringComparison.OrdinalIgnoreCase))
                    return true;
            }
        }

        return false;
    }

    private static string GetParentProcessName(int pid)
    {
        if (pid <= 0) return "Unknown";

        if (PidParentCache.TryGetValue(pid, out var cached))
        {
            return cached.Name;
        }

        int ppid = -1;
        try
        {
            var statPath = $"/proc/{pid}/stat";
            if (File.Exists(statPath))
            {
                var statContent = File.ReadAllText(statPath);
                int lastParen = statContent.LastIndexOf(')');
                if (lastParen > 0 && lastParen + 2 < statContent.Length)
                {
                    string afterComm = statContent[(lastParen + 2)..];
                    string[] fields = afterComm.Split(' ', StringSplitOptions.RemoveEmptyEntries);
                    if (fields.Length > 0 && int.TryParse(fields[0], out int p))
                    {
                        ppid = p;
                    }
                }
            }
        }
        catch { }

        string parentName = "Unknown";
        if (ppid > 0)
        {
            try
            {
                var commPath = $"/proc/{ppid}/comm";
                if (File.Exists(commPath))
                {
                    parentName = File.ReadAllText(commPath).Trim();
                }
            }
            catch { }
        }

        PidParentCache[pid] = (ppid, parentName);
        return parentName;
    }

    private IReadOnlyList<NetworkConnection> ApplyFilters(IReadOnlyList<NetworkConnection> connections)
    {
        return connections.Where(MatchesFilters).ToList();
    }

    // ─────────────────────────────────────────────────────────────────────────
    //  Rendering
    // ─────────────────────────────────────────────────────────────────────────

    private void RenderRealTimeView()
    {
        lock (_renderLock)
        {
            if (_isFirstRender)
            {
                Console.Clear();
                _isFirstRender = false;
            }

            string? ebpfErr = null;
            if (_eventSource is EbpfNetworkEventSource ebpfSource && !ebpfSource.IsEbpfActive)
            {
                ebpfErr = ebpfSource.EbpfError;
            }

            var sb = new StringBuilder(8192);
            var now = DateTime.UtcNow;
            var uptime = now - _monitoringStartedUtc;

            // ANSI cursor home (flicker-free, no full screen clear)
            sb.Append("\x1b[H");

            // ── Header ──
            sb.AppendLine("╔══════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════╗");
            sb.AppendLine("║                                              N E T S C A N  v2.0 — Real-Time Network Monitor                                                                      ║");
            
            string modeName = "EVENT-DRIVEN";
            string color = "32"; // Green
            if (_eventSource is EbpfNetworkEventSource ebpfS)
            {
                if (ebpfS.IsEbpfActive)
                {
                    modeName = "eBPF KERNEL HOOKS";
                    color = "32"; // Green
                }
                else
                {
                    modeName = "EVENT-DRIVEN (eBPF FALLBACK)";
                    color = "31"; // Red
                }
            }

            string rawStatus = $"● {modeName}  ·  ALL PROTOCOLS  ·  DUAL-STACK";
            int totalWidth = 174;
            int leftPadding = (totalWidth - rawStatus.Length) / 2;
            int rightPadding = totalWidth - rawStatus.Length - leftPadding;
            string paddedStatus = new string(' ', leftPadding) + $"\x1b[{color}m" + rawStatus + "\x1b[0m" + new string(' ', rightPadding);
            sb.AppendLine($"║{paddedStatus}║");

            if (ebpfErr != null)
            {
                string rawErr = $"⚠️ eBPF ERROR: {ebpfErr}";
                int errLeftPadding = (totalWidth - rawErr.Length) / 2;
                int errRightPadding = totalWidth - rawErr.Length - errLeftPadding;
                if (errLeftPadding < 0) errLeftPadding = 0;
                if (errRightPadding < 0) errRightPadding = 0;
                string paddedErr = new string(' ', errLeftPadding) + "\x1b[31;1m" + rawErr + "\x1b[0m" + new string(' ', errRightPadding);
                sb.AppendLine($"║{paddedErr}║");
            }

            sb.AppendLine("╠══════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════╣");

            sb.AppendFormat("║  Host: {0,-25}  OS: {1,-40}                                                           ║\n",
                Truncate(Environment.MachineName, 25),
                Truncate(System.Runtime.InteropServices.RuntimeInformation.OSDescription, 40));

            sb.AppendFormat("║  Since: {0,-25} Uptime: {1,-15}                                                                            ║\n",
                _monitoringStartedUtc.ToLocalTime().ToString("yyyy-MM-dd HH:mm:ss"),
                FormatUptime(uptime));

            // ── Stats Bar ──
            sb.AppendLine("╠══════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════╣");

            var connList = _liveConnections.Values.ToList();

            // Smart Deduplication & Filtering
            var groupedConnections = connList
                .GroupBy(c => new { c.Protocol, c.RemoteAddress, c.ProcessName })
                .Select(g => g.First()) // Keep only one connection per unique Protocol + RemoteAddress + ProcessName
                .ToList();

            // Identify known remote IPs that are mapped to a specific process name
            var knownRemoteIps = groupedConnections
                .Where(c => c.ProcessName != "Unknown" && c.ProcessId > 0)
                .Select(c => c.RemoteAddress)
                .ToHashSet();

            // Filter out "Unknown" process entries if there is a known process for the same RemoteAddress
            var filteredList = groupedConnections
                .Where(c => !(c.ProcessName == "Unknown" && knownRemoteIps.Contains(c.RemoteAddress)))
                .ToList();

            // Protocol breakdown
            var protoGroups = filteredList.GroupBy(c => c.Protocol)
                .OrderByDescending(g => g.Count())
                .Select(g => $"{g.Key}:{g.Count()}");
            var protoSummary = string.Join("  ", protoGroups);

            // State breakdown (top 5)
            var stateGroups = filteredList.GroupBy(c => c.State)
                .OrderByDescending(g => g.Count())
                .Take(5)
                .Select(g => $"{g.Key}:{g.Count()}");
            var stateSummary = string.Join("  ", stateGroups);

            sb.AppendFormat("║  \x1b[36mConnections: {0,-6}\x1b[0m │ \x1b[32m▲ Opened: {1,-6}\x1b[0m │ Protocols: {2,-55}                                    ║\n",
                filteredList.Count, _totalNewEvents, Truncate(protoSummary, 55));

            sb.AppendFormat("║  States: {0,-155}  ║\n", Truncate(stateSummary, 155));

            // Active filters
            var filters = new List<string>();
            if (!string.IsNullOrEmpty(_options.FilterByUser)) filters.Add($"User={_options.FilterByUser}");
            if (!string.IsNullOrEmpty(_options.FilterByProtocol)) filters.Add($"Protocol={_options.FilterByProtocol}");
            if (!string.IsNullOrEmpty(_options.FilterByProcess)) filters.Add($"Process={_options.FilterByProcess}");
            if (filters.Count > 0)
            {
                sb.AppendFormat("║  \x1b[33mFilters: {0,-155}\x1b[0m║\n", string.Join("  ", filters));
            }

            // ── Connection Table ──
            sb.AppendLine("╠═══════╤════════════════════════╤═══════╤════════════════════════╤═══════╤══════════════════════════════════════════════════╤══════╤══════════════════════╤════════════════════╣");
            sb.AppendLine("║ PROTO │     LOCAL ADDRESS      │ LPORT │     REMOTE ADDRESS     │ RPORT │        DUAL-STACK (IPv4 / IPv6)                 │  PID │     APPLICATION      │        USER        ║");
            sb.AppendLine("╠═══════╪════════════════════════╪═══════╪════════════════════════╪═══════╪══════════════════════════════════════════════════╪══════╪══════════════════════╪════════════════════╣");

            // Sort: Newest connections first (by CapturedAtUtc descending)
            var displayConns = filteredList
                .OrderByDescending(c => c.CapturedAtUtc)
                .ThenByDescending(c => c.State == "ESTABLISHED")
                .ThenBy(c => c.Protocol)
                .ThenBy(c => c.LocalPort)
                .ToList();

            // Dynamically limit rows to fit the terminal window height to prevent scrolling and screen shifting
            int maxRows = _options.MaxDisplayRows;
            try
            {
                int headerReserved = ebpfErr != null ? 15 : 14;
                if (Console.WindowHeight > headerReserved + 1)
                {
                    // Leave space for headers, stats, borders, and footer
                    int availableRows = Console.WindowHeight - headerReserved;
                    if (maxRows <= 0 || availableRows < maxRows)
                    {
                        maxRows = Math.Max(5, availableRows);
                    }
                }
            }
            catch
            {
                // Fallback if Console.WindowHeight is not supported (e.g. redirected output)
                if (maxRows <= 0) maxRows = 20;
            }

            if (maxRows > 0 && displayConns.Count > maxRows)
            {
                displayConns = displayConns.Take(maxRows).ToList();
            }

            foreach (var conn in displayConns)
            {
                // Resolve dual-stack information from DNS cache
                string dualStackInfo = FormatDualStack(conn);

                sb.AppendFormat("║ {0,-5} │ {1,-22} │ {2,5} │ {3,-22} │ {4,5} │ {5} │ {6,4} │ {7,-20} │ {8,-18} ║\n",
                    conn.Protocol,
                    Truncate(conn.LocalAddress, 22),
                    conn.LocalPort,
                    Truncate(conn.RemoteAddress, 22),
                    conn.RemotePort,
                    PadOrTruncateAnsi(dualStackInfo, 48),
                    conn.ProcessId > 0 ? conn.ProcessId : 0,
                    Truncate(conn.ProcessName, 20),
                    Truncate(conn.UserName, 18));
            }

            if (maxRows > 0 && connList.Count > maxRows)
            {
                sb.AppendFormat("║  ... and {0} more connections (increase terminal height or filter to see all) ...                                                                                  ║\n",
                    connList.Count - maxRows);
            }

            sb.AppendLine("╚═══════╧════════════════════════╧═══════╧════════════════════════╧═══════╧══════════════════════════════════════════════════╧══════╧══════════════════════╧════════════════════╝");
            // Clear anything below the UI (to remove ghosting from previous frames)
            sb.AppendLine("  Press Ctrl+C to stop monitoring\x1b[J");

            Console.Write(sb.ToString());
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    //  Export
    // ─────────────────────────────────────────────────────────────────────────

    private async Task ExportCurrentStateAsync(CancellationToken ct)
    {
        if (_exporter == null) return;

        try
        {
            var snapshot = new ConnectionSnapshot
            {
                TimestampUtc = DateTime.UtcNow,
                Connections = _liveConnections.Values.ToList(),
            };

            var path = _options.ExportPath;
            await _exporter.ExportAsync(snapshot, path, ct);
            var fullPath = Path.GetFullPath(path + _exporter.FileExtension);
            _logger.LogInformation("Exported {Count} connections to {Path}", snapshot.TotalConnections, fullPath);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to export snapshot");
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    //  Helpers
    // ─────────────────────────────────────────────────────────────────────────

    private static string GetConnectionKey(NetworkConnection conn)
    {
        return $"{conn.Protocol}|{conn.LocalAddress}:{conn.LocalPort}|{conn.RemoteAddress}:{conn.RemotePort}";
    }

    private static string Truncate(string value, int maxLength)
    {
        if (string.IsNullOrEmpty(value)) return string.Empty;
        return value.Length <= maxLength ? value : value[..(maxLength - 1)] + "…";
    }

    private static string FormatUptime(TimeSpan ts)
    {
        if (ts.TotalHours >= 1)
            return $"{(int)ts.TotalHours}h {ts.Minutes}m {ts.Seconds}s";
        if (ts.TotalMinutes >= 1)
            return $"{ts.Minutes}m {ts.Seconds}s";
        return $"{ts.Seconds}s";
    }

    /// <summary>
    /// Formats the dual-stack (IPv4/IPv6) column for a connection using cached DNS results.
    /// Shows the alternate address when dual-stack is detected (the address family NOT shown in REMOTE ADDRESS).
    /// </summary>
    private string FormatDualStack(NetworkConnection conn)
    {
        var dnsResult = _dnsResolver.GetOrStartResolve(conn.RemoteAddress);

        if (dnsResult == null)
            return "\x1b[90mresolving...\x1b[0m";

        bool isIpv6 = conn.RemoteAddress.Contains(':');

        if (dnsResult.HasBothFamilies)
        {
            // Dual-stack: show the alternate address (the one NOT in REMOTE ADDRESS column)
            if (isIpv6)
                return $"\x1b[32m✓\x1b[0m \x1b[36m+v4:\x1b[0m {Truncate(dnsResult.IPv4Address ?? "?", 38)}";
            else
                return $"\x1b[32m✓\x1b[0m \x1b[36m+v6:\x1b[0m {Truncate(dnsResult.IPv6Address ?? "?", 38)}";
        }
        else
        {
            // Single-stack
            if (isIpv6)
                return "\x1b[33mv6 only\x1b[0m";
            else
                return "\x1b[33mv4 only\x1b[0m";
        }
    }

    private static int GetVisibleLength(string text)
    {
        if (string.IsNullOrEmpty(text)) return 0;
        int len = 0;
        bool inAnsi = false;
        for (int i = 0; i < text.Length; i++)
        {
            if (text[i] == '\x1b')
            {
                inAnsi = true;
            }
            else if (inAnsi && text[i] == 'm')
            {
                inAnsi = false;
            }
            else if (!inAnsi)
            {
                len++;
            }
        }
        return len;
    }

    private static string PadOrTruncateAnsi(string text, int width)
    {
        if (string.IsNullOrEmpty(text))
            return new string(' ', width);

        int visibleLength = GetVisibleLength(text);
        if (visibleLength <= width)
        {
            return text + new string(' ', width - visibleLength);
        }

        // We need to truncate. Let's aim for (width - 1) visible chars + '…'
        var sb = new System.Text.StringBuilder();
        int visibleCount = 0;
        int limit = width - 1;
        bool inAnsi = false;

        for (int i = 0; i < text.Length; i++)
        {
            if (text[i] == '\x1b')
            {
                sb.Append(text[i]);
                inAnsi = true;
            }
            else if (inAnsi)
            {
                sb.Append(text[i]);
                if (text[i] == 'm')
                {
                    inAnsi = false;
                }
            }
            else
            {
                if (visibleCount < limit)
                {
                    sb.Append(text[i]);
                    visibleCount++;
                }
                else
                {
                    sb.Append('…');
                    sb.Append("\x1b[0m");
                    break;
                }
            }
        }

        return sb.ToString();
    }

    private static bool IsPidAlive(int pid)
    {
        if (pid <= 0) return true;
        try
        {
            return Directory.Exists($"/proc/{pid}");
        }
        catch
        {
            return false;
        }
    }

    private static string ResolveLocalIpForRemote(string remoteAddress, int remotePort)
    {
        if (string.IsNullOrWhiteSpace(remoteAddress) || remoteAddress == "0.0.0.0" || remoteAddress == "::")
            return remoteAddress.Contains(':') ? "::" : "0.0.0.0";

        try
        {
            if (System.Net.IPAddress.TryParse(remoteAddress, out var remoteIp))
            {
                using var socket = new System.Net.Sockets.Socket(remoteIp.AddressFamily, System.Net.Sockets.SocketType.Dgram, System.Net.Sockets.ProtocolType.Udp);
                // Connect virtually (no packets sent for UDP)
                socket.Connect(remoteIp, remotePort > 0 ? remotePort : 443);
                if (socket.LocalEndPoint is System.Net.IPEndPoint localEp)
                {
                    return localEp.Address.ToString();
                }
            }
        }
        catch
        {
            // Fallback to original
        }

        return remoteAddress.Contains(':') ? "::" : "0.0.0.0";
    }
}
