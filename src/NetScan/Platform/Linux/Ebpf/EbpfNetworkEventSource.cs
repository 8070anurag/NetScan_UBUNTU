using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Threading.Channels;
using Microsoft.Extensions.Logging;
using NetScan.Abstractions;
using NetScan.Configuration;
using NetScan.Models;

namespace NetScan.Platform.Linux.Ebpf;

/// <summary>
/// eBPF-based implementation of <see cref="INetworkEventSource"/>.
///
/// This is the Linux equivalent of WFP's ALE (Application Layer Enforcement) layers:
///   - FWPM_LAYER_ALE_AUTH_CONNECT_V4/V6 → kprobe on tcp_v4_connect / tcp_v6_connect
///   - FWPM_LAYER_ALE_CONNECT_REDIRECT   → kretprobe on inet_csk_accept
///   - Connection close detection          → tracepoint/sock/inet_sock_set_state
///
/// Unlike the Ftrace-based <see cref="LinuxNetworkEventSource"/>, this implementation
/// receives per-connection events directly from the kernel with full process attribution
/// (PID, process name, UID) included in each event. No /proc/net/ scanning or
/// reconciliation is needed for event detection.
///
/// Architecture:
///   1. Loads a compiled eBPF program (netscan_ebpf.bpf.o) into the kernel via libbpf
///   2. The eBPF program attaches kprobes/tracepoints to kernel functions
///   3. On each connection event, the kernel pushes a structured event to a BPF ring buffer
///   4. This class polls the ring buffer and converts events to NetworkEvent objects
///   5. Events are yielded via IAsyncEnumerable for consumption by LiveMonitorService
///
/// Requirements:
///   - Linux kernel 5.8+ (BPF ring buffer support)
///   - libbpf.so.1 installed on the system
///   - Root privileges (required for loading eBPF programs)
///   - Compiled netscan_ebpf.bpf.o file (build via Makefile)
/// </summary>
internal sealed class EbpfNetworkEventSource : INetworkEventSource
{
    private readonly INetworkScanner _scanner;
    private readonly MonitoringOptions _options;
    private readonly ILogger<EbpfNetworkEventSource> _logger;

    // eBPF resources (native handles)
    private IntPtr _bpfObject = IntPtr.Zero;
    private IntPtr _ringBuffer = IntPtr.Zero;
    private readonly List<IntPtr> _links = new();

    public bool IsEbpfActive { get; private set; }
    public string? EbpfError { get; private set; }

    // We MUST hold a reference to the callback delegate to prevent GC collection
    // while libbpf's native code holds the function pointer.
    private LibBpfInterop.RingBufferCallback? _callbackDelegate;

    // TCP state name lookup (matches Linux kernel tcp_states.h)
    private static readonly Dictionary<int, string> TcpStateNames = new()
    {
        [1]  = "ESTABLISHED",
        [2]  = "SYN_SENT",
        [3]  = "SYN_RECV",
        [4]  = "FIN_WAIT1",
        [5]  = "FIN_WAIT2",
        [6]  = "TIME_WAIT",
        [7]  = "CLOSE",
        [8]  = "CLOSE_WAIT",
        [9]  = "LAST_ACK",
        [10] = "LISTEN",
        [11] = "CLOSING",
        [12] = "NEW_SYN_RECV",
    };

    // Well-known IP protocol numbers (for RAW sockets mapping)
    private static readonly Dictionary<int, string> RawProtocolMap = new()
    {
        [1]   = "ICMP",
        [2]   = "IGMP",
        [6]   = "TCP",
        [17]  = "UDP",
        [41]  = "IPv6",
        [47]  = "GRE",
        [50]  = "ESP",
        [51]  = "AH",
        [58]  = "ICMPv6",
        [89]  = "OSPF",
        [103] = "PIM",
        [132] = "SCTP",
        [255] = "RAW",
    };

    private static string ResolveRawProtocolState(int localPort)
    {
        return RawProtocolMap.GetValueOrDefault(localPort, $"PROTO_{localPort}");
    }



    public EbpfNetworkEventSource(
        INetworkScanner scanner,
        MonitoringOptions options,
        ILogger<EbpfNetworkEventSource> logger)
    {
        _scanner = scanner;
        _options = options;
        _logger = logger;
    }

    /// <inheritdoc />
    public async IAsyncEnumerable<NetworkEvent> MonitorAsync(
        [EnumeratorCancellation] CancellationToken cancellationToken = default)
    {
        _logger.LogInformation("eBPF event source starting — WFP ALE-equivalent mode");

        // Channel to decouple the native ring buffer callback from the async yield
        var channel = Channel.CreateUnbounded<NetworkEvent>(new UnboundedChannelOptions
        {
            SingleReader = true,
            SingleWriter = false, // Ring buffer callback may fire from different threads
        });

        // Start the eBPF polling loop in the background
        var pollTask = Task.Run(() => EbpfPollLoopAsync(channel.Writer, cancellationToken), cancellationToken);

        // Yield events from the channel
        await foreach (var evt in channel.Reader.ReadAllAsync(cancellationToken))
        {
            yield return evt;
        }

        // Ensure poll task completes
        await pollTask;
    }

    /// <summary>
    /// Background task that loads the eBPF program, attaches probes,
    /// and polls the ring buffer for kernel events.
    /// </summary>
    private async Task EbpfPollLoopAsync(ChannelWriter<NetworkEvent> writer, CancellationToken ct)
    {
        try
        {
            // ── Phase 1: Load and attach the eBPF program ──
            if (!LoadAndAttachEbpfProgram())
            {
                IsEbpfActive = false;
                _logger.LogWarning("eBPF loading failed. Falling back to Ftrace/polling mode.");
                await FallbackToScanningAsync(writer, ct);
                return;
            }

            // ── Phase 2: Create ring buffer consumer ──
            var eventsMap = LibBpfInterop.bpf_object__find_map_by_name(_bpfObject, "events");
            if (eventsMap == IntPtr.Zero)
            {
                IsEbpfActive = false;
                EbpfError = "Failed to find 'events' ring buffer map";
                _logger.LogError("Failed to find 'events' ring buffer map in eBPF program");
                await FallbackToScanningAsync(writer, ct);
                return;
            }

            int mapFd = LibBpfInterop.bpf_map__fd(eventsMap);
            if (mapFd < 0)
            {
                IsEbpfActive = false;
                EbpfError = $"Failed to get map file descriptor (fd={mapFd})";
                _logger.LogError("Failed to get file descriptor for events map: fd={Fd}", mapFd);
                await FallbackToScanningAsync(writer, ct);
                return;
            }

            // Create the callback — MUST be stored as a class field to prevent GC!
            _callbackDelegate = (ctx, data, dataSz) =>
            {
                try
                {
                    return HandleEbpfEvent(writer, data, dataSz);
                }
                catch (Exception ex)
                {
                    _logger.LogDebug(ex, "Error processing eBPF event");
                    return 0; // Continue processing
                }
            };

            _ringBuffer = LibBpfInterop.ring_buffer__new(mapFd, _callbackDelegate, IntPtr.Zero, IntPtr.Zero);
            if (_ringBuffer == IntPtr.Zero)
            {
                IsEbpfActive = false;
                EbpfError = "Failed to create ring buffer consumer";
                _logger.LogError("Failed to create ring buffer consumer");
                await FallbackToScanningAsync(writer, ct);
                return;
            }

            IsEbpfActive = true;
            EbpfError = null;
            _logger.LogInformation(
                "eBPF loaded: per-connection kernel callbacks active. " +
                "Hooks: TCP, UDP, RAW/ICMP, DCCP, SCTP, MPTCP, Bluetooth, SMC, CAN, RDS, L2TP, PPPoE. " +
                "Architecture: WFP ALE-equivalent (zero-polling, kernel-push).");

            // ── Phase 3: Also emit initial snapshot as ConnectionOpened events ──
            var initial = await _scanner.ScanAsync(ct);
            foreach (var conn in initial)
            {
                await writer.WriteAsync(new NetworkEvent
                {
                    EventType = NetworkEventType.ConnectionOpened,
                    Connection = conn,
                }, ct);
            }

            _logger.LogDebug("Initial snapshot: {Count} existing connections emitted", initial.Count);

            // ── Phase 4: Poll the ring buffer for kernel events ──
            // ring_buffer__poll blocks until events arrive or timeout expires.
            // This is true event-driven: the kernel pushes events to us.
            while (!ct.IsCancellationRequested)
            {
                // Poll with 100ms timeout — returns number of events consumed
                // The callback (_callbackDelegate) is invoked for each event
                int consumed = LibBpfInterop.ring_buffer__poll(_ringBuffer, 100);

                if (consumed < 0 && !ct.IsCancellationRequested)
                {
                    _logger.LogWarning("ring_buffer__poll returned error: {Error}", consumed);
                    await Task.Delay(500, ct); // Brief backoff on error
                }
            }
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            // Normal shutdown
        }
        catch (DllNotFoundException ex)
        {
            IsEbpfActive = false;
            EbpfError = "libbpf.so.1 not found. Run 'sudo apt install libbpf-dev'";
            _logger.LogWarning(ex,
                "libbpf.so.1 not found. Install libbpf: " +
                "RHEL/CentOS: sudo yum install libbpf-devel | " +
                "Ubuntu: sudo apt install libbpf-dev. " +
                "Falling back to Ftrace/polling mode.");
            await FallbackToScanningAsync(writer, ct);
        }
        catch (Exception ex)
        {
            IsEbpfActive = false;
            EbpfError = $"Exception: {ex.Message}";
            _logger.LogError(ex, "Error in eBPF poll loop");
        }
        finally
        {
            writer.Complete();
        }
    }

    /// <summary>
    /// Loads the compiled eBPF object file and attaches all programs to their kernel targets.
    /// </summary>
    private bool LoadAndAttachEbpfProgram()
    {
        // Search for the compiled .bpf.o file in several locations
        string? bpfObjectPath = FindEbpfObjectFile();
        if (bpfObjectPath == null)
        {
            EbpfError = "netscan_ebpf.bpf.o not found. Please compile it first.";
            _logger.LogError(
                "eBPF object file 'netscan_ebpf.bpf.o' not found. " +
                "Build it: make -C src/NetScan/Platform/Linux/Ebpf/");
            return false;
        }

        _logger.LogInformation("Loading eBPF program from: {Path}", bpfObjectPath);

        // Open the BPF object file
        _bpfObject = LibBpfInterop.bpf_object__open_file(bpfObjectPath, IntPtr.Zero);
        if (_bpfObject == IntPtr.Zero)
        {
            EbpfError = $"Failed to open eBPF object file: {Path.GetFileName(bpfObjectPath)}";
            _logger.LogError("Failed to open eBPF object file: {Path}", bpfObjectPath);
            return false;
        }

        // Load programs and maps into the kernel
        int loadResult = LibBpfInterop.bpf_object__load(_bpfObject);
        if (loadResult != 0)
        {
            EbpfError = $"Failed to load eBPF bytecode (error={loadResult}). Run with sudo/root!";
            _logger.LogError("Failed to load eBPF programs into kernel (error={Error}). " +
                "Possible causes: kernel too old (need 5.8+), insufficient privileges, " +
                "or CONFIG_DEBUG_INFO_BTF not enabled.", loadResult);
            LibBpfInterop.bpf_object__close(_bpfObject);
            _bpfObject = IntPtr.Zero;
            return false;
        }

        _logger.LogInformation("eBPF programs loaded into kernel successfully");

        // Attach all programs
        var programNames = new[]
        {
            // ── TCP ──
            "trace_tcp_v4_connect_entry",   // kprobe/tcp_v4_connect
            "trace_tcp_v4_connect_exit",    // kretprobe/tcp_v4_connect
            "trace_tcp_v6_connect_entry",   // kprobe/tcp_v6_connect
            "trace_tcp_v6_connect_exit",    // kretprobe/tcp_v6_connect
            "trace_inet_csk_accept",        // kretprobe/inet_csk_accept
            "trace_inet_sock_set_state",    // tracepoint/sock/inet_sock_set_state
            "trace_tcp_sendmsg_entry",      // kprobe/tcp_sendmsg
            "trace_tcp_sendmsg_exit",       // kretprobe/tcp_sendmsg
            // ── UDP ──
            "trace_udp_sendmsg_entry",      // kprobe/udp_sendmsg
            "trace_udp_sendmsg_exit",       // kretprobe/udp_sendmsg
            "trace_udpv6_sendmsg_entry",    // kprobe/udpv6_sendmsg
            "trace_udpv6_sendmsg_exit",     // kretprobe/udpv6_sendmsg
            // ── RAW / ICMP / Ping ──
            "trace_raw_sendmsg_entry",      // kprobe/raw_sendmsg
            "trace_raw_sendmsg_exit",       // kretprobe/raw_sendmsg
            "trace_rawv6_sendmsg_entry",    // kprobe/rawv6_sendmsg
            "trace_rawv6_sendmsg_exit",     // kretprobe/rawv6_sendmsg
            "trace_ping_v4_sendmsg_entry",  // kprobe/ping_v4_sendmsg
            "trace_ping_v4_sendmsg_exit",   // kretprobe/ping_v4_sendmsg
            "trace_ping_v6_sendmsg_entry",  // kprobe/ping_v6_sendmsg
            "trace_ping_v6_sendmsg_exit",   // kretprobe/ping_v6_sendmsg
            // ── DCCP ──
            "trace_dccp_sendmsg_entry",     // kprobe/dccp_sendmsg
            "trace_dccp_sendmsg_exit",      // kretprobe/dccp_sendmsg
            // ── SCTP ──
            "trace_sctp_sendmsg_entry",     // kprobe/sctp_sendmsg
            "trace_sctp_sendmsg_exit",      // kretprobe/sctp_sendmsg
            // ── UDP Receive (incoming — catches silent listeners) ──
            "trace_udp_recvmsg_entry",      // kprobe/udp_recvmsg
            "trace_udp_recvmsg_exit",       // kretprobe/udp_recvmsg
            "trace_udpv6_recvmsg_entry",    // kprobe/udpv6_recvmsg
            "trace_udpv6_recvmsg_exit",     // kretprobe/udpv6_recvmsg
            // ── Bluetooth (L2CAP, RFCOMM, SCO) ──
            "trace_l2cap_sock_sendmsg_entry",     // kprobe/l2cap_sock_sendmsg
            "trace_l2cap_sock_sendmsg_exit",      // kretprobe/l2cap_sock_sendmsg
            "trace_rfcomm_sock_sendmsg_entry",    // kprobe/rfcomm_sock_sendmsg
            "trace_rfcomm_sock_sendmsg_exit",     // kretprobe/rfcomm_sock_sendmsg
            "trace_sco_sock_sendmsg_entry",       // kprobe/sco_sock_sendmsg
            "trace_sco_sock_sendmsg_exit",        // kretprobe/sco_sock_sendmsg
            // ── SMC (Shared Memory Communications) ──
            "trace_smc_sendmsg_entry",             // kprobe/smc_sendmsg
            "trace_smc_sendmsg_exit",              // kretprobe/smc_sendmsg
            // ── CAN (Controller Area Network) ──
            "trace_can_send_entry",                // kprobe/can_send
            // ── RDS (Reliable Datagram Sockets) ──
            "trace_rds_sendmsg_entry",             // kprobe/rds_sendmsg
            "trace_rds_sendmsg_exit",              // kretprobe/rds_sendmsg
            // ── MPTCP (Multipath TCP) ──
            "trace_mptcp_sendmsg_entry",           // kprobe/mptcp_sendmsg
            "trace_mptcp_sendmsg_exit",            // kretprobe/mptcp_sendmsg
            // ── L2TP (Layer 2 Tunneling) ──
            "trace_l2tp_ip_sendmsg_entry",         // kprobe/l2tp_ip_sendmsg
            "trace_l2tp_ip_sendmsg_exit",          // kretprobe/l2tp_ip_sendmsg
            // ── PPPoE ──
            "trace_pppoe_sendmsg_entry",           // kprobe/pppoe_sendmsg
            "trace_pppoe_sendmsg_exit",            // kretprobe/pppoe_sendmsg
            // ── Kernel-Internal Protocols ──
            "trace_arp_send",                      // kprobe/arp_send
            "trace_igmp_join",                     // kprobe/ip_mc_join_group
            "trace_igmp_leave",                    // kprobe/ip_mc_leave_group
            "trace_conntrack_confirm",             // kprobe/__nf_conntrack_confirm
            "trace_ipvs_conn_new",                 // kprobe/ip_vs_conn_new
        };

        foreach (var name in programNames)
        {
            var prog = LibBpfInterop.bpf_object__find_program_by_name(_bpfObject, name);
            if (prog == IntPtr.Zero)
            {
                _logger.LogWarning("eBPF program '{Name}' not found in object file", name);
                continue;
            }

            var link = LibBpfInterop.bpf_program__attach(prog);
            if (link == IntPtr.Zero)
            {
                _logger.LogWarning("Failed to attach eBPF program '{Name}'", name);
                continue;
            }

            _links.Add(link);
            _logger.LogDebug("Attached eBPF program: {Name}", name);
        }

        if (_links.Count == 0)
        {
            _logger.LogError("No eBPF programs could be attached");
            LibBpfInterop.bpf_object__close(_bpfObject);
            _bpfObject = IntPtr.Zero;
            return false;
        }

        _logger.LogInformation("Attached {Count}/{Total} eBPF hooks to kernel",
            _links.Count, programNames.Length);
        return true;
    }

    /// <summary>
    /// Handles a single event received from the eBPF ring buffer.
    /// Called by libbpf's ring_buffer__poll for each kernel event.
    /// </summary>
    private int HandleEbpfEvent(ChannelWriter<NetworkEvent> writer, IntPtr data, UIntPtr dataSz)
    {
        int size = (int)dataSz.ToUInt32();
        if (size < Marshal.SizeOf<NetscanEbpfEvent>())
            return 0; // Ignore malformed events

        // Marshal the raw kernel data to our managed struct
        var evt = Marshal.PtrToStructure<NetscanEbpfEvent>(data);

        // Filter out IPv6 events early if configured to not include IPv6
        if (!_options.IncludeIPv6 && evt.IpVersion == 6)
            return 0;

        // Convert to NetScan's NetworkEvent model
        var networkEvent = ConvertToNetworkEvent(evt);
        if (networkEvent != null)
        {
            // Non-blocking write to the channel
            writer.TryWrite(networkEvent);
        }

        return 0; // Continue processing
    }

    /// <summary>
    /// Converts an eBPF kernel event to a NetScan NetworkEvent.
    /// </summary>
    private NetworkEvent? ConvertToNetworkEvent(NetscanEbpfEvent evt)
    {
        // Determine event type
        NetworkEventType eventType;
        switch (evt.EventType)
        {
            case NetscanEventType.Connect:
            case NetscanEventType.Accept:
            case NetscanEventType.State:
                eventType = NetworkEventType.ConnectionOpened;
                break;
            case NetscanEventType.Close:
                eventType = NetworkEventType.ConnectionClosed;
                break;
            default:
                return null;
        }

        // Resolve state name
        string state;
        if (evt.Protocol == 255)
        {
            // For RAW sockets, the "state" is the underlying IP protocol resolved from the local port (Sport)
            state = ResolveRawProtocolState(evt.Sport);
        }
        else if (evt.Protocol == 204)
        {
            // Bluetooth: sport carries socket type, dport carries BT protocol
            state = evt.Dport switch { 0 => "L2CAP", 1 => "HCI", 2 => "SCO", 3 => "RFCOMM", 5 => "BNEP", 6 => "CMTP", 7 => "HIDP", _ => $"BT_PROTO_{evt.Dport}" };
        }
        else if (evt.Protocol == 218)
        {
            // ARP: sport carries ARP type (1=REQUEST, 2=REPLY)
            state = evt.Sport switch { 1 => "REQUEST", 2 => "REPLY", _ => $"ARP_TYPE_{evt.Sport}" };
        }
        else if (evt.Protocol == 219)
        {
            // IGMP: event type determines JOIN
            state = "JOIN";
        }
        else if (evt.EventType == NetscanEventType.State)
        {
            state = TcpStateNames.GetValueOrDefault(evt.NewState, $"STATE_{evt.NewState}");
        }
        else if (evt.EventType == NetscanEventType.Accept)
        {
            state = "ESTABLISHED";
        }
        else
        {
            state = evt.Protocol switch
            {
                6 => "SYN_SENT",
                33 => "REQUESTING",  // DCCP equivalent of SYN_SENT
                _ => "ACTIVE",       // Generic for SCTP, UDP-Lite, etc.
            };
        }

        // Resolve user name from UID
        string userName = ResolveUserName((int)evt.Uid);

        // Determine protocol name
        string protocolName = evt.Protocol switch
        {
            6 => "TCP",
            17 => "UDP",
            33 => "DCCP",
            132 => "SCTP",
            204 => "BLUETOOTH",
            205 => "SMC",
            206 => "CAN",
            207 => "RDS",
            208 => "MPTCP",
            209 => "L2TP",
            210 => "PPPOE",
            218 => "ARP",
            219 => "IGMP",
            220 => "CONNTRACK",
            221 => "IPVS",
            255 => "RAW",
            _ => $"PROTO_{evt.Protocol}"
        };

        // Build the connection record — non-IP protocols get special address formatting
        string localAddress, remoteAddress;
        int localPort, remotePort;

        if (evt.Protocol >= 200)
        {
            // Non-IP protocols: use descriptive addresses
            localAddress = protocolName.ToLowerInvariant() + "://local";
            remoteAddress = protocolName.ToLowerInvariant() + "://peer";
            localPort = evt.Sport;
            remotePort = evt.Dport;
        }
        else
        {
            localAddress = evt.GetSourceAddress();
            remoteAddress = evt.GetDestinationAddress();
            localPort = evt.Sport;
            remotePort = evt.Dport;
        }

        var connection = new NetworkConnection
        {
            Protocol = protocolName,
            LocalAddress = localAddress,
            LocalPort = localPort,
            RemoteAddress = remoteAddress,
            RemotePort = remotePort,
            State = state,
            ProcessId = (int)evt.Pid,
            ProcessName = GetMainProcessName((int)evt.Pid, evt.GetProcessName()),
            UserName = userName,
            CommandLine = ReadCommandLine((int)evt.Pid),
            CapturedAtUtc = DateTime.UtcNow,
        };

        return new NetworkEvent
        {
            EventType = eventType,
            Connection = connection,
        };
    }

    private static string GetMainProcessName(int pid, string fallback)
    {
        if (pid <= 0) return ProcessNameNormalizer.Normalize(fallback);
        try
        {
            var commPath = $"/proc/{pid}/comm";
            if (File.Exists(commPath))
            {
                return ProcessNameNormalizer.Normalize(File.ReadAllText(commPath));
            }
        }
        catch { }
        return ProcessNameNormalizer.Normalize(fallback);
    }

    /// <summary>
    /// Fallback: if eBPF fails, use the existing scanner-based reconciliation approach.
    /// This ensures the application always works, even on older kernels.
    /// </summary>
    private async Task FallbackToScanningAsync(ChannelWriter<NetworkEvent> writer, CancellationToken ct)
    {
        _logger.LogInformation("Running in fallback mode: scan-based change detection (no eBPF)");

        var currentState = new Dictionary<string, NetworkConnection>();

        // Initial snapshot
        var initial = await _scanner.ScanAsync(ct);
        foreach (var conn in initial)
        {
            var key = GetConnectionKey(conn);
            if (currentState.TryAdd(key, conn))
            {
                await writer.WriteAsync(new NetworkEvent
                {
                    EventType = NetworkEventType.ConnectionOpened,
                    Connection = conn,
                }, ct);
            }
        }

        // Polling loop
        int intervalMs = Math.Max(_options.EventScanIntervalMs, 50);
        while (!ct.IsCancellationRequested)
        {
            await Task.Delay(intervalMs, ct);

            var latest = await _scanner.ScanAsync(ct);
            var latestMap = new Dictionary<string, NetworkConnection>();

            foreach (var conn in latest)
            {
                var key = GetConnectionKey(conn);
                latestMap.TryAdd(key, conn);
            }

            // Detect new or updated connections
            foreach (var kvp in latestMap)
            {
                if (!currentState.TryGetValue(kvp.Key, out var currentConn) || currentConn.State != kvp.Value.State)
                {
                    await writer.WriteAsync(new NetworkEvent
                    {
                        EventType = NetworkEventType.ConnectionOpened,
                        Connection = kvp.Value,
                    }, ct);
                }
            }

            // Detect closed connections
            foreach (var kvp in currentState)
            {
                if (!latestMap.ContainsKey(kvp.Key))
                {
                    await writer.WriteAsync(new NetworkEvent
                    {
                        EventType = NetworkEventType.ConnectionClosed,
                        Connection = kvp.Value,
                    }, ct);
                }
            }

            currentState = latestMap;
        }
    }

    /// <inheritdoc />
    public async Task<IReadOnlyList<NetworkConnection>> GetCurrentConnectionsAsync(
        CancellationToken cancellationToken = default)
    {
        // Snapshot mode always uses the /proc/net/ scanner
        return await _scanner.ScanAsync(cancellationToken);
    }

    /// <inheritdoc />
    public ValueTask DisposeAsync()
    {
        // Detach all eBPF programs
        foreach (var link in _links)
        {
            if (link != IntPtr.Zero)
            {
                try { LibBpfInterop.bpf_link__destroy(link); }
                catch { /* Ignore cleanup errors */ }
            }
        }
        _links.Clear();

        // Free ring buffer
        if (_ringBuffer != IntPtr.Zero)
        {
            try { LibBpfInterop.ring_buffer__free(_ringBuffer); }
            catch { }
            _ringBuffer = IntPtr.Zero;
        }

        // Close BPF object (unloads programs from kernel)
        if (_bpfObject != IntPtr.Zero)
        {
            try { LibBpfInterop.bpf_object__close(_bpfObject); }
            catch { }
            _bpfObject = IntPtr.Zero;
        }

        _callbackDelegate = null;

        _logger.LogInformation("eBPF programs detached and unloaded from kernel");
        return ValueTask.CompletedTask;
    }

    // ─────────────────────────────────────────────────────────────
    //  Helpers
    // ─────────────────────────────────────────────────────────────

    /// <summary>
    /// Searches for the compiled eBPF object file in several locations.
    /// </summary>
    private static string? FindEbpfObjectFile()
    {
        var candidates = new[]
        {
            // Same directory as the .NET binary
            Path.Combine(AppContext.BaseDirectory, "netscan_ebpf.bpf.o"),
            // Source directory
            Path.Combine(AppContext.BaseDirectory, "..", "..", "..", "Platform", "Linux", "Ebpf", "netscan_ebpf.bpf.o"),
            // Current working directory
            Path.Combine(Directory.GetCurrentDirectory(), "netscan_ebpf.bpf.o"),
            // Absolute path in source tree
            "src/NetScan/Platform/Linux/Ebpf/netscan_ebpf.bpf.o",
        };

        foreach (var path in candidates)
        {
            if (File.Exists(path))
                return Path.GetFullPath(path);
        }

        return null;
    }

    private static string GetConnectionKey(NetworkConnection conn)
    {
        return $"{conn.Protocol}|{conn.LocalAddress}:{conn.LocalPort}|{conn.RemoteAddress}:{conn.RemotePort}";
    }

    /// <summary>
    /// Reads the full command line for a process from /proc/[pid]/cmdline.
    /// </summary>
    private static string ReadCommandLine(int pid)
    {
        if (pid <= 0) return string.Empty;
        try
        {
            var path = $"/proc/{pid}/cmdline";
            if (!File.Exists(path)) return string.Empty;
            var raw = File.ReadAllBytes(path);
            return System.Text.Encoding.UTF8.GetString(raw).Replace('\0', ' ').Trim();
        }
        catch
        {
            return string.Empty;
        }
    }

    /// <summary>
    /// Resolves a UID to username via /etc/passwd.
    /// Uses a simple cache to avoid repeated file reads.
    /// </summary>
    private static readonly Lazy<Dictionary<int, string>> UidCache = new(() =>
    {
        var map = new Dictionary<int, string>();
        try
        {
            if (File.Exists("/etc/passwd"))
            {
                foreach (var line in File.ReadAllLines("/etc/passwd"))
                {
                    if (string.IsNullOrWhiteSpace(line) || line.StartsWith('#')) continue;
                    var parts = line.Split(':');
                    if (parts.Length >= 3 && int.TryParse(parts[2], out int uid))
                        map.TryAdd(uid, parts[0]);
                }
            }
        }
        catch { }
        return map;
    });

    private static string ResolveUserName(int uid)
    {
        if (uid < 0) return "Unknown";
        return UidCache.Value.GetValueOrDefault(uid, $"uid:{uid}");
    }
}
