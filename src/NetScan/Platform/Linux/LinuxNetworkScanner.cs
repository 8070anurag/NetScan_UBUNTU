using Microsoft.Extensions.Logging;
using NetScan.Abstractions;
using NetScan.Configuration;
using NetScan.Models;

namespace NetScan.Platform.Linux;

/// <summary>
/// Linux implementation of INetworkScanner — the "God's Eye" scanner.
/// Reads ALL /proc/net/ files for EVERY socket type the kernel exposes.
/// Supports: TCP, UDP, ICMP, RAW, DCCP, SCTP.
/// </summary>
internal sealed class LinuxNetworkScanner : INetworkScanner
{
    private readonly ILogger<LinuxNetworkScanner> _logger;
    private readonly LinuxProcessResolver _processResolver;
    private readonly MonitoringOptions _options;

    /// <summary>
    /// Standard-format /proc/net/ files (same column layout).
    /// Covers TCP, UDP, ICMP, RAW, UDP-Lite, DCCP — each with IPv4 and IPv6.
    /// </summary>
    private static readonly (string Path, string Protocol, string BaseProto)[] StandardProcFiles =
    [
        // ── Core Transport ──
        ("/proc/net/tcp",       "TCP",     "TCP"),
        ("/proc/net/tcp6",      "TCP",     "TCP"),
        ("/proc/net/udp",       "UDP",     "UDP"),
        ("/proc/net/udp6",      "UDP",     "UDP"),

        // ── Control / Diagnostic ──
        ("/proc/net/icmp",      "ICMP",    "ICMP"),
        ("/proc/net/icmp6",     "ICMP",    "ICMP"),
        ("/proc/net/raw",       "RAW",     "RAW"),
        ("/proc/net/raw6",      "RAW",     "RAW"),

        // ── Extended Transport ──
        ("/proc/net/dccp",      "DCCP",    "DCCP"),
        ("/proc/net/dccp6",     "DCCP",    "DCCP"),
    ];

    public LinuxNetworkScanner(ILogger<LinuxNetworkScanner> logger, MonitoringOptions options)
    {
        _logger = logger;
        _options = options;
        _processResolver = new LinuxProcessResolver(logger);
    }

    /// <inheritdoc />
    public Task<IReadOnlyList<NetworkConnection>> ScanAsync(CancellationToken cancellationToken = default)
    {
        var captureTime = DateTime.UtcNow;
        var allConnections = new List<NetworkConnection>();

        // Invalidate process resolver cache for fresh inode-to-PID mapping
        _processResolver.InvalidateCache();

        // ── Step 1: Parse ALL /proc/net/ sources ──
        var rawConnections = new List<RawConnection>();

        // 1a. Standard-format files (TCP, UDP, ICMP, RAW, DCCP)
        foreach (var (path, protocol, baseProto) in StandardProcFiles)
        {
            cancellationToken.ThrowIfCancellationRequested();

            bool isIpv6 = path.Contains('6');
            if (!_options.IncludeIPv6 && isIpv6)
                continue;

            var parsed = ProcNetParser.ParseStandard(path, baseProto, isIpv6, _logger);
            rawConnections.AddRange(parsed);
        }

        // 1b. SCTP (custom format — requires sctp kernel module)
        rawConnections.AddRange(ProcNetParser.ParseSctpAssociations(_logger));
        rawConnections.AddRange(ProcNetParser.ParseSctpEndpoints(_logger));



        // ── Extended Protocol Sources (ProcNetParserExtended) ──

        // 1f. Conntrack — Netfilter connection tracking (firewall/NAT tracked flows)
        rawConnections.AddRange(ProcNetParserExtended.ParseConntrack(_logger));

        // 1g. ARP — Address Resolution Protocol (network neighbors)
        rawConnections.AddRange(ProcNetParserExtended.ParseArp(_logger));

        // 1h. IGMP — Multicast group memberships (IPv4 and IPv6)
        rawConnections.AddRange(ProcNetParserExtended.ParseIgmp(_logger));
        rawConnections.AddRange(ProcNetParserExtended.ParseIgmp6(_logger));

        // 1i. Bluetooth — L2CAP, RFCOMM, SCO, BNEP, HCI
        rawConnections.AddRange(ProcNetParserExtended.ParseBluetooth(_logger));

        // 1j. IPVS — IP Virtual Server (load balancer connections)
        rawConnections.AddRange(ProcNetParserExtended.ParseIpvs(_logger));

        // 1k. Additional Exotic Protocols (excluding removed protocols)
        rawConnections.AddRange(ProcNetParserExtended.ParseCan(_logger));       // Controller Area Network
        rawConnections.AddRange(ProcNetParserExtended.ParseRds(_logger));       // Reliable Datagram Sockets
        rawConnections.AddRange(ProcNetParserExtended.ParseSmc(_logger));       // Shared Memory Communications
        rawConnections.AddRange(ProcNetParserExtended.ParseL2tp(_logger));      // L2TP
        rawConnections.AddRange(ProcNetParserExtended.ParsePppoe(_logger));     // PPPoE

        // 1m. MPTCP — Multipath TCP (RHEL 8.3+)
        rawConnections.AddRange(ProcNetParserExtended.ParseMptcp(_logger));

        // 1n. CATCH-ALL (The True God's Eye)
        // Scans any remaining file in /proc/net/ that hasn't been explicitly handled
        rawConnections.AddRange(ProcNetParserExtended.ParseCatchAll(_logger));

        _logger.LogDebug("Parsed {Count} raw sockets from all /proc/net/ sources", rawConnections.Count);

        if (rawConnections.Count == 0)
        {
            return Task.FromResult<IReadOnlyList<NetworkConnection>>(allConnections);
        }

        // ── Step 2: Build inode-to-PID mapping (requires root) ──
        var inodeToPid = _processResolver.BuildInodeToPidMap();

        // ── Step 3: Enrich with process and user information ──
        foreach (var raw in rawConnections)
        {
            cancellationToken.ThrowIfCancellationRequested();

            // Apply loopback filter (only for IP-based protocols)
            if (!_options.IncludeLoopback && IsLoopback(raw.LocalAddress))
                continue;

            int pid = inodeToPid.GetValueOrDefault(raw.Inode, -1);
            string processName = _processResolver.GetProcessName(pid);
            string commandLine = _processResolver.GetCommandLine(pid);

            // Use UID from /proc/net when available, else try to resolve from PID
            string userName = raw.Uid >= 0
                ? _processResolver.GetUserName(raw.Uid)
                : (pid > 0 ? _processResolver.GetProcessOwnerFromPid(pid) : "Unknown");

            var connection = new NetworkConnection
            {
                Protocol = raw.Protocol,
                LocalAddress = raw.LocalAddress,
                LocalPort = raw.LocalPort,
                RemoteAddress = raw.RemoteAddress,
                RemotePort = raw.RemotePort,
                State = raw.State,
                ProcessId = pid,
                ProcessName = processName,
                CommandLine = commandLine,
                UserName = userName,
                CapturedAtUtc = captureTime,
            };

            allConnections.Add(connection);
        }

        _logger.LogDebug("Enriched {Count} connections with process/user data", allConnections.Count);

        return Task.FromResult<IReadOnlyList<NetworkConnection>>(allConnections);
    }

    private static bool IsLoopback(string address)
    {
        return address.StartsWith("127.") || address == "::1";
    }
}
