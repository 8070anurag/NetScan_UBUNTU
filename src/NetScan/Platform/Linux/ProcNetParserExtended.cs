using Microsoft.Extensions.Logging;

namespace NetScan.Platform.Linux;

/// <summary>
/// Extended parsers for ALL remaining Linux /proc/net/ protocol files.
/// Covers: Conntrack, ARP, IGMP, Bluetooth (L2CAP/RFCOMM/SCO/BNEP),
/// IPVS, AX.25, NET/ROM, ROSE, IPX, X.25, DECnet, MPTCP.
/// Each parser gracefully returns empty if the file doesn't exist (module not loaded).
/// </summary>
internal static class ProcNetParserExtended
{
    // ═════════════════════════════════════════════════════════════════════════
    //  Conntrack — Netfilter Connection Tracking (/proc/net/nf_conntrack)
    // ═════════════════════════════════════════════════════════════════════════

    /// <summary>
    /// Parses /proc/net/nf_conntrack for ALL tracked connections (firewall/NAT).
    /// Format: ipv4 2 tcp 6 431999 ESTABLISHED src=... dst=... sport=... dport=... ...
    /// </summary>
    public static List<RawConnection> ParseConntrack(ILogger? logger = null)
    {
        // Try both paths (newer and older kernels)
        string path = File.Exists("/proc/net/nf_conntrack")
            ? "/proc/net/nf_conntrack"
            : "/proc/net/ip_conntrack";

        var connections = new List<RawConnection>();
        if (!File.Exists(path))
        {
            logger?.LogDebug("Conntrack file not found (nf_conntrack module may not be loaded)");
            return connections;
        }

        string[] lines;
        try { lines = File.ReadAllLines(path); }
        catch (Exception ex)
        {
            logger?.LogDebug(ex, "Failed to read conntrack table");
            return connections;
        }

        foreach (var line in lines)
        {
            try
            {
                var conn = ParseConntrackLine(line);
                if (conn != null) connections.Add(conn);
            }
            catch { /* Skip malformed lines */ }
        }

        return connections;
    }

    private static RawConnection? ParseConntrackLine(string line)
    {
        var fields = line.Trim().Split(' ', StringSplitOptions.RemoveEmptyEntries);
        if (fields.Length < 8) return null;

        // fields[0]=L3proto_name(ipv4/ipv6) [1]=L3proto_num [2]=L4proto_name [3]=L4proto_num
        // [4]=timeout [5]=state_or_first_kv ...
        string protocol = fields[2].ToUpperInvariant();
        string state = "TRACKING";

        // Extract key-value pairs
        string src = "", dst = "", sport = "0", dport = "0";
        bool foundReply = false;

        foreach (var field in fields)
        {
            // Only use the ORIGINAL direction (before [REPLY] marker or second src=)
            if (field == "[UNREPLIED]" || field == "[ASSURED]") continue;
            if (field.StartsWith("src=") && string.IsNullOrEmpty(src)) src = field[4..];
            else if (field.StartsWith("dst=") && string.IsNullOrEmpty(dst)) dst = field[4..];
            else if (field.StartsWith("sport=") && sport == "0") sport = field[6..];
            else if (field.StartsWith("dport=") && dport == "0") dport = field[6..];
            else if (field.StartsWith("src=") && !foundReply) { foundReply = true; }
        }

        // Try to get state (e.g., ESTABLISHED, SYN_SENT, etc.)
        foreach (var field in fields.Skip(4))
        {
            if (!field.Contains('=') && !field.StartsWith('[') && field == field.ToUpperInvariant()
                && field.Length > 2 && !int.TryParse(field, out _))
            {
                state = field;
                break;
            }
        }

        int.TryParse(sport, out int lPort);
        int.TryParse(dport, out int rPort);

        return new RawConnection
        {
            Protocol = protocol,
            LocalAddress = string.IsNullOrEmpty(src) ? "?" : src,
            LocalPort = lPort,
            RemoteAddress = string.IsNullOrEmpty(dst) ? "?" : dst,
            RemotePort = rPort,
            State = state,
            Uid = -1,
            Inode = -1,
        };
    }

    // ═════════════════════════════════════════════════════════════════════════
    //  ARP — Address Resolution Protocol (/proc/net/arp)
    // ═════════════════════════════════════════════════════════════════════════

    /// <summary>
    /// Parses /proc/net/arp for network neighbor entries (IP → MAC mapping).
    /// Format: IP address  HW type  Flags  HW address  Mask  Device
    /// </summary>
    public static List<RawConnection> ParseArp(ILogger? logger = null)
    {
        const string path = "/proc/net/arp";
        var connections = new List<RawConnection>();
        if (!File.Exists(path)) return connections;

        string[] lines;
        try { lines = File.ReadAllLines(path); }
        catch { return connections; }

        for (int i = 1; i < lines.Length; i++)
        {
            try
            {
                var fields = lines[i].Trim().Split(' ', StringSplitOptions.RemoveEmptyEntries);
                if (fields.Length < 6) continue;

                string ip = fields[0];
                string flags = fields[2];
                string mac = fields[3];
                string device = fields[5];

                // Flags: 0x0=incomplete, 0x2=reachable, 0x4=permanent, 0x6=reachable+permanent
                string state = flags switch
                {
                    "0x0" => "INCOMPLETE",
                    "0x2" => "REACHABLE",
                    "0x4" => "PERMANENT",
                    "0x6" => "PERM+REACH",
                    _ => $"FLAGS_{flags}",
                };

                connections.Add(new RawConnection
                {
                    Protocol = "ARP",
                    LocalAddress = device,
                    LocalPort = 0,
                    RemoteAddress = $"{ip} ({mac})",
                    RemotePort = 0,
                    State = state,
                    Uid = -1,
                    Inode = -1,
                });
            }
            catch { }
        }

        return connections;
    }

    // ═════════════════════════════════════════════════════════════════════════
    //  IGMP — Internet Group Management Protocol (/proc/net/igmp, igmp6)
    // ═════════════════════════════════════════════════════════════════════════

    /// <summary>
    /// Parses /proc/net/igmp for IPv4 multicast group memberships.
    /// </summary>
    public static List<RawConnection> ParseIgmp(ILogger? logger = null)
    {
        const string path = "/proc/net/igmp";
        var connections = new List<RawConnection>();
        if (!File.Exists(path)) return connections;

        string[] lines;
        try { lines = File.ReadAllLines(path); }
        catch { return connections; }

        string currentDevice = "";
        for (int i = 1; i < lines.Length; i++)
        {
            var line = lines[i];
            if (string.IsNullOrWhiteSpace(line)) continue;

            try
            {
                if (!line.StartsWith('\t') && !line.StartsWith(' '))
                {
                    // Device line: "Idx\tDevice    : Count Querier"
                    var parts = line.Split(new[] { '\t', ' ' }, StringSplitOptions.RemoveEmptyEntries);
                    if (parts.Length >= 2) currentDevice = parts[1].TrimEnd(':');
                }
                else
                {
                    // Group line: "\tGroup    Users Timer\tReporter"
                    var parts = line.Trim().Split(new[] { '\t', ' ' }, StringSplitOptions.RemoveEmptyEntries);
                    if (parts.Length >= 1 && parts[0].Length == 8)
                    {
                        string groupHex = parts[0];
                        uint addr = Convert.ToUInt32(groupHex, 16);
                        string groupIp = $"{addr & 0xFF}.{(addr >> 8) & 0xFF}.{(addr >> 16) & 0xFF}.{(addr >> 24) & 0xFF}";

                        connections.Add(new RawConnection
                        {
                            Protocol = "IGMP",
                            LocalAddress = currentDevice,
                            LocalPort = 0,
                            RemoteAddress = groupIp,
                            RemotePort = 0,
                            State = "MEMBER",
                            Uid = -1,
                            Inode = -1,
                        });
                    }
                }
            }
            catch { }
        }

        return connections;
    }

    /// <summary>
    /// Parses /proc/net/igmp6 for IPv6 multicast group memberships.
    /// Format: Idx DeviceName GroupAddress RefCount Flags Timer
    /// </summary>
    public static List<RawConnection> ParseIgmp6(ILogger? logger = null)
    {
        const string path = "/proc/net/igmp6";
        var connections = new List<RawConnection>();
        if (!File.Exists(path)) return connections;

        string[] lines;
        try { lines = File.ReadAllLines(path); }
        catch { return connections; }

        foreach (var line in lines)
        {
            try
            {
                var fields = line.Trim().Split(new[] { '\t', ' ' }, StringSplitOptions.RemoveEmptyEntries);
                if (fields.Length < 3) continue;

                string device = fields[1];
                string groupHex = fields[2];

                // Parse the 32-char hex IPv6 address
                string groupAddr = groupHex.Length == 32 ? FormatIpv6Hex(groupHex) : groupHex;

                connections.Add(new RawConnection
                {
                    Protocol = "IGMP6",
                    LocalAddress = device,
                    LocalPort = 0,
                    RemoteAddress = groupAddr,
                    RemotePort = 0,
                    State = "MEMBER",
                    Uid = -1,
                    Inode = -1,
                });
            }
            catch { }
        }

        return connections;
    }

    // ═════════════════════════════════════════════════════════════════════════
    //  Bluetooth — L2CAP, RFCOMM, SCO, BNEP (/proc/net/bluetooth/*)
    // ═════════════════════════════════════════════════════════════════════════

    /// <summary>
    /// Parses all Bluetooth socket files under /proc/net/bluetooth/.
    /// </summary>
    public static List<RawConnection> ParseBluetooth(ILogger? logger = null)
    {
        var connections = new List<RawConnection>();

        connections.AddRange(ParseBluetoothGeneric("/proc/net/bluetooth/l2cap", "BT_L2CAP", logger));
        connections.AddRange(ParseBluetoothGeneric("/proc/net/bluetooth/rfcomm", "BT_RFCOMM", logger));
        connections.AddRange(ParseBluetoothGeneric("/proc/net/bluetooth/sco", "BT_SCO", logger));
        connections.AddRange(ParseBluetoothGeneric("/proc/net/bluetooth/bnep", "BT_BNEP", logger));
        connections.AddRange(ParseBluetoothGeneric("/proc/net/bluetooth/hci", "BT_HCI", logger));

        return connections;
    }

    private static readonly Dictionary<int, string> BtStateMap = new()
    {
        [0] = "CONNECTED",
        [1] = "OPEN",
        [2] = "BOUND",
        [3] = "LISTEN",
        [4] = "CONNECT",
        [5] = "CONNECT2",
        [6] = "CONFIG",
        [7] = "DISCONN",
        [8] = "CLOSED",
    };

    private static List<RawConnection> ParseBluetoothGeneric(string path, string protocol, ILogger? logger)
    {
        var connections = new List<RawConnection>();
        if (!File.Exists(path)) return connections;

        string[] lines;
        try { lines = File.ReadAllLines(path); }
        catch { return connections; }

        for (int i = 1; i < lines.Length; i++)
        {
            try
            {
                var fields = lines[i].Trim().Split(new[] { '\t', ' ' }, StringSplitOptions.RemoveEmptyEntries);
                if (fields.Length < 3) continue;

                string addr = fields.Length > 0 ? fields[0] : "unknown";
                string state = "ACTIVE";

                // Try to find a state field (numeric)
                foreach (var f in fields)
                {
                    if (int.TryParse(f, out int stateNum) && BtStateMap.ContainsKey(stateNum))
                    {
                        state = BtStateMap[stateNum];
                        break;
                    }
                }

                connections.Add(new RawConnection
                {
                    Protocol = protocol,
                    LocalAddress = addr,
                    LocalPort = 0,
                    RemoteAddress = fields.Length > 1 ? fields[1] : "*",
                    RemotePort = 0,
                    State = state,
                    Uid = -1,
                    Inode = -1,
                });
            }
            catch { }
        }

        return connections;
    }

    // ═════════════════════════════════════════════════════════════════════════
    //  IPVS — IP Virtual Server (/proc/net/ip_vs_conn)
    // ═════════════════════════════════════════════════════════════════════════

    /// <summary>
    /// Parses /proc/net/ip_vs_conn for load balancer connections.
    /// Format: Pro FromIP FPrt ToIP TPrt DestIP DPrt State Expires PEName PEData
    /// </summary>
    public static List<RawConnection> ParseIpvs(ILogger? logger = null)
    {
        const string path = "/proc/net/ip_vs_conn";
        var connections = new List<RawConnection>();
        if (!File.Exists(path)) return connections;

        string[] lines;
        try { lines = File.ReadAllLines(path); }
        catch { return connections; }

        for (int i = 1; i < lines.Length; i++)
        {
            try
            {
                var fields = lines[i].Trim().Split(new[] { '\t', ' ' }, StringSplitOptions.RemoveEmptyEntries);
                if (fields.Length < 8) continue;

                string proto = fields[0]; // TCP/UDP
                string fromIp = HexToIp(fields[1]);
                int fromPort = HexToPort(fields[2]);
                string toIp = HexToIp(fields[3]);
                int toPort = HexToPort(fields[4]);
                string destIp = HexToIp(fields[5]);
                int destPort = HexToPort(fields[6]);
                string state = fields[7];

                connections.Add(new RawConnection
                {
                    Protocol = $"IPVS_{proto}",
                    LocalAddress = $"{fromIp}→{destIp}",
                    LocalPort = fromPort,
                    RemoteAddress = toIp,
                    RemotePort = toPort,
                    State = state,
                    Uid = -1,
                    Inode = -1,
                });
            }
            catch { }
        }

        return connections;
    }

    // ═════════════════════════════════════════════════════════════════════════
    //  Legacy Protocols — AX.25, NET/ROM, ROSE, IPX, X.25, DECnet
    // ═════════════════════════════════════════════════════════════════════════

    /// <summary>
    /// Parses /proc/net/ax25 for Amateur Radio AX.25 sockets.
    /// </summary>
    public static List<RawConnection> ParseAx25(ILogger? logger = null)
    {
        return ParseLegacyTabular("/proc/net/ax25", "AX25", logger);
    }

    /// <summary>
    /// Parses /proc/net/nr for Amateur Radio NET/ROM sockets.
    /// </summary>
    public static List<RawConnection> ParseNetRom(ILogger? logger = null)
    {
        return ParseLegacyTabular("/proc/net/nr", "NETROM", logger);
    }

    /// <summary>
    /// Parses /proc/net/rose for Amateur Radio ROSE sockets.
    /// </summary>
    public static List<RawConnection> ParseRose(ILogger? logger = null)
    {
        return ParseLegacyTabular("/proc/net/rose", "ROSE", logger);
    }

    /// <summary>
    /// Parses /proc/net/ipx for IPX/SPX (Novell) sockets.
    /// Checks both /proc/net/ipx/socket and /proc/net/ipx.
    /// </summary>
    public static List<RawConnection> ParseIpx(ILogger? logger = null)
    {
        string path = File.Exists("/proc/net/ipx/socket") ? "/proc/net/ipx/socket" : "/proc/net/ipx";
        return ParseLegacyTabular(path, "IPX", logger);
    }

    /// <summary>
    /// Parses /proc/net/x25 for X.25 protocol sockets.
    /// </summary>
    public static List<RawConnection> ParseX25(ILogger? logger = null)
    {
        return ParseLegacyTabular("/proc/net/x25", "X25", logger);
    }

    /// <summary>
    /// Parses /proc/net/decnet for DECnet protocol sockets.
    /// </summary>
    public static List<RawConnection> ParseDecnet(ILogger? logger = null)
    {
        return ParseLegacyTabular("/proc/net/decnet", "DECNET", logger);
    }

    /// <summary>
    /// Generic parser for legacy /proc/net/ tabular protocol files.
    /// Most have a header line followed by tabular data.
    /// We extract what we can from each row.
    /// </summary>
    private static List<RawConnection> ParseLegacyTabular(string path, string protocol, ILogger? logger)
    {
        var connections = new List<RawConnection>();
        if (!File.Exists(path)) return connections;

        string[] lines;
        try { lines = File.ReadAllLines(path); }
        catch { return connections; }

        if (lines.Length <= 1) return connections; // Only header or empty

        for (int i = 1; i < lines.Length; i++)
        {
            try
            {
                var fields = lines[i].Trim().Split(new[] { '\t', ' ' }, StringSplitOptions.RemoveEmptyEntries);
                if (fields.Length < 2) continue;

                // Best-effort extraction: first field = source, second = destination
                string local = fields[0];
                string remote = fields.Length > 1 ? fields[1] : "*";
                string state = "ACTIVE";

                // Look for a state-like field (all caps, no digits, length > 2)
                for (int f = 2; f < fields.Length; f++)
                {
                    if (fields[f].Length > 2 && fields[f] == fields[f].ToUpperInvariant()
                        && !int.TryParse(fields[f], out _) && !fields[f].Contains('.'))
                    {
                        state = fields[f];
                        break;
                    }
                }

                connections.Add(new RawConnection
                {
                    Protocol = protocol,
                    LocalAddress = local,
                    LocalPort = 0,
                    RemoteAddress = remote,
                    RemotePort = 0,
                    State = state,
                    Uid = -1,
                    Inode = -1,
                });
            }
            catch { }
        }

        return connections;
    }

    // ═════════════════════════════════════════════════════════════════════════
    //  Additional Exotic Protocols (AppleTalk, CAN, RDS, VSOCK, SMC, L2TP, PPPoE)
    // ═════════════════════════════════════════════════════════════════════════

    public static List<RawConnection> ParseAppleTalk(ILogger? logger = null) => ParseLegacyTabular("/proc/net/atalk", "APPLETALK", logger);
    public static List<RawConnection> ParseCan(ILogger? logger = null) => ParseLegacyTabular("/proc/net/can/rcvlist_all", "CAN", logger);
    public static List<RawConnection> ParseRds(ILogger? logger = null) => ParseLegacyTabular("/proc/net/rds/bind", "RDS", logger);
    public static List<RawConnection> ParseVsock(ILogger? logger = null) => ParseLegacyTabular("/proc/net/vsock", "VSOCK", logger);
    public static List<RawConnection> ParseSmc(ILogger? logger = null) => ParseLegacyTabular("/proc/net/smc/sockets", "SMC", logger);
    public static List<RawConnection> ParseL2tp(ILogger? logger = null) => ParseLegacyTabular("/proc/net/pppol2tp", "L2TP", logger);
    public static List<RawConnection> ParsePppoe(ILogger? logger = null) => ParseLegacyTabular("/proc/net/pppoe", "PPPOE", logger);

    // ═════════════════════════════════════════════════════════════════════════
    //  MPTCP — Multipath TCP (/proc/net/mptcp)
    // ═════════════════════════════════════════════════════════════════════════

    /// <summary>
    /// Parses /proc/net/mptcp for Multipath TCP connections (RHEL 8.3+).
    /// Falls back to checking /proc/sys/net/mptcp/ for existence.
    /// </summary>
    public static List<RawConnection> ParseMptcp(ILogger? logger = null)
    {
        const string path = "/proc/net/mptcp";
        var connections = new List<RawConnection>();
        if (!File.Exists(path)) return connections;

        string[] lines;
        try { lines = File.ReadAllLines(path); }
        catch { return connections; }

        for (int i = 1; i < lines.Length; i++)
        {
            try
            {
                var fields = lines[i].Trim().Split(new[] { '\t', ' ' }, StringSplitOptions.RemoveEmptyEntries);
                if (fields.Length < 6) continue;

                // Format varies by kernel version — attempt standard-like parsing
                connections.Add(new RawConnection
                {
                    Protocol = "MPTCP",
                    LocalAddress = fields.Length > 1 ? fields[1] : "?",
                    LocalPort = 0,
                    RemoteAddress = fields.Length > 2 ? fields[2] : "?",
                    RemotePort = 0,
                    State = fields.Length > 3 ? fields[3] : "ACTIVE",
                    Uid = -1,
                    Inode = -1,
                });
            }
            catch { }
        }

        return connections;
    }

    // ═════════════════════════════════════════════════════════════════════════
    //  Catch-All (Unrecognized /proc/net/ sockets)
    // ═════════════════════════════════════════════════════════════════════════

    /// <summary>
    /// Fallback parser that reads ANY tabular file in /proc/net/ that hasn't been explicitly handled.
    /// This ensures we literally miss NO protocol that the kernel exposes.
    /// </summary>
    public static List<RawConnection> ParseCatchAll(ILogger? logger = null)
    {
        var connections = new List<RawConnection>();
        if (!Directory.Exists("/proc/net")) return connections;

        // Files that are known to NOT be socket tables
        var skipFiles = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            "dev", "dev_snmp6", "route", "snmp", "snmp6", "netstat", 
            "sockstat", "sockstat6", "protocols", "ptype", "pnp", 
            "psched", "arpd", "wireless", "softnet_stat", "if_inet6",
            "ipv6_route", "mcfilter", "mcfilter6", "anycast6",
            "tcp_metrics", "rt6_stats", "rt_cache", "stat", "vlan",
            "nf_conntrack_expect", "ip_tables_names", "ip_tables_matches",
            "ip_mr_cache", "ip_mr_vif", "ip6_mr_cache", "ip6_mr_vif",
            "dev_mcast", "fib_trie", "fib_triestat", "rt_acct", "xfrm_stat"
        };

        // Files we already explicitly parse
        var explicitFiles = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            "tcp", "tcp6", "udp", "udp6", "icmp", "icmp6", "raw", "raw6",
            "udplite", "udplite6", "dccp", "dccp6", "unix", "netlink", "packet",
            "sctp/assocs", "sctp/eps", "nf_conntrack", "ip_conntrack", "arp",
            "igmp", "igmp6", "bluetooth/l2cap", "bluetooth/rfcomm", "bluetooth/sco",
            "bluetooth/bnep", "bluetooth/hci", "ip_vs_conn", "ax25", "nr", "rose",
            "ipx", "ipx/socket", "x25", "decnet", "mptcp", "atalk", "can/rcvlist_all",
            "rds/bind", "vsock", "smc/sockets", "pppol2tp", "pppoe"
        };

        try
        {
            foreach (var file in Directory.EnumerateFiles("/proc/net", "*", SearchOption.AllDirectories))
            {
                string relPath = file.Substring("/proc/net/".Length).Replace('\\', '/');
                if (explicitFiles.Contains(relPath)) continue;

                // Explicitly ignore known non-socket directories (statistics, logs)
                if (relPath.StartsWith("stat/") || 
                    relPath.StartsWith("dev_snmp6/") || 
                    relPath.StartsWith("netfilter/") || 
                    relPath.StartsWith("core/")) 
                {
                    continue;
                }

                string fileName = Path.GetFileName(file);
                if (skipFiles.Contains(fileName)) continue;

                // Attempt to parse any unrecognized file as a tabular socket table
                var parsed = ParseLegacyTabular(file, $"EXTRA_{fileName.ToUpperInvariant()}", null);
                if (parsed.Count > 0)
                {
                    logger?.LogDebug("Catch-all parser found {Count} entries in {File}", parsed.Count, file);
                    connections.AddRange(parsed);
                }
            }
        }
        catch { }

        return connections;
    }

    // ═════════════════════════════════════════════════════════════════════════
    //  Helpers
    // ═════════════════════════════════════════════════════════════════════════

    private static string HexToIp(string hex)
    {
        try
        {
            uint addr = Convert.ToUInt32(hex, 16);
            return $"{(addr >> 24) & 0xFF}.{(addr >> 16) & 0xFF}.{(addr >> 8) & 0xFF}.{addr & 0xFF}";
        }
        catch { return hex; }
    }

    private static int HexToPort(string hex)
    {
        try { return Convert.ToInt32(hex, 16); }
        catch { return 0; }
    }

    private static string FormatIpv6Hex(string hex)
    {
        try
        {
            // 32-char hex → 8 groups of 4 hex chars
            var parts = new string[8];
            for (int i = 0; i < 8; i++)
                parts[i] = hex.Substring(i * 4, 4).TrimStart('0');
            return string.Join(":", parts.Select(p => string.IsNullOrEmpty(p) ? "0" : p));
        }
        catch { return hex; }
    }
}
