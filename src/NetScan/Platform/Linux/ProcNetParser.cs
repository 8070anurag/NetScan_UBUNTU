using System.Net;
using Microsoft.Extensions.Logging;

namespace NetScan.Platform.Linux;

/// <summary>
/// Parses /proc/net/ files for ALL socket types available on Linux.
/// Standard format: TCP, UDP, ICMP, RAW, UDP-Lite, DCCP
/// Custom format:   SCTP, Unix Domain, Netlink, Packet
/// </summary>
internal static class ProcNetParser
{
    // ═════════════════════════════════════════════════════════════════════════
    //  State / Type Lookup Tables
    // ═════════════════════════════════════════════════════════════════════════

    /// <summary>TCP/DCCP connection state codes from the Linux kernel.</summary>
    private static readonly Dictionary<string, string> TcpStateMap = new(StringComparer.OrdinalIgnoreCase)
    {
        ["01"] = "ESTABLISHED",
        ["02"] = "SYN_SENT",
        ["03"] = "SYN_RECV",
        ["04"] = "FIN_WAIT1",
        ["05"] = "FIN_WAIT2",
        ["06"] = "TIME_WAIT",
        ["07"] = "CLOSE",
        ["08"] = "CLOSE_WAIT",
        ["09"] = "LAST_ACK",
        ["0A"] = "LISTEN",
        ["0B"] = "CLOSING",
    };

    /// <summary>SCTP association state codes.</summary>
    private static readonly Dictionary<int, string> SctpStateMap = new()
    {
        [0] = "EMPTY",
        [1] = "CLOSED",
        [2] = "COOKIE_WAIT",
        [3] = "COOKIE_ECHOED",
        [4] = "ESTABLISHED",
        [5] = "SHUTDOWN_PENDING",
        [6] = "SHUTDOWN_SENT",
        [7] = "SHUTDOWN_RECEIVED",
        [8] = "SHUTDOWN_ACK_SENT",
    };

    /// <summary>ICMP type names for common types.</summary>
    private static readonly Dictionary<int, string> IcmpTypeMap = new()
    {
        [0]  = "ECHO_REPLY",
        [3]  = "DEST_UNREACH",
        [5]  = "REDIRECT",
        [8]  = "ECHO_REQUEST",
        [11] = "TIME_EXCEEDED",
        [13] = "TIMESTAMP",
        [14] = "TIMESTAMP_REPLY",
    };

    /// <summary>Well-known IP protocol numbers (for RAW sockets).</summary>
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

    /// <summary>Unix socket type names.</summary>
    private static readonly Dictionary<int, string> UnixTypeMap = new()
    {
        [1] = "STREAM",
        [2] = "DGRAM",
        [5] = "SEQPACKET",
    };

    /// <summary>Unix socket state names.</summary>
    private static readonly Dictionary<int, string> UnixStateMap = new()
    {
        [0] = "UNCONNECTED",
        [1] = "LISTENING",
        [2] = "CONNECTING",
        [3] = "CONNECTED",
        [4] = "DISCONNECTING",
    };

    /// <summary>Netlink protocol family names.</summary>
    private static readonly Dictionary<int, string> NetlinkProtocolMap = new()
    {
        [0]  = "ROUTE",
        [2]  = "USERSOCK",
        [3]  = "FIREWALL",
        [4]  = "SOCK_DIAG",
        [5]  = "NFLOG",
        [6]  = "XFRM",
        [7]  = "SELINUX",
        [8]  = "ISCSI",
        [9]  = "AUDIT",
        [10] = "FIB_LOOKUP",
        [11] = "CONNECTOR",
        [12] = "NETFILTER",
        [13] = "IP6_FW",
        [14] = "DNRTMSG",
        [15] = "KOBJECT_UEVENT",
        [16] = "GENERIC",
        [18] = "SCSITRANSPORT",
        [19] = "ECRYPTFS",
        [20] = "RDMA",
        [21] = "CRYPTO",
        [22] = "SMC",
    };

    /// <summary>Well-known Ethernet protocol types (for packet sockets).</summary>
    private static readonly Dictionary<int, string> EthProtocolMap = new()
    {
        [0x0003] = "ETH_ALL",
        [0x0004] = "802.2",
        [0x0800] = "IPv4",
        [0x0806] = "ARP",
        [0x8035] = "RARP",
        [0x8100] = "802.1Q",
        [0x86DD] = "IPv6",
        [0x8863] = "PPPoE_D",
        [0x8864] = "PPPoE_S",
        [0x88A8] = "802.1ad",
        [0x88CC] = "LLDP",
    };

    // ═════════════════════════════════════════════════════════════════════════
    //  Standard /proc/net/ parser (TCP, UDP, ICMP, RAW, DCCP)
    // ═════════════════════════════════════════════════════════════════════════

    /// <summary>
    /// Parses a standard-format /proc/net/ file (tcp, udp, icmp, raw, dccp).
    /// </summary>
    public static List<RawConnection> ParseStandard(string filePath, string protocol, bool isIpv6, ILogger? logger = null)
    {
        var connections = new List<RawConnection>();

        if (!File.Exists(filePath))
        {
            // TCP/UDP are essential; others are optional kernel modules
            if (protocol == "TCP" || protocol == "UDP")
                logger?.LogWarning("Proc net file not found: {FilePath}", filePath);
            else
                logger?.LogDebug("Optional proc net file not found: {FilePath}", filePath);
            return connections;
        }

        string[] lines;
        try
        {
            lines = File.ReadAllLines(filePath);
        }
        catch (Exception ex)
        {
            logger?.LogError(ex, "Failed to read {FilePath}", filePath);
            return connections;
        }

        for (int i = 1; i < lines.Length; i++)
        {
            try
            {
                var conn = ParseStandardLine(lines[i], protocol, isIpv6);
                if (conn != null)
                    connections.Add(conn);
            }
            catch (Exception ex)
            {
                logger?.LogDebug(ex, "Failed to parse line {LineNumber} in {FilePath}: {Line}",
                    i + 1, filePath, lines[i].Trim());
            }
        }

        return connections;
    }

    private static RawConnection? ParseStandardLine(string line, string protocol, bool isIpv6)
    {
        var trimmed = line.Trim();
        if (string.IsNullOrEmpty(trimmed))
            return null;

        var fields = trimmed.Split(' ', StringSplitOptions.RemoveEmptyEntries);
        if (fields.Length < 10)
            return null;

        // [0]=sl [1]=local_address [2]=rem_address [3]=st [4]=tx_queue:rx_queue
        // [5]=tr:tm->when [6]=retrnsmt [7]=uid [8]=timeout [9]=inode

        var (localAddr, localPort) = ParseHexAddress(fields[1], isIpv6);
        var (remoteAddr, remotePort) = ParseHexAddress(fields[2], isIpv6);

        string state = ResolveState(protocol, fields[3], remoteAddr, remotePort, localPort);

        if (!int.TryParse(fields[7], out int uid))
            uid = -1;

        if (!long.TryParse(fields[9], out long inode))
            inode = -1;

        return new RawConnection
        {
            Protocol = protocol,
            LocalAddress = localAddr,
            LocalPort = localPort,
            RemoteAddress = remoteAddr,
            RemotePort = remotePort,
            State = state,
            Uid = uid,
            Inode = inode,
        };
    }

    private static string ResolveState(string protocol, string stateHex, string remoteAddr, int remotePort, int localPort)
    {
        switch (protocol)
        {
            case "TCP":
            case "DCCP":
                return TcpStateMap.GetValueOrDefault(stateHex, "UNKNOWN");

            case "UDP":
                return (remoteAddr == "0.0.0.0" || remoteAddr == "::") && remotePort == 0
                    ? "UNCONNECTED"
                    : "ESTABLISHED";

            case "ICMP":
                if (int.TryParse(stateHex, System.Globalization.NumberStyles.HexNumber, null, out int icmpType))
                    return IcmpTypeMap.GetValueOrDefault(icmpType, $"TYPE_{icmpType}");
                return "OPEN";

            case "RAW":
                return RawProtocolMap.GetValueOrDefault(localPort, $"PROTO_{localPort}");

            default:
                return "UNKNOWN";
        }
    }

    // ═════════════════════════════════════════════════════════════════════════
    //  SCTP parsers (/proc/net/sctp/assocs and /proc/net/sctp/eps)
    // ═════════════════════════════════════════════════════════════════════════

    /// <summary>
    /// Parses /proc/net/sctp/assocs for active SCTP associations.
    /// </summary>
    public static List<RawConnection> ParseSctpAssociations(ILogger? logger = null)
    {
        const string path = "/proc/net/sctp/assocs";
        var connections = new List<RawConnection>();

        if (!File.Exists(path))
        {
            logger?.LogDebug("SCTP associations file not found (sctp module may not be loaded)");
            return connections;
        }

        string[] lines;
        try { lines = File.ReadAllLines(path); }
        catch (Exception ex)
        {
            logger?.LogDebug(ex, "Failed to read SCTP associations");
            return connections;
        }

        for (int i = 1; i < lines.Length; i++)
        {
            try
            {
                var conn = ParseSctpAssocLine(lines[i]);
                if (conn != null) connections.Add(conn);
            }
            catch (Exception ex)
            {
                logger?.LogDebug(ex, "Failed to parse SCTP assoc line {LineNumber}", i + 1);
            }
        }

        return connections;
    }

    private static RawConnection? ParseSctpAssocLine(string line)
    {
        var fields = line.Trim().Split(' ', StringSplitOptions.RemoveEmptyEntries);
        if (fields.Length < 15) return null;

        // ASSOC SOCK STY SST ST HBKT ASSOC-ID TX_QUEUE RX_QUEUE UID INODE LPORT RPORT LADDRS <-> RADDRS
        int.TryParse(fields[4], out int stateCode);
        int.TryParse(fields[9], out int uid);
        long.TryParse(fields[10], out long inode);
        int.TryParse(fields[11], out int localPort);
        int.TryParse(fields[12], out int remotePort);

        string localAddr = "0.0.0.0", remoteAddr = "0.0.0.0";
        int arrowIdx = Array.IndexOf(fields, "<->");
        if (arrowIdx > 13 && arrowIdx < fields.Length - 1)
        {
            localAddr = fields[13];
            remoteAddr = fields[arrowIdx + 1];
        }
        else if (fields.Length > 13)
        {
            localAddr = fields[13];
        }

        return new RawConnection
        {
            Protocol = "SCTP",
            LocalAddress = localAddr, LocalPort = localPort,
            RemoteAddress = remoteAddr, RemotePort = remotePort,
            State = SctpStateMap.GetValueOrDefault(stateCode, $"STATE_{stateCode}"),
            Uid = uid, Inode = inode,
        };
    }

    /// <summary>
    /// Parses /proc/net/sctp/eps for SCTP listening endpoints.
    /// </summary>
    public static List<RawConnection> ParseSctpEndpoints(ILogger? logger = null)
    {
        const string path = "/proc/net/sctp/eps";
        var connections = new List<RawConnection>();

        if (!File.Exists(path)) return connections;

        string[] lines;
        try { lines = File.ReadAllLines(path); }
        catch (Exception ex)
        {
            logger?.LogDebug(ex, "Failed to read SCTP endpoints");
            return connections;
        }

        for (int i = 1; i < lines.Length; i++)
        {
            try
            {
                var conn = ParseSctpEpLine(lines[i]);
                if (conn != null) connections.Add(conn);
            }
            catch (Exception ex)
            {
                logger?.LogDebug(ex, "Failed to parse SCTP endpoint line {LineNumber}", i + 1);
            }
        }

        return connections;
    }

    private static RawConnection? ParseSctpEpLine(string line)
    {
        var fields = line.Trim().Split(' ', StringSplitOptions.RemoveEmptyEntries);
        if (fields.Length < 8) return null;

        // ENDPT SOCK STY SST HBKT LPORT UID INODE LADDRS...
        int.TryParse(fields[5], out int localPort);
        int.TryParse(fields[6], out int uid);
        long.TryParse(fields[7], out long inode);
        string localAddr = fields.Length > 8 ? fields[8] : "0.0.0.0";

        return new RawConnection
        {
            Protocol = "SCTP",
            LocalAddress = localAddr, LocalPort = localPort,
            RemoteAddress = "*", RemotePort = 0,
            State = "LISTEN",
            Uid = uid, Inode = inode,
        };
    }

    // ═════════════════════════════════════════════════════════════════════════
    //  Unix Domain Sockets (/proc/net/unix)
    // ═════════════════════════════════════════════════════════════════════════

    /// <summary>
    /// Parses /proc/net/unix for Unix domain sockets.
    /// Format: Num RefCount Protocol Flags Type St Inode Path
    /// </summary>
    public static List<RawConnection> ParseUnixSockets(ILogger? logger = null)
    {
        const string path = "/proc/net/unix";
        var connections = new List<RawConnection>();

        if (!File.Exists(path))
        {
            logger?.LogWarning("Unix socket file not found: {Path}", path);
            return connections;
        }

        string[] lines;
        try { lines = File.ReadAllLines(path); }
        catch (Exception ex)
        {
            logger?.LogError(ex, "Failed to read Unix sockets");
            return connections;
        }

        for (int i = 1; i < lines.Length; i++)
        {
            try
            {
                var conn = ParseUnixLine(lines[i]);
                if (conn != null) connections.Add(conn);
            }
            catch (Exception ex)
            {
                logger?.LogDebug(ex, "Failed to parse Unix socket line {LineNumber}", i + 1);
            }
        }

        return connections;
    }

    private static RawConnection? ParseUnixLine(string line)
    {
        var trimmed = line.Trim();
        if (string.IsNullOrEmpty(trimmed)) return null;

        // Num: RefCount Protocol Flags Type St Inode [Path]
        // The path field is optional and may contain spaces
        var fields = trimmed.Split(' ', StringSplitOptions.RemoveEmptyEntries);
        if (fields.Length < 7) return null;

        // fields[0] = pointer (hex with colon)
        // fields[1] = RefCount
        // fields[2] = Protocol
        // fields[3] = Flags (hex)
        // fields[4] = Type
        // fields[5] = St (state)
        // fields[6] = Inode
        // fields[7..] = Path (optional)

        if (!int.TryParse(fields[4], out int sockType))
            sockType = 0;

        if (!int.TryParse(fields[5], out int state))
            state = 0;

        if (!long.TryParse(fields[6], out long inode))
            inode = -1;

        // Path is everything from field 7 onwards (may contain spaces)
        string socketPath = fields.Length > 7
            ? string.Join(' ', fields[7..])
            : "(unnamed)";

        string typeName = UnixTypeMap.GetValueOrDefault(sockType, $"TYPE_{sockType}");
        string stateName = UnixStateMap.GetValueOrDefault(state, $"STATE_{state}");

        return new RawConnection
        {
            Protocol = "UNIX",
            LocalAddress = socketPath,
            LocalPort = 0,
            RemoteAddress = typeName,   // Show socket type as remote for easy reading
            RemotePort = 0,
            State = stateName,
            Uid = -1,   // /proc/net/unix doesn't include UID directly
            Inode = inode,
        };
    }

    // ═════════════════════════════════════════════════════════════════════════
    //  Netlink Sockets (/proc/net/netlink)
    // ═════════════════════════════════════════════════════════════════════════

    /// <summary>
    /// Parses /proc/net/netlink for kernel-userspace netlink sockets.
    /// Format: sk Eth Pid Groups Rmem Wmem Dump Locks Drops Inode
    /// </summary>
    public static List<RawConnection> ParseNetlinkSockets(ILogger? logger = null)
    {
        const string path = "/proc/net/netlink";
        var connections = new List<RawConnection>();

        if (!File.Exists(path))
        {
            logger?.LogDebug("Netlink socket file not found");
            return connections;
        }

        string[] lines;
        try { lines = File.ReadAllLines(path); }
        catch (Exception ex)
        {
            logger?.LogError(ex, "Failed to read Netlink sockets");
            return connections;
        }

        for (int i = 1; i < lines.Length; i++)
        {
            try
            {
                var conn = ParseNetlinkLine(lines[i]);
                if (conn != null) connections.Add(conn);
            }
            catch (Exception ex)
            {
                logger?.LogDebug(ex, "Failed to parse Netlink socket line {LineNumber}", i + 1);
            }
        }

        return connections;
    }

    private static RawConnection? ParseNetlinkLine(string line)
    {
        var fields = line.Trim().Split(' ', StringSplitOptions.RemoveEmptyEntries);
        if (fields.Length < 10) return null;

        // sk Eth Pid Groups Rmem Wmem Dump Locks Drops Inode
        if (!int.TryParse(fields[1], out int ethProtocol))
            ethProtocol = 0;

        if (!int.TryParse(fields[2], out int pid))
            pid = 0;

        if (!long.TryParse(fields[9], out long inode))
            inode = -1;

        string protocolName = NetlinkProtocolMap.GetValueOrDefault(ethProtocol, $"NL_{ethProtocol}");

        return new RawConnection
        {
            Protocol = "NETLINK",
            LocalAddress = pid > 0 ? $"pid:{pid}" : "kernel",
            LocalPort = ethProtocol,
            RemoteAddress = protocolName,   // Show netlink family as remote
            RemotePort = 0,
            State = pid == 0 ? "KERNEL" : "USERSPACE",
            Uid = -1,
            Inode = inode,
        };
    }

    // ═════════════════════════════════════════════════════════════════════════
    //  Packet Sockets (/proc/net/packet)
    // ═════════════════════════════════════════════════════════════════════════

    /// <summary>
    /// Parses /proc/net/packet for raw packet capture sockets (used by tcpdump, wireshark, etc).
    /// Format: sk RefCnt Type Proto Iface R Rmem User Inode
    /// </summary>
    public static List<RawConnection> ParsePacketSockets(ILogger? logger = null)
    {
        const string path = "/proc/net/packet";
        var connections = new List<RawConnection>();

        if (!File.Exists(path))
        {
            logger?.LogDebug("Packet socket file not found");
            return connections;
        }

        string[] lines;
        try { lines = File.ReadAllLines(path); }
        catch (Exception ex)
        {
            logger?.LogError(ex, "Failed to read Packet sockets");
            return connections;
        }

        for (int i = 1; i < lines.Length; i++)
        {
            try
            {
                var conn = ParsePacketLine(lines[i]);
                if (conn != null) connections.Add(conn);
            }
            catch (Exception ex)
            {
                logger?.LogDebug(ex, "Failed to parse Packet socket line {LineNumber}", i + 1);
            }
        }

        return connections;
    }

    private static RawConnection? ParsePacketLine(string line)
    {
        var fields = line.Trim().Split(' ', StringSplitOptions.RemoveEmptyEntries);
        if (fields.Length < 9) return null;

        // sk RefCnt Type Proto Iface R Rmem User Inode
        if (!int.TryParse(fields[2], out int sockType))
            sockType = 0;

        // Proto is in hex (network byte order)
        int ethProto = 0;
        try
        {
            ethProto = Convert.ToInt32(fields[3], 16);
            // Convert from network byte order (big-endian) to host
            ethProto = (ushort)System.Net.IPAddress.NetworkToHostOrder((short)ethProto);
        }
        catch { }

        if (!int.TryParse(fields[4], out int ifaceIdx))
            ifaceIdx = 0;

        if (!int.TryParse(fields[7], out int uid))
            uid = -1;

        if (!long.TryParse(fields[8], out long inode))
            inode = -1;

        string typeName = sockType == 3 ? "RAW" : sockType == 1 ? "DGRAM" : $"TYPE_{sockType}";
        string protoName = EthProtocolMap.GetValueOrDefault(ethProto, ethProto > 0 ? $"0x{ethProto:X4}" : "ALL");

        return new RawConnection
        {
            Protocol = "PACKET",
            LocalAddress = $"iface:{ifaceIdx}",
            LocalPort = ifaceIdx,
            RemoteAddress = protoName,      // Show captured protocol type
            RemotePort = 0,
            State = typeName,               // RAW or DGRAM
            Uid = uid,
            Inode = inode,
        };
    }

    // ═════════════════════════════════════════════════════════════════════════
    //  Hex address parsing (shared by all standard /proc/net/ files)
    // ═════════════════════════════════════════════════════════════════════════

    private static (string Address, int Port) ParseHexAddress(string hexAddrPort, bool isIpv6)
    {
        int colonIndex = hexAddrPort.IndexOf(':');
        if (colonIndex < 0)
            return ("0.0.0.0", 0);

        string hexIp = hexAddrPort[..colonIndex];
        int port = Convert.ToInt32(hexAddrPort[(colonIndex + 1)..], 16);

        string address = isIpv6 ? ParseHexIPv6(hexIp) : ParseHexIPv4(hexIp);
        return (address, port);
    }

    private static string ParseHexIPv4(string hex)
    {
        if (hex.Length != 8)
            return "0.0.0.0";

        uint addr = Convert.ToUInt32(hex, 16);
        return $"{addr & 0xFF}.{(addr >> 8) & 0xFF}.{(addr >> 16) & 0xFF}.{(addr >> 24) & 0xFF}";
    }

    private static string ParseHexIPv6(string hex)
    {
        if (hex.Length != 32)
            return "::";

        var bytes = new byte[16];
        for (int i = 0; i < 4; i++)
        {
            uint word = Convert.ToUInt32(hex.Substring(i * 8, 8), 16);
            bytes[i * 4 + 0] = (byte)(word & 0xFF);
            bytes[i * 4 + 1] = (byte)((word >> 8) & 0xFF);
            bytes[i * 4 + 2] = (byte)((word >> 16) & 0xFF);
            bytes[i * 4 + 3] = (byte)((word >> 24) & 0xFF);
        }

        var ipAddr = new IPAddress(bytes);

        if (ipAddr.IsIPv4MappedToIPv6)
            return ipAddr.MapToIPv4().ToString();

        return ipAddr.ToString();
    }
}

/// <summary>
/// Represents a raw connection record parsed from /proc/net/ files,
/// before process and user resolution.
/// </summary>
internal sealed class RawConnection
{
    public required string Protocol { get; init; }
    public required string LocalAddress { get; init; }
    public required int LocalPort { get; init; }
    public required string RemoteAddress { get; init; }
    public required int RemotePort { get; init; }
    public required string State { get; init; }
    public required int Uid { get; init; }
    public required long Inode { get; init; }
}
