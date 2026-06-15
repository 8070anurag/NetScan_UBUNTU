namespace NetScan.Models;

/// <summary>
/// Represents a single captured network connection with full metadata.
/// </summary>
public sealed record NetworkConnection
{
    /// <summary>Transport protocol (TCP or UDP).</summary>
    public required string Protocol { get; init; }

    /// <summary>Local (source) IP address.</summary>
    public required string LocalAddress { get; init; }

    /// <summary>Local (source) port number.</summary>
    public required int LocalPort { get; init; }

    /// <summary>Remote (destination) IP address.</summary>
    public required string RemoteAddress { get; init; }

    /// <summary>Remote (destination) port number.</summary>
    public required int RemotePort { get; init; }

    /// <summary>Connection state (e.g., ESTABLISHED, LISTEN, TIME_WAIT).</summary>
    public required string State { get; set; }

    /// <summary>Process ID owning this connection. -1 if unresolvable.</summary>
    public int ProcessId { get; init; } = -1;

    /// <summary>Name of the application/process owning this connection.</summary>
    public string ProcessName { get; init; } = "Unknown";

    /// <summary>Username of the account that started the process.</summary>
    public string UserName { get; init; } = "Unknown";

    /// <summary>Full command line of the process (if available).</summary>
    public string CommandLine { get; init; } = string.Empty;

    /// <summary>UTC timestamp when this connection was captured.</summary>
    public DateTime CapturedAtUtc { get; set; } = DateTime.UtcNow;

    /// <summary>Resolved hostname for the remote address (via reverse DNS). Null if not yet resolved.</summary>
    public string? ResolvedHostname { get; set; }

    /// <summary>Alternate IP address for the remote host (IPv4 if connection is IPv6, IPv6 if connection is IPv4). Null if not available.</summary>
    public string? AlternateRemoteAddress { get; set; }
}

/// <summary>
/// Normalizes internal system/child process names into user-friendly main application names (e.g. Firefox child processes to "firefox").
/// </summary>
public static class ProcessNameNormalizer
{
    public static string Normalize(string processName)
    {
        if (string.IsNullOrWhiteSpace(processName))
            return "Unknown";

        string trimmed = processName.Trim();
        string lower = trimmed.ToLowerInvariant();

        // Firefox child/helper processes
        if (lower == "isolated web co" ||
            lower == "web content" ||
            lower == "webextensions" ||
            lower == "privileged cont" ||
            lower == "socket process" ||
            lower == "geckomain" ||
            lower == "rdd process" ||
            lower == "utility process" ||
            lower.StartsWith("firefox"))
        {
            return "firefox";
        }

        // Chrome/Chromium child/helper processes
        if (lower == "chrome-sandbox" ||
            lower == "nacl_helper" ||
            lower.StartsWith("chrome"))
        {
            return "chrome";
        }

        // Microsoft Edge
        if (lower.StartsWith("msedge"))
        {
            return "msedge";
        }

        // Brave Browser
        if (lower.StartsWith("brave"))
        {
            return "brave";
        }

        // Opera Browser
        if (lower.StartsWith("opera"))
        {
            return "opera";
        }

        return trimmed;
    }
}
