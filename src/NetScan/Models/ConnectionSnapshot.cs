namespace NetScan.Models;

/// <summary>
/// A point-in-time snapshot of all active network connections on the system.
/// </summary>
public sealed record ConnectionSnapshot
{
    /// <summary>UTC timestamp when the snapshot was taken.</summary>
    public DateTime TimestampUtc { get; init; } = DateTime.UtcNow;

    /// <summary>Hostname of the machine.</summary>
    public string Hostname { get; init; } = Environment.MachineName;

    /// <summary>Operating system description.</summary>
    public string OperatingSystem { get; init; } = System.Runtime.InteropServices.RuntimeInformation.OSDescription;

    /// <summary>Total number of connections in this snapshot.</summary>
    public int TotalConnections => Connections.Count;

    /// <summary>All captured network connections.</summary>
    public IReadOnlyList<NetworkConnection> Connections { get; init; } = Array.Empty<NetworkConnection>();

    /// <summary>Summary counts by protocol.</summary>
    public Dictionary<string, int> ProtocolSummary =>
        Connections.GroupBy(c => c.Protocol)
                   .ToDictionary(g => g.Key, g => g.Count());

    /// <summary>Summary counts by connection state.</summary>
    public Dictionary<string, int> StateSummary =>
        Connections.GroupBy(c => c.State)
                   .ToDictionary(g => g.Key, g => g.Count());
}
