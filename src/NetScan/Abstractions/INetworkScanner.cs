using NetScan.Models;

namespace NetScan.Abstractions;

/// <summary>
/// Platform-agnostic interface for scanning active network connections.
/// </summary>
public interface INetworkScanner
{
    /// <summary>
    /// Scans and returns all currently active network connections on the system.
    /// </summary>
    /// <param name="cancellationToken">Cancellation token for cooperative cancellation.</param>
    /// <returns>A read-only list of all active network connections.</returns>
    Task<IReadOnlyList<NetworkConnection>> ScanAsync(CancellationToken cancellationToken = default);
}
