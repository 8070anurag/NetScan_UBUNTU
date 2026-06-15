using NetScan.Models;

namespace NetScan.Abstractions;

/// <summary>
/// Event-driven network monitoring interface.
/// Implementations yield <see cref="NetworkEvent"/> objects as connections open and close in real time.
/// </summary>
public interface INetworkEventSource : IAsyncDisposable
{
    /// <summary>
    /// Begins monitoring and yields connection events as they are detected.
    /// The first batch of events will be <see cref="NetworkEventType.ConnectionOpened"/> for all
    /// currently active connections (initial snapshot).
    /// </summary>
    /// <param name="cancellationToken">Cancellation token to stop monitoring.</param>
    /// <returns>An async stream of network events.</returns>
    IAsyncEnumerable<NetworkEvent> MonitorAsync(CancellationToken cancellationToken = default);

    /// <summary>
    /// Gets a one-time snapshot of all current connections.
    /// </summary>
    Task<IReadOnlyList<NetworkConnection>> GetCurrentConnectionsAsync(CancellationToken cancellationToken = default);
}
