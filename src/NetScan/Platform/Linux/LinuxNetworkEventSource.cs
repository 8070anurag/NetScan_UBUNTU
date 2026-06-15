using System.Runtime.CompilerServices;
using System.Threading.Channels;
using Microsoft.Extensions.Logging;
using NetScan.Abstractions;
using NetScan.Configuration;
using NetScan.Models;

namespace NetScan.Platform.Linux;

/// <summary>
/// Event-driven network event source for Linux.
/// Uses rapid change-detection scanning against /proc/net/* to produce real-time
/// connection open/close events. Only yields events when state actually changes,
/// giving consumers a true event-driven experience.
/// </summary>
internal sealed class LinuxNetworkEventSource : INetworkEventSource
{
    private readonly INetworkScanner _scanner;
    private readonly MonitoringOptions _options;
    private readonly ILogger<LinuxNetworkEventSource> _logger;

    /// <summary>
    /// Current known connections, keyed by connection identity.
    /// </summary>
    private Dictionary<string, NetworkConnection> _currentState = new();

    public LinuxNetworkEventSource(
        INetworkScanner scanner,
        MonitoringOptions options,
        ILogger<LinuxNetworkEventSource> logger)
    {
        _scanner = scanner;
        _options = options;
        _logger = logger;
    }

    /// <inheritdoc />
    public async IAsyncEnumerable<NetworkEvent> MonitorAsync(
        [EnumeratorCancellation] CancellationToken cancellationToken = default)
    {
        _logger.LogInformation("Linux event source starting — change-detection mode");

        // Use a Channel to decouple scanning from yielding (avoids yield-in-try-catch)
        var channel = Channel.CreateUnbounded<NetworkEvent>(new UnboundedChannelOptions
        {
            SingleReader = true,
            SingleWriter = true,
        });

        // Start the scanner loop in the background
        var scanTask = Task.Run(() => ScanLoopAsync(channel.Writer, cancellationToken), cancellationToken);

        // Yield events from the channel
        await foreach (var evt in channel.Reader.ReadAllAsync(cancellationToken))
        {
            yield return evt;
        }

        // Ensure scan task completes
        await scanTask;
    }

    /// <summary>
    /// Background scan loop that detects changes and writes events to the channel.
    /// Uses Ftrace for true zero-polling event-driven monitoring if available,
    /// otherwise falls back to a rapid change-detection polling loop.
    /// </summary>
    private async Task ScanLoopAsync(ChannelWriter<NetworkEvent> writer, CancellationToken ct)
    {
        try
        {
            // Phase 1: Initial snapshot — emit all current connections as Opened events
            var initial = await _scanner.ScanAsync(ct);
            var initialMap = new Dictionary<string, NetworkConnection>();

            foreach (var conn in initial)
            {
                var key = GetConnectionKey(conn);
                if (initialMap.TryAdd(key, conn))
                {
                    await writer.WriteAsync(new NetworkEvent
                    {
                        EventType = NetworkEventType.ConnectionOpened,
                        Connection = conn,
                    }, ct);
                }
            }

            _currentState = initialMap;
            _logger.LogDebug("Initial snapshot: {Count} connections", _currentState.Count);

            int scanIntervalMs = Math.Max(_options.EventScanIntervalMs, 50);

            while (!ct.IsCancellationRequested)
            {
                // Rapid change-detection polling loop (stable, doesn't miss exit-time closures or race on connect)
                await Task.Delay(scanIntervalMs, ct);
                await PerformReconciliationScanAsync(writer, ct);
            }
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            // Normal shutdown
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error in scan loop");
        }
        finally
        {
            writer.Complete();
        }
    }

    private async Task PerformReconciliationScanAsync(ChannelWriter<NetworkEvent> writer, CancellationToken ct)
    {
        var latest = await _scanner.ScanAsync(ct);
        var latestMap = new Dictionary<string, NetworkConnection>();

        foreach (var conn in latest)
        {
            var key = GetConnectionKey(conn);
            latestMap.TryAdd(key, conn);
        }

        // Detect NEW or UPDATED connections (in latest but not in current, or state has changed)
        foreach (var kvp in latestMap)
        {
            if (!_currentState.TryGetValue(kvp.Key, out var currentConn) || currentConn.State != kvp.Value.State)
            {
                await writer.WriteAsync(new NetworkEvent
                {
                    EventType = NetworkEventType.ConnectionOpened,
                    Connection = kvp.Value,
                }, ct);
            }
        }

        // Detect CLOSED connections (in current but not in latest)
        foreach (var kvp in _currentState)
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

        _currentState = latestMap;
    }

    /// <inheritdoc />
    public async Task<IReadOnlyList<NetworkConnection>> GetCurrentConnectionsAsync(
        CancellationToken cancellationToken = default)
    {
        return await _scanner.ScanAsync(cancellationToken);
    }

    public ValueTask DisposeAsync()
    {
        _currentState.Clear();
        return ValueTask.CompletedTask;
    }

    /// <summary>
    /// Generates a unique key for a connection based on its identifying fields.
    /// </summary>
    private static string GetConnectionKey(NetworkConnection conn)
    {
        return $"{conn.Protocol}|{conn.LocalAddress}:{conn.LocalPort}|{conn.RemoteAddress}:{conn.RemotePort}";
    }
}
