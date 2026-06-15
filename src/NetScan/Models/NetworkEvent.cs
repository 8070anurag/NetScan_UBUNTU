namespace NetScan.Models;

/// <summary>
/// Represents a real-time network connection change event.
/// </summary>
public enum NetworkEventType
{
    /// <summary>A new connection was detected.</summary>
    ConnectionOpened,

    /// <summary>An existing connection was closed/removed.</summary>
    ConnectionClosed,
}

/// <summary>
/// A single network event representing a connection opening or closing.
/// </summary>
public sealed record NetworkEvent
{
    /// <summary>Whether the connection was opened or closed.</summary>
    public required NetworkEventType EventType { get; init; }

    /// <summary>The connection associated with this event.</summary>
    public required NetworkConnection Connection { get; init; }

    /// <summary>UTC timestamp when the event was detected.</summary>
    public DateTime TimestampUtc { get; init; } = DateTime.UtcNow;
}
