using Microsoft.Extensions.Logging;
using NetScan.Abstractions;
using NetScan.Configuration;
using NetScan.Models;

namespace NetScan.Platform.Linux.Ebpf;

/// <summary>
/// INetworkScanner wrapper for eBPF mode.
///
/// eBPF provides event-driven monitoring only — it does not replace the need
/// for /proc/net/ scanning in snapshot mode. This class delegates to the
/// existing <see cref="LinuxNetworkScanner"/> for snapshot operations.
///
/// In the future, this could be extended to use BPF map iteration for
/// real-time connection enumeration without /proc/net/ parsing.
/// </summary>
internal sealed class EbpfNetworkScanner : INetworkScanner
{
    private readonly INetworkScanner _innerScanner;
    private readonly ILogger<EbpfNetworkScanner> _logger;

    public EbpfNetworkScanner(
        INetworkScanner innerScanner,
        ILogger<EbpfNetworkScanner> logger)
    {
        _innerScanner = innerScanner;
        _logger = logger;
    }

    /// <inheritdoc />
    /// <remarks>
    /// Delegates to LinuxNetworkScanner for snapshot operations.
    /// eBPF is used for event-driven monitoring only.
    /// </remarks>
    public Task<IReadOnlyList<NetworkConnection>> ScanAsync(CancellationToken cancellationToken = default)
    {
        return _innerScanner.ScanAsync(cancellationToken);
    }
}
