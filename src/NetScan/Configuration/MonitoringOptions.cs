namespace NetScan.Configuration;

/// <summary>
/// Configuration options for the network monitoring service.
/// </summary>
public sealed class MonitoringOptions
{
    public const string SectionName = "Monitoring";

    /// <summary>Change-detection scan interval in milliseconds for real-time monitoring. Default: 100ms.</summary>
    public int EventScanIntervalMs { get; set; } = 100;

    /// <summary>If set, only show connections belonging to this user.</summary>
    public string? FilterByUser { get; set; }

    /// <summary>If set, only show connections using this protocol (TCP/UDP/ICMP/RAW/SCTP).</summary>
    public string? FilterByProtocol { get; set; }

    /// <summary>If set, only show connections for this process name.</summary>
    public string? FilterByProcess { get; set; }

    /// <summary>Export format: "json", "csv", or null for no export.</summary>
    public string? ExportFormat { get; set; }

    /// <summary>Export file path. Default: "./netscan_export" (extension added automatically).</summary>
    public string ExportPath { get; set; } = "./netscan_export";

    /// <summary>Whether to run in live (continuous) mode or snapshot (one-time) mode.</summary>
    public bool LiveMode { get; set; } = true;

    /// <summary>Include IPv6 connections in the scan.</summary>
    public bool IncludeIPv6 { get; set; } = false;

    /// <summary>Include loopback connections (127.0.0.1 / ::1).</summary>
    public bool IncludeLoopback { get; set; } = true;

    /// <summary>
    /// Use eBPF kernel hooks for true per-connection event-driven monitoring.
    /// Equivalent to WFP ALE layers (FWPM_LAYER_ALE_AUTH_CONNECT) on Windows.
    /// Requires: Linux kernel 5.8+, libbpf, root privileges, compiled netscan_ebpf.bpf.o.
    /// Falls back to Ftrace/polling if eBPF loading fails.
    /// </summary>
    public bool UseEbpf { get; set; } = false;

    /// <summary>Maximum number of connections to display in live mode. 0 = unlimited.</summary>
    public int MaxDisplayRows { get; set; } = 100;

    /// <summary>Maximum number of recent events to show in the live event feed.</summary>
    public int MaxEventLogRows { get; set; } = 15;
}
