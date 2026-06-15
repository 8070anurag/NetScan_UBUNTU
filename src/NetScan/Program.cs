using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using NetScan.Abstractions;
using NetScan.Configuration;
using NetScan.Platform;
using NetScan.Services;
using NetScan.Services.Exporters;

namespace NetScan;

/// <summary>
/// Entry point for the NetScan network monitoring tool.
/// Linux-only — supports RHEL, CentOS, Ubuntu, Fedora.
/// </summary>
public static class Program
{
    public static async Task<int> Main(string[] args)
    {
        // Parse command-line overrides before building the host
        var cliOverrides = ParseCommandLineArgs(args);

        if (cliOverrides.ShowHelp)
        {
            PrintHelp();
            return 0;
        }

        if (cliOverrides.ShowVersion)
        {
            PrintVersion();
            return 0;
        }

        try
        {
            while (true)
            {
                var builder = Host.CreateApplicationBuilder(args);

                // Bind monitoring options from configuration
                var options = new MonitoringOptions();
                builder.Configuration.GetSection(MonitoringOptions.SectionName).Bind(options);

                // Apply CLI overrides
                ApplyCliOverrides(options, cliOverrides);

                // Show interactive menu if no arguments are provided
                if (args.Length == 0)
                {
                    var continueExecution = ShowInteractiveMenu(options);
                    if (!continueExecution)
                    {
                        return 0;
                    }
                }

                // Register services (Linux scanner + event source)
                builder.Services.AddSingleton(options);
                builder.Services.AddNetworkScanner(options);

                // Register exporter based on configuration
                RegisterExporter(builder.Services, options);

                // Register the monitoring service
                builder.Services.AddSingleton<DnsAddressResolver>();
                builder.Services.AddSingleton<LiveMonitorService>();

                // Configure logging — suppress noisy framework logs in live mode
                if (options.LiveMode)
                {
                    builder.Logging.SetMinimumLevel(LogLevel.Warning);
                    builder.Logging.AddFilter("NetScan", LogLevel.Warning);
                }

                var host = builder.Build();

                // Print banner
                PrintBanner(options);

                using var cts = new CancellationTokenSource();
                ConsoleCancelEventHandler cancelHandler = (sender, e) =>
                {
                    e.Cancel = true; // Prevent app termination
                    try { cts.Cancel(); } catch { }
                };

                Console.CancelKeyPress += cancelHandler;

                try
                {
                    var monitor = host.Services.GetRequiredService<LiveMonitorService>();
                    await monitor.RunAsync(cts.Token);
                }
                catch (TaskCanceledException) { }
                catch (OperationCanceledException) { }
                finally
                {
                    Console.CancelKeyPress -= cancelHandler;

                    // Dispose event source
                    var eventSource = host.Services.GetService<INetworkEventSource>();
                    if (eventSource != null)
                        await eventSource.DisposeAsync();
                }

                Console.WriteLine();
                Console.WriteLine("  ► Monitoring stopped. Returning to menu...");
                Console.WriteLine();

                // In snapshot mode, wait for user to read results before clearing screen
                if (!options.LiveMode)
                {
                    Console.Write("  Press Enter to return to menu...");
                    Console.ReadLine();
                }
                else
                {
                    Thread.Sleep(1000);
                }

                // If launched with CLI arguments, run only once and exit
                if (args.Length > 0)
                {
                    break;
                }
            }
            return 0;
        }
        catch (PlatformNotSupportedException ex)
        {
            Console.Error.WriteLine($"[ERROR] {ex.Message}");
            return 2;
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"[FATAL] Unhandled exception: {ex.Message}");
            Console.Error.WriteLine(ex.StackTrace);
            return 1;
        }
    }

    /// <summary>
    /// Registers the appropriate exporter based on configuration.
    /// </summary>
    private static void RegisterExporter(IServiceCollection services, MonitoringOptions options)
    {
        if (string.IsNullOrEmpty(options.ExportFormat))
        {
            // No exporter configured — LiveMonitorService will handle null gracefully
            return;
        }

        switch (options.ExportFormat.ToLowerInvariant())
        {
            case "json":
                services.AddSingleton<IConnectionExporter>(new JsonExporter());
                break;
            case "csv":
                services.AddSingleton<IConnectionExporter>(new CsvExporter());
                break;
            default:
                Console.Error.WriteLine($"[WARN] Unknown export format '{options.ExportFormat}'. Supported: json, csv");
                break;
        }
    }

    /// <summary>
    /// Displays an interactive menu to the user if no CLI arguments are provided.
    /// </summary>
    /// <returns>True if execution should continue, false if the user chose to exit.</returns>
    private static bool ShowInteractiveMenu(MonitoringOptions options)
    {
        while (true)
        {
            Console.Clear();
            Console.WriteLine();
            Console.WriteLine("  ███╗   ██╗███████╗████████╗███████╗ ██████╗ █████╗ ███╗   ██╗");
            Console.WriteLine("  ████╗  ██║██╔════╝╚══██╔══╝██╔════╝██╔════╝██╔══██╗████╗  ██║");
            Console.WriteLine("  ██╔██╗ ██║█████╗     ██║   ███████╗██║     ███████║██╔██╗ ██║");
            Console.WriteLine("  ██║╚██╗██║██╔══╝     ██║   ╚════██║██║     ██╔══██║██║╚██╗██║");
            Console.WriteLine("  ██║ ╚████║███████╗   ██║   ███████║╚██████╗██║  ██║██║ ╚████║");
            Console.WriteLine("  ╚═╝  ╚═══╝╚══════╝   ╚═╝   ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝");
            Console.WriteLine();
            Console.WriteLine("  v2.0 — Real-Time Event-Driven Network Monitor (Linux)");
            Console.WriteLine("  15+ Protocols: TCP · UDP · ICMP · RAW · SCTP · DCCP · Conntrack · ARP");
            Console.WriteLine("                 IGMP · Bluetooth · IPVS · MPTCP · SMC · RDS · CAN · L2TP · PPPoE");
            Console.WriteLine();
            Console.WriteLine("  ══════════════════════════════════════════════════════════════");
            Console.WriteLine("  1. Real-Time Monitoring (All Protocols)");
            Console.WriteLine("  2. Real-Time Monitoring with Filters (User/Process/Protocol)");
            Console.WriteLine("  3. Network Snapshot (Single Scan, All Protocols)");
            Console.WriteLine("  4. Real-Time Monitoring + Export to File (JSON/CSV)");
            Console.WriteLine("  5. Real-Time Monitoring + eBPF Kernel Hooks (WFP ALE-equivalent)");
            Console.WriteLine("  6. Exit");
            Console.WriteLine();
            Console.Write("  Select an option [1-6]: ");
            
            var choice = Console.ReadLine()?.Trim();

            switch (choice)
            {
                case "1":
                    options.LiveMode = true;
                    return true;
                case "2":
                    options.LiveMode = true;
                    ConfigureFiltering(options);
                    return true;
                case "3":
                    options.LiveMode = false;
                    return true;
                case "4":
                    options.LiveMode = true;
                    ConfigureExport(options);
                    return true;
                case "5":
                    options.LiveMode = true;
                    options.UseEbpf = true;
                    Console.WriteLine();
                    Console.WriteLine("  eBPF mode enabled — per-connection kernel callbacks (WFP ALE-equivalent)");
                    Console.WriteLine("  Hooks: tcp_v4_connect, tcp_v6_connect, inet_csk_accept, inet_sock_set_state");
                    Console.WriteLine("  Requires: kernel 5.8+, libbpf, root. Falls back to Ftrace if unavailable.");
                    Thread.Sleep(1500);
                    return true;
                case "6":
                case "exit":
                case "q":
                    return false;
                default:
                    Console.WriteLine("  Invalid option. Please press Enter and try again.");
                    Console.ReadLine();
                    break;
            }
        }
    }

    private static void ConfigureFiltering(MonitoringOptions options)
    {
        Console.WriteLine();
        Console.Write("  Filter by User (leave empty to skip): ");
        var user = Console.ReadLine()?.Trim();
        if (!string.IsNullOrEmpty(user)) options.FilterByUser = user;

        Console.Write("  Filter by Process Name (leave empty to skip): ");
        var proc = Console.ReadLine()?.Trim();
        if (!string.IsNullOrEmpty(proc)) options.FilterByProcess = proc;

        Console.Write("  Filter by Protocol [TCP/UDP/ICMP/RAW/SCTP/DCCP] (leave empty to skip): ");
        var proto = Console.ReadLine()?.Trim();
        if (!string.IsNullOrEmpty(proto)) options.FilterByProtocol = proto;
    }

    private static void ConfigureExport(MonitoringOptions options)
    {
        Console.WriteLine();
        Console.Write("  Export format [json/csv] (default: json): ");
        var format = Console.ReadLine()?.Trim().ToLowerInvariant();
        if (string.IsNullOrEmpty(format)) format = "json";
        
        if (format == "json" || format == "csv")
        {
            options.ExportFormat = format;
            Console.Write($"  Export path without extension (default: {options.ExportPath}): ");
            var path = Console.ReadLine()?.Trim();
            if (!string.IsNullOrEmpty(path)) options.ExportPath = path;
        }
        else
        {
            Console.WriteLine("  Invalid format. Using JSON.");
            options.ExportFormat = "json";
        }
    }

    /// <summary>
    /// Prints the startup banner.
    /// </summary>
    private static void PrintBanner(MonitoringOptions options)
    {
        Console.WriteLine();
        Console.WriteLine("  ███╗   ██╗███████╗████████╗███████╗ ██████╗ █████╗ ███╗   ██╗");
        Console.WriteLine("  ████╗  ██║██╔════╝╚══██╔══╝██╔════╝██╔════╝██╔══██╗████╗  ██║");
        Console.WriteLine("  ██╔██╗ ██║█████╗     ██║   ███████╗██║     ███████║██╔██╗ ██║");
        Console.WriteLine("  ██║╚██╗██║██╔══╝     ██║   ╚════██║██║     ██╔══██║██║╚██╗██║");
        Console.WriteLine("  ██║ ╚████║███████╗   ██║   ███████║╚██████╗██║  ██║██║ ╚████║");
        Console.WriteLine("  ╚═╝  ╚═══╝╚══════╝   ╚═╝   ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝");
        Console.WriteLine();
        Console.WriteLine($"  v2.0 — Real-Time Event-Driven Network Monitor (Linux)");
        string modeText = options.LiveMode
            ? (options.UseEbpf ? "eBPF KERNEL HOOKS — WFP ALE-EQUIVALENT (Ctrl+C to stop)" : "REAL-TIME EVENT-DRIVEN (Ctrl+C to stop)")
            : "SNAPSHOT";
        Console.WriteLine($"  Mode: {modeText}");
        if (options.UseEbpf)
        {
            Console.WriteLine($"  Engine: eBPF kprobes — tcp_v4_connect, tcp_v6_connect, inet_csk_accept, inet_sock_set_state");
        }
        Console.WriteLine($"  15+ Protocols — God's Eye: Core transport, diagnostic, virtual & wireless sockets");
        Console.WriteLine();
    }

    /// <summary>
    /// Prints usage help.
    /// </summary>
    private static void PrintHelp()
    {
        PrintVersion();
        Console.WriteLine();
        Console.WriteLine("USAGE:");
        Console.WriteLine("  netscan [OPTIONS]");
        Console.WriteLine();
        Console.WriteLine("OPTIONS:");
        Console.WriteLine("  --live              Run in real-time event-driven mode (default)");
        Console.WriteLine("  --snapshot          Run a single snapshot scan and exit");
        Console.WriteLine("  --user <name>       Filter connections by username");
        Console.WriteLine("  --protocol <proto>  Filter by protocol (TCP, UDP, ICMP, RAW, SCTP, DCCP)");
        Console.WriteLine("  --process <name>    Filter by process name");
        Console.WriteLine("  --export <format>   Export data: json or csv");
        Console.WriteLine("  --export-path <p>   Export file path (default: ./netscan_export)");
        Console.WriteLine("  --interval <ms>     Change-detection interval in ms (default: 100)");
        Console.WriteLine("  --max-rows <n>      Max rows to display (default: 100, 0=unlimited)");
        Console.WriteLine("  --ebpf              Use eBPF kernel hooks (WFP ALE-equivalent, requires kernel 5.8+)");
        Console.WriteLine("  --no-ipv6           Exclude IPv6 connections");
        Console.WriteLine("  --no-loopback       Exclude loopback connections");
        Console.WriteLine("  --version           Show version information");
        Console.WriteLine("  --help              Show this help message");
        Console.WriteLine();
        Console.WriteLine("SUPPORTED PROTOCOLS (God's Eye — Core Transport, Diagnostic & Exotic sockets):");
        Console.WriteLine();
        Console.WriteLine("  Core Transport:");
        Console.WriteLine("    TCP      — Transmission Control Protocol      UDP      — User Datagram Protocol");
        Console.WriteLine("    DCCP     — Datagram Congestion Control       SCTP     — Stream Control Transmission");
        Console.WriteLine("    MPTCP    — Multipath TCP");
        Console.WriteLine();
        Console.WriteLine("  Network/Diagnostic:");
        Console.WriteLine("    ICMP     — Internet Control Message Protocol  RAW      — Raw IP sockets");
        Console.WriteLine("    ARP      — Address Resolution Protocol        IGMP     — Multicast groups");
        Console.WriteLine("    CONNTRACK— Netfilter tracked connections      IPVS     — IP Virtual Server (LB)");
        Console.WriteLine();
        Console.WriteLine("  Extended/Exotic:");
        Console.WriteLine("    BT_*     — Bluetooth (L2CAP/RFCOMM/SCO/BNEP)  SMC      — Shared Memory Comms");
        Console.WriteLine("    RDS      — Reliable Datagram Sockets          CAN      — Controller Area Network");
        Console.WriteLine("    L2TP     — Layer 2 Tunneling Protocol         PPPOE    — PPP over Ethernet");
        Console.WriteLine();
        Console.WriteLine("  + CATCH-ALL: Automatically detects and parses ANY undocumented/future protocol in /proc/net!");
        Console.WriteLine();
        Console.WriteLine("EXAMPLES:");
        Console.WriteLine("  netscan --live --user admin");
        Console.WriteLine("  netscan --snapshot --export json --export-path ./report");
        Console.WriteLine("  netscan --protocol TCP --interval 50");
        Console.WriteLine("  netscan --protocol ICMP");
        Console.WriteLine("  netscan --process nginx --no-loopback");
        Console.WriteLine("  netscan --live --ebpf                          # eBPF mode (WFP ALE-equivalent)");
        Console.WriteLine("  netscan --live --ebpf --protocol TCP            # eBPF + TCP filter");
        Console.WriteLine();
        Console.WriteLine("NOTE: Run as root/sudo on Linux for full process and user visibility.");
    }

    /// <summary>
    /// Prints version information.
    /// </summary>
    private static void PrintVersion()
    {
        Console.WriteLine("NetScan v2.0.0 — Real-Time Event-Driven Network Monitor (Linux)");
        Console.WriteLine($"Runtime: {System.Runtime.InteropServices.RuntimeInformation.FrameworkDescription}");
        Console.WriteLine($"OS: {System.Runtime.InteropServices.RuntimeInformation.OSDescription}");
    }

    #region CLI Argument Parsing

    private sealed class CliOptions
    {
        public bool ShowHelp { get; set; }
        public bool ShowVersion { get; set; }
        public bool? LiveMode { get; set; }
        public string? FilterByUser { get; set; }
        public string? FilterByProtocol { get; set; }
        public string? FilterByProcess { get; set; }
        public string? ExportFormat { get; set; }
        public string? ExportPath { get; set; }
        public int? EventScanIntervalMs { get; set; }
        public int? MaxDisplayRows { get; set; }
        public bool? IncludeIPv6 { get; set; }
        public bool? IncludeLoopback { get; set; }
        public bool? UseEbpf { get; set; }
    }

    private static CliOptions ParseCommandLineArgs(string[] args)
    {
        var options = new CliOptions();

        for (int i = 0; i < args.Length; i++)
        {
            var arg = args[i].ToLowerInvariant();

            switch (arg)
            {
                case "--help" or "-h":
                    options.ShowHelp = true;
                    break;
                case "--version" or "-v":
                    options.ShowVersion = true;
                    break;
                case "--live":
                    options.LiveMode = true;
                    break;
                case "--snapshot":
                    options.LiveMode = false;
                    break;
                case "--user" when i + 1 < args.Length:
                    options.FilterByUser = args[++i];
                    break;
                case "--protocol" when i + 1 < args.Length:
                    options.FilterByProtocol = args[++i];
                    break;
                case "--process" when i + 1 < args.Length:
                    options.FilterByProcess = args[++i];
                    break;
                case "--export" when i + 1 < args.Length:
                    options.ExportFormat = args[++i];
                    break;
                case "--export-path" when i + 1 < args.Length:
                    options.ExportPath = args[++i];
                    break;
                case "--interval" when i + 1 < args.Length:
                    if (int.TryParse(args[++i], out int interval))
                        options.EventScanIntervalMs = interval;
                    break;
                case "--max-rows" when i + 1 < args.Length:
                    if (int.TryParse(args[++i], out int rows))
                        options.MaxDisplayRows = rows;
                    break;
                case "--no-ipv6":
                    options.IncludeIPv6 = false;
                    break;
                case "--no-loopback":
                    options.IncludeLoopback = false;
                    break;
                case "--ebpf":
                    options.UseEbpf = true;
                    break;
            }
        }

        return options;
    }

    private static void ApplyCliOverrides(MonitoringOptions options, CliOptions cli)
    {
        if (cli.LiveMode.HasValue) options.LiveMode = cli.LiveMode.Value;
        if (cli.FilterByUser != null) options.FilterByUser = cli.FilterByUser;
        if (cli.FilterByProtocol != null) options.FilterByProtocol = cli.FilterByProtocol;
        if (cli.FilterByProcess != null) options.FilterByProcess = cli.FilterByProcess;
        if (cli.ExportFormat != null) options.ExportFormat = cli.ExportFormat;
        if (cli.ExportPath != null) options.ExportPath = cli.ExportPath;
        if (cli.EventScanIntervalMs.HasValue) options.EventScanIntervalMs = cli.EventScanIntervalMs.Value;
        if (cli.MaxDisplayRows.HasValue) options.MaxDisplayRows = cli.MaxDisplayRows.Value;
        if (cli.IncludeIPv6.HasValue) options.IncludeIPv6 = cli.IncludeIPv6.Value;
        if (cli.IncludeLoopback.HasValue) options.IncludeLoopback = cli.IncludeLoopback.Value;
        if (cli.UseEbpf.HasValue) options.UseEbpf = cli.UseEbpf.Value;
    }

    #endregion
}
