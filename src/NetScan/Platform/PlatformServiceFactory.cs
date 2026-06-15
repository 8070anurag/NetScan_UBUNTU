using System.Runtime.InteropServices;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using NetScan.Abstractions;
using NetScan.Configuration;
using NetScan.Platform.Linux;
using NetScan.Platform.Linux.Ebpf;

namespace NetScan.Platform;

/// <summary>
/// Factory that registers Linux-specific network monitoring services.
/// Supports: Linux (RHEL, Ubuntu, Fedora, CentOS).
///
/// Two event-driven engines are available:
///   1. eBPF (--ebpf) — Per-connection kernel callbacks via kprobes/tracepoints.
///      Equivalent to WFP ALE layers on Windows. Requires kernel 5.8+ and libbpf.
///   2. Ftrace/Polling (default) — Change-detection via /proc/net/ scanning,
///      triggered by Ftrace tracepoints or timed polling.
/// </summary>
public static class PlatformServiceFactory
{
    /// <summary>
    /// Registers the INetworkScanner and INetworkEventSource for Linux.
    /// </summary>
    /// <param name="services">The service collection to register into.</param>
    /// <param name="options">Monitoring configuration options.</param>
    /// <returns>The service collection for chaining.</returns>
    /// <exception cref="PlatformNotSupportedException">
    /// Thrown when running on a non-Linux operating system.
    /// </exception>
    public static IServiceCollection AddNetworkScanner(
        this IServiceCollection services, MonitoringOptions options)
    {
        if (!RuntimeInformation.IsOSPlatform(OSPlatform.Linux))
        {
            throw new PlatformNotSupportedException(
                $"NetScan requires Linux. Current OS: {RuntimeInformation.OSDescription}. " +
                "Supported platforms: RHEL, CentOS, Ubuntu, Fedora.");
        }

        // Register the scanner (used by event source internally, and for snapshot mode)
        // Always uses /proc/net/ parsing — eBPF is event-driven only
        services.AddSingleton<INetworkScanner>(sp =>
            new LinuxNetworkScanner(
                sp.GetRequiredService<ILogger<LinuxNetworkScanner>>(),
                options));

        // Register the event source based on configuration
        if (options.UseEbpf)
        {
            // eBPF mode — Per-connection kernel callbacks (WFP ALE-equivalent)
            // Hooks: kprobe/tcp_v4_connect, tcp_v6_connect, inet_csk_accept,
            //        tracepoint/sock/inet_sock_set_state
            // Falls back to Ftrace/polling automatically if eBPF loading fails
            services.AddSingleton<INetworkEventSource>(sp =>
                new EbpfNetworkEventSource(
                    sp.GetRequiredService<INetworkScanner>(),
                    options,
                    sp.GetRequiredService<ILogger<EbpfNetworkEventSource>>()));
        }
        else
        {
            // Default mode — Ftrace/polling change-detection
            services.AddSingleton<INetworkEventSource>(sp =>
                new LinuxNetworkEventSource(
                    sp.GetRequiredService<INetworkScanner>(),
                    options,
                    sp.GetRequiredService<ILogger<LinuxNetworkEventSource>>()));
        }

        return services;
    }
}
