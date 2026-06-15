using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;
using Microsoft.Extensions.Logging;

namespace NetScan.Services;

/// <summary>
/// Asynchronous DNS resolver that discovers both IPv4 and IPv6 addresses for a remote host.
/// Resolution strategy (in order):
///   1. Reverse DNS (IP → hostname) + check AddressList
///   2. Forward DNS on exact hostname (hostname → A/AAAA)
///   3. Forward DNS on base domain  (e.g. facebook.com)
///   4. Forward DNS on www.baseDomain (e.g. www.cloudflare.com)
///   5. Pre-cache all sibling IPs so other connections to same service get instant results
/// Results are cached with a 5-minute TTL (success) or 60-second TTL (failure) for retries.
/// Thread-safe and non-blocking — returns cached results immediately or null while resolving.
/// </summary>
internal sealed class DnsAddressResolver
{
    private readonly ILogger<DnsAddressResolver> _logger;

    /// <summary>
    /// Cached DNS resolution results, keyed by remote IP address.
    /// </summary>
    private readonly ConcurrentDictionary<string, DnsResult> _cache = new();

    /// <summary>
    /// Tracks IPs currently being resolved to prevent duplicate lookups.
    /// </summary>
    private readonly ConcurrentDictionary<string, byte> _inProgress = new();

    /// <summary>Cache TTL for successful resolutions.</summary>
    private static readonly TimeSpan SuccessCacheTtl = TimeSpan.FromMinutes(5);

    /// <summary>Cache TTL for failed resolutions — shorter to allow retries sooner.</summary>
    private static readonly TimeSpan FailedCacheTtl = TimeSpan.FromSeconds(60);

    public DnsAddressResolver(ILogger<DnsAddressResolver> logger)
    {
        _logger = logger;
    }

    /// <summary>
    /// Gets the cached DNS result for the given remote IP, or null if not yet resolved.
    /// If not cached, starts an async resolution in the background (fire-and-forget).
    /// </summary>
    /// <param name="remoteIp">The remote IP address to resolve.</param>
    /// <returns>The cached result, or null if resolution is still in progress.</returns>
    public DnsResult? GetOrStartResolve(string remoteIp)
    {
        if (string.IsNullOrWhiteSpace(remoteIp))
            return null;

        // Check cache first
        if (_cache.TryGetValue(remoteIp, out var cached))
        {
            // Use shorter TTL for failed results to retry sooner
            var ttl = cached.HasBothFamilies || cached.Hostname != null ? SuccessCacheTtl : FailedCacheTtl;
            if (DateTime.UtcNow - cached.ResolvedAtUtc < ttl)
                return cached;

            // Expired — remove and re-resolve
            _cache.TryRemove(remoteIp, out _);
        }

        // Start async resolution if not already in progress
        if (_inProgress.TryAdd(remoteIp, 0))
        {
            _ = ResolveAsync(remoteIp); // Fire-and-forget
        }

        return null; // Not yet available
    }

    /// <summary>
    /// Performs the actual DNS resolution:
    ///   1. Reverse lookup (IP → hostname) + check AddressList
    ///   2. Forward lookup on exact hostname (hostname → A/AAAA)
    ///   3. Fallback forward lookup on base domain (e.g. facebook.com)
    ///   4. Fallback forward lookup on www.baseDomain (e.g. www.openai.com)
    ///   5. Pre-cache sibling IPs from forward lookup to benefit other connections
    /// </summary>
    private async Task ResolveAsync(string remoteIp)
    {
        try
        {
            // Determine the address family of the connection's remote IP
            bool isIpv6 = remoteIp.Contains(':');

            string? hostname = null;
            string? ipv4Address = null;
            string? ipv6Address = null;

            // Assign the known address from the connection itself
            if (isIpv6)
                ipv6Address = remoteIp;
            else
                ipv4Address = remoteIp;

            // Step 1: Reverse DNS lookup (IP → hostname) — also checks AddressList
            try
            {
                var hostEntry = await Dns.GetHostEntryAsync(remoteIp).ConfigureAwait(false);
                hostname = hostEntry.HostName;

                // If reverse DNS just returns the IP back, it's not useful
                if (hostname == remoteIp)
                    hostname = null;

                // Check addresses returned by the reverse lookup itself
                foreach (var addr in hostEntry.AddressList)
                {
                    if (addr.AddressFamily == AddressFamily.InterNetwork && ipv4Address == null)
                        ipv4Address = addr.ToString();
                    else if (addr.AddressFamily == AddressFamily.InterNetworkV6 && ipv6Address == null && !addr.IsIPv6LinkLocal)
                        ipv6Address = addr.ToString();
                }
            }
            catch (SocketException)
            {
                // Reverse DNS failed — this is common, cache as "no hostname"
            }

            // Step 2: Forward DNS lookup on the exact hostname (hostname → all A and AAAA records)
            if (hostname != null && (ipv4Address == null || ipv6Address == null))
            {
                (ipv4Address, ipv6Address) = await TryResolveAddressesAsync(hostname, ipv4Address, ipv6Address);
            }

            // Step 3: Try the base domain if we still don't have both address families.
            // CDN edge hostnames (e.g. edge-star-mini-shv-01-iad3.facebook.com) often lack AAAA records,
            // but the base domain (facebook.com) does have them.
            string? baseDomain = hostname != null ? ExtractBaseDomain(hostname) : null;
            if (hostname != null && (ipv4Address == null || ipv6Address == null))
            {
                if (baseDomain != null && !baseDomain.Equals(hostname, StringComparison.OrdinalIgnoreCase))
                {
                    (ipv4Address, ipv6Address) = await TryResolveAddressesAsync(baseDomain, ipv4Address, ipv6Address);
                }
            }

            // Step 4: Try www.baseDomain as final fallback.
            // Some services (e.g. chatgpt.com/openai.com via Cloudflare) have AAAA on www. subdomain
            // but not on the apex or edge hostname.
            if (baseDomain != null && (ipv4Address == null || ipv6Address == null))
            {
                string wwwDomain = "www." + baseDomain;
                if (!wwwDomain.Equals(hostname, StringComparison.OrdinalIgnoreCase))
                {
                    (ipv4Address, ipv6Address) = await TryResolveAddressesAsync(wwwDomain, ipv4Address, ipv6Address);
                }
            }

            // Determine the alternate address (the one NOT used by the connection)
            string? alternateAddress = isIpv6 ? ipv4Address : ipv6Address;

            var result = new DnsResult
            {
                Hostname = hostname,
                IPv4Address = ipv4Address,
                IPv6Address = ipv6Address,
                AlternateAddress = alternateAddress,
                HasBothFamilies = ipv4Address != null && ipv6Address != null,
                ResolvedAtUtc = DateTime.UtcNow,
            };

            _cache[remoteIp] = result;

            // Step 5: Pre-cache sibling IPs from the resolved domain.
            // When we discover that facebook.com has both v4 and v6, cache that result
            // for ALL IPs returned by forward DNS on the hostname. This way, even if
            // reverse DNS fails for another IP of the same service, it still shows dual-stack.
            if (result.HasBothFamilies && hostname != null)
            {
                await PreCacheSiblingIpsAsync(hostname, result);
            }
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "DNS resolution failed for {RemoteIp}", remoteIp);

            // Cache a "failed" result — uses shorter FailedCacheTtl for faster retry
            _cache[remoteIp] = new DnsResult
            {
                Hostname = null,
                IPv4Address = remoteIp.Contains(':') ? null : remoteIp,
                IPv6Address = remoteIp.Contains(':') ? remoteIp : null,
                AlternateAddress = null,
                HasBothFamilies = false,
                ResolvedAtUtc = DateTime.UtcNow,
            };
        }
        finally
        {
            _inProgress.TryRemove(remoteIp, out _);
        }
    }

    /// <summary>
    /// Pre-caches the dual-stack result for all IPs associated with a hostname.
    /// This ensures that if reverse DNS fails for one IP but succeeded for a sibling IP
    /// of the same domain, the dual-stack info is still available instantly.
    /// </summary>
    private async Task PreCacheSiblingIpsAsync(string hostname, DnsResult sharedResult)
    {
        try
        {
            var allAddresses = await Dns.GetHostAddressesAsync(hostname).ConfigureAwait(false);
            foreach (var addr in allAddresses)
            {
                string addrStr = addr.ToString();
                // Only pre-cache if this IP isn't already cached with a result
                _cache.TryAdd(addrStr, sharedResult);
            }

            // Also pre-cache for the base domain's IPs
            string? baseDomain = ExtractBaseDomain(hostname);
            if (baseDomain != null && !baseDomain.Equals(hostname, StringComparison.OrdinalIgnoreCase))
            {
                var baseAddresses = await Dns.GetHostAddressesAsync(baseDomain).ConfigureAwait(false);
                foreach (var addr in baseAddresses)
                {
                    _cache.TryAdd(addr.ToString(), sharedResult);
                }
            }
        }
        catch
        {
            // Pre-caching is best-effort; failures are silently ignored
        }
    }

    /// <summary>
    /// Attempts to resolve IPv4 and IPv6 addresses for a given hostname via forward DNS lookup.
    /// Returns updated address values without overwriting addresses that are already known.
    /// </summary>
    private static async Task<(string? ipv4, string? ipv6)> TryResolveAddressesAsync(
        string hostname, string? currentIpv4, string? currentIpv6)
    {
        try
        {
            var addresses = await Dns.GetHostAddressesAsync(hostname).ConfigureAwait(false);

            foreach (var addr in addresses)
            {
                if (addr.AddressFamily == AddressFamily.InterNetwork && currentIpv4 == null)
                {
                    currentIpv4 = addr.ToString();
                }
                else if (addr.AddressFamily == AddressFamily.InterNetworkV6 && currentIpv6 == null)
                {
                    // Skip link-local IPv6 addresses
                    if (!addr.IsIPv6LinkLocal)
                        currentIpv6 = addr.ToString();
                }
            }
        }
        catch (SocketException)
        {
            // Forward DNS failed — keep what we have
        }

        return (currentIpv4, currentIpv6);
    }

    /// <summary>
    /// Extracts the base/apex domain from a hostname.
    /// e.g., "edge-star-mini-shv-01-iad3.facebook.com" → "facebook.com"
    /// Handles common multi-part TLDs like .co.uk, .co.in, .com.au
    /// </summary>
    private static string? ExtractBaseDomain(string? hostname)
    {
        if (string.IsNullOrWhiteSpace(hostname))
            return null;

        // Remove trailing dot if present (FQDN notation)
        hostname = hostname.TrimEnd('.');

        var parts = hostname.Split('.');
        if (parts.Length < 2)
            return null;

        // Handle common multi-part TLDs (co.uk, co.in, com.au, etc.)
        // If the second-to-last part is very short (≤3 chars), treat last 3 parts as the base domain
        if (parts.Length >= 3 && parts[^2].Length <= 3 && parts[^1].Length <= 3)
            return string.Join('.', parts[^3..]);

        return parts[^2] + "." + parts[^1];
    }
}

/// <summary>
/// Represents the result of a DNS resolution for a remote IP address.
/// </summary>
internal sealed class DnsResult
{
    /// <summary>The resolved hostname (via reverse DNS). Null if reverse DNS failed.</summary>
    public string? Hostname { get; init; }

    /// <summary>The IPv4 address (A record) for the host. Null if no A record exists.</summary>
    public string? IPv4Address { get; init; }

    /// <summary>The IPv6 address (AAAA record) for the host. Null if no AAAA record exists.</summary>
    public string? IPv6Address { get; init; }

    /// <summary>The alternate IP address (the address family NOT used by the actual connection). Null if only one family exists.</summary>
    public string? AlternateAddress { get; init; }

    /// <summary>True if both IPv4 and IPv6 addresses were found (dual-stack).</summary>
    public bool HasBothFamilies { get; init; }

    /// <summary>UTC timestamp when this resolution was completed.</summary>
    public DateTime ResolvedAtUtc { get; init; }
}
