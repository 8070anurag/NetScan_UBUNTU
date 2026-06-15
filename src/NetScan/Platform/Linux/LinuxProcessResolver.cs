using System.Text;
using Microsoft.Extensions.Logging;
using NetScan.Models;

namespace NetScan.Platform.Linux;

/// <summary>
/// Resolves PIDs, process names, command lines, and usernames on Linux
/// using the /proc filesystem.
/// </summary>
internal sealed class LinuxProcessResolver
{
    private readonly ILogger _logger;
    private Dictionary<long, int>? _inodeToPidCache;
    private Dictionary<int, string>? _uidToUserCache;

    public LinuxProcessResolver(ILogger logger)
    {
        _logger = logger;
    }

    /// <summary>
    /// Builds a mapping from socket inode numbers to process IDs
    /// by scanning /proc/[pid]/fd/ directories.
    /// </summary>
    /// <remarks>Requires root privileges for full visibility.</remarks>
    public Dictionary<long, int> BuildInodeToPidMap()
    {
        var map = new Dictionary<long, int>();

        string[] procDirs;
        try
        {
            procDirs = Directory.GetDirectories("/proc");
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to enumerate /proc directories. Are you running as root?");
            return map;
        }

        foreach (var procDir in procDirs)
        {
            var dirName = Path.GetFileName(procDir);
            if (!int.TryParse(dirName, out int pid))
                continue;

            var fdDir = Path.Combine(procDir, "fd");
            if (!Directory.Exists(fdDir))
                continue;

            string[] fdEntries;
            try
            {
                fdEntries = Directory.GetFiles(fdDir);
            }
            catch (UnauthorizedAccessException)
            {
                // Expected for processes we don't own (unless running as root)
                continue;
            }
            catch (DirectoryNotFoundException)
            {
                // Process may have exited
                continue;
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "Failed to enumerate fd directory for PID {Pid}", pid);
                continue;
            }

            foreach (var fdPath in fdEntries)
            {
                try
                {
                    var target = ReadSymlinkTarget(fdPath);
                    if (string.IsNullOrEmpty(target)) continue;

                    // Socket links look like "socket:[12345]"
                    if (target.StartsWith("socket:[") && target.EndsWith("]"))
                    {
                        var inodeStr = target[8..^1]; // Extract the inode number
                        if (long.TryParse(inodeStr, out long inode))
                        {
                            map.TryAdd(inode, pid);
                        }
                    }
                }
                catch
                {
                    // Silently ignore individual fd resolution failures
                }
            }
        }

        _inodeToPidCache = map;
        if (map.Count == 0)
        {
            _logger.LogWarning("Inode-to-PID map is EMPTY. Process names and PIDs will not be resolved. Ensure you are running as root (sudo).");
        }
        else
        {
            _logger.LogDebug("Built inode-to-PID map with {Count} entries", map.Count);
        }
        return map;
    }

    /// <summary>
    /// Reads a symlink target using multiple fallback strategies.
    /// /proc/[pid]/fd/ entries are symlinks like "socket:[12345]".
    /// </summary>
    private string? ReadSymlinkTarget(string path)
    {
        // Strategy 1: FileInfo.LinkTarget (fastest, .NET 7+)
        try
        {
            var target = new FileInfo(path).LinkTarget;
            if (!string.IsNullOrEmpty(target)) return target;
        }
        catch { }

        // Strategy 2: File.ResolveLinkTarget (returns FileSystemInfo)
        try
        {
            var resolved = File.ResolveLinkTarget(path, returnFinalTarget: false);
            var target = resolved?.ToString();
            if (!string.IsNullOrEmpty(target)) return target;
        }
        catch { }

        return null;
    }

    /// <summary>
    /// Gets the PID for a given socket inode number.
    /// </summary>
    public int GetPidForInode(long inode)
    {
        var map = _inodeToPidCache ?? BuildInodeToPidMap();
        return map.GetValueOrDefault(inode, -1);
    }

    /// <summary>
    /// Gets the process name (comm) for a given PID.
    /// </summary>
    public string GetProcessName(int pid)
    {
        if (pid <= 0) return "Unknown";

        try
        {
            var commPath = $"/proc/{pid}/comm";
            if (File.Exists(commPath))
            {
                return ProcessNameNormalizer.Normalize(File.ReadAllText(commPath));
            }
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "Failed to read process name for PID {Pid}", pid);
        }

        return "Unknown";
    }

    /// <summary>
    /// Gets the full command line for a given PID.
    /// </summary>
    public string GetCommandLine(int pid)
    {
        if (pid <= 0) return string.Empty;

        try
        {
            var cmdlinePath = $"/proc/{pid}/cmdline";
            if (File.Exists(cmdlinePath))
            {
                var raw = File.ReadAllBytes(cmdlinePath);
                // cmdline uses null bytes as separators
                var cmdline = Encoding.UTF8.GetString(raw).Replace('\0', ' ').Trim();
                return cmdline;
            }
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "Failed to read command line for PID {Pid}", pid);
        }

        return string.Empty;
    }

    /// <summary>
    /// Resolves a UID to a username by reading /etc/passwd.
    /// </summary>
    public string GetUserName(int uid)
    {
        if (uid < 0) return "Unknown";

        // Build cache on first call
        if (_uidToUserCache == null)
        {
            _uidToUserCache = BuildUidToUserMap();
        }

        return _uidToUserCache.GetValueOrDefault(uid, $"uid:{uid}");
    }

    /// <summary>
    /// Parses /etc/passwd to build a UID-to-username mapping.
    /// </summary>
    private Dictionary<int, string> BuildUidToUserMap()
    {
        var map = new Dictionary<int, string>();

        try
        {
            if (!File.Exists("/etc/passwd"))
            {
                _logger.LogWarning("/etc/passwd not found");
                return map;
            }

            foreach (var line in File.ReadAllLines("/etc/passwd"))
            {
                if (string.IsNullOrWhiteSpace(line) || line.StartsWith('#'))
                    continue;

                // Format: username:x:uid:gid:gecos:home:shell
                var parts = line.Split(':');
                if (parts.Length >= 3 && int.TryParse(parts[2], out int uid))
                {
                    map.TryAdd(uid, parts[0]);
                }
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to parse /etc/passwd");
        }

        _logger.LogDebug("Built UID-to-user map with {Count} entries", map.Count);
        return map;
    }

    /// <summary>
    /// Resolves the owner username of a process by reading /proc/[pid]/status for its UID.
    /// Used for socket types that don't include UID in /proc/net/ (e.g., Unix, Netlink, Packet).
    /// </summary>
    public string GetProcessOwnerFromPid(int pid)
    {
        if (pid <= 0) return "Unknown";

        try
        {
            var statusPath = $"/proc/{pid}/status";
            if (!File.Exists(statusPath)) return "Unknown";

            foreach (var line in File.ReadLines(statusPath))
            {
                if (line.StartsWith("Uid:", StringComparison.Ordinal))
                {
                    // Format: Uid:\treal\teffective\tsaved\tfs
                    var parts = line.Split('\t', StringSplitOptions.RemoveEmptyEntries);
                    if (parts.Length >= 2 && int.TryParse(parts[1], out int uid))
                    {
                        return GetUserName(uid);
                    }
                    break;
                }
            }
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "Failed to resolve owner for PID {Pid}", pid);
        }

        return "Unknown";
    }

    /// <summary>
    /// Invalidates cached data. Call before each scan cycle for fresh results.
    /// </summary>
    public void InvalidateCache()
    {
        _inodeToPidCache = null;
        // We keep _uidToUserCache since /etc/passwd rarely changes
    }
}
