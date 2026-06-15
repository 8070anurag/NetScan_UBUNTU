using System.Runtime.InteropServices;

namespace NetScan.Platform.Linux.Ebpf;

/// <summary>
/// P/Invoke bindings for libbpf.so.1 — the standard BPF library for loading
/// and managing eBPF programs on Linux.
///
/// These bindings provide the minimal API surface required to:
///   1. Open and load a compiled eBPF object file (.bpf.o)
///   2. Find and attach BPF programs (kprobes, tracepoints)
///   3. Find BPF maps (ring buffer)
///   4. Poll the ring buffer for events from the kernel
///
/// Reference: https://libbpf.readthedocs.io/en/latest/api.html
/// </summary>
internal static class LibBpfInterop
{
    private const string LibBpf = "libbpf.so.1";

    // ═══════════════════════════════════════════════════════════════
    //  BPF Object Lifecycle
    // ═══════════════════════════════════════════════════════════════

    /// <summary>
    /// Opens a BPF object file (.bpf.o) for loading.
    /// </summary>
    /// <param name="path">Path to the compiled .bpf.o file.</param>
    /// <param name="opts">Options (pass IntPtr.Zero for defaults).</param>
    /// <returns>Pointer to bpf_object, or IntPtr.Zero on failure.</returns>
    [DllImport(LibBpf, CallingConvention = CallingConvention.Cdecl)]
    public static extern IntPtr bpf_object__open_file(
        [MarshalAs(UnmanagedType.LPStr)] string path,
        IntPtr opts);

    /// <summary>
    /// Loads BPF programs and maps into the kernel.
    /// Must be called after bpf_object__open_file.
    /// </summary>
    /// <param name="obj">Pointer to bpf_object.</param>
    /// <returns>0 on success, negative errno on failure.</returns>
    [DllImport(LibBpf, CallingConvention = CallingConvention.Cdecl)]
    public static extern int bpf_object__load(IntPtr obj);

    /// <summary>
    /// Closes and frees a BPF object, detaching all programs and freeing maps.
    /// </summary>
    /// <param name="obj">Pointer to bpf_object.</param>
    [DllImport(LibBpf, CallingConvention = CallingConvention.Cdecl)]
    public static extern void bpf_object__close(IntPtr obj);

    // ═══════════════════════════════════════════════════════════════
    //  BPF Program Discovery & Attachment
    // ═══════════════════════════════════════════════════════════════

    /// <summary>
    /// Finds a BPF program by its section name (e.g., "kprobe/tcp_v4_connect").
    /// </summary>
    /// <param name="obj">Pointer to bpf_object.</param>
    /// <param name="name">Section name of the program.</param>
    /// <returns>Pointer to bpf_program, or IntPtr.Zero if not found.</returns>
    [DllImport(LibBpf, CallingConvention = CallingConvention.Cdecl)]
    public static extern IntPtr bpf_object__find_program_by_name(
        IntPtr obj,
        [MarshalAs(UnmanagedType.LPStr)] string name);

    /// <summary>
    /// Attaches a BPF program to its target (kprobe, tracepoint, etc.).
    /// The attachment type is inferred from the program's section name.
    /// </summary>
    /// <param name="prog">Pointer to bpf_program.</param>
    /// <returns>Pointer to bpf_link (attachment handle), or IntPtr.Zero on failure.</returns>
    [DllImport(LibBpf, CallingConvention = CallingConvention.Cdecl)]
    public static extern IntPtr bpf_program__attach(IntPtr prog);

    /// <summary>
    /// Destroys a BPF link, detaching the program from its target.
    /// </summary>
    /// <param name="link">Pointer to bpf_link.</param>
    /// <returns>0 on success, negative errno on failure.</returns>
    [DllImport(LibBpf, CallingConvention = CallingConvention.Cdecl)]
    public static extern int bpf_link__destroy(IntPtr link);

    // ═══════════════════════════════════════════════════════════════
    //  BPF Map Discovery
    // ═══════════════════════════════════════════════════════════════

    /// <summary>
    /// Finds a BPF map by its name (e.g., "events").
    /// </summary>
    /// <param name="obj">Pointer to bpf_object.</param>
    /// <param name="name">Name of the map.</param>
    /// <returns>Pointer to bpf_map, or IntPtr.Zero if not found.</returns>
    [DllImport(LibBpf, CallingConvention = CallingConvention.Cdecl)]
    public static extern IntPtr bpf_object__find_map_by_name(
        IntPtr obj,
        [MarshalAs(UnmanagedType.LPStr)] string name);

    /// <summary>
    /// Gets the file descriptor for a BPF map.
    /// Required for creating ring buffer consumers.
    /// </summary>
    /// <param name="map">Pointer to bpf_map.</param>
    /// <returns>File descriptor (>= 0) on success, negative errno on failure.</returns>
    [DllImport(LibBpf, CallingConvention = CallingConvention.Cdecl)]
    public static extern int bpf_map__fd(IntPtr map);

    // ═══════════════════════════════════════════════════════════════
    //  Ring Buffer Consumer (Event Delivery from Kernel)
    // ═══════════════════════════════════════════════════════════════

    /// <summary>
    /// Callback delegate invoked when the kernel pushes an event to the ring buffer.
    /// Signature: int callback(void *ctx, void *data, size_t data_sz)
    /// Return 0 to continue processing, non-zero to stop.
    /// </summary>
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    public delegate int RingBufferCallback(IntPtr ctx, IntPtr data, UIntPtr dataSz);

    /// <summary>
    /// Creates a new ring buffer consumer for the given map.
    /// </summary>
    /// <param name="mapFd">File descriptor of the BPF_MAP_TYPE_RINGBUF map.</param>
    /// <param name="sampleCb">Callback function invoked for each event.</param>
    /// <param name="ctx">User context pointer (passed to callback).</param>
    /// <param name="opts">Options (pass IntPtr.Zero for defaults).</param>
    /// <returns>Pointer to ring_buffer manager, or IntPtr.Zero on failure.</returns>
    [DllImport(LibBpf, CallingConvention = CallingConvention.Cdecl)]
    public static extern IntPtr ring_buffer__new(
        int mapFd,
        RingBufferCallback sampleCb,
        IntPtr ctx,
        IntPtr opts);

    /// <summary>
    /// Polls the ring buffer for events. Blocks until events arrive or timeout.
    /// Invokes the callback registered in ring_buffer__new for each event.
    /// </summary>
    /// <param name="rb">Pointer to ring_buffer manager.</param>
    /// <param name="timeoutMs">Timeout in milliseconds. -1 for infinite wait.</param>
    /// <returns>Number of events consumed (>= 0), or negative errno on error.</returns>
    [DllImport(LibBpf, CallingConvention = CallingConvention.Cdecl)]
    public static extern int ring_buffer__poll(IntPtr rb, int timeoutMs);

    /// <summary>
    /// Frees the ring buffer consumer.
    /// </summary>
    /// <param name="rb">Pointer to ring_buffer manager.</param>
    [DllImport(LibBpf, CallingConvention = CallingConvention.Cdecl)]
    public static extern void ring_buffer__free(IntPtr rb);

    // ═══════════════════════════════════════════════════════════════
    //  Error Handling
    // ═══════════════════════════════════════════════════════════════

    /// <summary>
    /// Returns the error number from the last libbpf operation.
    /// </summary>
    /// <param name="ret">The return value from a libbpf function.</param>
    /// <returns>Positive errno value.</returns>
    [DllImport(LibBpf, CallingConvention = CallingConvention.Cdecl)]
    public static extern int libbpf_get_error(IntPtr ret);
}

// ═══════════════════════════════════════════════════════════════
//  Managed Event Structure (mirrors the eBPF netscan_event struct)
// ═══════════════════════════════════════════════════════════════

/// <summary>
/// Managed representation of the eBPF netscan_event structure.
/// Must match the exact memory layout of the C struct for correct marshalling.
/// </summary>
[StructLayout(LayoutKind.Sequential, Pack = 1)]
internal struct NetscanEbpfEvent
{
    public uint Pid;                        // Process ID
    public uint Uid;                        // User ID

    [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
    public byte[] Comm;                     // Process name (null-terminated)

    public byte EventType;                  // 1=CONNECT, 2=ACCEPT, 3=CLOSE, 4=STATE
    public byte IpVersion;                  // 4 or 6
    public byte Protocol;                   // 6=TCP, 17=UDP
    public byte Pad;                        // Alignment

    public uint SaddrV4;                    // Source IPv4 (network byte order)
    public uint DaddrV4;                    // Destination IPv4 (network byte order)

    [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
    public byte[] SaddrV6;                  // Source IPv6

    [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
    public byte[] DaddrV6;                  // Destination IPv6

    public ushort Sport;                    // Source port (host byte order)
    public ushort Dport;                    // Destination port (host byte order)
    public int OldState;                    // Previous TCP state
    public int NewState;                    // New TCP state
    public ulong TimestampNs;               // Kernel timestamp (nanoseconds)

    /// <summary>
    /// Gets the process name as a string from the Comm byte array.
    /// </summary>
    public string GetProcessName()
    {
        if (Comm == null) return "Unknown";
        int len = Array.IndexOf(Comm, (byte)0);
        if (len == 0) return "Unknown";
        if (len < 0) len = Comm.Length;
        string name = System.Text.Encoding.UTF8.GetString(Comm, 0, len);
        return string.IsNullOrWhiteSpace(name) ? "Unknown" : name;
    }

    /// <summary>
    /// Gets the source IP address as a string.
    /// </summary>
    public string GetSourceAddress()
    {
        if (IpVersion == 4)
        {
            var bytes = BitConverter.GetBytes(SaddrV4);
            return new System.Net.IPAddress(bytes).ToString();
        }
        if (IpVersion == 6 && SaddrV6 != null)
        {
            return new System.Net.IPAddress(SaddrV6).ToString();
        }
        return "0.0.0.0";
    }

    /// <summary>
    /// Gets the destination IP address as a string.
    /// </summary>
    public string GetDestinationAddress()
    {
        if (IpVersion == 4)
        {
            var bytes = BitConverter.GetBytes(DaddrV4);
            return new System.Net.IPAddress(bytes).ToString();
        }
        if (IpVersion == 6 && DaddrV6 != null)
        {
            return new System.Net.IPAddress(DaddrV6).ToString();
        }
        return "0.0.0.0";
    }
}

/// <summary>
/// eBPF event type constants — must match the C #define values in netscan_ebpf.bpf.c
/// </summary>
internal static class NetscanEventType
{
    public const byte Connect = 1;  // Outbound connection (ALE_AUTH_CONNECT equivalent)
    public const byte Accept  = 2;  // Inbound connection (ALE_CONNECT_REDIRECT equivalent)
    public const byte Close   = 3;  // Connection closed
    public const byte State   = 4;  // TCP state transition
}
