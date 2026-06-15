// SPDX-License-Identifier: GPL-2.0
// NetScan eBPF Program — WFP ALE Layer Equivalent for Linux
//
// This program hooks into kernel functions to provide per-connection
// event-driven monitoring, equivalent to:
//   FWPM_LAYER_ALE_AUTH_CONNECT_V4/V6  → kprobe/tcp_v4_connect, tcp_v6_connect
//   FWPM_LAYER_ALE_CONNECT_REDIRECT    → kretprobe/inet_csk_accept
//   Connection close detection          → tracepoint/sock/inet_sock_set_state
//
// Events are pushed to user space via BPF Ring Buffer.
// Requires: Linux kernel 5.8+, libbpf, clang/llvm
//
// Build: make -C src/NetScan/Platform/Linux/Ebpf/

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>

// ═══════════════════════════════════════════════════════════════
//  Event Type Constants (matches C# NetscanEventType enum)
// ═══════════════════════════════════════════════════════════════

#define EVENT_TYPE_CONNECT   1   // Outbound connection attempt (ALE_AUTH_CONNECT)
#define EVENT_TYPE_ACCEPT    2   // Inbound connection accepted (ALE_CONNECT_REDIRECT)
#define EVENT_TYPE_CLOSE     3   // Connection closed (state → TCP_CLOSE)
#define EVENT_TYPE_STATE     4   // TCP state transition

// IP version constants
#define AF_INET   2
#define AF_INET6  10
#define AF_UNIX   1
#define AF_NETLINK 16
#define AF_PACKET  17
#define AF_VSOCK   40
#define AF_BLUETOOTH 31

// TCP state constants (from Linux kernel include/net/tcp_states.h)
#define TCP_ESTABLISHED  1
#define TCP_SYN_SENT     2
#define TCP_SYN_RECV     3
#define TCP_FIN_WAIT1    4
#define TCP_FIN_WAIT2    5
#define TCP_TIME_WAIT    6
#define TCP_CLOSE        7
#define TCP_CLOSE_WAIT   8
#define TCP_LAST_ACK     9
#define TCP_LISTEN       10
#define TCP_CLOSING      11
#define TCP_NEW_SYN_RECV 12

// ═══════════════════════════════════════════════════════════════
//  Event Structure — Sent to User Space via Ring Buffer
// ═══════════════════════════════════════════════════════════════

struct netscan_event {
    __u32 pid;              // Process ID
    __u32 uid;              // User ID
    char  comm[16];         // Process name (command)
    __u8  event_type;       // EVENT_TYPE_CONNECT / ACCEPT / CLOSE / STATE
    __u8  ip_version;       // 4 or 6
    __u8  protocol;         // IPPROTO_TCP(6) or IPPROTO_UDP(17)
    __u8  pad;              // Alignment padding
    __u32 saddr_v4;         // Source IPv4 address (network byte order)
    __u32 daddr_v4;         // Destination IPv4 address (network byte order)
    __u8  saddr_v6[16];     // Source IPv6 address
    __u8  daddr_v6[16];     // Destination IPv6 address
    __u16 sport;            // Source port (host byte order)
    __u16 dport;            // Destination port (host byte order)
    __s32 old_state;        // Previous TCP state (for state change events)
    __s32 new_state;        // New TCP state (for state change events)
    __u64 timestamp_ns;     // Kernel timestamp (nanoseconds)
} __attribute__((packed));

// ═══════════════════════════════════════════════════════════════
//  BPF Maps
// ═══════════════════════════════════════════════════════════════

// Ring buffer for sending events to user space
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);  // 256 KB ring buffer
} events SEC(".maps");

// Hash map to temporarily store socket pointers between kprobe entry and kretprobe exit
// Key: thread ID (pid_tgid), Value: pointer to struct sock
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, __u64);
    __type(value, struct sock *);
} connect_start SEC(".maps");

// Flow key for egress flow tracking
struct flow_key {
    __u32 saddr_v4;
    __u32 daddr_v4;
    __u8  saddr_v6[16];
    __u8  daddr_v6[16];
    __u16 sport;
    __u16 dport;
    __u8  ip_version;
    __u8  pad;
} __attribute__((packed));

// Stashed arguments for sendmsg entries (UDP, RAW, ping)
struct sendmsg_start_args {
    struct sock *sk;
    struct msghdr *msg;
};

// Temp hash map to store sendmsg entry args
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, __u64);
    __type(value, struct sendmsg_start_args);
} sendmsg_start_map SEC(".maps");

// LRU hash map to keep track of seen flows for deduplication
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 10240);
    __type(key, struct flow_key);
    __type(value, __u64); // last sent timestamp in ns
} flow_dedup_map SEC(".maps");

// ═══════════════════════════════════════════════════════════════
//  Helper: Fill event with socket info
// ═══════════════════════════════════════════════════════════════

static __always_inline int fill_event_from_sock(struct netscan_event *evt, struct sock *sk)
{
    // Read address family
    __u16 family = BPF_CORE_READ(sk, __sk_common.skc_family);
    evt->protocol = 6; // IPPROTO_TCP

    if (family == AF_INET) {
        evt->ip_version = 4;
        evt->saddr_v4 = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);
        evt->daddr_v4 = BPF_CORE_READ(sk, __sk_common.skc_daddr);
    } else if (family == AF_INET6) {
        evt->ip_version = 6;
        BPF_CORE_READ_INTO(&evt->saddr_v6, sk, __sk_common.skc_v6_rcv_saddr.in6_u.u6_addr8);
        BPF_CORE_READ_INTO(&evt->daddr_v6, sk, __sk_common.skc_v6_daddr.in6_u.u6_addr8);
    } else {
        return -1; // Unsupported address family
    }

    // Read ports — skc_num is host byte order, skc_dport is network byte order
    evt->sport = BPF_CORE_READ(sk, __sk_common.skc_num);
    evt->dport = bpf_ntohs(BPF_CORE_READ(sk, __sk_common.skc_dport));

    // Resolve owner UID from the socket
    evt->uid = BPF_CORE_READ(sk, sk_uid.val);

    return 0;
}

static __always_inline void fill_process_info(struct netscan_event *evt)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u64 uid_gid  = bpf_get_current_uid_gid();

    evt->pid = pid_tgid >> 32;
    evt->uid = uid_gid & 0xFFFFFFFF;
    evt->timestamp_ns = bpf_ktime_get_ns();

    bpf_get_current_comm(&evt->comm, sizeof(evt->comm));
}

// ═══════════════════════════════════════════════════════════════
//  Helper: Process sendmsg (UDP/RAW) exit to build flow event
// ═══════════════════════════════════════════════════════════════

static __always_inline int resolve_flow_key(struct flow_key *key, struct sock *sk, struct msghdr *msg, __u8 report_protocol)
{
    __u16 family = BPF_CORE_READ(sk, __sk_common.skc_family);
    int ip_version = (family == AF_INET6) ? 6 : 4;
    key->ip_version = ip_version;

    // Resolve destination address and port from msghdr if present, otherwise from socket
    void *msg_name = NULL;
    if (msg && report_protocol != 6) {
        msg_name = BPF_CORE_READ(msg, msg_name);
    }

    int msg_name_resolved = 0;
    if (msg_name && report_protocol != 6) {
        __u16 dest_family = 0;
        if (bpf_probe_read_kernel(&dest_family, sizeof(dest_family), msg_name) < 0) {
            bpf_probe_read_user(&dest_family, sizeof(dest_family), msg_name);
        }
        if (dest_family == AF_INET) {
            struct sockaddr_in sin = {};
            int err = bpf_probe_read_kernel(&sin, sizeof(sin), msg_name);
            if (err < 0) {
                err = bpf_probe_read_user(&sin, sizeof(sin), msg_name);
            }
            if (err == 0) {
                key->daddr_v4 = sin.sin_addr.s_addr;
                key->dport = (report_protocol == 255) ? 0 : bpf_ntohs(sin.sin_port);
                key->ip_version = 4;
                
                if (family == AF_INET) {
                    key->saddr_v4 = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);
                } else if (family == AF_INET6) {
                    // Extract IPv4 source from IPv4-mapped IPv6 address (last 4 bytes)
                    __u8 v6src[16] = {};
                    BPF_CORE_READ_INTO(&v6src, sk, __sk_common.skc_v6_rcv_saddr.in6_u.u6_addr8);
                    __builtin_memcpy(&key->saddr_v4, &v6src[12], 4);
                }
                msg_name_resolved = 1;
            }
        } else if (dest_family == AF_INET6) {
            struct sockaddr_in6 sin6 = {};
            int err = bpf_probe_read_kernel(&sin6, sizeof(sin6), msg_name);
            if (err < 0) {
                err = bpf_probe_read_user(&sin6, sizeof(sin6), msg_name);
            }
            if (err == 0) {
                __builtin_memcpy(&key->daddr_v6, &sin6.sin6_addr, 16);
                key->dport = (report_protocol == 255) ? 0 : bpf_ntohs(sin6.sin6_port);
                key->ip_version = 6;

                if (family == AF_INET6) {
                    BPF_CORE_READ_INTO(&key->saddr_v6, sk, __sk_common.skc_v6_rcv_saddr.in6_u.u6_addr8);
                } else if (family == AF_INET) {
                    __u32 ipv4 = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);
                    key->saddr_v6[10] = 0xff;
                    key->saddr_v6[11] = 0xff;
                    __builtin_memcpy(&key->saddr_v6[12], &ipv4, 4);
                }
                msg_name_resolved = 1;
            }
        }
    }

    if (!msg_name_resolved) {
        if (ip_version == 4) {
            key->saddr_v4 = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);
            key->daddr_v4 = BPF_CORE_READ(sk, __sk_common.skc_daddr);
            key->dport = (report_protocol == 255) ? 0 : bpf_ntohs(BPF_CORE_READ(sk, __sk_common.skc_dport));
        } else {
            BPF_CORE_READ_INTO(&key->saddr_v6, sk, __sk_common.skc_v6_rcv_saddr.in6_u.u6_addr8);
            BPF_CORE_READ_INTO(&key->daddr_v6, sk, __sk_common.skc_v6_daddr.in6_u.u6_addr8);
            key->dport = (report_protocol == 255) ? 0 : bpf_ntohs(BPF_CORE_READ(sk, __sk_common.skc_dport));
        }
    }

    return 0;
}

static __always_inline int process_sendmsg_exit(void *ctx, int ret, __u8 report_protocol)
{
    if (ret < 0) return 0; // Ignore send failures

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    struct sendmsg_start_args *argsp = bpf_map_lookup_elem(&sendmsg_start_map, &pid_tgid);
    if (!argsp) return 0;

    struct sock *sk = argsp->sk;
    struct msghdr *msg = argsp->msg;
    bpf_map_delete_elem(&sendmsg_start_map, &pid_tgid);

    if (!sk) return 0;

    __u8 proto = BPF_CORE_READ(sk, sk_protocol);
    if (report_protocol != 255) {
        report_protocol = proto ? proto : report_protocol;
    }

    if (report_protocol == 136) {
        return 0;
    }

    struct flow_key key;
    __builtin_memset(&key, 0, sizeof(key));
    resolve_flow_key(&key, sk, msg, report_protocol);

    // Resolve local port/protocol for key.sport
    if (report_protocol == 255) {
        key.sport = proto;
    } else {
        key.sport = BPF_CORE_READ(sk, __sk_common.skc_num);
    }

    if (report_protocol != 255 && key.sport == 0) {
        return 0;
    }

    // Throttling
    __u64 now = bpf_ktime_get_ns();
    __u64 *last_ts = bpf_map_lookup_elem(&flow_dedup_map, &key);
    if (last_ts && (now - *last_ts < 5000000000ULL)) {
        return 0;
    }
    bpf_map_update_elem(&flow_dedup_map, &key, &now, BPF_ANY);

    // Emit event
    struct netscan_event *evt = bpf_ringbuf_reserve(&events, sizeof(*evt), 0);
    if (!evt) return 0;

    __builtin_memset(evt, 0, sizeof(*evt));
    evt->event_type = EVENT_TYPE_CONNECT;
    evt->protocol = report_protocol;
    evt->ip_version = key.ip_version;

    fill_process_info(evt);
    evt->uid = BPF_CORE_READ(sk, sk_uid.val);

    if (key.ip_version == 4) {
        evt->saddr_v4 = key.saddr_v4;
        evt->daddr_v4 = key.daddr_v4;
    } else {
        __builtin_memcpy(evt->saddr_v6, key.saddr_v6, 16);
        __builtin_memcpy(evt->daddr_v6, key.daddr_v6, 16);
    }
    evt->sport = key.sport;
    evt->dport = key.dport;

    bpf_ringbuf_submit(evt, 0);
    return 0;
}

// ═══════════════════════════════════════════════════════════════
//  Helper: Process recvmsg (UDP) exit to build inbound flow event
// ═══════════════════════════════════════════════════════════════

static __always_inline int process_recvmsg_exit(void *ctx, int ret)
{
    if (ret < 0) return 0; // Ignore receive failures

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    struct sendmsg_start_args *argsp = bpf_map_lookup_elem(&sendmsg_start_map, &pid_tgid);
    if (!argsp) return 0;

    struct sock *sk = argsp->sk;
    struct msghdr *msg = argsp->msg;
    bpf_map_delete_elem(&sendmsg_start_map, &pid_tgid);

    if (!sk) return 0;

    struct flow_key key;
    __builtin_memset(&key, 0, sizeof(key));
    resolve_flow_key(&key, sk, msg, 17); // always UDP (17) for recvmsg

    // Resolve local port/protocol for key.sport
    key.sport = BPF_CORE_READ(sk, __sk_common.skc_num);

    if (key.sport == 0) return 0;

    // Throttle
    __u64 now = bpf_ktime_get_ns();
    __u64 *last_ts = bpf_map_lookup_elem(&flow_dedup_map, &key);
    if (last_ts && (now - *last_ts < 5000000000ULL)) return 0;
    bpf_map_update_elem(&flow_dedup_map, &key, &now, BPF_ANY);

    // Emit event
    struct netscan_event *evt = bpf_ringbuf_reserve(&events, sizeof(*evt), 0);
    if (!evt) return 0;

    __builtin_memset(evt, 0, sizeof(*evt));
    evt->event_type = EVENT_TYPE_ACCEPT;
    evt->protocol = 17;
    evt->ip_version = key.ip_version;

    fill_process_info(evt);
    evt->uid = BPF_CORE_READ(sk, sk_uid.val);

    if (key.ip_version == 4) {
        evt->saddr_v4 = key.saddr_v4;
        evt->daddr_v4 = key.daddr_v4;
    } else {
        __builtin_memcpy(evt->saddr_v6, key.saddr_v6, 16);
        __builtin_memcpy(evt->daddr_v6, key.daddr_v6, 16);
    }
    evt->sport = key.sport;
    evt->dport = key.dport;

    bpf_ringbuf_submit(evt, 0);
    return 0;
}

// ═══════════════════════════════════════════════════════════════
//  UDP and RAW Socket Hooking — Entry / Exit Probes
// ═══════════════════════════════════════════════════════════════

SEC("kprobe/udp_sendmsg")
int BPF_KPROBE(trace_udp_sendmsg_entry, struct sock *sk, struct msghdr *msg, size_t len)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    struct sendmsg_start_args args = {};
    args.sk = sk;
    args.msg = msg;
    bpf_map_update_elem(&sendmsg_start_map, &pid_tgid, &args, BPF_ANY);
    return 0;
}

SEC("kretprobe/udp_sendmsg")
int BPF_KRETPROBE(trace_udp_sendmsg_exit, int ret)
{
    return process_sendmsg_exit(ctx, ret, 17);
}

SEC("kprobe/udpv6_sendmsg")
int BPF_KPROBE(trace_udpv6_sendmsg_entry, struct sock *sk, struct msghdr *msg, size_t len)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    struct sendmsg_start_args args = {};
    args.sk = sk;
    args.msg = msg;
    bpf_map_update_elem(&sendmsg_start_map, &pid_tgid, &args, BPF_ANY);
    return 0;
}

SEC("kretprobe/udpv6_sendmsg")
int BPF_KRETPROBE(trace_udpv6_sendmsg_exit, int ret)
{
    return process_sendmsg_exit(ctx, ret, 17);
}

SEC("kprobe/tcp_sendmsg")
int BPF_KPROBE(trace_tcp_sendmsg_entry, struct sock *sk, struct msghdr *msg, size_t len)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    struct sendmsg_start_args args = {};
    args.sk = sk;
    args.msg = msg;
    bpf_map_update_elem(&sendmsg_start_map, &pid_tgid, &args, BPF_ANY);
    return 0;
}

SEC("kretprobe/tcp_sendmsg")
int BPF_KRETPROBE(trace_tcp_sendmsg_exit, int ret)
{
    return process_sendmsg_exit(ctx, ret, 6);
}

// ── UDP Receive hooks (incoming UDP — catches silent listeners) ──

SEC("kprobe/udp_recvmsg")
int BPF_KPROBE(trace_udp_recvmsg_entry, struct sock *sk, struct msghdr *msg)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    struct sendmsg_start_args args = {};
    args.sk = sk;
    args.msg = msg;
    bpf_map_update_elem(&sendmsg_start_map, &pid_tgid, &args, BPF_ANY);
    return 0;
}

SEC("kretprobe/udp_recvmsg")
int BPF_KRETPROBE(trace_udp_recvmsg_exit, int ret)
{
    return process_recvmsg_exit(ctx, ret);
}

SEC("kprobe/udpv6_recvmsg")
int BPF_KPROBE(trace_udpv6_recvmsg_entry, struct sock *sk, struct msghdr *msg)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    struct sendmsg_start_args args = {};
    args.sk = sk;
    args.msg = msg;
    bpf_map_update_elem(&sendmsg_start_map, &pid_tgid, &args, BPF_ANY);
    return 0;
}

SEC("kretprobe/udpv6_recvmsg")
int BPF_KRETPROBE(trace_udpv6_recvmsg_exit, int ret)
{
    return process_recvmsg_exit(ctx, ret);
}

// ── RAW socket hooks ──
SEC("kprobe/raw_sendmsg")
int BPF_KPROBE(trace_raw_sendmsg_entry, struct sock *sk, struct msghdr *msg, size_t len)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    struct sendmsg_start_args args = {};
    args.sk = sk;
    args.msg = msg;
    bpf_map_update_elem(&sendmsg_start_map, &pid_tgid, &args, BPF_ANY);
    return 0;
}

SEC("kretprobe/raw_sendmsg")
int BPF_KRETPROBE(trace_raw_sendmsg_exit, int ret)
{
    return process_sendmsg_exit(ctx, ret, 255);
}

SEC("kprobe/rawv6_sendmsg")
int BPF_KPROBE(trace_rawv6_sendmsg_entry, struct sock *sk, struct msghdr *msg, size_t len)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    struct sendmsg_start_args args = {};
    args.sk = sk;
    args.msg = msg;
    bpf_map_update_elem(&sendmsg_start_map, &pid_tgid, &args, BPF_ANY);
    return 0;
}

SEC("kretprobe/rawv6_sendmsg")
int BPF_KRETPROBE(trace_rawv6_sendmsg_exit, int ret)
{
    return process_sendmsg_exit(ctx, ret, 255);
}

// ── Ping socket hooks ──
SEC("kprobe/ping_v4_sendmsg")
int BPF_KPROBE(trace_ping_v4_sendmsg_entry, struct sock *sk, struct msghdr *msg, size_t len)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    struct sendmsg_start_args args = {};
    args.sk = sk;
    args.msg = msg;
    bpf_map_update_elem(&sendmsg_start_map, &pid_tgid, &args, BPF_ANY);
    return 0;
}

SEC("kretprobe/ping_v4_sendmsg")
int BPF_KRETPROBE(trace_ping_v4_sendmsg_exit, int ret)
{
    return process_sendmsg_exit(ctx, ret, 255);
}

SEC("kprobe/ping_v6_sendmsg")
int BPF_KPROBE(trace_ping_v6_sendmsg_entry, struct sock *sk, struct msghdr *msg, size_t len)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    struct sendmsg_start_args args = {};
    args.sk = sk;
    args.msg = msg;
    bpf_map_update_elem(&sendmsg_start_map, &pid_tgid, &args, BPF_ANY);
    return 0;
}

SEC("kretprobe/ping_v6_sendmsg")
int BPF_KRETPROBE(trace_ping_v6_sendmsg_exit, int ret)
{
    return process_sendmsg_exit(ctx, ret, 255);
}

// ═══════════════════════════════════════════════════════════════
//  Hook 1: tcp_v4_connect — Outbound IPv4 TCP Connection
//  (Equivalent to FWPM_LAYER_ALE_AUTH_CONNECT_V4)
// ═══════════════════════════════════════════════════════════════

SEC("kprobe/tcp_v4_connect")
int BPF_KPROBE(trace_tcp_v4_connect_entry, struct sock *sk)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();

    // Stash the socket pointer — we'll retrieve it in the kretprobe
    bpf_map_update_elem(&connect_start, &pid_tgid, &sk, BPF_ANY);
    return 0;
}

SEC("kretprobe/tcp_v4_connect")
int BPF_KRETPROBE(trace_tcp_v4_connect_exit, int ret)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();

    // Retrieve the socket pointer stashed in the kprobe entry
    struct sock **skp = bpf_map_lookup_elem(&connect_start, &pid_tgid);
    if (!skp) return 0;

    struct sock *sk = *skp;
    bpf_map_delete_elem(&connect_start, &pid_tgid);

    // Only emit event if connect() was initiated (ret == 0 or EINPROGRESS)
    if (ret != 0 && ret != -115) // -EINPROGRESS = -115
        return 0;

    // Reserve space in ring buffer
    struct netscan_event *evt = bpf_ringbuf_reserve(&events, sizeof(*evt), 0);
    if (!evt) return 0;

    __builtin_memset(evt, 0, sizeof(*evt));
    evt->event_type = EVENT_TYPE_CONNECT;
    fill_process_info(evt);

    if (fill_event_from_sock(evt, sk) < 0) {
        bpf_ringbuf_discard(evt, 0);
        return 0;
    }

    bpf_ringbuf_submit(evt, 0);
    return 0;
}

// ═══════════════════════════════════════════════════════════════
//  Hook 2: tcp_v6_connect — Outbound IPv6 TCP Connection
//  (Equivalent to FWPM_LAYER_ALE_AUTH_CONNECT_V6)
// ═══════════════════════════════════════════════════════════════

SEC("kprobe/tcp_v6_connect")
int BPF_KPROBE(trace_tcp_v6_connect_entry, struct sock *sk)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    bpf_map_update_elem(&connect_start, &pid_tgid, &sk, BPF_ANY);
    return 0;
}

SEC("kretprobe/tcp_v6_connect")
int BPF_KRETPROBE(trace_tcp_v6_connect_exit, int ret)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();

    struct sock **skp = bpf_map_lookup_elem(&connect_start, &pid_tgid);
    if (!skp) return 0;

    struct sock *sk = *skp;
    bpf_map_delete_elem(&connect_start, &pid_tgid);

    if (ret != 0 && ret != -115)
        return 0;

    struct netscan_event *evt = bpf_ringbuf_reserve(&events, sizeof(*evt), 0);
    if (!evt) return 0;

    __builtin_memset(evt, 0, sizeof(*evt));
    evt->event_type = EVENT_TYPE_CONNECT;
    fill_process_info(evt);

    if (fill_event_from_sock(evt, sk) < 0) {
        bpf_ringbuf_discard(evt, 0);
        return 0;
    }

    bpf_ringbuf_submit(evt, 0);
    return 0;
}

// ═══════════════════════════════════════════════════════════════
//  Hook 3: inet_csk_accept — Inbound TCP Connection Accepted
//  (Equivalent to FWPM_LAYER_ALE_CONNECT_REDIRECT_V4/V6)
// ═══════════════════════════════════════════════════════════════

SEC("kretprobe/inet_csk_accept")
int BPF_KRETPROBE(trace_inet_csk_accept, struct sock *newsk)
{
    if (!newsk) return 0;

    struct netscan_event *evt = bpf_ringbuf_reserve(&events, sizeof(*evt), 0);
    if (!evt) return 0;

    __builtin_memset(evt, 0, sizeof(*evt));
    evt->event_type = EVENT_TYPE_ACCEPT;
    fill_process_info(evt);

    if (fill_event_from_sock(evt, newsk) < 0) {
        bpf_ringbuf_discard(evt, 0);
        return 0;
    }

    bpf_ringbuf_submit(evt, 0);
    return 0;
}

// ═══════════════════════════════════════════════════════════════
//  Hook 4: inet_sock_set_state — TCP State Transitions
//  Captures connection CLOSE events and state changes
// ═══════════════════════════════════════════════════════════════

SEC("tracepoint/sock/inet_sock_set_state")
int trace_inet_sock_set_state(struct trace_event_raw_inet_sock_set_state *ctx)
{
    // Only track TCP (protocol 6)
    __u16 protocol = ctx->protocol;
    if (protocol != 6) // IPPROTO_TCP
        return 0;

    int oldstate = ctx->oldstate;
    int newstate = ctx->newstate;

    // We're interested in:
    //   - Transitions TO TCP_ESTABLISHED (connection fully established)
    //   - Transitions TO TCP_CLOSE (connection closed)
    //   - Transitions TO TCP_CLOSE_WAIT (remote side closed)
    if (newstate != TCP_ESTABLISHED &&
        newstate != TCP_CLOSE &&
        newstate != TCP_CLOSE_WAIT &&
        newstate != TCP_FIN_WAIT1)
        return 0;

    struct netscan_event *evt = bpf_ringbuf_reserve(&events, sizeof(*evt), 0);
    if (!evt) return 0;

    __builtin_memset(evt, 0, sizeof(*evt));

    // Determine event type based on new state
    if (newstate == TCP_CLOSE || newstate == TCP_CLOSE_WAIT || newstate == TCP_FIN_WAIT1) {
        evt->event_type = EVENT_TYPE_CLOSE;
    } else {
        evt->event_type = EVENT_TYPE_STATE;
    }

    fill_process_info(evt);

    // Resolve the socket owner's UID directly from the socket structure,
    // since this tracepoint can run in softirq/interrupt context where 
    // bpf_get_current_uid_gid() returns the running task's or kernel's UID.
    struct sock *sk = (struct sock *)ctx->skaddr;
    if (sk) {
        evt->uid = BPF_CORE_READ(sk, sk_uid.val);
    }

    evt->old_state = oldstate;
    evt->new_state = newstate;
    evt->protocol = 6; // TCP

    // Read addresses from tracepoint context
    __u16 family = ctx->family;
    if (family == AF_INET) {
        evt->ip_version = 4;
        __builtin_memcpy(&evt->saddr_v4, ctx->saddr, 4);
        __builtin_memcpy(&evt->daddr_v4, ctx->daddr, 4);
    } else if (family == AF_INET6) {
        evt->ip_version = 6;
        bpf_probe_read_kernel(evt->saddr_v6, 16, ctx->saddr_v6);
        bpf_probe_read_kernel(evt->daddr_v6, 16, ctx->daddr_v6);
    } else {
        bpf_ringbuf_discard(evt, 0);
        return 0;
    }

    evt->sport = ctx->sport;
    evt->dport = bpf_ntohs(ctx->dport);

    bpf_ringbuf_submit(evt, 0);
    return 0;
}

// ═══════════════════════════════════════════════════════════════
//  DCCP Socket Hooking (protocol 33)
// ═══════════════════════════════════════════════════════════════

SEC("kprobe/dccp_sendmsg")
int BPF_KPROBE(trace_dccp_sendmsg_entry, struct sock *sk, struct msghdr *msg, size_t len)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    struct sendmsg_start_args args = {};
    args.sk = sk;
    args.msg = msg;
    bpf_map_update_elem(&sendmsg_start_map, &pid_tgid, &args, BPF_ANY);
    return 0;
}

SEC("kretprobe/dccp_sendmsg")
int BPF_KRETPROBE(trace_dccp_sendmsg_exit, int ret)
{
    return process_sendmsg_exit(ctx, ret, 33);
}

// ═══════════════════════════════════════════════════════════════
//  SCTP Socket Hooking (protocol 132)
// ═══════════════════════════════════════════════════════════════

SEC("kprobe/sctp_sendmsg")
int BPF_KPROBE(trace_sctp_sendmsg_entry, struct sock *sk, struct msghdr *msg, size_t len)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    struct sendmsg_start_args args = {};
    args.sk = sk;
    args.msg = msg;
    bpf_map_update_elem(&sendmsg_start_map, &pid_tgid, &args, BPF_ANY);
    return 0;
}

SEC("kretprobe/sctp_sendmsg")
int BPF_KRETPROBE(trace_sctp_sendmsg_exit, int ret)
{
    return process_sendmsg_exit(ctx, ret, 132);
}

// ═══════════════════════════════════════════════════════════════
//  Non-IP Protocol Helper
//  These protocols don't use IP addresses; we report socket-
//  specific metadata (type, protocol) in sport/dport.
// ═══════════════════════════════════════════════════════════════

static __always_inline int process_nonip_exit(void *ctx, int ret, __u8 report_protocol)
{
    if (ret < 0) return 0;

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    struct sendmsg_start_args *argsp = bpf_map_lookup_elem(&sendmsg_start_map, &pid_tgid);
    if (!argsp) return 0;

    struct sock *sk = argsp->sk;
    bpf_map_delete_elem(&sendmsg_start_map, &pid_tgid);

    if (!sk) return 0;

    // Construct dedup flow key using protocol-specific fields
    struct flow_key key;
    __builtin_memset(&key, 0, sizeof(key));
    key.ip_version = 0; // Non-IP marker

    __u32 pid = pid_tgid >> 32;

    // Generic non-IP protocol (204+): use socket type + PID for dedup
    key.sport = BPF_CORE_READ(sk, sk_type);
    key.saddr_v4 = pid;

    // Throttle: suppress duplicate events within 30 seconds
    __u64 now = bpf_ktime_get_ns();
    __u64 *last_ts = bpf_map_lookup_elem(&flow_dedup_map, &key);
    if (last_ts && (now - *last_ts < 5000000000ULL)) return 0;
    bpf_map_update_elem(&flow_dedup_map, &key, &now, BPF_ANY);

    // Emit event
    struct netscan_event *evt = bpf_ringbuf_reserve(&events, sizeof(*evt), 0);
    if (!evt) return 0;

    __builtin_memset(evt, 0, sizeof(*evt));
    evt->event_type = EVENT_TYPE_CONNECT;
    evt->protocol = report_protocol;
    evt->ip_version = 0; // Non-IP

    fill_process_info(evt);
    evt->uid = BPF_CORE_READ(sk, sk_uid.val);

    // Generic non-IP protocol (204+): sport = socket type, dport = sk_protocol
    evt->sport = BPF_CORE_READ(sk, sk_type);
    evt->dport = BPF_CORE_READ(sk, sk_protocol);

    bpf_ringbuf_submit(evt, 0);
    return 0;
}



// ═══════════════════════════════════════════════════════════════
//  Bluetooth Socket Hooking (protocol 204)
//  L2CAP (BLE, classic), RFCOMM (serial), SCO (audio)
// ═══════════════════════════════════════════════════════════════

SEC("kprobe/l2cap_sock_sendmsg")
int BPF_KPROBE(trace_l2cap_sock_sendmsg_entry, struct socket *sock, struct msghdr *msg, size_t len)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    struct sock *sk = BPF_CORE_READ(sock, sk);
    struct sendmsg_start_args args = {};
    args.sk = sk;
    args.msg = msg;
    bpf_map_update_elem(&sendmsg_start_map, &pid_tgid, &args, BPF_ANY);
    return 0;
}

SEC("kretprobe/l2cap_sock_sendmsg")
int BPF_KRETPROBE(trace_l2cap_sock_sendmsg_exit, int ret)
{
    return process_nonip_exit(ctx, ret, 204);
}

SEC("kprobe/rfcomm_sock_sendmsg")
int BPF_KPROBE(trace_rfcomm_sock_sendmsg_entry, struct socket *sock, struct msghdr *msg, size_t len)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    struct sock *sk = BPF_CORE_READ(sock, sk);
    struct sendmsg_start_args args = {};
    args.sk = sk;
    args.msg = msg;
    bpf_map_update_elem(&sendmsg_start_map, &pid_tgid, &args, BPF_ANY);
    return 0;
}

SEC("kretprobe/rfcomm_sock_sendmsg")
int BPF_KRETPROBE(trace_rfcomm_sock_sendmsg_exit, int ret)
{
    return process_nonip_exit(ctx, ret, 204);
}

SEC("kprobe/sco_sock_sendmsg")
int BPF_KPROBE(trace_sco_sock_sendmsg_entry, struct socket *sock, struct msghdr *msg, size_t len)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    struct sock *sk = BPF_CORE_READ(sock, sk);
    struct sendmsg_start_args args = {};
    args.sk = sk;
    args.msg = msg;
    bpf_map_update_elem(&sendmsg_start_map, &pid_tgid, &args, BPF_ANY);
    return 0;
}

SEC("kretprobe/sco_sock_sendmsg")
int BPF_KRETPROBE(trace_sco_sock_sendmsg_exit, int ret)
{
    return process_nonip_exit(ctx, ret, 204);
}

// ═══════════════════════════════════════════════════════════════
//  SMC — Shared Memory Communications over RDMA (protocol 205)
// ═══════════════════════════════════════════════════════════════

SEC("kprobe/smc_sendmsg")
int BPF_KPROBE(trace_smc_sendmsg_entry, struct socket *sock, struct msghdr *msg, size_t len)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    struct sock *sk = BPF_CORE_READ(sock, sk);
    struct sendmsg_start_args args = {};
    args.sk = sk;
    args.msg = msg;
    bpf_map_update_elem(&sendmsg_start_map, &pid_tgid, &args, BPF_ANY);
    return 0;
}

SEC("kretprobe/smc_sendmsg")
int BPF_KRETPROBE(trace_smc_sendmsg_exit, int ret)
{
    return process_nonip_exit(ctx, ret, 205);
}

// ═══════════════════════════════════════════════════════════════
//  CAN — Controller Area Network (protocol 206)
//  Hooks can_send() which is the global CAN transmit function.
//  PID is resolved from the calling task context.
// ═══════════════════════════════════════════════════════════════

SEC("kprobe/can_send")
int BPF_KPROBE(trace_can_send_entry, struct sk_buff *skb, int loop)
{
    struct netscan_event *evt = bpf_ringbuf_reserve(&events, sizeof(*evt), 0);
    if (!evt) return 0;

    __builtin_memset(evt, 0, sizeof(*evt));
    evt->event_type = EVENT_TYPE_CONNECT;
    evt->protocol = 206; // CAN
    evt->ip_version = 0;

    fill_process_info(evt);
    evt->sport = 0;
    evt->dport = 0;

    bpf_ringbuf_submit(evt, 0);
    return 0;
}

// ═══════════════════════════════════════════════════════════════
//  RDS — Reliable Datagram Sockets / Amazon RDS (protocol 207)
// ═══════════════════════════════════════════════════════════════

SEC("kprobe/rds_sendmsg")
int BPF_KPROBE(trace_rds_sendmsg_entry, struct socket *sock, struct msghdr *msg, size_t len)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    struct sock *sk = BPF_CORE_READ(sock, sk);
    struct sendmsg_start_args args = {};
    args.sk = sk;
    args.msg = msg;
    bpf_map_update_elem(&sendmsg_start_map, &pid_tgid, &args, BPF_ANY);
    return 0;
}

SEC("kretprobe/rds_sendmsg")
int BPF_KRETPROBE(trace_rds_sendmsg_exit, int ret)
{
    return process_nonip_exit(ctx, ret, 207);
}

// ═══════════════════════════════════════════════════════════════
//  MPTCP — Multipath TCP (protocol 208)
// ═══════════════════════════════════════════════════════════════

SEC("kprobe/mptcp_sendmsg")
int BPF_KPROBE(trace_mptcp_sendmsg_entry, struct sock *sk, struct msghdr *msg, size_t len)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    struct sendmsg_start_args args = {};
    args.sk = sk;
    args.msg = msg;
    bpf_map_update_elem(&sendmsg_start_map, &pid_tgid, &args, BPF_ANY);
    return 0;
}

SEC("kretprobe/mptcp_sendmsg")
int BPF_KRETPROBE(trace_mptcp_sendmsg_exit, int ret)
{
    return process_nonip_exit(ctx, ret, 208);
}

// ═══════════════════════════════════════════════════════════════
//  L2TP — Layer 2 Tunneling Protocol (protocol 209)
// ═══════════════════════════════════════════════════════════════

SEC("kprobe/l2tp_ip_sendmsg")
int BPF_KPROBE(trace_l2tp_ip_sendmsg_entry, struct sock *sk, struct msghdr *msg, size_t len)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    struct sendmsg_start_args args = {};
    args.sk = sk;
    args.msg = msg;
    bpf_map_update_elem(&sendmsg_start_map, &pid_tgid, &args, BPF_ANY);
    return 0;
}

SEC("kretprobe/l2tp_ip_sendmsg")
int BPF_KRETPROBE(trace_l2tp_ip_sendmsg_exit, int ret)
{
    return process_nonip_exit(ctx, ret, 209);
}

// ═══════════════════════════════════════════════════════════════
//  PPPoE — Point-to-Point Protocol over Ethernet (protocol 210)
// ═══════════════════════════════════════════════════════════════

SEC("kprobe/pppoe_sendmsg")
int BPF_KPROBE(trace_pppoe_sendmsg_entry, struct socket *sock, struct msghdr *msg, size_t len)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    struct sock *sk = BPF_CORE_READ(sock, sk);
    struct sendmsg_start_args args = {};
    args.sk = sk;
    args.msg = msg;
    bpf_map_update_elem(&sendmsg_start_map, &pid_tgid, &args, BPF_ANY);
    return 0;
}

SEC("kretprobe/pppoe_sendmsg")
int BPF_KRETPROBE(trace_pppoe_sendmsg_exit, int ret)
{
    return process_nonip_exit(ctx, ret, 210);
}



// ═══════════════════════════════════════════════════════════════
//  ARP — Address Resolution Protocol (protocol 218)
//  Kernel-internal: hooks arp_send directly. PID is the calling
//  task (may be kernel/0 for automatic ARP).
// ═══════════════════════════════════════════════════════════════

SEC("kprobe/arp_send")
int BPF_KPROBE(trace_arp_send, int type, int ptype, __be32 dest_ip,
               struct net_device *dev, __be32 src_ip)
{
    // Dedup: throttle per src_ip+dest_ip pair
    struct flow_key key;
    __builtin_memset(&key, 0, sizeof(key));
    key.ip_version = 4;
    key.saddr_v4 = src_ip;
    key.daddr_v4 = dest_ip;
    key.sport = type; // ARP type (1=REQUEST, 2=REPLY)

    __u64 now = bpf_ktime_get_ns();
    __u64 *last_ts = bpf_map_lookup_elem(&flow_dedup_map, &key);
    if (last_ts && (now - *last_ts < 30000000000ULL)) return 0;
    bpf_map_update_elem(&flow_dedup_map, &key, &now, BPF_ANY);

    struct netscan_event *evt = bpf_ringbuf_reserve(&events, sizeof(*evt), 0);
    if (!evt) return 0;

    __builtin_memset(evt, 0, sizeof(*evt));
    evt->event_type = EVENT_TYPE_CONNECT;
    evt->protocol = 218; // ARP
    evt->ip_version = 4;

    fill_process_info(evt);
    evt->saddr_v4 = src_ip;
    evt->daddr_v4 = dest_ip;
    evt->sport = type;  // 1=REQUEST, 2=REPLY
    evt->dport = 0;

    bpf_ringbuf_submit(evt, 0);
    return 0;
}

// ═══════════════════════════════════════════════════════════════
//  IGMP — Multicast Group Membership (protocol 219)
//  Hooks ip_mc_join_group/ip_mc_leave_group for group changes.
//  These have socket context so PID is accurate.
// ═══════════════════════════════════════════════════════════════

SEC("kprobe/ip_mc_join_group")
int BPF_KPROBE(trace_igmp_join, struct sock *sk, struct ip_mreqn *imr)
{
    struct netscan_event *evt = bpf_ringbuf_reserve(&events, sizeof(*evt), 0);
    if (!evt) return 0;

    __builtin_memset(evt, 0, sizeof(*evt));
    evt->event_type = EVENT_TYPE_CONNECT; // JOIN = open
    evt->protocol = 219; // IGMP
    evt->ip_version = 4;

    fill_process_info(evt);
    evt->uid = BPF_CORE_READ(sk, sk_uid.val);

    // Read multicast address from imr
    struct ip_mreqn imr_local;
    if (bpf_probe_read_kernel(&imr_local, sizeof(imr_local), imr) == 0) {
        evt->daddr_v4 = imr_local.imr_multiaddr.s_addr;
    }
    evt->saddr_v4 = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);
    evt->sport = 0;
    evt->dport = 0;

    bpf_ringbuf_submit(evt, 0);
    return 0;
}

SEC("kprobe/ip_mc_leave_group")
int BPF_KPROBE(trace_igmp_leave, struct sock *sk, struct ip_mreqn *imr)
{
    struct netscan_event *evt = bpf_ringbuf_reserve(&events, sizeof(*evt), 0);
    if (!evt) return 0;

    __builtin_memset(evt, 0, sizeof(*evt));
    evt->event_type = EVENT_TYPE_CLOSE; // LEAVE = close
    evt->protocol = 219; // IGMP
    evt->ip_version = 4;

    fill_process_info(evt);
    evt->uid = BPF_CORE_READ(sk, sk_uid.val);

    struct ip_mreqn imr_local;
    if (bpf_probe_read_kernel(&imr_local, sizeof(imr_local), imr) == 0) {
        evt->daddr_v4 = imr_local.imr_multiaddr.s_addr;
    }
    evt->saddr_v4 = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);
    evt->sport = 0;
    evt->dport = 0;

    bpf_ringbuf_submit(evt, 0);
    return 0;
}

// ═══════════════════════════════════════════════════════════════
//  Conntrack — Netfilter Connection Tracking (protocol 220)
//  Hooks __nf_conntrack_confirm for newly tracked flows.
//  Runs in softirq context — PID may be kernel.
// ═══════════════════════════════════════════════════════════════

SEC("kprobe/__nf_conntrack_confirm")
int BPF_KPROBE(trace_conntrack_confirm, struct sk_buff *skb)
{
    struct netscan_event *evt = bpf_ringbuf_reserve(&events, sizeof(*evt), 0);
    if (!evt) return 0;

    __builtin_memset(evt, 0, sizeof(*evt));
    evt->event_type = EVENT_TYPE_CONNECT;
    evt->protocol = 220; // CONNTRACK
    evt->ip_version = 0;

    fill_process_info(evt);
    evt->sport = 0;
    evt->dport = 0;

    bpf_ringbuf_submit(evt, 0);
    return 0;
}

// ═══════════════════════════════════════════════════════════════
//  IPVS — IP Virtual Server / Load Balancer (protocol 221)
//  Hooks ip_vs_conn_new for new virtual server connections.
//  Runs in softirq context — PID may be kernel.
// ═══════════════════════════════════════════════════════════════

SEC("kprobe/ip_vs_conn_new")
int BPF_KPROBE(trace_ipvs_conn_new)
{
    struct netscan_event *evt = bpf_ringbuf_reserve(&events, sizeof(*evt), 0);
    if (!evt) return 0;

    __builtin_memset(evt, 0, sizeof(*evt));
    evt->event_type = EVENT_TYPE_CONNECT;
    evt->protocol = 221; // IPVS
    evt->ip_version = 0;

    fill_process_info(evt);
    evt->sport = 0;
    evt->dport = 0;

    bpf_ringbuf_submit(evt, 0);
    return 0;
}

// ═══════════════════════════════════════════════════════════════
//  License (required for eBPF programs using GPL-only helpers)
// ═══════════════════════════════════════════════════════════════

char LICENSE[] SEC("license") = "GPL";

