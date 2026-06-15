# NetScan v2.0 — Real-Time Event-Driven Network Monitor

A real-time, event-driven network monitoring tool for **Linux** (RHEL, CentOS, Ubuntu, Fedora).

## Key Features

- **True Event-Driven Architecture (Zero Polling)** — Unlike standard tools that poll every few seconds, NetScan hooks directly into the Linux Kernel via **Ftrace Tracepoints** (`sys_enter_socket`, `sys_enter_connect`). The application sleeps with 0% CPU usage until the kernel fires a hardware interrupt that a socket was created or destroyed.
- **The "God's Eye" Protocol Engine** — Supports **25+ protocols**, parsing every single socket address family exposed by the Linux kernel. If a socket exists, NetScan sees it. 
- **Live Event Feed** — Shows a scrolling log of NEW/CLOSED connection events instantly.
- **Process & User Resolution** — Maps every connection to its owning process, command line, and user via `/proc`.
- **Interactive CLI Menu** — No arguments needed; just run and choose a mode.
- **Flicker-Free UI** — Smooth console rendering with background uptime ticking.
- **Export** — Save snapshots to JSON or CSV.
- **IPv4 & IPv6** — Full dual-stack support.

## Supported Protocols (25+)

NetScan parses over 30 unique `/proc/net/` sources to cover every address family.

| Category | Protocols | Source |
|----------|-----------|--------|
| **Core Transport** | TCP, UDP, SCTP, DCCP, UDP-Lite, MPTCP | `/proc/net/tcp`, `udp`, etc. |
| **Diagnostic & IP** | ICMP, RAW, ARP, IGMP, Conntrack, IPVS | `/proc/net/raw`, `nf_conntrack` |
| **Local / IPC** | UNIX, NETLINK, PACKET | `/proc/net/unix`, `packet` |
| **Exotic / Advanced** | VSOCK, SMC, RDS, L2TP, CAN, PPPoE | `/proc/net/vsock`, `can` |
| **Legacy** | IPX, AX25, NETROM, ROSE, X25, DECnet | Auto-detected if loaded |
| **Catch-All Engine** | *Any future protocol* | Universal parser |

## Requirements

- **.NET 8.0 Runtime** (or SDK for building)
- **Linux** (RHEL 7+, CentOS 7+, Ubuntu 18.04+, Fedora)
- **Root/sudo** for full process and user visibility

## Quick Start

```bash
# Build
dotnet build src/NetScan/NetScan.csproj -c Release

# Run (interactive menu)
sudo dotnet run --project src/NetScan/NetScan.csproj

# Or run with CLI arguments
sudo dotnet run --project src/NetScan/NetScan.csproj -- --live --protocol TCP
```

## Usage

```
netscan [OPTIONS]

OPTIONS:
  --live              Run in real-time event-driven mode (default)
  --snapshot          Run a single snapshot scan and exit
  --user <name>       Filter connections by username
  --protocol <proto>  Filter by protocol (TCP, UDP, ICMP, RAW, SCTP)
  --process <name>    Filter by process name
  --export <format>   Export data: json or csv
  --export-path <p>   Export file path (default: ./netscan_export)
  --interval <ms>     Change-detection interval in ms (default: 100)
  --max-rows <n>      Max rows to display (default: 100, 0=unlimited)
  --no-ipv6           Exclude IPv6 connections
  --no-loopback       Exclude loopback connections

EXAMPLES:
  netscan --live --user admin
  netscan --snapshot --export json
  netscan --protocol ICMP
  netscan --process nginx --no-loopback
```

## Architecture

## Architecture

```
INetworkEventSource (Event-driven interface)
  └── LinuxNetworkEventSource
        ├── Hooks into Linux Kernel Ftrace (/sys/kernel/tracing/trace_pipe)
        ├── Sleeps with 0% CPU until hardware interrupt fires on socket creation
        ├── Uses Channel<NetworkEvent> for async event streaming
        └── Triggers INetworkScanner strictly on-demand

INetworkScanner (Snapshot interface)
  └── LinuxNetworkScanner
        ├── ProcNetParser (Core protocols)
        ├── ProcNetParserExtended (Exotic, Legacy, and Catch-All parsing)
        └── LinuxProcessResolver (/proc/[pid]/fd, /proc/[pid]/comm, /proc/[pid]/status)

LiveMonitorService (User Interface)
  ├── Consumes INetworkEventSource.MonitorAsync()
  ├── Maintains live connection state (ConcurrentDictionary)
  ├── Renders Flicker-Free ANSI console UI and Event Feed
  └── Background Timer updates Uptime clock seamlessly
```
