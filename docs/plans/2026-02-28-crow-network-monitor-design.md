# Crow: macOS Network Monitor — Design Document

## Overview

Crow is a real-time TUI tool that monitors local network activity per-process on macOS. It shows which processes are making network requests, where they connect, bandwidth usage, DNS resolutions, connection states, and latency.

**Language:** Rust
**Platform:** macOS (primary), Linux (future)
**Privileges:** Requires sudo or BPF group membership

## Architecture

Three-thread pipeline: Capture → Aggregate → Render.

```
Capture Thread (libpcap on pktap,all)
  → reads pktap_header for PID + process name inline
  → parses IP/TCP/UDP layers, DNS payloads
  → sends PacketEvent via mpsc channel

Aggregator Thread
  → maintains per-PID rolling byte counters (1s/5s/30s windows)
  → builds DNS cache (IP → hostname) from captured DNS packets
  → polls proc_pidfdinfo every 100ms for connection state
  → writes to Arc<RwLock<AppState>>

TUI Thread (ratatui + crossterm, ~10fps)
  → reads AppState snapshot
  → renders process table, connection details, stats bar
  → handles keyboard input (navigate, sort, filter, switch views)
```

### Why PKTAP

macOS has a `pktap` pseudo-interface that tags every captured packet with PID and process name in the packet header. This avoids the `lsof` shell-out approach (bandwhich's weakness) and gives exact per-packet process attribution with zero additional lookups.

## Core Data Structures

```rust
struct PacketEvent {
    timestamp: Instant,
    pid: u32,
    proc_name: String,
    direction: Direction,      // Inbound / Outbound
    protocol: Protocol,        // TCP / UDP / ICMP / Other
    src: SocketAddr,
    dst: SocketAddr,
    payload_len: u32,
    dns_info: Option<DnsInfo>,
}

struct ProcessInfo {
    pid: u32,
    name: String,
    path: String,
    bytes_tx: RollingCounter,
    bytes_rx: RollingCounter,
    connections: Vec<Connection>,
    first_seen: Instant,
}

struct Connection {
    protocol: Protocol,
    local_addr: SocketAddr,
    remote_addr: SocketAddr,
    remote_hostname: Option<String>,
    state: TcpState,
    bytes_tx: u64,
    bytes_rx: u64,
    latency: Option<Duration>,  // SYN→SYN-ACK RTT
}
```

## TUI Layout

```
┌─ crow ──────────────────────────────────────────────────────────┐
│  ▲ 12.3 MB/s  ▼ 45.6 MB/s │ Connections: 87 │ Processes: 23   │
├─────────────────────────────────────────────────────────────────┤
│ PID   Process         ▲ Upload  ▼ Download  Conns  First Seen  │
│ 1234  Google Chrome    2.1 MB/s  8.3 MB/s    34   2m ago       │
│   ├─ TCP 142.250.80.14:443  google.com      ESTABLISHED        │
│   ├─ TCP 151.101.1.69:443   reddit.com      ESTABLISHED        │
│   └─ ... (31 more)                                              │
│ 5678  Slack             512 KB/s  1.2 MB/s   12   15m ago      │
│ 9012  curl              0 B/s     0 B/s       1   3s ago       │
│   └─ TCP 104.21.32.1:443    api.example.com CLOSE_WAIT         │
├─────────────────────────────────────────────────────────────────┤
│ [q]Quit [s]Sort [/]Filter [Enter]Expand [Tab]View Sort:▼Traffic│
└─────────────────────────────────────────────────────────────────┘
```

### Keybindings

- `↑/↓` or `j/k`: Navigate processes
- `Enter`: Expand/collapse connections
- `s`: Cycle sort (traffic / connections / PID / name)
- `/`: Filter by process name or hostname
- `Tab`: Switch view (Process / Connection / Domain)
- `q`: Quit

### Views

1. **Process view** (default): Grouped by process, expandable connections
2. **Connection view**: Flat list of all connections, one per row
3. **Domain view**: Grouped by destination hostname, showing which processes connect

## Permissions

- On startup, check BPF access by attempting to open `/dev/bpf0`
- If denied, print: `crow requires BPF access. Run with: sudo crow`
- Document alternative: add user to `access_bpf` group for sudo-free usage

## Error Handling

- Capture thread panic → notify main thread, graceful exit with error message
- Process exits → keep in display for 30s (grayed out), then remove
- DNS parse failure → silently skip, display raw IP
- Terminal resize → ratatui auto-adapts

## Project Structure

```
crow/
├── Cargo.toml
├── src/
│   ├── main.rs                # Entry, arg parsing, permission check
│   ├── capture/
│   │   ├── mod.rs
│   │   ├── pktap.rs           # PKTAP header definition and parsing
│   │   └── packet.rs          # Packet parsing → PacketEvent
│   ├── aggregate/
│   │   ├── mod.rs
│   │   ├── state.rs           # AppState, ProcessInfo, Connection
│   │   ├── dns.rs             # DNS cache (IP → hostname)
│   │   └── counter.rs         # RollingCounter sliding window
│   ├── process/
│   │   ├── mod.rs
│   │   └── macos.rs           # proc_pidfdinfo, proc_name wrappers
│   └── tui/
│       ├── mod.rs
│       ├── app.rs             # TUI main loop, keyboard events
│       ├── views/
│       │   ├── process.rs     # Process view
│       │   ├── connection.rs  # Connection view
│       │   └── domain.rs      # Domain view
│       └── widgets.rs         # Custom widgets (traffic rate bars)
```

## Dependencies

```toml
[dependencies]
pcap = "2"
pnet_packet = "0.35"
netstat2 = "0.9"
libproc = "0.14"
ratatui = "0.29"
crossterm = "0.28"
dns-parser = "0.8"
clap = { version = "4", features = ["derive"] }
anyhow = "1"
```

## Design Decisions

| Decision | Choice | Rationale |
|----------|--------|-----------|
| Language | Rust | Zero-cost packet parsing, no GC jitter for TUI, strong threading safety |
| Capture method | PKTAP via libpcap | Direct PID attribution per-packet, no lsof shell-out |
| TUI framework | ratatui | Most mature Rust TUI, rich widget ecosystem |
| Thread sync | Arc<RwLock<AppState>> | Readers (TUI) don't block writer (aggregator) |
| DNS tracking | Passive UDP:53 capture | No extra syscall hooking needed, works with PKTAP |
| Connection state | proc_pidfdinfo polling | Supplements PKTAP with TCP state (ESTABLISHED, etc.) |
