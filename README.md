# crow

Real-time per-process network monitor for macOS. Built with Rust.

![macOS](https://img.shields.io/badge/platform-macOS-blue)
![Rust](https://img.shields.io/badge/language-Rust-orange)

## Features

- **Per-process network monitoring** — see upload/download rates and totals for every process
- **PKTAP integration** — uses macOS PKTAP for direct per-packet PID attribution
- **Proxy detection** — detects proxy software (Clash, sing-box, V2Ray, Karing, etc.) and shows which connections are proxied vs direct
- **DNS resolution** — captures DNS responses to show hostnames instead of raw IPs
- **Expandable connections** — drill into each process to see individual TCP/UDP connections with state and route info
- **Live filtering** — type to filter processes instantly, Esc to clear
- **Multiple views** — Process, Connection, and Domain views (Tab to switch)

## Installation

### Prerequisites

- macOS (uses macOS-specific APIs: PKTAP, libproc)
- Rust toolchain
- libpcap (included with macOS)

### Build

```bash
cargo build --release
```

The binary will be at `target/release/crow`.

## Usage

crow requires root privileges for packet capture:

```bash
sudo ./target/release/crow
```

Or during development:

```bash
sudo cargo run --release
```

### Keybindings

| Key | Action |
|-----|--------|
| **Type** | Filter processes by name |
| **Esc** | Clear filter |
| **Up/Down** | Navigate process list |
| **Enter** | Expand/collapse connections |
| **Tab** | Switch view (Process/Connection/Domain) |
| **F1** | Cycle sort mode (Traffic/Connections/PID/Name) |
| **q** | Quit (when filter is empty) |
| **Ctrl+C** | Quit |

### CLI Options

```
crow [OPTIONS] [PROCESS]

Arguments:
  [PROCESS]  Filter by process name

Options:
  -i, --interface <INTERFACE>  Capture interface [default: pktap,all]
  -h, --help                   Print help
  -V, --version                Print version
```

## Architecture

```
src/
├── main.rs              # Entry point, thread orchestration
├── capture/
│   ├── mod.rs           # Packet capture loop (pcap + PKTAP)
│   ├── packet.rs        # IP/TCP/UDP/DNS packet parsing
│   └── pktap.rs         # macOS PKTAP header parsing
├── aggregate/
│   ├── mod.rs           # Aggregator loop, event processing
│   ├── state.rs         # Shared application state types
│   ├── counter.rs       # Rolling window rate counters
│   ├── dns.rs           # DNS cache (IP → hostname)
│   └── proxy.rs         # Proxy detection logic
├── process/
│   ├── mod.rs
│   └── macos.rs         # libproc socket enumeration
└── tui/
    ├── mod.rs
    ├── app.rs           # TUI main loop, keybindings
    ├── widgets.rs       # Formatting helpers
    └── views/
        ├── process.rs   # Process view (grouped, expandable)
        ├── connection.rs # Flat connection list
        └── domain.rs    # Domain-grouped view
```

**Three threads:**
1. **Capture** — reads packets via libpcap with PKTAP headers
2. **Aggregator** — processes events, maintains state, polls socket snapshots
3. **TUI** — renders the interface at ~10fps

## License

MIT
