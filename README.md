# crow

Real-time per-process network monitor for macOS. Built with Rust.

![macOS](https://img.shields.io/badge/platform-macOS-blue)
![Rust](https://img.shields.io/badge/language-Rust-orange)

## Features

- **Per-process network monitoring** — see upload/download rates and totals for every process
- **PKTAP integration** — uses macOS PKTAP for direct per-packet PID attribution
- **Packet inspection** — expand a process to see TLS SNI hostnames, HTTP requests, and DNS queries in real time
- **Proxy detection** — detects proxy software (Clash, sing-box, V2Ray, Karing, etc.) and shows which connections are proxied vs direct
- **DNS resolution** — captures DNS responses to show hostnames instead of raw IPs
- **Expandable connections** — drill into each process to see individual TCP/UDP connections with state, route info, and recent packet activity
- **Sort with direction** — press `s` to cycle ascending/descending within each sort field, with visual indicators (▲/▼) in the header
- **Live filtering** — press `/` to filter, Enter to confirm and expand first match, Esc to cancel
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
| **j/k** or **Up/Down** | Navigate process list |
| **Enter** | Expand/collapse process (shows connections) |
| **v** | Open packet log detail view for selected process |
| **/** | Enter filter mode (type to filter, live preview) |
| **Enter** (filter mode) | Confirm filter, select and expand first match |
| **Esc** (filter mode) | Cancel filter |
| **Esc** (normal mode) | Collapse last expanded process; if none, clear filter |
| **s** | Cycle sort: ascending ▲ → descending ▼ → next field |
| **Tab** | Switch view (Process / Connection / Domain) |
| **q** | Quit |
| **Ctrl+C** | Quit |

### Packet Log Detail View

Select a process and press **v** to open a full-screen packet log showing all captured protocol-level events:

- `TLS -> example.com` — TLS handshake SNI (shows which domain HTTPS traffic goes to)
- `GET /api/data` — HTTP request method and path
- `DNS example.com -> 3 addr` — DNS resolution results

Each entry shows a millisecond-precision local timestamp (e.g. `19:04:43.217`), direction (^ upload / v download), and packet size.

| Key | Action |
|-----|--------|
| **j/k** or **Up/Down** | Scroll one line |
| **Space/f/PageDown** | Page down |
| **b/PageUp** | Page up |
| **d/u** | Half page down/up |
| **g/Home** | Jump to top |
| **G/End** | Jump to bottom |
| **Esc/q** | Back to process list |

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
│   ├── packet.rs        # IP/TCP/UDP/DNS/TLS/HTTP packet parsing
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
        ├── process.rs   # Process view (grouped, expandable, packet log)
        ├── connection.rs # Flat connection list
        └── domain.rs    # Domain-grouped view
```

**Three threads:**
1. **Capture** — reads packets via libpcap with PKTAP headers, parses IP/TCP/UDP + protocol-level info (TLS SNI, HTTP requests, DNS)
2. **Aggregator** — processes events, maintains state, polls socket snapshots, detects proxies
3. **TUI** — renders the interface at ~10fps

## How It Works

crow uses macOS's PKTAP pseudo-interface to capture packets with per-packet PID attribution. Each packet is parsed for:

- **IP layer** — source/destination addresses
- **Transport layer** — TCP/UDP ports, connection state
- **Application layer** — TLS ClientHello SNI extraction, HTTP request lines, DNS query/response parsing

The aggregator correlates packets with processes, tracks connection states via `libproc` socket enumeration, and detects proxy software by matching process names against a known list and analyzing their LISTEN ports.

## License

MIT
