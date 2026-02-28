use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::Instant;

use super::counter::RollingCounter;
use super::dns::DnsCache;

/// Direction of a packet relative to the local machine.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    Inbound,
    Outbound,
}

/// Network protocol.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Protocol {
    Tcp,
    Udp,
    Icmp,
    Other(u8),
}

/// TCP connection state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TcpState {
    SynSent,
    SynReceived,
    Established,
    FinWait1,
    FinWait2,
    CloseWait,
    Closing,
    LastAck,
    TimeWait,
    Closed,
    Listen,
    Unknown,
}

impl std::fmt::Display for TcpState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TcpState::SynSent => write!(f, "SYN_SENT"),
            TcpState::SynReceived => write!(f, "SYN_RCVD"),
            TcpState::Established => write!(f, "ESTABLISHED"),
            TcpState::FinWait1 => write!(f, "FIN_WAIT_1"),
            TcpState::FinWait2 => write!(f, "FIN_WAIT_2"),
            TcpState::CloseWait => write!(f, "CLOSE_WAIT"),
            TcpState::Closing => write!(f, "CLOSING"),
            TcpState::LastAck => write!(f, "LAST_ACK"),
            TcpState::TimeWait => write!(f, "TIME_WAIT"),
            TcpState::Closed => write!(f, "CLOSED"),
            TcpState::Listen => write!(f, "LISTEN"),
            TcpState::Unknown => write!(f, "UNKNOWN"),
        }
    }
}

/// DNS information extracted from a captured DNS response.
#[derive(Debug, Clone)]
pub struct DnsInfo {
    pub query_name: String,
    pub resolved_ips: Vec<std::net::IpAddr>,
    pub ttl: Option<u32>,
}

/// A single captured packet event, produced by the capture thread.
#[derive(Debug, Clone)]
pub struct PacketEvent {
    pub timestamp: Instant,
    pub pid: u32,
    pub proc_name: String,
    pub direction: Direction,
    pub protocol: Protocol,
    pub src: SocketAddr,
    pub dst: SocketAddr,
    pub payload_len: u32,
    pub dns_info: Option<DnsInfo>,
}

/// A tracked network connection.
pub struct Connection {
    pub protocol: Protocol,
    pub local_addr: SocketAddr,
    pub remote_addr: SocketAddr,
    pub remote_hostname: Option<String>,
    pub state: TcpState,
    pub bytes_tx: u64,
    pub bytes_rx: u64,
    pub latency: Option<std::time::Duration>,
}

impl Connection {
    pub fn protocol_str(&self) -> &'static str {
        match self.protocol {
            Protocol::Tcp => "TCP",
            Protocol::Udp => "UDP",
            Protocol::Icmp => "ICMP",
            Protocol::Other(_) => "OTHER",
        }
    }

    /// Display the remote endpoint: hostname if available, otherwise IP.
    pub fn remote_display(&self) -> String {
        match self.remote_hostname.as_deref() {
            Some(h) if !h.is_empty() => h.to_string(),
            _ => self.remote_addr.ip().to_string(),
        }
    }
}

/// Per-process network information.
pub struct ProcessInfo {
    pub name: String,
    pub bytes_tx: RollingCounter,
    pub bytes_rx: RollingCounter,
    pub connections: Vec<Connection>,
    pub first_seen: Instant,
    pub last_seen: Instant,
    pub alive: bool,
}

impl ProcessInfo {
    pub fn new(name: String, now: Instant) -> Self {
        Self {
            name,
            bytes_tx: RollingCounter::new(),
            bytes_rx: RollingCounter::new(),
            connections: Vec::new(),
            first_seen: now,
            last_seen: now,
            alive: true,
        }
    }

    /// Check if this process matches a filter string (case-insensitive).
    /// Matches against process name, connection hostnames, and remote addresses.
    pub fn matches_filter(&self, filter_lower: &str) -> bool {
        if self.name.to_lowercase().contains(filter_lower) {
            return true;
        }
        self.connections.iter().any(|c| {
            c.remote_hostname
                .as_deref()
                .unwrap_or("")
                .to_lowercase()
                .contains(filter_lower)
                || c.remote_addr.to_string().contains(filter_lower)
        })
    }
}

/// Sort criteria for the process list.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SortBy {
    Traffic,
    Connections,
    Pid,
    Name,
}

impl SortBy {
    pub fn next(self) -> Self {
        match self {
            SortBy::Traffic => SortBy::Connections,
            SortBy::Connections => SortBy::Pid,
            SortBy::Pid => SortBy::Name,
            SortBy::Name => SortBy::Traffic,
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            SortBy::Traffic => "Traffic",
            SortBy::Connections => "Conns",
            SortBy::Pid => "PID",
            SortBy::Name => "Name",
        }
    }
}

/// Which TUI view is active.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ViewMode {
    Process,
    Connection,
    Domain,
}

impl ViewMode {
    pub fn next(self) -> Self {
        match self {
            ViewMode::Process => ViewMode::Connection,
            ViewMode::Connection => ViewMode::Domain,
            ViewMode::Domain => ViewMode::Process,
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            ViewMode::Process => "Process",
            ViewMode::Connection => "Connection",
            ViewMode::Domain => "Domain",
        }
    }
}

/// Shared application state, written by the aggregator and read by the TUI.
pub struct AppState {
    pub processes: HashMap<u32, ProcessInfo>,
    pub dns_cache: DnsCache,
    pub total_tx: RollingCounter,
    pub total_rx: RollingCounter,
    // TUI state
    pub sort_by: SortBy,
    pub view_mode: ViewMode,
    /// Selected process PID (tracks the process, not the row index)
    pub selected_pid: Option<u32>,
    pub expanded_pids: std::collections::HashSet<u32>,
    pub filter: Option<String>,
}

impl AppState {
    pub fn new() -> Self {
        Self {
            processes: HashMap::new(),
            dns_cache: DnsCache::new(),
            total_tx: RollingCounter::new(),
            total_rx: RollingCounter::new(),
            sort_by: SortBy::Traffic,
            view_mode: ViewMode::Process,
            selected_pid: None,
            expanded_pids: std::collections::HashSet::new(),
            filter: None,
        }
    }

    /// Total number of tracked connections across all processes.
    pub fn total_connections(&self) -> usize {
        self.processes.values().map(|p| p.connections.len()).sum()
    }

    /// Return PIDs sorted according to current sort criteria.
    /// Pre-computes sort keys (Schwartzian transform) to avoid redundant work.
    pub fn sorted_pids(&self, now: Instant) -> Vec<u32> {
        match self.sort_by {
            SortBy::Traffic => {
                let mut keyed: Vec<(u32, f64)> = self
                    .processes
                    .iter()
                    .map(|(&pid, p)| {
                        let rate = p.bytes_tx.rate_1s(now) + p.bytes_rx.rate_1s(now);
                        (pid, rate)
                    })
                    .collect();
                keyed.sort_by(|a, b| {
                    b.1.partial_cmp(&a.1)
                        .unwrap_or(std::cmp::Ordering::Equal)
                        .then(a.0.cmp(&b.0))
                });
                keyed.into_iter().map(|(pid, _)| pid).collect()
            }
            SortBy::Connections => {
                let mut keyed: Vec<(u32, usize)> = self
                    .processes
                    .iter()
                    .map(|(&pid, p)| (pid, p.connections.len()))
                    .collect();
                keyed.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
                keyed.into_iter().map(|(pid, _)| pid).collect()
            }
            SortBy::Pid => {
                let mut pids: Vec<u32> = self.processes.keys().copied().collect();
                pids.sort();
                pids
            }
            SortBy::Name => {
                let mut keyed: Vec<(u32, &str)> = self
                    .processes
                    .iter()
                    .map(|(&pid, p)| (pid, p.name.as_str()))
                    .collect();
                keyed.sort_by(|a, b| a.1.cmp(b.1).then(a.0.cmp(&b.0)));
                keyed.into_iter().map(|(pid, _)| pid).collect()
            }
        }
    }
}

impl Default for AppState {
    fn default() -> Self {
        Self::new()
    }
}
