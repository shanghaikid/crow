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
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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
}

/// Per-process network information.
pub struct ProcessInfo {
    pub pid: u32,
    pub name: String,
    pub bytes_tx: RollingCounter,
    pub bytes_rx: RollingCounter,
    pub connections: Vec<Connection>,
    pub first_seen: Instant,
    pub last_seen: Instant,
    pub alive: bool,
}

impl ProcessInfo {
    pub fn new(pid: u32, name: String, now: Instant) -> Self {
        Self {
            pid,
            name,
            bytes_tx: RollingCounter::new(),
            bytes_rx: RollingCounter::new(),
            connections: Vec::new(),
            first_seen: now,
            last_seen: now,
            alive: true,
        }
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
    pub total_connections: usize,

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
            total_connections: 0,
            sort_by: SortBy::Traffic,
            view_mode: ViewMode::Process,
            selected_pid: None,
            expanded_pids: std::collections::HashSet::new(),
            filter: None,
        }
    }

    /// Return PIDs sorted according to current sort criteria.
    /// All sort modes use PID as a stable tiebreaker to prevent jitter.
    pub fn sorted_pids(&self, now: Instant) -> Vec<u32> {
        let mut pids: Vec<u32> = self.processes.keys().copied().collect();
        match self.sort_by {
            SortBy::Traffic => {
                pids.sort_by(|a, b| {
                    let rate_a = self.processes[a].bytes_tx.rate_1s(now)
                        + self.processes[a].bytes_rx.rate_1s(now);
                    let rate_b = self.processes[b].bytes_tx.rate_1s(now)
                        + self.processes[b].bytes_rx.rate_1s(now);
                    rate_b
                        .partial_cmp(&rate_a)
                        .unwrap_or(std::cmp::Ordering::Equal)
                        .then(a.cmp(b))
                });
            }
            SortBy::Connections => {
                pids.sort_by(|a, b| {
                    self.processes[b]
                        .connections
                        .len()
                        .cmp(&self.processes[a].connections.len())
                        .then(a.cmp(b))
                });
            }
            SortBy::Pid => {
                pids.sort();
            }
            SortBy::Name => {
                pids.sort_by(|a, b| {
                    self.processes[a].name.cmp(&self.processes[b].name)
                        .then(a.cmp(b))
                });
            }
        }
        pids
    }
}

impl Default for AppState {
    fn default() -> Self {
        Self::new()
    }
}
