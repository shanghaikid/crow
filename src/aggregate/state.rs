use std::collections::{HashMap, HashSet, VecDeque};
use std::net::{SocketAddr, UdpSocket};
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

/// Route classification for a connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionRoute {
    Direct,
    Proxied,
    Unknown,
}

impl std::fmt::Display for ConnectionRoute {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ConnectionRoute::Direct => write!(f, "DIRECT"),
            ConnectionRoute::Proxied => write!(f, "PROXY"),
            ConnectionRoute::Unknown => write!(f, ""),
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
    /// Protocol-level info: HTTP request line, TLS SNI, DNS query, etc.
    pub protocol_info: Option<String>,
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
    pub route: ConnectionRoute,
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

/// A recent packet activity log entry.
#[allow(dead_code)]
pub struct PacketLogEntry {
    /// Local time as (hour, minute, second, millisecond).
    pub time_hms: (u8, u8, u8, u16),
    pub direction: Direction,
    pub remote: SocketAddr,
    pub size: u32,
    pub info: String, // "TLS → example.com", "GET /api/data", "DNS ? example.com"
}

const MAX_PACKET_LOG: usize = 5000;

/// Per-process network information.
pub struct ProcessInfo {
    pub name: String,
    pub bytes_tx: RollingCounter,
    pub bytes_rx: RollingCounter,
    pub total_tx: u64,
    pub total_rx: u64,
    pub connections: Vec<Connection>,
    pub packet_log: VecDeque<PacketLogEntry>,
    pub last_seen: Instant,
    pub alive: bool,
    pub is_proxy: bool,
}

impl ProcessInfo {
    pub fn new(name: String, now: Instant) -> Self {
        Self {
            name,
            bytes_tx: RollingCounter::new(),
            bytes_rx: RollingCounter::new(),
            total_tx: 0,
            total_rx: 0,
            connections: Vec::new(),
            packet_log: VecDeque::new(),
            last_seen: now,
            alive: true,
            is_proxy: false,
        }
    }

    pub fn push_log(&mut self, entry: PacketLogEntry) {
        if self.packet_log.len() >= MAX_PACKET_LOG {
            self.packet_log.pop_front();
        }
        self.packet_log.push_back(entry);
    }

    /// Whether this process has any recorded traffic.
    pub fn has_traffic(&self) -> bool {
        self.connections.iter().any(|c| c.bytes_tx > 0 || c.bytes_rx > 0)
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

/// Sort criteria for the connection list.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnSortBy {
    Process,
    Proto,
    State,
    Route,
    TX,
    RX,
}

impl ConnSortBy {
    pub fn next(self) -> Self {
        match self {
            ConnSortBy::Process => ConnSortBy::Proto,
            ConnSortBy::Proto => ConnSortBy::State,
            ConnSortBy::State => ConnSortBy::Route,
            ConnSortBy::Route => ConnSortBy::TX,
            ConnSortBy::TX => ConnSortBy::RX,
            ConnSortBy::RX => ConnSortBy::Process,
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            ConnSortBy::Process => "Process",
            ConnSortBy::Proto => "Proto",
            ConnSortBy::State => "State",
            ConnSortBy::Route => "Route",
            ConnSortBy::TX => "TX",
            ConnSortBy::RX => "RX",
        }
    }
}

/// Sort criteria for the domain list.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DomainSortBy {
    Domain,
    Conns,
    TX,
    RX,
}

impl DomainSortBy {
    pub fn next(self) -> Self {
        match self {
            DomainSortBy::Domain => DomainSortBy::Conns,
            DomainSortBy::Conns => DomainSortBy::TX,
            DomainSortBy::TX => DomainSortBy::RX,
            DomainSortBy::RX => DomainSortBy::Domain,
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            DomainSortBy::Domain => "Domain",
            DomainSortBy::Conns => "Conns",
            DomainSortBy::TX => "TX",
            DomainSortBy::RX => "RX",
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
    pub grand_total_tx: u64,
    pub grand_total_rx: u64,
    /// Listen addresses of detected proxy processes.
    pub proxy_listen_addrs: HashSet<SocketAddr>,
    // TUI state
    pub sort_by: SortBy,
    pub sort_descending: bool,
    pub conn_sort_by: ConnSortBy,
    pub conn_sort_desc: bool,
    pub domain_sort_by: DomainSortBy,
    pub domain_sort_desc: bool,
    pub view_mode: ViewMode,
    /// Selected process PID (tracks the process, not the row index)
    pub selected_pid: Option<u32>,
    pub expanded_pids: std::collections::HashSet<u32>,
    /// Tracks expansion order for Esc to undo last expand.
    pub expansion_order: Vec<u32>,
    pub filter: Option<String>,
    /// When set, show full-screen packet log for this PID.
    pub detail_pid: Option<u32>,
    pub detail_scroll: usize,
    pub started_at: Instant,
    pub local_ip: String,
}

impl AppState {
    pub fn new() -> Self {
        Self {
            processes: HashMap::new(),
            dns_cache: DnsCache::new(),
            total_tx: RollingCounter::new(),
            total_rx: RollingCounter::new(),
            grand_total_tx: 0,
            grand_total_rx: 0,
            proxy_listen_addrs: HashSet::new(),
            sort_by: SortBy::Traffic,
            sort_descending: true,
            conn_sort_by: ConnSortBy::TX,
            conn_sort_desc: true,
            domain_sort_by: DomainSortBy::TX,
            domain_sort_desc: true,
            view_mode: ViewMode::Process,
            selected_pid: None,
            expanded_pids: std::collections::HashSet::new(),
            expansion_order: Vec::new(),
            filter: None,
            detail_pid: None,
            detail_scroll: 0,
            local_ip: get_local_ip(),
            started_at: Instant::now(),
        }
    }

    /// Return visible PIDs: sorted, with traffic, and matching the current filter.
    pub fn visible_pids(&self, now: Instant) -> Vec<u32> {
        let pids = self.sorted_pids(now);
        let filter_lower = self.filter.as_ref().map(|f| f.to_lowercase());
        match filter_lower {
            Some(fl) => pids
                .into_iter()
                .filter(|pid| {
                    self.processes
                        .get(pid)
                        .map(|p| p.matches_filter(&fl))
                        .unwrap_or(false)
                })
                .collect(),
            None => pids,
        }
    }

    /// Total number of tracked connections across all processes.
    pub fn total_connections(&self) -> usize {
        self.processes.values().map(|p| p.connections.len()).sum()
    }

    /// Return PIDs sorted according to current sort criteria.
    /// Only includes processes that have actual traffic data.
    /// Dead processes are always sorted to the end.
    pub fn sorted_pids(&self, now: Instant) -> Vec<u32> {
        let active = self
            .processes
            .iter()
            .filter(|(_, p)| p.has_traffic());

        let desc = self.sort_descending;
        let mut pids: Vec<u32> = match self.sort_by {
            SortBy::Traffic => {
                let mut keyed: Vec<(u32, f64)> = active
                    .map(|(&pid, p)| {
                        let rate = p.bytes_tx.rate_1s(now) + p.bytes_rx.rate_1s(now);
                        (pid, rate)
                    })
                    .collect();
                keyed.sort_by(|a, b| {
                    let ord = a.1.partial_cmp(&b.1).unwrap_or(std::cmp::Ordering::Equal);
                    let ord = if desc { ord.reverse() } else { ord };
                    ord.then(a.0.cmp(&b.0))
                });
                keyed.into_iter().map(|(pid, _)| pid).collect()
            }
            SortBy::Connections => {
                let mut keyed: Vec<(u32, usize)> = active
                    .map(|(&pid, p)| (pid, p.connections.len()))
                    .collect();
                keyed.sort_by(|a, b| {
                    let ord = a.1.cmp(&b.1);
                    let ord = if desc { ord.reverse() } else { ord };
                    ord.then(a.0.cmp(&b.0))
                });
                keyed.into_iter().map(|(pid, _)| pid).collect()
            }
            SortBy::Pid => {
                let mut p: Vec<u32> = active.map(|(&pid, _)| pid).collect();
                p.sort();
                if desc { p.reverse(); }
                p
            }
            SortBy::Name => {
                let mut keyed: Vec<(u32, &str)> = active
                    .map(|(&pid, p)| (pid, p.name.as_str()))
                    .collect();
                keyed.sort_by(|a, b| {
                    let ord = a.1.cmp(b.1);
                    let ord = if desc { ord.reverse() } else { ord };
                    ord.then(a.0.cmp(&b.0))
                });
                keyed.into_iter().map(|(pid, _)| pid).collect()
            }
        };

        // Dead processes always at the end
        let procs = &self.processes;
        pids.sort_by_key(|pid| !procs.get(pid).map(|p| p.alive).unwrap_or(false));

        pids
    }
}

impl Default for AppState {
    fn default() -> Self {
        Self::new()
    }
}

/// Detect the local IP by connecting a UDP socket to a public address.
fn get_local_ip() -> String {
    UdpSocket::bind("0.0.0.0:0")
        .and_then(|s| {
            s.connect("8.8.8.8:80")?;
            s.local_addr()
        })
        .map(|a| a.ip().to_string())
        .unwrap_or_else(|_| "unknown".to_string())
}
