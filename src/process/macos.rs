//! macOS process introspection via libproc.
//!
//! Enumerates all processes and their TCP/UDP socket connections to build
//! a lookup table mapping (local_addr, remote_addr) → (PID, process name).
//! This is the fallback approach when PKTAP headers are not available.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use libproc::libproc::file_info::{pidfdinfo, ListFDs, ProcFDType};
use libproc::libproc::net_info::{SocketFDInfo, SocketInfoKind};
use libproc::libproc::proc_pid;
use libproc::processes::{pids_by_type, ProcFilter};

use crate::aggregate::{Direction, Protocol, TcpState};

/// A discovered socket connection for a process.
#[derive(Debug, Clone)]
pub struct SocketConnection {
    pub pid: u32,
    pub proc_name: String,
    pub local_addr: SocketAddr,
    pub remote_addr: SocketAddr,
    pub tcp_state: TcpState,
    pub protocol: Protocol,
}

/// Result of a process lookup, including direction.
#[derive(Debug, Clone)]
pub struct ProcessMatch {
    pub pid: u32,
    pub name: String,
    pub direction: Direction,
}

/// Snapshot of all process socket connections on the system.
/// Used to attribute captured packets to processes.
pub struct SocketSnapshot {
    /// Map from socket key → process info (for outbound matching by local port)
    by_local_port: HashMap<u16, Vec<SocketConnection>>,
    /// All connections indexed by (local, remote) pair
    by_pair: HashMap<(SocketAddr, SocketAddr), SocketConnection>,
    /// Connections indexed by PID
    by_pid: HashMap<u32, Vec<SocketConnection>>,
}

impl SocketSnapshot {
    /// Build a snapshot of all process sockets on the system.
    pub fn capture() -> Self {
        let mut all_conns = Vec::new();

        // Enumerate all PIDs
        let pids = match pids_by_type(ProcFilter::All) {
            Ok(pids) => pids,
            Err(_) => return Self::empty(),
        };

        for pid in pids {
            if pid == 0 {
                continue;
            }
            let name = full_process_name(pid as i32)
                .or_else(|| proc_pid::name(pid as i32).ok())
                .unwrap_or_default();
            let conns = get_process_connections(pid as i32, &name);
            all_conns.extend(conns);
        }

        let mut by_local_port: HashMap<u16, Vec<SocketConnection>> = HashMap::new();
        let mut by_pair: HashMap<(SocketAddr, SocketAddr), SocketConnection> = HashMap::new();
        let mut by_pid: HashMap<u32, Vec<SocketConnection>> = HashMap::new();

        for conn in all_conns {
            // Always index by PID (including LISTEN sockets for proxy detection)
            by_pid
                .entry(conn.pid)
                .or_default()
                .push(conn.clone());

            // Skip LISTEN sockets from pair/port indices to avoid polluting packet matching
            if conn.tcp_state == TcpState::Listen {
                continue;
            }

            by_local_port
                .entry(conn.local_addr.port())
                .or_default()
                .push(conn.clone());
            by_pair.insert((conn.local_addr, conn.remote_addr), conn);
        }

        Self {
            by_local_port,
            by_pair,
            by_pid,
        }
    }

    pub fn empty() -> Self {
        Self {
            by_local_port: HashMap::new(),
            by_pair: HashMap::new(),
            by_pid: HashMap::new(),
        }
    }

    /// Look up a process by exact (local, remote) address pair.
    fn lookup_exact(&self, local: &SocketAddr, remote: &SocketAddr) -> Option<&SocketConnection> {
        self.by_pair.get(&(*local, *remote))
    }

    /// Look up a process by local port and remote address.
    /// Falls back to matching just by local port if exact remote doesn't match.
    fn lookup_by_port(&self, local_port: u16, remote: &SocketAddr) -> Option<&SocketConnection> {
        let candidates = self.by_local_port.get(&local_port)?;
        // Try exact remote match first
        if let Some(conn) = candidates.iter().find(|c| c.remote_addr == *remote) {
            return Some(conn);
        }
        // Fall back to any connection on this local port
        candidates.first()
    }

    /// Match a captured packet (src, dst) to a process and determine direction.
    /// Tries both directions: src as local (outbound) and dst as local (inbound).
    pub fn match_packet(&self, src: &SocketAddr, dst: &SocketAddr) -> Option<ProcessMatch> {
        // Try outbound: src is local, dst is remote
        if let Some(conn) = self.lookup_exact(src, dst) {
            return Some(conn.to_match(Direction::Outbound));
        }
        // Try inbound: dst is local, src is remote
        if let Some(conn) = self.lookup_exact(dst, src) {
            return Some(conn.to_match(Direction::Inbound));
        }
        // Fallback: match by port (src as local = outbound)
        if let Some(conn) = self.lookup_by_port(src.port(), dst) {
            return Some(conn.to_match(Direction::Outbound));
        }
        // Fallback: match by port (dst as local = inbound)
        if let Some(conn) = self.lookup_by_port(dst.port(), src) {
            return Some(conn.to_match(Direction::Inbound));
        }
        None
    }

    /// Get all connections for a specific PID.
    pub fn connections_for_pid(&self, pid: u32) -> &[SocketConnection] {
        self.by_pid.get(&pid).map(|v| v.as_slice()).unwrap_or(&[])
    }

    /// Iterate over all connections across all PIDs.
    pub fn all_connections(&self) -> impl Iterator<Item = &SocketConnection> {
        self.by_pid.values().flat_map(|v| v.iter())
    }

    /// Iterate over all processes: yields (pid, name, connections) for each PID.
    pub fn all_processes(&self) -> impl Iterator<Item = (u32, String, &[SocketConnection])> {
        self.by_pid.iter().map(|(&pid, conns)| {
            let name = conns
                .first()
                .map(|c| c.proc_name.clone())
                .unwrap_or_default();
            (pid, name, conns.as_slice())
        })
    }
}

impl SocketConnection {
    fn to_match(&self, direction: Direction) -> ProcessMatch {
        ProcessMatch {
            pid: self.pid,
            name: self.proc_name.clone(),
            direction,
        }
    }
}

/// Query all TCP and UDP socket connections for a given PID.
fn get_process_connections(pid: i32, name: &str) -> Vec<SocketConnection> {
    let mut connections = Vec::new();

    let fds = match proc_pid::listpidinfo::<ListFDs>(pid, 256) {
        Ok(fds) => fds,
        Err(_) => return connections,
    };

    for fd_info in fds {
        if fd_info.proc_fdtype != ProcFDType::Socket as u32 {
            continue;
        }

        let socket_info = match pidfdinfo::<SocketFDInfo>(pid, fd_info.proc_fd) {
            Ok(info) => info,
            Err(_) => continue,
        };

        let si = &socket_info.psi;

        let (proto, state) = match si.soi_kind {
            kind if kind == SocketInfoKind::Tcp as i32 => {
                let tcp_info = unsafe { si.soi_proto.pri_tcp };
                (Protocol::Tcp, tcp_state_from_raw(tcp_info.tcpsi_state))
            }
            kind if kind == SocketInfoKind::In as i32 => {
                // Generic internet socket — likely UDP
                (Protocol::Udp, TcpState::Unknown)
            }
            _ => continue,
        };

        let inet_info = match si.soi_kind {
            kind if kind == SocketInfoKind::Tcp as i32 => {
                unsafe { &si.soi_proto.pri_tcp.tcpsi_ini }
            }
            kind if kind == SocketInfoKind::In as i32 => {
                unsafe { &si.soi_proto.pri_in }
            }
            _ => continue,
        };

        let (local_addr, remote_addr) = if inet_info.insi_vflag == 1 {
            // IPv4
            let local_ip = unsafe {
                let bytes = inet_info.insi_laddr.ina_46.i46a_addr4.s_addr;
                IpAddr::V4(Ipv4Addr::from(u32::from_be(bytes)))
            };
            let remote_ip = unsafe {
                let bytes = inet_info.insi_faddr.ina_46.i46a_addr4.s_addr;
                IpAddr::V4(Ipv4Addr::from(u32::from_be(bytes)))
            };
            (
                SocketAddr::new(local_ip, u16::from_be(inet_info.insi_lport as u16)),
                SocketAddr::new(remote_ip, u16::from_be(inet_info.insi_fport as u16)),
            )
        } else if inet_info.insi_vflag == 4 || inet_info.insi_vflag == 2 {
            // IPv6
            let local_ip = unsafe {
                let bytes = inet_info.insi_laddr.ina_6.s6_addr;
                IpAddr::V6(Ipv6Addr::from(bytes))
            };
            let remote_ip = unsafe {
                let bytes = inet_info.insi_faddr.ina_6.s6_addr;
                IpAddr::V6(Ipv6Addr::from(bytes))
            };
            (
                SocketAddr::new(local_ip, u16::from_be(inet_info.insi_lport as u16)),
                SocketAddr::new(remote_ip, u16::from_be(inet_info.insi_fport as u16)),
            )
        } else {
            // Unknown address family — skip
            continue;
        };

        connections.push(SocketConnection {
            pid: pid as u32,
            proc_name: name.to_string(),
            local_addr,
            remote_addr,
            tcp_state: state,
            protocol: proto,
        });
    }

    connections
}

/// Get process name by PID. Uses pidpath for full name, falls back to proc_name.
/// Returns None if the process has exited.
pub fn get_process_name(pid: i32) -> Option<String> {
    full_process_name(pid).or_else(|| proc_pid::name(pid).ok())
}

/// Get full process name via pidpath (avoids MAXCOMLEN truncation).
fn full_process_name(pid: i32) -> Option<String> {
    let path = proc_pid::pidpath(pid).ok()?;
    path.rsplit('/').next().map(|s| s.to_string())
}

/// Convert raw macOS TCP state integer to our TcpState enum.
fn tcp_state_from_raw(state: i32) -> TcpState {
    match state {
        0 => TcpState::Closed,
        1 => TcpState::Listen,
        2 => TcpState::SynSent,
        3 => TcpState::SynReceived,
        4 => TcpState::Established,
        5 => TcpState::CloseWait,
        6 => TcpState::FinWait1,
        7 => TcpState::Closing,
        8 => TcpState::LastAck,
        9 => TcpState::FinWait2,
        10 => TcpState::TimeWait,
        _ => TcpState::Unknown,
    }
}
