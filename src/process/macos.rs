//! macOS process introspection via libproc.
//!
//! Queries socket file descriptors for a given PID to discover
//! TCP connection states (ESTABLISHED, CLOSE_WAIT, etc.) that
//! supplement the PKTAP capture data.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use libproc::libproc::file_info::{pidfdinfo, ListFDs, ProcFDType};
use libproc::libproc::net_info::{SocketFDInfo, SocketInfoKind};
use libproc::libproc::proc_pid;

use crate::aggregate::TcpState;

/// A discovered socket connection for a process.
#[derive(Debug)]
pub struct SocketConnection {
    pub local_addr: SocketAddr,
    pub remote_addr: SocketAddr,
    pub tcp_state: TcpState,
}

/// Query all TCP socket connections for a given PID.
/// Returns an empty Vec if the process has exited or we lack permissions.
pub fn get_process_connections(pid: i32) -> Vec<SocketConnection> {
    let mut connections = Vec::new();

    // List all file descriptors for the process
    let fds = match proc_pid::listpidinfo::<ListFDs>(pid, 256) {
        Ok(fds) => fds,
        Err(_) => return connections,
    };

    for fd_info in fds {
        // Only interested in socket FDs
        if fd_info.proc_fdtype != ProcFDType::Socket as u32 {
            continue;
        }

        let socket_info = match pidfdinfo::<SocketFDInfo>(pid, fd_info.proc_fd) {
            Ok(info) => info,
            Err(_) => continue,
        };

        let si = &socket_info.psi;

        // Only interested in TCP sockets
        if si.soi_kind != SocketInfoKind::Tcp as i32 {
            continue;
        }

        // Extract TCP-specific info (union access requires unsafe)
        let tcp_info = unsafe { si.soi_proto.pri_tcp };
        let inet_info = &tcp_info.tcpsi_ini;

        let state = tcp_state_from_raw(tcp_info.tcpsi_state);

        // Determine IPv4 vs IPv6 from the vflag
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
            let local = SocketAddr::new(local_ip, inet_info.insi_lport as u16);
            let remote = SocketAddr::new(remote_ip, inet_info.insi_fport as u16);
            (local, remote)
        } else {
            // IPv6
            let local_ip = unsafe {
                let bytes = inet_info.insi_laddr.ina_6.s6_addr;
                IpAddr::V6(Ipv6Addr::from(bytes))
            };
            let remote_ip = unsafe {
                let bytes = inet_info.insi_faddr.ina_6.s6_addr;
                IpAddr::V6(Ipv6Addr::from(bytes))
            };
            let local = SocketAddr::new(local_ip, inet_info.insi_lport as u16);
            let remote = SocketAddr::new(remote_ip, inet_info.insi_fport as u16);
            (local, remote)
        };

        connections.push(SocketConnection {
            local_addr,
            remote_addr,
            tcp_state: state,
        });
    }

    connections
}

/// Get process name by PID. Returns None if the process has exited.
pub fn get_process_name(pid: i32) -> Option<String> {
    proc_pid::name(pid).ok()
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
