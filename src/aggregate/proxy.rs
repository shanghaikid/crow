//! Proxy detection: identify proxy processes and classify connection routes.

use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use crate::process::macos::SocketSnapshot;
use crate::aggregate::state::{AppState, ConnectionRoute, TcpState};

/// Known proxy / VPN tunnel process name substrings (lowercase).
const KNOWN_PROXY_NAMES: &[&str] = &[
    "karing",
    "karingservice",
    "clash",
    "clashx",
    "clashmeta",
    "sing-box",
    "singbox",
    "v2ray",
    "xray",
    "trojan",
    "shadowsocks",
    "ss-local",
    "sslocal",
    "hysteria",
    "naiveproxy",
    "tuic",
    "mihomo",
    "surge",
    "quantumult",
];

/// Check if a process name matches a known proxy.
pub fn is_proxy_process(name: &str) -> bool {
    let lower = name.to_lowercase();
    KNOWN_PROXY_NAMES.iter().any(|p| lower.contains(p))
}

/// Scan the socket snapshot for LISTEN sockets belonging to proxy processes.
/// Returns the set of local addresses those proxies are listening on.
pub fn detect_proxy_listen_addrs(snapshot: &SocketSnapshot) -> HashSet<SocketAddr> {
    let mut addrs = HashSet::new();
    for conn in snapshot.all_connections() {
        if conn.tcp_state != TcpState::Listen {
            continue;
        }
        if is_proxy_process(&conn.proc_name) {
            addrs.insert(conn.local_addr);
        }
    }
    addrs
}

/// Check if a connection's remote address matches one of the proxy listen addresses.
/// Handles 0.0.0.0 ↔ 127.0.0.1 normalization (proxy may listen on 0.0.0.0 but
/// connections go to 127.0.0.1, or vice versa).
pub fn is_proxied_connection(remote: &SocketAddr, proxy_addrs: &HashSet<SocketAddr>) -> bool {
    if proxy_addrs.contains(remote) {
        return true;
    }
    // Normalize: if remote is 127.0.0.1:port, also check 0.0.0.0:port and vice versa
    if let IpAddr::V4(ip) = remote.ip() {
        let alt_ip = if ip == Ipv4Addr::LOCALHOST {
            Ipv4Addr::UNSPECIFIED
        } else if ip == Ipv4Addr::UNSPECIFIED {
            Ipv4Addr::LOCALHOST
        } else {
            return false;
        };
        let alt = SocketAddr::new(IpAddr::V4(alt_ip), remote.port());
        proxy_addrs.contains(&alt)
    } else {
        false
    }
}

/// Update proxy status on all processes and classify connection routes.
pub fn update_proxy_status(app: &mut AppState) {
    let proxy_addrs = &app.proxy_listen_addrs;

    for proc_info in app.processes.values_mut() {
        proc_info.is_proxy = is_proxy_process(&proc_info.name);

        for conn in &mut proc_info.connections {
            if proxy_addrs.is_empty() {
                conn.route = ConnectionRoute::Unknown;
            } else if is_proxied_connection(&conn.remote_addr, proxy_addrs) {
                conn.route = ConnectionRoute::Proxied;
            } else {
                conn.route = ConnectionRoute::Direct;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, SocketAddr};

    #[test]
    fn test_known_proxy_names() {
        assert!(is_proxy_process("Karing"));
        assert!(is_proxy_process("karingService"));
        assert!(is_proxy_process("com.apple.clash"));
        assert!(is_proxy_process("ClashX"));
        assert!(is_proxy_process("sing-box"));
        assert!(is_proxy_process("v2ray-core"));
        assert!(is_proxy_process("Surge"));
        assert!(!is_proxy_process("Safari"));
        assert!(!is_proxy_process("curl"));
        assert!(!is_proxy_process("nginx"));
    }

    #[test]
    fn test_proxied_connection_exact_match() {
        let mut addrs = HashSet::new();
        let proxy = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 7890);
        addrs.insert(proxy);

        assert!(is_proxied_connection(&proxy, &addrs));
        let other = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)), 443);
        assert!(!is_proxied_connection(&other, &addrs));
    }

    #[test]
    fn test_proxied_connection_normalize_loopback() {
        let mut addrs = HashSet::new();
        // Proxy listens on 0.0.0.0:7890
        let listen = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 7890);
        addrs.insert(listen);

        // Connection goes to 127.0.0.1:7890 — should match
        let remote = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 7890);
        assert!(is_proxied_connection(&remote, &addrs));
    }

    #[test]
    fn test_proxied_connection_normalize_unspecified() {
        let mut addrs = HashSet::new();
        // Proxy listens on 127.0.0.1:7890
        let listen = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 7890);
        addrs.insert(listen);

        // Connection goes to 0.0.0.0:7890 — should match
        let remote = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 7890);
        assert!(is_proxied_connection(&remote, &addrs));
    }

    #[test]
    fn test_proxied_connection_wrong_port() {
        let mut addrs = HashSet::new();
        let listen = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 7890);
        addrs.insert(listen);

        let remote = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8080);
        assert!(!is_proxied_connection(&remote, &addrs));
    }
}
