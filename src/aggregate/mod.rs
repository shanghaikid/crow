pub mod counter;
pub mod dns;
pub mod proxy;
pub mod state;

pub use state::{
    AppState, Connection, ConnectionRoute, Direction, DnsInfo, PacketEvent, PacketLogEntry,
    ProcessInfo, Protocol, TcpState, ViewMode,
};

use std::sync::mpsc;
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

use crate::capture::CaptureMode;
use crate::process::macos::{self, SocketSnapshot};

/// Run the aggregator loop. Consumes PacketEvents from the channel and
/// updates shared AppState. In RawIp mode, uses periodic socket snapshots
/// to attribute packets to processes.
///
/// This function blocks and should be called from a dedicated thread.
pub fn aggregator_loop(
    rx: mpsc::Receiver<PacketEvent>,
    state: Arc<RwLock<AppState>>,
    mode: CaptureMode,
) {
    let mut last_snapshot = Instant::now();
    let snapshot_interval = Duration::from_millis(500);
    let process_expiry = Duration::from_secs(30);

    // Initial socket snapshot (needed for connection state updates and proxy detection)
    let mut snapshot = SocketSnapshot::capture();

    loop {
        // Try to receive with a short timeout so we can do periodic work
        match rx.recv_timeout(Duration::from_millis(50)) {
            Ok(mut event) => {
                // In raw IP mode, resolve PID via socket matching
                if mode == CaptureMode::RawIp && event.pid == 0 {
                    if let Some(m) = snapshot.match_packet(&event.src, &event.dst) {
                        event.pid = m.pid;
                        event.proc_name = m.name;
                        event.direction = m.direction;
                    } else {
                        // Can't attribute this packet — skip it
                        continue;
                    }
                }

                let mut app = state.write().unwrap();
                process_event(&mut app, event);
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(mpsc::RecvTimeoutError::Disconnected) => break,
        }

        let now = Instant::now();

        // Periodic snapshot refresh and connection state polling
        if now.duration_since(last_snapshot) >= snapshot_interval {
            last_snapshot = now;

            snapshot = SocketSnapshot::capture();

            let proxy_addrs = proxy::detect_proxy_listen_addrs(&snapshot);

            let mut app = state.write().unwrap();
            app.proxy_listen_addrs = proxy_addrs;
            sync_processes_from_snapshot(&mut app, &snapshot, now);
            update_connection_states(&mut app, &snapshot);
            proxy::update_proxy_status(&mut app);
            expire_processes(&mut app, now, process_expiry);
            prune_closed_connections(&mut app);
            app.dns_cache.prune_expired();
        }
    }
}

/// Process a single PacketEvent into the AppState.
fn process_event(app: &mut AppState, event: PacketEvent) {
    let now = event.timestamp;

    // Update total counters
    match event.direction {
        Direction::Outbound => {
            app.total_tx.add(event.payload_len as u64, now);
            app.grand_total_tx += event.payload_len as u64;
        }
        Direction::Inbound => {
            app.total_rx.add(event.payload_len as u64, now);
            app.grand_total_rx += event.payload_len as u64;
        }
    }

    // Update DNS cache from DNS responses
    if let Some(ref dns) = event.dns_info {
        for ip in &dns.resolved_ips {
            app.dns_cache
                .insert(*ip, dns.query_name.clone(), dns.ttl);
        }
    }

    // Update per-process state
    // Use pidpath for full name to avoid MAXCOMLEN (16 char) truncation
    let full_name = if event.pid > 0 {
        macos::get_process_name(event.pid as i32)
            .or_else(|| if event.proc_name.is_empty() { None } else { Some(event.proc_name.clone()) })
            .unwrap_or_else(|| format!("<{}>", event.pid))
    } else {
        if event.proc_name.is_empty() { "kernel".to_string() } else { event.proc_name.clone() }
    };

    let proc_info = app
        .processes
        .entry(event.pid)
        .or_insert_with(|| ProcessInfo::new(full_name.clone(), now));

    proc_info.last_seen = now;
    proc_info.alive = true;

    if proc_info.name.is_empty() || (proc_info.name.len() <= 16 && full_name.len() > proc_info.name.len()) {
        proc_info.name = full_name;
    }

    match event.direction {
        Direction::Outbound => {
            proc_info.bytes_tx.add(event.payload_len as u64, now);
            proc_info.total_tx += event.payload_len as u64;
        }
        Direction::Inbound => {
            proc_info.bytes_rx.add(event.payload_len as u64, now);
            proc_info.total_rx += event.payload_len as u64;
        }
    }

    // Determine local/remote addresses
    let remote_addr = match event.direction {
        Direction::Outbound => event.dst,
        Direction::Inbound => event.src,
    };
    let local_addr = match event.direction {
        Direction::Outbound => event.src,
        Direction::Inbound => event.dst,
    };

    // Record packet log if there's interesting protocol info
    if let Some(ref info) = event.protocol_info {
        let elapsed = now.duration_since(app.started_at).as_secs_f64();
        proc_info.push_log(PacketLogEntry {
            elapsed_secs: elapsed,
            direction: event.direction,
            remote: remote_addr,
            size: event.payload_len,
            info: info.clone(),
        });
    }

    // Look up hostname for remote address
    let hostname = app
        .dns_cache
        .lookup(&remote_addr.ip())
        .map(|s| s.to_string());

    // Find existing connection or create new one
    let conn = proc_info.connections.iter_mut().find(|c| {
        c.remote_addr == remote_addr && c.local_addr == local_addr && c.protocol == event.protocol
    });

    match conn {
        Some(c) => {
            match event.direction {
                Direction::Outbound => c.bytes_tx += event.payload_len as u64,
                Direction::Inbound => c.bytes_rx += event.payload_len as u64,
            }
            if hostname.is_some() {
                c.remote_hostname = hostname;
            }
        }
        None => {
            let (tx, rx) = match event.direction {
                Direction::Outbound => (event.payload_len as u64, 0),
                Direction::Inbound => (0, event.payload_len as u64),
            };
            proc_info.connections.push(Connection {
                protocol: event.protocol,
                local_addr,
                remote_addr,
                remote_hostname: hostname,
                state: TcpState::Unknown,
                bytes_tx: tx,
                bytes_rx: rx,
                route: ConnectionRoute::Unknown,
            });
        }
    }
}

/// Discover processes from the socket snapshot that aren't yet tracked.
/// This ensures processes with active connections appear even if their
/// packets weren't captured (e.g., due to DLT limitations or idle connections).
fn sync_processes_from_snapshot(app: &mut AppState, snapshot: &SocketSnapshot, now: Instant) {
    for (pid, name, conns) in snapshot.all_processes() {
        // Skip kernel / PID 0
        if pid == 0 {
            continue;
        }

        // Only care about processes with non-LISTEN connections
        let active_conns: Vec<_> = conns
            .iter()
            .filter(|c| c.tcp_state != TcpState::Listen)
            .collect();
        if active_conns.is_empty() {
            continue;
        }

        let proc_info = app
            .processes
            .entry(pid)
            .or_insert_with(|| ProcessInfo::new(name.clone(), now));

        proc_info.last_seen = now;
        proc_info.alive = true;

        if proc_info.name.is_empty() && !name.is_empty() {
            proc_info.name.clone_from(&name);
        }

        // Add connections not yet tracked
        for sc in &active_conns {
            let already_tracked = proc_info.connections.iter().any(|c| {
                c.local_addr == sc.local_addr
                    && c.remote_addr == sc.remote_addr
                    && c.protocol == sc.protocol
            });
            if !already_tracked {
                let hostname = app
                    .dns_cache
                    .lookup(&sc.remote_addr.ip())
                    .map(|s| s.to_string());
                proc_info.connections.push(Connection {
                    protocol: sc.protocol,
                    local_addr: sc.local_addr,
                    remote_addr: sc.remote_addr,
                    remote_hostname: hostname,
                    state: sc.tcp_state,
                    bytes_tx: 0,
                    bytes_rx: 0,
                    route: ConnectionRoute::Unknown,
                });
            }
        }
    }
}

/// Update TCP connection states from the socket snapshot.
fn update_connection_states(app: &mut AppState, snapshot: &SocketSnapshot) {
    let pids: Vec<u32> = app.processes.keys().copied().collect();

    for pid in pids {
        let sock_conns = snapshot.connections_for_pid(pid);

        if let Some(proc_info) = app.processes.get_mut(&pid) {
            if sock_conns.is_empty()
                && proc_info.alive
                && macos::get_process_name(pid as i32).is_none()
            {
                proc_info.alive = false;
            }

            for conn in &mut proc_info.connections {
                if conn.protocol != Protocol::Tcp {
                    continue;
                }
                if let Some(sc) = sock_conns.iter().find(|sc| {
                    sc.local_addr == conn.local_addr && sc.remote_addr == conn.remote_addr
                }) {
                    conn.state = sc.tcp_state;
                }
            }
        }
    }
}

/// Remove processes that have been dead for longer than `expiry`.
fn expire_processes(app: &mut AppState, now: Instant, expiry: Duration) {
    app.processes.retain(|_, p| {
        p.alive || now.duration_since(p.last_seen) < expiry
    });
}

/// Remove connections in terminal states (Closed, TimeWait) to prevent unbounded growth.
fn prune_closed_connections(app: &mut AppState) {
    for proc_info in app.processes.values_mut() {
        proc_info.connections.retain(|c| {
            c.protocol != Protocol::Tcp
                || !matches!(c.state, TcpState::Closed | TcpState::TimeWait)
        });
    }
}
