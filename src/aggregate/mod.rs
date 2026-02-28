pub mod counter;
pub mod dns;
pub mod state;

pub use state::{
    AppState, Connection, Direction, DnsInfo, PacketEvent, ProcessInfo, Protocol, TcpState,
    ViewMode,
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

    // Initial socket snapshot for raw IP mode
    let mut snapshot = if mode == CaptureMode::RawIp {
        SocketSnapshot::capture()
    } else {
        SocketSnapshot::empty()
    };

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

            if mode == CaptureMode::RawIp {
                snapshot = SocketSnapshot::capture();
            }

            let mut app = state.write().unwrap();
            update_connection_states(&mut app, &snapshot);
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
        Direction::Outbound => app.total_tx.add(event.payload_len as u64, now),
        Direction::Inbound => app.total_rx.add(event.payload_len as u64, now),
    }

    // Update DNS cache from DNS responses
    if let Some(ref dns) = event.dns_info {
        for ip in &dns.resolved_ips {
            app.dns_cache
                .insert(*ip, dns.query_name.clone(), dns.ttl);
        }
    }

    // Update per-process state
    let proc_info = app
        .processes
        .entry(event.pid)
        .or_insert_with(|| ProcessInfo::new(event.proc_name.clone(), now));

    proc_info.last_seen = now;
    proc_info.alive = true;

    if !event.proc_name.is_empty() && proc_info.name.is_empty() {
        proc_info.name.clone_from(&event.proc_name);
    }

    match event.direction {
        Direction::Outbound => proc_info.bytes_tx.add(event.payload_len as u64, now),
        Direction::Inbound => proc_info.bytes_rx.add(event.payload_len as u64, now),
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
                latency: None,
            });
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
