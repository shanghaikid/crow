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

use crate::process::macos;

/// Run the aggregator loop. Consumes PacketEvents from the channel and
/// updates shared AppState. Also periodically polls process connections.
///
/// This function blocks and should be called from a dedicated thread.
pub fn aggregator_loop(
    rx: mpsc::Receiver<PacketEvent>,
    state: Arc<RwLock<AppState>>,
) {
    let mut last_conn_poll = Instant::now();
    let conn_poll_interval = Duration::from_millis(500);
    let process_expiry = Duration::from_secs(30);

    loop {
        // Try to receive with a short timeout so we can do periodic work
        match rx.recv_timeout(Duration::from_millis(50)) {
            Ok(event) => {
                let mut app = state.write().unwrap();
                process_event(&mut app, event);
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(mpsc::RecvTimeoutError::Disconnected) => break,
        }

        let now = Instant::now();

        // Periodic connection state polling
        if now.duration_since(last_conn_poll) >= conn_poll_interval {
            last_conn_poll = now;
            let mut app = state.write().unwrap();
            poll_connections(&mut app);
            expire_processes(&mut app, now, process_expiry);
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
        .or_insert_with(|| ProcessInfo::new(event.pid, event.proc_name.clone(), now));

    proc_info.last_seen = now;
    proc_info.alive = true;

    // Update the process name if we got a better one
    if !event.proc_name.is_empty() && proc_info.name.is_empty() {
        proc_info.name = event.proc_name.clone();
    }

    match event.direction {
        Direction::Outbound => proc_info.bytes_tx.add(event.payload_len as u64, now),
        Direction::Inbound => proc_info.bytes_rx.add(event.payload_len as u64, now),
    }

    // Update or create connection entry
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

/// Poll libproc for TCP connection states for all tracked processes.
fn poll_connections(app: &mut AppState) {
    let pids: Vec<u32> = app.processes.keys().copied().collect();
    for pid in pids {
        let sock_conns = macos::get_process_connections(pid as i32);

        if let Some(proc_info) = app.processes.get_mut(&pid) {
            // If we got no connections and the process was previously alive,
            // it might have exited
            if sock_conns.is_empty()
                && proc_info.alive
                && macos::get_process_name(pid as i32).is_none()
            {
                proc_info.alive = false;
            }

            // Update TCP states for our tracked connections
            for conn in &mut proc_info.connections {
                if conn.protocol != Protocol::Tcp {
                    continue;
                }
                // Find matching socket connection by addresses
                if let Some(sc) = sock_conns.iter().find(|sc| {
                    sc.local_addr == conn.local_addr && sc.remote_addr == conn.remote_addr
                }) {
                    conn.state = sc.tcp_state;
                }
            }
        }
    }

    // Update total connection count
    app.total_connections = app
        .processes
        .values()
        .map(|p| p.connections.len())
        .sum();
}

/// Remove processes that have been dead for longer than `expiry`.
fn expire_processes(app: &mut AppState, now: Instant, expiry: Duration) {
    app.processes.retain(|_, p| {
        p.alive || now.duration_since(p.last_seen) < expiry
    });
}
