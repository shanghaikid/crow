//! Connection view: flat list of all connections, one per row.

use std::collections::HashSet;
use std::net::IpAddr;
use std::time::Instant;

use ratatui::layout::Constraint;
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Cell, Row, Table, TableState};
use ratatui::Frame;

use crate::aggregate::state::{ConnSortBy, ConnectionRoute, TcpState};
use crate::aggregate::AppState;
use crate::tui::widgets::format_bytes;

struct ConnRow {
    proc_name: String,
    alive: bool,
    is_proxy: bool,
    proto: &'static str,
    local: String,
    remote: String,
    remote_ip: IpAddr,
    state: TcpState,
    route: ConnectionRoute,
    tx: u64,
    rx: u64,
}

/// Build the sorted list of connection rows (shared logic for render + selection).
fn build_rows(state: &AppState) -> Vec<ConnRow> {
    let now = Instant::now();
    let pids = state.sorted_pids(now);
    let filter_lower = state.filter.as_ref().map(|f| f.to_lowercase());

    let mut conn_rows: Vec<ConnRow> = Vec::new();

    for &pid in &pids {
        let proc_info = match state.processes.get(&pid) {
            Some(p) => p,
            None => continue,
        };

        for conn in &proc_info.connections {
            if let Some(ref fl) = filter_lower {
                if !proc_info.matches_filter(fl) {
                    continue;
                }
            }

            let remote = conn.remote_display();

            conn_rows.push(ConnRow {
                proc_name: proc_info.name.clone(),
                alive: proc_info.alive,
                is_proxy: proc_info.is_proxy,
                proto: conn.protocol_str(),
                local: conn.local_addr.to_string(),
                remote: format!("{}:{}", remote, conn.remote_addr.port()),
                remote_ip: conn.remote_addr.ip(),
                state: conn.state,
                route: conn.route,
                tx: conn.bytes_tx,
                rx: conn.bytes_rx,
            });
        }
    }

    // Sort
    let sort_by = state.conn_sort_by;
    let desc = state.conn_sort_desc;
    conn_rows.sort_by(|a, b| {
        // Dead processes always at end
        let alive_ord = b.alive.cmp(&a.alive);
        if alive_ord != std::cmp::Ordering::Equal {
            return alive_ord;
        }

        let ord = match sort_by {
            ConnSortBy::Process => a.proc_name.to_lowercase().cmp(&b.proc_name.to_lowercase()),
            ConnSortBy::Proto => a.proto.cmp(b.proto),
            ConnSortBy::State => a.state.to_string().cmp(&b.state.to_string()),
            ConnSortBy::Route => route_rank(a.route).cmp(&route_rank(b.route)),
            ConnSortBy::TX => a.tx.cmp(&b.tx),
            ConnSortBy::RX => a.rx.cmp(&b.rx),
        };
        if desc { ord.reverse() } else { ord }
    });

    conn_rows
}

/// Get the remote IP and label for the currently selected row.
pub fn selected_ip(state: &AppState, selected: usize) -> Option<(IpAddr, String)> {
    let rows = build_rows(state);
    rows.get(selected).map(|r| (r.remote_ip, r.remote.clone()))
}

pub fn render(
    f: &mut Frame,
    area: ratatui::layout::Rect,
    state: &AppState,
    table_state: &mut TableState,
    blocked_ips: &HashSet<IpAddr>,
) {
    let conn_rows = build_rows(state);

    // Build rows
    let rows: Vec<Row> = conn_rows.iter().map(|cr| {
        let is_blocked = blocked_ips.contains(&cr.remote_ip);

        let name_style = if !cr.alive {
            Style::default().fg(Color::DarkGray)
        } else if cr.is_proxy {
            Style::default().fg(Color::Magenta)
        } else {
            Style::default()
        };

        let proto_style = if !cr.alive {
            Style::default().fg(Color::DarkGray)
        } else {
            match cr.proto {
                "TCP" => Style::default().fg(Color::Cyan),
                "UDP" => Style::default().fg(Color::Yellow),
                _ => Style::default(),
            }
        };

        let state_style = if !cr.alive {
            Style::default().fg(Color::DarkGray)
        } else {
            match cr.state {
                TcpState::Established => Style::default().fg(Color::Green),
                TcpState::Listen => Style::default().fg(Color::Cyan),
                TcpState::CloseWait | TcpState::LastAck | TcpState::Closing => {
                    Style::default().fg(Color::Yellow)
                }
                TcpState::TimeWait | TcpState::Closed => Style::default().fg(Color::DarkGray),
                TcpState::SynSent | TcpState::SynReceived => Style::default().fg(Color::Blue),
                _ => Style::default(),
            }
        };

        let route_style = if !cr.alive {
            Style::default().fg(Color::DarkGray)
        } else {
            match cr.route {
                ConnectionRoute::Proxied => Style::default().fg(Color::Green),
                ConnectionRoute::Direct => Style::default().fg(Color::Blue),
                ConnectionRoute::Unknown => Style::default().fg(Color::DarkGray),
            }
        };

        let base_style = if !cr.alive {
            Style::default().fg(Color::DarkGray)
        } else if is_blocked {
            Style::default().fg(Color::Red)
        } else {
            Style::default()
        };

        let remote_display = if is_blocked {
            format!("[B] {}", cr.remote)
        } else {
            cr.remote.clone()
        };

        Row::new(vec![
            Cell::from(Span::styled(cr.proc_name.clone(), name_style)),
            Cell::from(Span::styled(cr.proto.to_string(), proto_style)),
            Cell::from(Span::styled(cr.local.clone(), base_style)),
            Cell::from(Span::styled(remote_display, base_style)),
            Cell::from(Span::styled(cr.state.to_string(), state_style)),
            Cell::from(Span::styled(cr.route.to_string(), route_style)),
            Cell::from(Span::styled(format_bytes(cr.tx), base_style)),
            Cell::from(Span::styled(format_bytes(cr.rx), base_style)),
        ])
    }).collect();

    // Clamp selection to valid range
    if let Some(selected) = table_state.selected() {
        if !rows.is_empty() && selected >= rows.len() {
            table_state.select(Some(rows.len() - 1));
        }
    } else if !rows.is_empty() {
        table_state.select(Some(0));
    }

    let header = build_header(state.conn_sort_by, state.conn_sort_desc);

    let widths = [
        Constraint::Length(16),
        Constraint::Length(6),
        Constraint::Length(22),
        Constraint::Min(24),
        Constraint::Length(13),
        Constraint::Length(7),
        Constraint::Length(10),
        Constraint::Length(10),
    ];

    let table = Table::new(rows, widths)
        .header(header)
        .row_highlight_style(Style::default().add_modifier(Modifier::BOLD).fg(Color::Yellow))
        .highlight_symbol("> ")
        .block(Block::default().borders(Borders::NONE));

    f.render_stateful_widget(table, area, table_state);
}

fn route_rank(r: ConnectionRoute) -> u8 {
    match r {
        ConnectionRoute::Proxied => 0,
        ConnectionRoute::Direct => 1,
        ConnectionRoute::Unknown => 2,
    }
}

fn build_header(sort_by: ConnSortBy, descending: bool) -> Row<'static> {
    let normal = Style::default()
        .fg(Color::White)
        .add_modifier(Modifier::BOLD);
    let active = Style::default()
        .fg(Color::Yellow)
        .add_modifier(Modifier::BOLD);

    let columns: &[(&str, Option<ConnSortBy>)] = &[
        ("Process", Some(ConnSortBy::Process)),
        ("Proto", Some(ConnSortBy::Proto)),
        ("Local", None),
        ("Remote", None),
        ("State", Some(ConnSortBy::State)),
        ("Route", Some(ConnSortBy::Route)),
        ("TX", Some(ConnSortBy::TX)),
        ("RX", Some(ConnSortBy::RX)),
    ];

    let arrow = if descending { " ▼" } else { " ▲" };

    let cells: Vec<Cell> = columns
        .iter()
        .map(|(label, key)| {
            let is_active = key.map(|k| k == sort_by).unwrap_or(false);
            if is_active {
                Cell::from(Line::from(vec![
                    Span::styled(label.to_string(), active),
                    Span::styled(arrow, active),
                ]))
            } else {
                Cell::from(Span::styled(label.to_string(), normal))
            }
        })
        .collect();

    Row::new(cells)
}
