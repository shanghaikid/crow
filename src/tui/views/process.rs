//! Process view: grouped by process, with expandable connections.

use std::time::Instant;

use ratatui::layout::Constraint;
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Cell, Row, Table, TableState};
use ratatui::Frame;

use crate::aggregate::state::{ConnectionRoute, SortBy};
use crate::aggregate::AppState;
use crate::tui::widgets::{format_bytes, format_rate};

/// Render the process view into the given area.
pub fn render(f: &mut Frame, area: ratatui::layout::Rect, state: &AppState, table_state: &mut TableState) {
    let now = Instant::now();
    let pids = state.sorted_pids(now);
    let filter_lower = state.filter.as_ref().map(|f| f.to_lowercase());

    let mut rows: Vec<Row> = Vec::new();
    let mut selected_row: Option<usize> = None;

    for &pid in &pids {
        let proc_info = match state.processes.get(&pid) {
            Some(p) => p,
            None => continue,
        };

        // Apply filter
        if let Some(ref fl) = filter_lower {
            if !proc_info.matches_filter(fl) {
                continue;
            }
        }

        let tx_rate = format_rate(proc_info.bytes_tx.rate_1s(now));
        let rx_rate = format_rate(proc_info.bytes_rx.rate_1s(now));
        let conns = proc_info.connections.len().to_string();

        let style = if !proc_info.alive {
            Style::default().fg(Color::DarkGray)
        } else if proc_info.is_proxy {
            Style::default().fg(Color::Magenta)
        } else {
            Style::default()
        };

        let expanded = state.expanded_pids.contains(&pid);
        let expand_marker = if proc_info.connections.is_empty() {
            " "
        } else if expanded {
            "v"
        } else {
            ">"
        };

        // Determine aggregate route for the process
        let route_label = if proc_info.is_proxy {
            "PROXY".to_string()
        } else {
            let has_proxied = proc_info
                .connections
                .iter()
                .any(|c| c.route == ConnectionRoute::Proxied);
            let has_direct = proc_info
                .connections
                .iter()
                .any(|c| c.route == ConnectionRoute::Direct);
            match (has_proxied, has_direct) {
                (true, true) => "MIXED".to_string(),
                (true, false) => "PROXY".to_string(),
                (false, true) => "DIRECT".to_string(),
                _ => String::new(),
            }
        };

        // Track selected row index
        if state.selected_pid == Some(pid) {
            selected_row = Some(rows.len());
        }

        rows.push(
            Row::new(vec![
                format!("{} {}", expand_marker, pid),
                proc_info.name.clone(),
                tx_rate,
                rx_rate,
                format_bytes(proc_info.total_tx),
                format_bytes(proc_info.total_rx),
                conns,
                route_label,
            ])
            .style(style),
        );

        // Show connections if expanded
        if expanded {
            for conn in &proc_info.connections {
                let remote = conn.remote_display();

                let conn_style = if !proc_info.alive {
                    Style::default().fg(Color::DarkGray)
                } else if conn.route == ConnectionRoute::Proxied {
                    Style::default().fg(Color::Green)
                } else {
                    Style::default().fg(Color::Cyan)
                };

                rows.push(
                    Row::new(vec![
                        String::new(),
                        format!(
                            "  {} {}:{}  {}",
                            conn.protocol_str(),
                            remote,
                            conn.remote_addr.port(),
                            conn.state,
                        ),
                        String::new(),
                        String::new(),
                        format_bytes(conn.bytes_tx),
                        format_bytes(conn.bytes_rx),
                        String::new(),
                        conn.route.to_string(),
                    ])
                    .style(conn_style),
                );
            }

            // Show recent packet log (most recent last, show last 10)
            let log_style = Style::default().fg(Color::DarkGray);
            let log_entries: Vec<_> = proc_info.packet_log.iter().rev().take(10).collect();
            for entry in log_entries.into_iter().rev() {
                let arrow = match entry.direction {
                    crate::aggregate::Direction::Outbound => "^",
                    crate::aggregate::Direction::Inbound => "v",
                };
                let ts = format_log_time(entry.elapsed_secs);
                rows.push(
                    Row::new(vec![
                        String::new(),
                        format!("    {} {} {} ({}B)", ts, arrow, entry.info, entry.size),
                        String::new(),
                        String::new(),
                        String::new(),
                        String::new(),
                        String::new(),
                        String::new(),
                    ])
                    .style(log_style),
                );
            }
        }
    }

    // Update table state for scroll tracking
    table_state.select(selected_row);

    let header = build_header(state.sort_by, state.sort_descending);

    let widths = [
        Constraint::Length(8),
        Constraint::Min(20),
        Constraint::Length(10),
        Constraint::Length(10),
        Constraint::Length(10),
        Constraint::Length(10),
        Constraint::Length(6),
        Constraint::Length(7),
    ];

    let table = Table::new(rows, widths)
        .header(header)
        .row_highlight_style(Style::default().add_modifier(Modifier::BOLD).fg(Color::Yellow))
        .highlight_symbol("> ")
        .block(Block::default().borders(Borders::NONE));

    f.render_stateful_widget(table, area, table_state);
}

/// Build the header row with a sort indicator on the active column.
fn build_header(sort_by: SortBy, descending: bool) -> Row<'static> {
    let normal = Style::default()
        .fg(Color::White)
        .add_modifier(Modifier::BOLD);
    let active = Style::default()
        .fg(Color::Yellow)
        .add_modifier(Modifier::BOLD);

    let columns: &[(&str, Option<SortBy>)] = &[
        ("PID", Some(SortBy::Pid)),
        ("Process", Some(SortBy::Name)),
        ("Up/s", Some(SortBy::Traffic)),
        ("Down/s", None),       // part of Traffic sort
        ("Total Up", None),
        ("Total Dn", None),
        ("Conns", Some(SortBy::Connections)),
        ("Route", None),
    ];

    let arrow = if descending { " ▼" } else { " ▲" };

    let cells: Vec<Cell> = columns
        .iter()
        .map(|(label, key)| {
            let is_active = key.map(|k| k == sort_by).unwrap_or(false)
                || (*label == "Down/s" && sort_by == SortBy::Traffic);

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

fn format_log_time(elapsed_secs: f64) -> String {
    let secs = elapsed_secs as u64;
    let m = secs / 60;
    let s = secs % 60;
    format!("{m}:{s:02}")
}
