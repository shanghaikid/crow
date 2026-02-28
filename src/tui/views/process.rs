//! Process view: grouped by process, with expandable connections.

use std::time::Instant;

use ratatui::layout::Constraint;
use ratatui::style::{Color, Modifier, Style};
use ratatui::widgets::{Block, Borders, Row, Table, TableState};
use ratatui::Frame;

use crate::aggregate::state::ConnectionRoute;
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
        }
    }

    // Update table state for scroll tracking
    table_state.select(selected_row);

    let header = Row::new(vec![
        "PID", "Process", "Up/s", "Down/s", "Total Up", "Total Dn", "Conns", "Route",
    ])
    .style(
        Style::default()
            .fg(Color::White)
            .add_modifier(Modifier::BOLD),
    );

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
