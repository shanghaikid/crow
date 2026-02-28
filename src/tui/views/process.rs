//! Process view: grouped by process, with expandable connections.

use std::time::Instant;

use ratatui::layout::Constraint;
use ratatui::style::{Color, Modifier, Style};
use ratatui::widgets::{Block, Borders, Row, Table};
use ratatui::Frame;

use crate::aggregate::AppState;
use crate::tui::widgets::{format_age, format_rate};

/// Render the process view into the given area.
pub fn render(f: &mut Frame, area: ratatui::layout::Rect, state: &AppState) {
    let now = Instant::now();
    let pids = state.sorted_pids(now);
    let filter_lower = state.filter.as_ref().map(|f| f.to_lowercase());

    let mut rows: Vec<Row> = Vec::new();
    let is_selected = |pid: u32| state.selected_pid == Some(pid);

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
        let age = format_age(now.duration_since(proc_info.first_seen).as_secs());
        let conns = proc_info.connections.len().to_string();

        let style = if !proc_info.alive {
            Style::default().fg(Color::DarkGray)
        } else if is_selected(pid) {
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD)
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

        rows.push(
            Row::new(vec![
                format!("{} {}", expand_marker, pid),
                proc_info.name.clone(),
                tx_rate,
                rx_rate,
                conns,
                age,
            ])
            .style(style),
        );

        // Show connections if expanded
        if expanded {
            for conn in &proc_info.connections {
                let remote = if let Some(ref hostname) = conn.remote_hostname {
                    if hostname.is_empty() {
                        conn.remote_addr.to_string()
                    } else {
                        format!("{}  {}", conn.remote_addr, hostname)
                    }
                } else {
                    conn.remote_addr.to_string()
                };

                let conn_style = if !proc_info.alive {
                    Style::default().fg(Color::DarkGray)
                } else {
                    Style::default().fg(Color::Cyan)
                };

                rows.push(
                    Row::new(vec![
                        String::new(),
                        format!("  {} {}", conn.protocol_str(), remote),
                        String::new(),
                        String::new(),
                        conn.state.to_string(),
                        String::new(),
                    ])
                    .style(conn_style),
                );
            }
        }
    }

    let header = Row::new(vec!["PID", "Process", "Upload", "Download", "Conns", "First Seen"])
        .style(
            Style::default()
                .fg(Color::White)
                .add_modifier(Modifier::BOLD),
        );

    let widths = [
        Constraint::Length(8),
        Constraint::Min(16),
        Constraint::Length(12),
        Constraint::Length(12),
        Constraint::Length(6),
        Constraint::Length(10),
    ];

    let table = Table::new(rows, widths)
        .header(header)
        .block(Block::default().borders(Borders::NONE));

    f.render_widget(table, area);
}
