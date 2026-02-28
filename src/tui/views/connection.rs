//! Connection view: flat list of all connections, one per row.

use std::time::Instant;

use ratatui::layout::Constraint;
use ratatui::style::{Color, Modifier, Style};
use ratatui::widgets::{Block, Borders, Row, Table};
use ratatui::Frame;

use crate::aggregate::AppState;
use crate::tui::widgets::format_bytes;

pub fn render(f: &mut Frame, area: ratatui::layout::Rect, state: &AppState) {
    let now = Instant::now();
    let pids = state.sorted_pids(now);

    let mut rows: Vec<Row> = Vec::new();

    for &pid in &pids {
        let proc_info = match state.processes.get(&pid) {
            Some(p) => p,
            None => continue,
        };

        for conn in &proc_info.connections {
            // Apply filter
            if let Some(ref filter) = state.filter {
                let filter_lower = filter.to_lowercase();
                let matches = proc_info.name.to_lowercase().contains(&filter_lower)
                    || conn
                        .remote_hostname
                        .as_deref()
                        .unwrap_or("")
                        .to_lowercase()
                        .contains(&filter_lower)
                    || conn.remote_addr.to_string().contains(&filter_lower);
                if !matches {
                    continue;
                }
            }

            let remote = conn
                .remote_hostname
                .as_deref()
                .unwrap_or(&conn.remote_addr.ip().to_string())
                .to_string();

            let style = if !proc_info.alive {
                Style::default().fg(Color::DarkGray)
            } else {
                Style::default()
            };

            rows.push(
                Row::new(vec![
                    proc_info.name.clone(),
                    conn.protocol_str().to_string(),
                    conn.local_addr.to_string(),
                    format!("{}:{}", remote, conn.remote_addr.port()),
                    conn.state.to_string(),
                    format_bytes(conn.bytes_tx),
                    format_bytes(conn.bytes_rx),
                ])
                .style(style),
            );
        }
    }

    let header = Row::new(vec![
        "Process", "Proto", "Local", "Remote", "State", "TX", "RX",
    ])
    .style(
        Style::default()
            .fg(Color::White)
            .add_modifier(Modifier::BOLD),
    );

    let widths = [
        Constraint::Length(16),
        Constraint::Length(6),
        Constraint::Length(22),
        Constraint::Min(24),
        Constraint::Length(13),
        Constraint::Length(10),
        Constraint::Length(10),
    ];

    let table = Table::new(rows, widths)
        .header(header)
        .block(Block::default().borders(Borders::NONE));

    f.render_widget(table, area);
}
