//! Domain view: grouped by destination hostname, showing which processes connect.

use std::collections::HashMap;

use ratatui::layout::Constraint;
use ratatui::style::{Color, Modifier, Style};
use ratatui::widgets::{Block, Borders, Row, Table};
use ratatui::Frame;

use crate::aggregate::AppState;
use crate::tui::widgets::format_bytes;

struct DomainEntry {
    processes: Vec<String>,
    total_tx: u64,
    total_rx: u64,
    conn_count: usize,
}

pub fn render(f: &mut Frame, area: ratatui::layout::Rect, state: &AppState) {
    // Aggregate connections by hostname
    let mut domains: HashMap<String, DomainEntry> = HashMap::new();

    for proc_info in state.processes.values() {
        for conn in &proc_info.connections {
            let hostname = conn
                .remote_hostname
                .as_deref()
                .unwrap_or(&conn.remote_addr.ip().to_string())
                .to_string();

            // Apply filter
            if let Some(ref filter) = state.filter {
                let filter_lower = filter.to_lowercase();
                if !hostname.to_lowercase().contains(&filter_lower)
                    && !proc_info.name.to_lowercase().contains(&filter_lower)
                {
                    continue;
                }
            }

            let entry = domains.entry(hostname).or_insert_with(|| DomainEntry {
                processes: Vec::new(),
                total_tx: 0,
                total_rx: 0,
                conn_count: 0,
            });

            if !entry.processes.contains(&proc_info.name) {
                entry.processes.push(proc_info.name.clone());
            }
            entry.total_tx += conn.bytes_tx;
            entry.total_rx += conn.bytes_rx;
            entry.conn_count += 1;
        }
    }

    // Sort by total traffic descending
    let mut sorted: Vec<(String, DomainEntry)> = domains.into_iter().collect();
    sorted.sort_by(|a, b| {
        let total_a = a.1.total_tx + a.1.total_rx;
        let total_b = b.1.total_tx + b.1.total_rx;
        total_b.cmp(&total_a)
    });

    let rows: Vec<Row> = sorted
        .iter()
        .map(|(hostname, entry)| {
            let procs = entry.processes.join(", ");
            Row::new(vec![
                hostname.clone(),
                procs,
                entry.conn_count.to_string(),
                format_bytes(entry.total_tx),
                format_bytes(entry.total_rx),
            ])
        })
        .collect();

    let header = Row::new(vec!["Domain", "Processes", "Conns", "TX Total", "RX Total"]).style(
        Style::default()
            .fg(Color::White)
            .add_modifier(Modifier::BOLD),
    );

    let widths = [
        Constraint::Min(24),
        Constraint::Min(20),
        Constraint::Length(6),
        Constraint::Length(10),
        Constraint::Length(10),
    ];

    let table = Table::new(rows, widths)
        .header(header)
        .block(Block::default().borders(Borders::NONE));

    f.render_widget(table, area);
}
