//! Domain view: grouped by destination hostname, showing which processes connect.

use std::collections::{HashMap, HashSet};

use ratatui::layout::Constraint;
use ratatui::style::{Color, Modifier, Style};
use ratatui::widgets::{Block, Borders, Row, Table};
use ratatui::Frame;

use crate::aggregate::AppState;
use crate::tui::widgets::format_bytes;

struct DomainEntry {
    processes: HashSet<String>,
    total_tx: u64,
    total_rx: u64,
    conn_count: usize,
}

pub fn render(f: &mut Frame, area: ratatui::layout::Rect, state: &AppState) {
    // Aggregate connections by hostname
    let mut domains: HashMap<String, DomainEntry> = HashMap::new();
    let filter_lower = state.filter.as_ref().map(|f| f.to_lowercase());

    for proc_info in state.processes.values() {
        for conn in &proc_info.connections {
            let hostname = conn.remote_display();

            // Apply filter
            if let Some(ref fl) = filter_lower {
                if !hostname.to_lowercase().contains(fl.as_str())
                    && !proc_info.name.to_lowercase().contains(fl.as_str())
                {
                    continue;
                }
            }

            let entry = domains.entry(hostname).or_insert_with(|| DomainEntry {
                processes: HashSet::new(),
                total_tx: 0,
                total_rx: 0,
                conn_count: 0,
            });

            entry.processes.insert(proc_info.name.clone());
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
            let mut procs: Vec<&str> = entry.processes.iter().map(|s| s.as_str()).collect();
            procs.sort();
            Row::new(vec![
                hostname.clone(),
                procs.join(", "),
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
