//! Domain view: grouped by destination hostname, showing which processes connect.

use std::collections::{HashMap, HashSet};

use ratatui::layout::Constraint;
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Cell, Row, Table, TableState};
use ratatui::Frame;

use crate::aggregate::state::DomainSortBy;
use crate::aggregate::AppState;
use crate::tui::widgets::format_bytes;

struct DomainEntry {
    processes: HashSet<String>,
    total_tx: u64,
    total_rx: u64,
    conn_count: usize,
}

pub fn render(f: &mut Frame, area: ratatui::layout::Rect, state: &AppState, table_state: &mut TableState) {
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

    // Sort
    let sort_by = state.domain_sort_by;
    let desc = state.domain_sort_desc;
    let mut sorted: Vec<(String, DomainEntry)> = domains.into_iter().collect();
    sorted.sort_by(|a, b| {
        let ord = match sort_by {
            DomainSortBy::Domain => a.0.to_lowercase().cmp(&b.0.to_lowercase()),
            DomainSortBy::Conns => a.1.conn_count.cmp(&b.1.conn_count),
            DomainSortBy::TX => a.1.total_tx.cmp(&b.1.total_tx),
            DomainSortBy::RX => a.1.total_rx.cmp(&b.1.total_rx),
        };
        if desc { ord.reverse() } else { ord }
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

    // Clamp selection to valid range
    if let Some(selected) = table_state.selected() {
        if !rows.is_empty() && selected >= rows.len() {
            table_state.select(Some(rows.len() - 1));
        }
    } else if !rows.is_empty() {
        table_state.select(Some(0));
    }

    let header = build_header(state.domain_sort_by, state.domain_sort_desc);

    let widths = [
        Constraint::Min(24),
        Constraint::Min(20),
        Constraint::Length(6),
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

fn build_header(sort_by: DomainSortBy, descending: bool) -> Row<'static> {
    let normal = Style::default()
        .fg(Color::White)
        .add_modifier(Modifier::BOLD);
    let active = Style::default()
        .fg(Color::Yellow)
        .add_modifier(Modifier::BOLD);

    let columns: &[(&str, Option<DomainSortBy>)] = &[
        ("Domain", Some(DomainSortBy::Domain)),
        ("Processes", None),
        ("Conns", Some(DomainSortBy::Conns)),
        ("TX Total", Some(DomainSortBy::TX)),
        ("RX Total", Some(DomainSortBy::RX)),
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
