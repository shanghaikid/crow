//! Detail view: full-screen packet log for a single process.

use ratatui::layout::{Constraint, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph, Row, Table};
use ratatui::Frame;

use crate::aggregate::{AppState, Direction};
use crate::tui::widgets::format_bytes;

/// Render the full-screen packet log detail view.
pub fn render(f: &mut Frame, area: Rect, state: &AppState) {
    let pid = match state.detail_pid {
        Some(p) => p,
        None => return,
    };
    let proc_info = match state.processes.get(&pid) {
        Some(p) => p,
        None => return,
    };

    // Title bar
    let title = Line::from(vec![
        Span::styled(" Packet Log ", Style::default().fg(Color::Green).add_modifier(Modifier::BOLD)),
        Span::styled(
            format!("{} (PID: {}) ", proc_info.name, pid),
            Style::default().fg(Color::Cyan),
        ),
        Span::styled(
            format!("  {} entries ", proc_info.packet_log.len()),
            Style::default().fg(Color::DarkGray),
        ),
        Span::styled(
            format!("  ^ {}  v {} ",
                format_bytes(proc_info.total_tx),
                format_bytes(proc_info.total_rx),
            ),
            Style::default().fg(Color::White),
        ),
        Span::styled("  [Esc] Back  [j/k] Scroll", Style::default().fg(Color::DarkGray)),
    ]);

    let block = Block::default()
        .title(title)
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::DarkGray));

    let inner = block.inner(area);
    f.render_widget(block, area);

    if proc_info.packet_log.is_empty() {
        let msg = Paragraph::new("  No packet log entries yet.")
            .style(Style::default().fg(Color::DarkGray));
        f.render_widget(msg, inner);
        return;
    }

    // Header
    let header = Row::new(vec!["Time", "Dir", "Info", "Size"])
        .style(Style::default().fg(Color::White).add_modifier(Modifier::BOLD));

    let widths = [
        Constraint::Length(8),
        Constraint::Length(4),
        Constraint::Min(30),
        Constraint::Length(10),
    ];

    // Build rows from packet log, respecting scroll offset
    let visible_height = inner.height.saturating_sub(1) as usize; // minus header
    let total = proc_info.packet_log.len();
    let scroll = state.detail_scroll.min(total.saturating_sub(visible_height));

    let rows: Vec<Row> = proc_info
        .packet_log
        .iter()
        .skip(scroll)
        .take(visible_height)
        .map(|entry| {
            let (arrow, color) = match entry.direction {
                Direction::Outbound => ("^", Color::Red),
                Direction::Inbound => ("v", Color::Blue),
            };
            let ts = format_log_time(entry.elapsed_secs);
            Row::new(vec![
                ts,
                arrow.to_string(),
                entry.info.clone(),
                format_bytes(entry.size as u64),
            ])
            .style(Style::default().fg(color))
        })
        .collect();

    let table = Table::new(rows, widths)
        .header(header)
        .block(Block::default().borders(Borders::NONE));

    f.render_widget(table, inner);
}

fn format_log_time(elapsed_secs: f64) -> String {
    let secs = elapsed_secs as u64;
    let m = secs / 60;
    let s = secs % 60;
    format!("{m}:{s:02}")
}
