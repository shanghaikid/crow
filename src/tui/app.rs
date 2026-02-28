//! TUI main loop: rendering, keyboard events, and view dispatching.

use std::io;
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

use crossterm::event::{self, Event, KeyCode, KeyModifiers};
use crossterm::execute;
use crossterm::terminal::{
    disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen,
};
use ratatui::backend::CrosstermBackend;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph, TableState};
use ratatui::Terminal;

use crate::aggregate::{AppState, ViewMode};
use crate::tui::views;
use crate::tui::widgets::{format_bytes, format_rate};

/// Run the TUI. Blocks until the user quits.
pub fn run_tui(state: Arc<RwLock<AppState>>) -> anyhow::Result<()> {
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let tick_rate = Duration::from_millis(100); // ~10fps

    let result = run_loop(&mut terminal, state, tick_rate);

    // Restore terminal
    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    terminal.show_cursor()?;

    result
}

fn run_loop(
    terminal: &mut Terminal<CrosstermBackend<io::Stdout>>,
    state: Arc<RwLock<AppState>>,
    tick_rate: Duration,
) -> anyhow::Result<()> {
    let mut filter_text = String::new();
    let mut table_state = TableState::default();

    loop {
        // Draw
        terminal.draw(|f| {
            let app = state.read().unwrap();
            draw_ui(f, &app, &filter_text, &mut table_state);
        })?;

        // Handle input
        if event::poll(tick_rate)? {
            if let Event::Key(key) = event::read()? {
                match key.code {
                    KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                        return Ok(())
                    }
                    KeyCode::Char('q') if filter_text.is_empty() => return Ok(()),
                    KeyCode::Esc => {
                        filter_text.clear();
                        let mut app = state.write().unwrap();
                        app.filter = None;
                    }
                    KeyCode::Up => move_selection(&state, -1),
                    KeyCode::Down => move_selection(&state, 1),
                    KeyCode::Enter => {
                        let mut app = state.write().unwrap();
                        if let Some(pid) = app.selected_pid {
                            if !app.expanded_pids.remove(&pid) {
                                app.expanded_pids.insert(pid);
                            }
                        }
                    }
                    KeyCode::Tab => {
                        let mut app = state.write().unwrap();
                        app.view_mode = app.view_mode.next();
                    }
                    KeyCode::F(1) => {
                        let mut app = state.write().unwrap();
                        app.sort_by = app.sort_by.next();
                    }
                    KeyCode::Backspace => {
                        filter_text.pop();
                        let mut app = state.write().unwrap();
                        app.filter = if filter_text.is_empty() {
                            None
                        } else {
                            Some(filter_text.clone())
                        };
                    }
                    KeyCode::Char(c) => {
                        filter_text.push(c);
                        let mut app = state.write().unwrap();
                        app.filter = Some(filter_text.clone());
                    }
                    _ => {}
                }
            }
        }
    }
}

/// Move the process selection up (delta=-1) or down (delta=1).
/// Uses visible_pids so selection respects the current filter.
fn move_selection(state: &Arc<RwLock<AppState>>, delta: i32) {
    let mut app = state.write().unwrap();
    let now = Instant::now();
    let pids = app.visible_pids(now);
    if pids.is_empty() {
        return;
    }
    let cur_idx = app
        .selected_pid
        .and_then(|p| pids.iter().position(|&x| x == p))
        .unwrap_or(0);
    let new_idx = if delta < 0 {
        cur_idx.saturating_sub((-delta) as usize)
    } else {
        (cur_idx + delta as usize).min(pids.len() - 1)
    };
    app.selected_pid = pids.get(new_idx).copied();
}

fn draw_ui(f: &mut ratatui::Frame, app: &AppState, filter_text: &str, table_state: &mut TableState) {
    let size = f.area();

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3), // Stats bar
            Constraint::Min(5),   // Main content
            Constraint::Length(1), // Status/help bar
        ])
        .split(size);

    draw_stats_bar(f, chunks[0], app);
    draw_main_content(f, chunks[1], app, table_state);
    draw_help_bar(f, chunks[2], app, filter_text);
}

fn draw_stats_bar(f: &mut ratatui::Frame, area: Rect, app: &AppState) {
    let now = Instant::now();
    let tx_rate = format_rate(app.total_tx.rate_1s(now));
    let rx_rate = format_rate(app.total_rx.rate_1s(now));
    let proc_count = app.processes.len();
    let proxy_count = app.processes.values().filter(|p| p.is_proxy).count();

    let uptime = format_uptime(now.duration_since(app.started_at).as_secs());

    let mut spans = vec![
        Span::styled(" crow ", Style::default().fg(Color::Green).add_modifier(Modifier::BOLD)),
        Span::styled(uptime, Style::default().fg(Color::DarkGray)),
        Span::raw("  "),
        Span::styled(
            format!("^ {} ({})", tx_rate, format_bytes(app.grand_total_tx)),
            Style::default().fg(Color::Red),
        ),
        Span::raw("  "),
        Span::styled(
            format!("v {} ({})", rx_rate, format_bytes(app.grand_total_rx)),
            Style::default().fg(Color::Blue),
        ),
        Span::raw("  |  "),
        Span::styled(
            app.local_ip.as_str(),
            Style::default().fg(Color::Cyan),
        ),
        Span::raw(format!(
            "  |  Conns: {}  Procs: {}",
            app.total_connections(), proc_count
        )),
    ];

    if proxy_count > 0 {
        spans.push(Span::raw("  |  "));
        spans.push(Span::styled(
            format!("Proxies: {}", proxy_count),
            Style::default().fg(Color::Magenta),
        ));
    }

    let text = Line::from(spans);

    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::DarkGray));

    let paragraph = Paragraph::new(text).block(block);
    f.render_widget(paragraph, area);
}

fn draw_main_content(f: &mut ratatui::Frame, area: Rect, app: &AppState, table_state: &mut TableState) {
    match app.view_mode {
        ViewMode::Process => views::process::render(f, area, app, table_state),
        ViewMode::Connection => views::connection::render(f, area, app),
        ViewMode::Domain => views::domain::render(f, area, app),
    }
}

fn draw_help_bar(
    f: &mut ratatui::Frame,
    area: Rect,
    app: &AppState,
    filter_text: &str,
) {
    let mut spans = vec![
        Span::styled(" [q]", Style::default().fg(Color::Yellow)),
        Span::raw("Quit "),
        Span::styled("[Enter]", Style::default().fg(Color::Yellow)),
        Span::raw("Expand "),
        Span::styled("[Tab]", Style::default().fg(Color::Yellow)),
        Span::raw(format!("View:{} ", app.view_mode.label())),
        Span::styled("[F1]", Style::default().fg(Color::Yellow)),
        Span::raw(format!("Sort:{} ", app.sort_by.label())),
        Span::styled("[Esc]", Style::default().fg(Color::Yellow)),
        Span::raw("Clear "),
    ];

    if !filter_text.is_empty() {
        spans.push(Span::styled(
            format!(" Filter: {}", filter_text),
            Style::default().fg(Color::Magenta).add_modifier(Modifier::BOLD),
        ));
        spans.push(Span::styled(
            "_",
            Style::default().fg(Color::Magenta).add_modifier(Modifier::SLOW_BLINK),
        ));
    }

    let line = Line::from(spans);
    let paragraph = Paragraph::new(line);
    f.render_widget(paragraph, area);
}

fn format_uptime(secs: u64) -> String {
    let h = secs / 3600;
    let m = (secs % 3600) / 60;
    let s = secs % 60;
    if h > 0 {
        format!("{h}:{m:02}:{s:02}")
    } else {
        format!("{m}:{s:02}")
    }
}
