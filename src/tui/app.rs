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
    let mut filter_input: Option<String> = None; // Some = filter editing mode
    let mut table_state = TableState::default();

    loop {
        // Draw
        terminal.draw(|f| {
            let app = state.read().unwrap();
            draw_ui(f, &app, &filter_input, &mut table_state);
        })?;

        // Handle input
        if event::poll(tick_rate)? {
            if let Event::Key(key) = event::read()? {
                // Global: Ctrl+C always quits
                if key.code == KeyCode::Char('c') && key.modifiers.contains(KeyModifiers::CONTROL) {
                    return Ok(());
                }

                // Detail view mode
                {
                    let in_detail = state.read().unwrap().detail_pid.is_some();
                    if in_detail {
                        let page_size = terminal.size().map(|s| s.height.saturating_sub(4) as usize).unwrap_or(20);
                        let half_page = page_size / 2;
                        match key.code {
                            KeyCode::Esc | KeyCode::Char('q') => {
                                let mut app = state.write().unwrap();
                                app.detail_pid = None;
                                app.detail_scroll = 0;
                            }
                            // Single line: j/k, Up/Down, Enter(down)
                            KeyCode::Char('j') | KeyCode::Down | KeyCode::Enter => {
                                let mut app = state.write().unwrap();
                                app.detail_scroll = app.detail_scroll.saturating_add(1);
                            }
                            KeyCode::Char('k') | KeyCode::Up => {
                                let mut app = state.write().unwrap();
                                app.detail_scroll = app.detail_scroll.saturating_sub(1);
                            }
                            // Page down: Space, f, PageDown
                            KeyCode::Char(' ') | KeyCode::Char('f') | KeyCode::PageDown => {
                                let mut app = state.write().unwrap();
                                app.detail_scroll = app.detail_scroll.saturating_add(page_size);
                            }
                            // Page up: b, PageUp
                            KeyCode::Char('b') | KeyCode::PageUp => {
                                let mut app = state.write().unwrap();
                                app.detail_scroll = app.detail_scroll.saturating_sub(page_size);
                            }
                            // Half page: d(down), u(up)
                            KeyCode::Char('d') => {
                                let mut app = state.write().unwrap();
                                app.detail_scroll = app.detail_scroll.saturating_add(half_page);
                            }
                            KeyCode::Char('u') => {
                                let mut app = state.write().unwrap();
                                app.detail_scroll = app.detail_scroll.saturating_sub(half_page);
                            }
                            // Top/Bottom: g/G
                            KeyCode::Char('g') | KeyCode::Home => {
                                let mut app = state.write().unwrap();
                                app.detail_scroll = 0;
                            }
                            KeyCode::Char('G') | KeyCode::End => {
                                let mut app = state.write().unwrap();
                                let pid = app.detail_pid.unwrap();
                                let total = app.processes.get(&pid)
                                    .map(|p| p.packet_log.len())
                                    .unwrap_or(0);
                                app.detail_scroll = total;
                            }
                            _ => {}
                        }
                        continue;
                    }
                }

                let page_size = terminal.size().map(|s| s.height.saturating_sub(6) as usize).unwrap_or(20);
                let half_page = page_size / 2;

                // Global keys (work in all modes including filter editing)
                match key.code {
                    // Arrow keys & PageUp/Down/Home/End navigate even during filter editing
                    KeyCode::Up => {
                        navigate(&state, &mut table_state, -1);
                        continue;
                    }
                    KeyCode::Down => {
                        navigate(&state, &mut table_state, 1);
                        continue;
                    }
                    KeyCode::PageDown => {
                        navigate(&state, &mut table_state, page_size as i32);
                        continue;
                    }
                    KeyCode::PageUp => {
                        navigate(&state, &mut table_state, -(page_size as i32));
                        continue;
                    }
                    KeyCode::Home => {
                        navigate_to(&state, &mut table_state, NavTarget::Top);
                        continue;
                    }
                    KeyCode::End => {
                        navigate_to(&state, &mut table_state, NavTarget::Bottom);
                        continue;
                    }
                    KeyCode::Tab => {
                        let mut app = state.write().unwrap();
                        app.view_mode = app.view_mode.next();
                        table_state.select(Some(0));
                        continue;
                    }
                    _ => {}
                }

                // Filter editing mode
                if let Some(ref mut input) = filter_input {
                    match key.code {
                        KeyCode::Esc => {
                            filter_input = None;
                            let mut app = state.write().unwrap();
                            app.filter = None;
                        }
                        KeyCode::Enter => {
                            let text = input.clone();
                            filter_input = None;
                            let mut app = state.write().unwrap();
                            if text.is_empty() {
                                app.filter = None;
                            }
                            let now = Instant::now();
                            let visible = app.visible_pids(now);
                            if let Some(&first_pid) = visible.first() {
                                app.selected_pid = Some(first_pid);
                                if app.expanded_pids.insert(first_pid) {
                                    app.expansion_order.push(first_pid);
                                }
                            }
                        }
                        KeyCode::Backspace => {
                            input.pop();
                            let mut app = state.write().unwrap();
                            app.filter = if input.is_empty() {
                                None
                            } else {
                                Some(input.clone())
                            };
                        }
                        KeyCode::Char(c) => {
                            input.push(c);
                            let mut app = state.write().unwrap();
                            app.filter = Some(input.clone());
                        }
                        _ => {}
                    }
                    continue;
                }

                // Normal mode
                match key.code {
                    KeyCode::Char('q') => return Ok(()),
                    // Single line: j/k
                    KeyCode::Char('j') => navigate(&state, &mut table_state, 1),
                    KeyCode::Char('k') => navigate(&state, &mut table_state, -1),
                    // Page down: Space, f
                    KeyCode::Char(' ') | KeyCode::Char('f') => {
                        navigate(&state, &mut table_state, page_size as i32);
                    }
                    // Page up: b
                    KeyCode::Char('b') => {
                        navigate(&state, &mut table_state, -(page_size as i32));
                    }
                    // Half page: d(down), u(up)
                    KeyCode::Char('d') => {
                        navigate(&state, &mut table_state, half_page as i32);
                    }
                    KeyCode::Char('u') => {
                        navigate(&state, &mut table_state, -(half_page as i32));
                    }
                    // Top: g
                    KeyCode::Char('g') => {
                        navigate_to(&state, &mut table_state, NavTarget::Top);
                    }
                    // Bottom: G
                    KeyCode::Char('G') => {
                        navigate_to(&state, &mut table_state, NavTarget::Bottom);
                    }
                    KeyCode::Char('s') => {
                        let mut app = state.write().unwrap();
                        match app.view_mode {
                            ViewMode::Process => {
                                if app.sort_descending {
                                    app.sort_by = app.sort_by.next();
                                    app.sort_descending = false;
                                } else {
                                    app.sort_descending = true;
                                }
                            }
                            ViewMode::Connection => {
                                if app.conn_sort_desc {
                                    app.conn_sort_by = app.conn_sort_by.next();
                                    app.conn_sort_desc = false;
                                } else {
                                    app.conn_sort_desc = true;
                                }
                            }
                            ViewMode::Domain => {
                                if app.domain_sort_desc {
                                    app.domain_sort_by = app.domain_sort_by.next();
                                    app.domain_sort_desc = false;
                                } else {
                                    app.domain_sort_desc = true;
                                }
                            }
                        }
                    }
                    KeyCode::Char('/') => {
                        filter_input = Some(String::new());
                    }
                    KeyCode::Char('v') => {
                        let mut app = state.write().unwrap();
                        if let Some(pid) = app.selected_pid {
                            app.detail_pid = Some(pid);
                            app.detail_scroll = 0;
                        }
                    }
                    KeyCode::Enter => {
                        let mut app = state.write().unwrap();
                        if let Some(pid) = app.selected_pid {
                            if app.expanded_pids.remove(&pid) {
                                app.expansion_order.retain(|&p| p != pid);
                            } else {
                                app.expanded_pids.insert(pid);
                                app.expansion_order.push(pid);
                            }
                        }
                    }
                    KeyCode::Esc => {
                        let mut app = state.write().unwrap();
                        if let Some(pid) = app.expansion_order.pop() {
                            app.expanded_pids.remove(&pid);
                        } else {
                            app.filter = None;
                        }
                    }
                    _ => {}
                }
            }
        }
    }
}

enum NavTarget {
    Top,
    Bottom,
}

/// Navigate by delta lines in the current view.
fn navigate(state: &Arc<RwLock<AppState>>, table_state: &mut TableState, delta: i32) {
    let view = state.read().unwrap().view_mode;
    match view {
        ViewMode::Process => {
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
        _ => {
            let cur = table_state.selected().unwrap_or(0);
            let new = if delta < 0 {
                cur.saturating_sub((-delta) as usize)
            } else {
                cur.saturating_add(delta as usize)
            };
            table_state.select(Some(new));
        }
    }
}

/// Navigate to top or bottom of the current view.
fn navigate_to(state: &Arc<RwLock<AppState>>, table_state: &mut TableState, target: NavTarget) {
    let view = state.read().unwrap().view_mode;
    match view {
        ViewMode::Process => {
            let mut app = state.write().unwrap();
            let now = Instant::now();
            let pids = app.visible_pids(now);
            if pids.is_empty() {
                return;
            }
            match target {
                NavTarget::Top => app.selected_pid = pids.first().copied(),
                NavTarget::Bottom => app.selected_pid = pids.last().copied(),
            }
        }
        _ => match target {
            NavTarget::Top => table_state.select(Some(0)),
            NavTarget::Bottom => table_state.select(Some(usize::MAX / 2)),
        },
    }
}

fn draw_ui(f: &mut ratatui::Frame, app: &AppState, filter_input: &Option<String>, table_state: &mut TableState) {
    // Detail view takes over the whole screen
    if app.detail_pid.is_some() {
        views::detail::render(f, f.area(), app);
        return;
    }

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
    draw_help_bar(f, chunks[2], app, filter_input);
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
        ViewMode::Connection => views::connection::render(f, area, app, table_state),
        ViewMode::Domain => views::domain::render(f, area, app, table_state),
    }
}

fn draw_help_bar(
    f: &mut ratatui::Frame,
    area: Rect,
    app: &AppState,
    filter_input: &Option<String>,
) {
    let spans = if let Some(ref input) = filter_input {
        // Filter editing mode
        vec![
            Span::styled(" /", Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)),
            Span::styled(
                input.as_str(),
                Style::default().fg(Color::Magenta).add_modifier(Modifier::BOLD),
            ),
            Span::styled("_", Style::default().fg(Color::Magenta).add_modifier(Modifier::SLOW_BLINK)),
            Span::raw("  "),
            Span::styled("[Enter]", Style::default().fg(Color::DarkGray)),
            Span::raw(" Confirm  "),
            Span::styled("[Esc]", Style::default().fg(Color::DarkGray)),
            Span::raw(" Cancel"),
        ]
    } else {
        // Normal mode
        let mut s = vec![
            Span::styled(" [q]", Style::default().fg(Color::Yellow)),
            Span::raw("Quit "),
            Span::styled("[j/k]", Style::default().fg(Color::Yellow)),
            Span::raw("Scroll "),
            Span::styled("[f/b]", Style::default().fg(Color::Yellow)),
            Span::raw("Page "),
            Span::styled("[d/u]", Style::default().fg(Color::Yellow)),
            Span::raw("½Page "),
            Span::styled("[g/G]", Style::default().fg(Color::Yellow)),
            Span::raw("Top/End "),
            Span::styled("[/]", Style::default().fg(Color::Yellow)),
            Span::raw("Filter "),
            Span::styled("[s]", Style::default().fg(Color::Yellow)),
            Span::raw(format!("Sort:{}{} ",
                match app.view_mode {
                    ViewMode::Process => app.sort_by.label(),
                    ViewMode::Connection => app.conn_sort_by.label(),
                    ViewMode::Domain => app.domain_sort_by.label(),
                },
                match app.view_mode {
                    ViewMode::Process => if app.sort_descending { "▼" } else { "▲" },
                    ViewMode::Connection => if app.conn_sort_desc { "▼" } else { "▲" },
                    ViewMode::Domain => if app.domain_sort_desc { "▼" } else { "▲" },
                },
            )),
            Span::styled("[Tab]", Style::default().fg(Color::Yellow)),
            Span::raw(format!("View:{} ", app.view_mode.label())),
        ];
        if let Some(ref filter) = app.filter {
            s.push(Span::styled(
                format!("  /{}", filter),
                Style::default().fg(Color::Magenta),
            ));
            s.push(Span::raw(" "));
            s.push(Span::styled("[Esc]", Style::default().fg(Color::Yellow)));
            s.push(Span::raw("Clear"));
        }
        s
    };

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
