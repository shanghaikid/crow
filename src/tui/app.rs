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
use ratatui::widgets::{Block, Borders, Paragraph};
use ratatui::Terminal;

use crate::aggregate::{AppState, ViewMode};
use crate::tui::views;
use crate::tui::widgets::format_rate;

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
    let mut filter_input: Option<String> = None; // Some = filter mode active

    loop {
        // Draw
        terminal.draw(|f| {
            let app = state.read().unwrap();
            draw_ui(f, &app, &filter_input);
        })?;

        // Handle input
        if event::poll(tick_rate)? {
            if let Event::Key(key) = event::read()? {
                // If in filter input mode, handle text entry
                if let Some(ref mut input) = filter_input {
                    match key.code {
                        KeyCode::Esc => {
                            filter_input = None;
                            let mut app = state.write().unwrap();
                            app.filter = None;
                        }
                        KeyCode::Enter => {
                            let filter_text = input.clone();
                            filter_input = None;
                            let mut app = state.write().unwrap();
                            if filter_text.is_empty() {
                                app.filter = None;
                            } else {
                                app.filter = Some(filter_text);
                            }
                        }
                        KeyCode::Backspace => {
                            input.pop();
                            let mut app = state.write().unwrap();
                            if input.is_empty() {
                                app.filter = None;
                            } else {
                                app.filter = Some(input.clone());
                            }
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

                // Normal mode keybindings
                match key.code {
                    KeyCode::Char('q') => return Ok(()),
                    KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                        return Ok(())
                    }
                    KeyCode::Up | KeyCode::Char('k') => {
                        let mut app = state.write().unwrap();
                        app.selected_index = app.selected_index.saturating_sub(1);
                    }
                    KeyCode::Down | KeyCode::Char('j') => {
                        let mut app = state.write().unwrap();
                        let max = app.processes.len().saturating_sub(1);
                        if app.selected_index < max {
                            app.selected_index += 1;
                        }
                    }
                    KeyCode::Enter => {
                        let mut app = state.write().unwrap();
                        // Toggle expand for the selected process
                        let now = Instant::now();
                        let pids = app.sorted_pids(now);
                        if let Some(&pid) = pids.get(app.selected_index) {
                            if app.expanded_pids.contains(&pid) {
                                app.expanded_pids.remove(&pid);
                            } else {
                                app.expanded_pids.insert(pid);
                            }
                        }
                    }
                    KeyCode::Char('s') => {
                        let mut app = state.write().unwrap();
                        app.sort_by = app.sort_by.next();
                    }
                    KeyCode::Char('/') => {
                        filter_input = Some(String::new());
                    }
                    KeyCode::Tab => {
                        let mut app = state.write().unwrap();
                        app.view_mode = app.view_mode.next();
                    }
                    _ => {}
                }
            }
        }
    }
}

fn draw_ui(f: &mut ratatui::Frame, app: &AppState, filter_input: &Option<String>) {
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
    draw_main_content(f, chunks[1], app);
    draw_help_bar(f, chunks[2], app, filter_input);
}

fn draw_stats_bar(f: &mut ratatui::Frame, area: Rect, app: &AppState) {
    let now = Instant::now();
    let tx_rate = format_rate(app.total_tx.rate_1s(now));
    let rx_rate = format_rate(app.total_rx.rate_1s(now));
    let proc_count = app.processes.len();

    let text = Line::from(vec![
        Span::styled(" crow ", Style::default().fg(Color::Green).add_modifier(Modifier::BOLD)),
        Span::raw("  "),
        Span::styled(
            format!("^ {}", tx_rate),
            Style::default().fg(Color::Red),
        ),
        Span::raw("  "),
        Span::styled(
            format!("v {}", rx_rate),
            Style::default().fg(Color::Blue),
        ),
        Span::raw("  |  "),
        Span::raw(format!(
            "Connections: {}  |  Processes: {}",
            app.total_connections, proc_count
        )),
    ]);

    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::DarkGray));

    let paragraph = Paragraph::new(text).block(block);
    f.render_widget(paragraph, area);
}

fn draw_main_content(f: &mut ratatui::Frame, area: Rect, app: &AppState) {
    match app.view_mode {
        ViewMode::Process => views::process::render(f, area, app),
        ViewMode::Connection => views::connection::render(f, area, app),
        ViewMode::Domain => views::domain::render(f, area, app),
    }
}

fn draw_help_bar(
    f: &mut ratatui::Frame,
    area: Rect,
    app: &AppState,
    filter_input: &Option<String>,
) {
    let spans = if let Some(ref input) = filter_input {
        vec![
            Span::styled(" /", Style::default().fg(Color::Yellow)),
            Span::raw(input.as_str()),
            Span::styled("_", Style::default().fg(Color::Yellow).add_modifier(Modifier::SLOW_BLINK)),
            Span::raw("  [Enter] Apply  [Esc] Cancel"),
        ]
    } else {
        vec![
            Span::styled(" [q]", Style::default().fg(Color::Yellow)),
            Span::raw("Quit "),
            Span::styled("[s]", Style::default().fg(Color::Yellow)),
            Span::raw("Sort "),
            Span::styled("[/]", Style::default().fg(Color::Yellow)),
            Span::raw("Filter "),
            Span::styled("[Enter]", Style::default().fg(Color::Yellow)),
            Span::raw("Expand "),
            Span::styled("[Tab]", Style::default().fg(Color::Yellow)),
            Span::raw(format!("View:{} ", app.view_mode.label())),
            Span::raw(format!(" Sort:{}", app.sort_by.label())),
            if let Some(ref filter) = app.filter {
                Span::styled(
                    format!("  Filter:\"{}\"", filter),
                    Style::default().fg(Color::Magenta),
                )
            } else {
                Span::raw("")
            },
        ]
    };

    let line = Line::from(spans);
    let paragraph = Paragraph::new(line);
    f.render_widget(paragraph, area);
}
