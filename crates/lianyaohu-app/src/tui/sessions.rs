//! Inline session manager: lists background sessions with live activity
//! (working/idle, attached clients), and drives attach, kill, and new-session
//! actions. Drawn in place like the quick-pick so it can repeatedly hand the
//! terminal to an attach and reappear cleanly afterwards.

use std::path::Path;
use std::time::{Duration, Instant};

use lianyaohu_core::Result;
use ratatui::Frame;
use ratatui::crossterm::event::{self, Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use ratatui::layout::{Constraint, Layout};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, List, ListItem, ListState, Paragraph};

use crate::session::{self, Activity, SessionEntry, classify_activity};

use super::{TerminalGuard, theme};

const TICK: Duration = Duration::from_secs(1);

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SessionManagerOutcome {
    Attach(String),
    NewSession,
    Quit,
}

/// One session as the picker shows it; derived from a `SessionEntry` at
/// refresh time so `draw` stays a pure function of the model.
struct Row {
    name: String,
    activity: Activity,
    attached: bool,
    uptime_secs: u64,
    vpn_interface: String,
    command: String,
    cwd: String,
}

impl Row {
    fn from_entry(entry: &SessionEntry, now: u64) -> Self {
        Self {
            name: entry.meta.name.clone(),
            activity: classify_activity(now, entry.status.as_ref()),
            attached: entry
                .status
                .map(|status| status.clients > 0)
                .unwrap_or(false),
            uptime_secs: now.saturating_sub(entry.meta.started_at),
            vpn_interface: entry.meta.vpn_interface.clone(),
            command: entry.meta.command.join(" "),
            cwd: entry.meta.cwd.clone(),
        }
    }
}

/// Pure picker state; `update` and `draw` never touch the terminal, so tests
/// drive them directly.
struct Model {
    rows: Vec<Row>,
    selected: usize,
    /// Session name awaiting `y` confirmation before a kill.
    confirm_kill: Option<String>,
    /// Result of the last action (kill outcome, launch failure).
    message: Option<String>,
}

enum Step {
    Continue,
    Redraw,
    Done(SessionManagerOutcome),
    Kill(String),
    RefreshNow,
}

impl Model {
    fn new(rows: Vec<Row>, message: Option<String>) -> Self {
        Self {
            rows,
            selected: 0,
            confirm_kill: None,
            message,
        }
    }

    fn selected_name(&self) -> Option<&str> {
        self.rows.get(self.selected).map(|row| row.name.as_str())
    }

    fn update(&mut self, key: KeyEvent) -> Step {
        if key.kind != KeyEventKind::Press {
            return Step::Continue;
        }
        if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('c') {
            return Step::Done(SessionManagerOutcome::Quit);
        }
        // A pending kill captures the next key: only `y` proceeds.
        if let Some(name) = self.confirm_kill.take() {
            return match key.code {
                KeyCode::Char('y') | KeyCode::Char('Y') => Step::Kill(name),
                _ => Step::Redraw,
            };
        }
        match key.code {
            KeyCode::Up | KeyCode::Char('k') => {
                if self.rows.is_empty() {
                    return Step::Continue;
                }
                self.selected = self.selected.checked_sub(1).unwrap_or(self.rows.len() - 1);
                Step::Redraw
            }
            KeyCode::Down | KeyCode::Char('j') => {
                if self.rows.is_empty() {
                    return Step::Continue;
                }
                self.selected = (self.selected + 1) % self.rows.len();
                Step::Redraw
            }
            KeyCode::Enter => match self.selected_name() {
                Some(name) => Step::Done(SessionManagerOutcome::Attach(name.to_string())),
                None => Step::Continue,
            },
            KeyCode::Char(digit @ '1'..='9') => {
                let index = digit as usize - '1' as usize;
                match self.rows.get(index) {
                    Some(row) => Step::Done(SessionManagerOutcome::Attach(row.name.clone())),
                    None => Step::Continue,
                }
            }
            KeyCode::Char('x') => {
                self.confirm_kill = self.selected_name().map(str::to_string);
                if self.confirm_kill.is_some() {
                    Step::Redraw
                } else {
                    Step::Continue
                }
            }
            KeyCode::Char('n') => Step::Done(SessionManagerOutcome::NewSession),
            KeyCode::Char('r') => Step::RefreshNow,
            KeyCode::Esc | KeyCode::Char('q') => Step::Done(SessionManagerOutcome::Quit),
            _ => Step::Continue,
        }
    }

    /// Replaces the rows with a fresh listing, keeping the selection pinned
    /// to the same session name when it still exists.
    fn refresh(&mut self, rows: Vec<Row>) {
        let current = self.selected_name().map(str::to_string);
        self.selected = current
            .and_then(|name| rows.iter().position(|row| row.name == name))
            .unwrap_or(0);
        self.rows = rows;
        if self.selected >= self.rows.len() {
            self.selected = 0;
        }
        // A vanished session invalidates its pending kill prompt.
        if let Some(name) = &self.confirm_kill
            && !self.rows.iter().any(|row| row.name == *name)
        {
            self.confirm_kill = None;
        }
    }

    fn status_line(&self) -> Line<'static> {
        if let Some(name) = &self.confirm_kill {
            return Line::from(Span::styled(
                format!("kill session {name}? y/N"),
                theme::warn_style(),
            ));
        }
        if let Some(message) = &self.message {
            return Line::from(Span::styled(message.clone(), theme::warn_style()));
        }
        theme::keybar_line(&[
            ("Enter", "attach"),
            ("n", "new"),
            ("x", "kill"),
            ("r", "refresh"),
            ("q", "quit"),
        ])
    }
}

fn format_uptime(seconds: u64) -> String {
    if seconds >= 3600 {
        format!("{}h{:02}m", seconds / 3600, (seconds % 3600) / 60)
    } else if seconds >= 60 {
        format!("{}m{:02}s", seconds / 60, seconds % 60)
    } else {
        format!("{seconds}s")
    }
}

fn activity_span(row: &Row) -> Span<'static> {
    match row.activity {
        Activity::Working => Span::styled("[working]", theme::up_style()),
        Activity::Idle => Span::styled("[idle]   ", theme::dim_style()),
    }
}

fn draw(frame: &mut Frame, model: &Model) {
    let [title_area, body_area, keybar_area] = Layout::vertical([
        Constraint::Length(1),
        Constraint::Min(3),
        Constraint::Length(1),
    ])
    .areas(frame.area());

    frame.render_widget(
        Paragraph::new(Line::from(vec![
            Span::styled(
                format!("Sessions — {} running", model.rows.len()),
                Style::new().add_modifier(Modifier::BOLD),
            ),
            Span::styled("  (1-9 attaches instantly)", theme::dim_style()),
        ])),
        title_area,
    );

    if model.rows.is_empty() {
        frame.render_widget(
            Paragraph::new(Line::from(Span::styled(
                "no running sessions — n starts one, q quits",
                theme::dim_style(),
            )))
            .block(Block::bordered()),
            body_area,
        );
    } else {
        let items: Vec<ListItem> = model
            .rows
            .iter()
            .enumerate()
            .map(|(offset, row)| {
                let mut spans = vec![
                    Span::raw(format!("{}. {:<20} ", offset + 1, row.name)),
                    activity_span(row),
                    Span::raw(format!(
                        " {:>7}  {:<8} ",
                        format_uptime(row.uptime_secs),
                        row.vpn_interface
                    )),
                ];
                if row.attached {
                    spans.push(Span::styled("attached ", theme::key_style()));
                }
                spans.push(Span::styled(
                    format!("{} ({})", row.command, row.cwd),
                    theme::dim_style(),
                ));
                ListItem::new(Line::from(spans))
            })
            .collect();
        let mut list_state = ListState::default().with_selected(Some(model.selected));
        frame.render_stateful_widget(
            List::new(items)
                .block(Block::bordered())
                .highlight_style(Style::new().add_modifier(Modifier::REVERSED))
                .highlight_symbol("> "),
            body_area,
            &mut list_state,
        );
    }

    frame.render_widget(Paragraph::new(model.status_line()), keybar_area);
}

fn load_rows(dir: &Path) -> Result<Vec<Row>> {
    let now = session::unix_now();
    Ok(session::list_sessions(dir)?
        .iter()
        .map(|entry| Row::from_entry(entry, now))
        .collect())
}

/// Runs the inline session manager. The caller has already checked that
/// stdin/stdout are a TTY; an optional message (e.g. a launch failure from a
/// previous round) is shown in the status line until the next action.
pub fn session_manager(dir: &Path, message: Option<String>) -> Result<SessionManagerOutcome> {
    let rows = load_rows(dir)?;
    let height = ((rows.len() as u16) + 5).clamp(8, 16);
    let mut model = Model::new(rows, message);

    let mut guard = TerminalGuard::inline(height)?;
    let outcome = run_loop(&mut guard, &mut model, dir);
    guard.clear();
    outcome
}

fn run_loop(
    guard: &mut TerminalGuard,
    model: &mut Model,
    dir: &Path,
) -> Result<SessionManagerOutcome> {
    let mut next_tick = Instant::now() + TICK;
    guard.terminal.draw(|frame| draw(frame, model))?;
    loop {
        let timeout = next_tick.saturating_duration_since(Instant::now());
        if event::poll(timeout)? {
            match event::read()? {
                Event::Key(key) => match model.update(key) {
                    Step::Continue => {}
                    Step::Redraw => {
                        guard.terminal.draw(|frame| draw(frame, model))?;
                    }
                    Step::Done(outcome) => return Ok(outcome),
                    Step::Kill(name) => {
                        let socket = session::socket_path(dir, &name);
                        model.message = Some(match session::client::kill(&socket, &name) {
                            Ok(Some(code)) => format!("session {name} exited with status {code}"),
                            Ok(None) => format!("kill requested for {name}"),
                            Err(_) => {
                                session::remove_session_files(dir, &name);
                                format!("session {name} was already gone; cleaned up")
                            }
                        });
                        model.refresh(load_rows(dir)?);
                        guard.terminal.draw(|frame| draw(frame, model))?;
                    }
                    Step::RefreshNow => {
                        model.refresh(load_rows(dir)?);
                        guard.terminal.draw(|frame| draw(frame, model))?;
                    }
                },
                Event::Resize(..) => {
                    guard.terminal.draw(|frame| draw(frame, model))?;
                }
                _ => {}
            }
        } else {
            next_tick = Instant::now() + TICK;
            model.refresh(load_rows(dir)?);
            guard.terminal.draw(|frame| draw(frame, model))?;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ratatui::Terminal;
    use ratatui::backend::TestBackend;

    fn row(name: &str, activity: Activity, attached: bool) -> Row {
        Row {
            name: name.to_string(),
            activity,
            attached,
            uptime_secs: 75,
            vpn_interface: "utun5".to_string(),
            command: "claude".to_string(),
            cwd: "/src/repo".to_string(),
        }
    }

    fn sample_model() -> Model {
        Model::new(
            vec![
                row("alpha", Activity::Working, true),
                row("beta", Activity::Idle, false),
            ],
            None,
        )
    }

    fn press(code: KeyCode) -> KeyEvent {
        KeyEvent::new(code, KeyModifiers::NONE)
    }

    #[test]
    fn navigation_wraps_and_attaches() {
        let mut model = sample_model();
        assert!(matches!(model.update(press(KeyCode::Down)), Step::Redraw));
        assert_eq!(model.selected, 1);
        assert!(matches!(model.update(press(KeyCode::Down)), Step::Redraw));
        assert_eq!(model.selected, 0);
        assert!(matches!(model.update(press(KeyCode::Up)), Step::Redraw));
        assert_eq!(model.selected, 1);

        match model.update(press(KeyCode::Enter)) {
            Step::Done(SessionManagerOutcome::Attach(name)) => assert_eq!(name, "beta"),
            _ => panic!("expected attach"),
        }
        match model.update(press(KeyCode::Char('1'))) {
            Step::Done(SessionManagerOutcome::Attach(name)) => assert_eq!(name, "alpha"),
            _ => panic!("expected digit attach"),
        }
        assert!(matches!(
            model.update(press(KeyCode::Char('9'))),
            Step::Continue
        ));
    }

    #[test]
    fn kill_requires_confirmation() {
        let mut model = sample_model();
        assert!(matches!(
            model.update(press(KeyCode::Char('x'))),
            Step::Redraw
        ));
        assert_eq!(model.confirm_kill.as_deref(), Some("alpha"));
        match model.update(press(KeyCode::Char('y'))) {
            Step::Kill(name) => assert_eq!(name, "alpha"),
            _ => panic!("expected kill"),
        }
        assert!(model.confirm_kill.is_none());

        // Any other key cancels the pending kill.
        assert!(matches!(
            model.update(press(KeyCode::Char('x'))),
            Step::Redraw
        ));
        assert!(matches!(model.update(press(KeyCode::Esc)), Step::Redraw));
        assert!(model.confirm_kill.is_none());
        assert!(matches!(
            model.update(press(KeyCode::Esc)),
            Step::Done(SessionManagerOutcome::Quit)
        ));
    }

    #[test]
    fn new_refresh_and_quit_paths() {
        let mut model = sample_model();
        assert!(matches!(
            model.update(press(KeyCode::Char('n'))),
            Step::Done(SessionManagerOutcome::NewSession)
        ));
        let mut model = sample_model();
        assert!(matches!(
            model.update(press(KeyCode::Char('r'))),
            Step::RefreshNow
        ));
        assert!(matches!(
            model.update(press(KeyCode::Char('q'))),
            Step::Done(SessionManagerOutcome::Quit)
        ));
        let mut model = sample_model();
        let ctrl_c = KeyEvent::new(KeyCode::Char('c'), KeyModifiers::CONTROL);
        assert!(matches!(
            model.update(ctrl_c),
            Step::Done(SessionManagerOutcome::Quit)
        ));
    }

    #[test]
    fn empty_list_ignores_selection_keys() {
        let mut model = Model::new(Vec::new(), None);
        assert!(matches!(model.update(press(KeyCode::Down)), Step::Continue));
        assert!(matches!(
            model.update(press(KeyCode::Enter)),
            Step::Continue
        ));
        assert!(matches!(
            model.update(press(KeyCode::Char('x'))),
            Step::Continue
        ));
        assert!(matches!(
            model.update(press(KeyCode::Char('n'))),
            Step::Done(SessionManagerOutcome::NewSession)
        ));
    }

    #[test]
    fn refresh_pins_selection_by_name_and_clamps() {
        let mut model = sample_model();
        model.selected = 1; // beta
        model.refresh(vec![
            row("beta", Activity::Idle, false),
            row("gamma", Activity::Working, false),
        ]);
        assert_eq!(model.selected, 0);
        assert_eq!(model.selected_name(), Some("beta"));

        // Vanished selection falls back to the top; empty listing clamps.
        model.selected = 1;
        model.refresh(vec![row("delta", Activity::Idle, false)]);
        assert_eq!(model.selected, 0);
        model.refresh(Vec::new());
        assert_eq!(model.selected_name(), None);

        // A pending kill for a vanished session is dropped.
        let mut model = sample_model();
        model.update(press(KeyCode::Char('x')));
        assert!(model.confirm_kill.is_some());
        model.refresh(vec![row("beta", Activity::Idle, false)]);
        assert!(model.confirm_kill.is_none());
    }

    fn render(model: &Model) -> String {
        let backend = TestBackend::new(100, 10);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal.draw(|frame| draw(frame, model)).unwrap();
        let buffer = terminal.backend().buffer().clone();
        let mut rendered = String::new();
        for y in 0..buffer.area.height {
            for x in 0..buffer.area.width {
                rendered.push_str(buffer[(x, y)].symbol());
            }
            rendered.push('\n');
        }
        rendered
    }

    #[test]
    fn draw_renders_rows_status_and_keybar() {
        let model = sample_model();
        let rendered = render(&model);
        assert!(rendered.contains("Sessions — 2 running"), "{rendered}");
        assert!(rendered.contains("1. alpha"), "{rendered}");
        assert!(rendered.contains("[working]"), "{rendered}");
        assert!(rendered.contains("[idle]"), "{rendered}");
        assert!(rendered.contains("attached"), "{rendered}");
        assert!(rendered.contains("1m15s"), "{rendered}");
        assert!(rendered.contains("utun5"), "{rendered}");
        assert!(rendered.contains("claude (/src/repo)"), "{rendered}");
        assert!(rendered.contains("Enter attach"), "{rendered}");
    }

    #[test]
    fn draw_renders_confirm_message_and_empty_state() {
        let mut model = sample_model();
        model.update(press(KeyCode::Char('x')));
        let rendered = render(&model);
        assert!(rendered.contains("kill session alpha? y/N"), "{rendered}");

        let model = Model::new(Vec::new(), Some("launch failed: boom".to_string()));
        let rendered = render(&model);
        assert!(rendered.contains("Sessions — 0 running"), "{rendered}");
        assert!(rendered.contains("no running sessions"), "{rendered}");
        assert!(rendered.contains("launch failed: boom"), "{rendered}");
    }
}
