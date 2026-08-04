//! Inline VPN interface picker: a list pane with a live detail pane, drawn in
//! place (no alternate screen), refreshing interface state on a timer so a
//! VPN coming up or down is visible without keypresses.

use std::time::{Duration, Instant};

use lianyaohu_core::interfaces::{NetworkInterface, vpn_interfaces};
use lianyaohu_core::route;
use lianyaohu_core::{Result, err};
use ratatui::Frame;
use ratatui::crossterm::event::{self, Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use ratatui::layout::{Constraint, Layout};
use ratatui::style::{Modifier, Style};
use ratatui::text::Line;
use ratatui::widgets::{Block, List, ListItem, ListState, Paragraph};

use super::TerminalGuard;

const TICK: Duration = Duration::from_millis(500);
const VIEW_HEIGHT: u16 = 10;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum QuickPickOutcome {
    Chosen { name: String, save: bool },
    Cancelled,
}

/// Pure picker state; `update` and `draw` never touch the terminal, so tests
/// drive them directly.
struct Model {
    interfaces: Vec<NetworkInterface>,
    selected: usize,
    save: bool,
    default_route: Option<String>,
}

enum Step {
    Continue,
    Redraw,
    Done(QuickPickOutcome),
}

impl Model {
    fn new(interfaces: Vec<NetworkInterface>, default_route: Option<String>) -> Self {
        Self {
            interfaces,
            selected: 0,
            save: false,
            default_route,
        }
    }

    fn selected_interface(&self) -> &NetworkInterface {
        &self.interfaces[self.selected]
    }

    fn update(&mut self, key: KeyEvent) -> Step {
        if key.kind != KeyEventKind::Press {
            return Step::Continue;
        }
        if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('c') {
            return Step::Done(QuickPickOutcome::Cancelled);
        }
        match key.code {
            KeyCode::Up | KeyCode::Char('k') => {
                self.selected = self
                    .selected
                    .checked_sub(1)
                    .unwrap_or(self.interfaces.len() - 1);
                Step::Redraw
            }
            KeyCode::Down | KeyCode::Char('j') => {
                self.selected = (self.selected + 1) % self.interfaces.len();
                Step::Redraw
            }
            KeyCode::Enter => Step::Done(QuickPickOutcome::Chosen {
                name: self.selected_interface().name.clone(),
                save: self.save,
            }),
            KeyCode::Char('s') => {
                self.save = !self.save;
                Step::Redraw
            }
            KeyCode::Char(digit @ '1'..='9') => {
                let index = digit as usize - '1' as usize;
                if index < self.interfaces.len() {
                    self.selected = index;
                    Step::Done(QuickPickOutcome::Chosen {
                        name: self.selected_interface().name.clone(),
                        save: self.save,
                    })
                } else {
                    Step::Continue
                }
            }
            KeyCode::Esc | KeyCode::Char('q') => Step::Done(QuickPickOutcome::Cancelled),
            _ => Step::Continue,
        }
    }

    /// Replaces the interface list with a fresh enumeration, keeping the
    /// selection pinned to the same interface name when it still exists.
    fn refresh(&mut self, interfaces: Vec<NetworkInterface>, default_route: Option<String>) {
        if interfaces.is_empty() {
            return;
        }
        let current = self.selected_interface().name.clone();
        self.selected = interfaces
            .iter()
            .position(|interface| interface.name == current)
            .unwrap_or(0);
        self.interfaces = interfaces;
        self.default_route = default_route;
    }

    fn detail_lines(&self) -> Vec<String> {
        let interface = self.selected_interface();
        let state = match (interface.is_up(), interface.is_running()) {
            (true, true) => "UP, RUNNING".to_string(),
            (true, false) => "UP, not running".to_string(),
            _ => "DOWN".to_string(),
        };
        let ipv4 = if interface.ipv4_addresses.is_empty() {
            "—".to_string()
        } else if let Some(peer) = interface.ipv4_peer_addresses.first() {
            format!("{} -> {peer}", interface.ipv4_addresses.join(", "))
        } else {
            interface.ipv4_addresses.join(", ")
        };
        let ipv6 = if interface.ipv6_addresses.is_empty() {
            "—".to_string()
        } else {
            interface.ipv6_addresses.join(", ")
        };
        let default_route = match &self.default_route {
            Some(name) if *name == interface.name => "yes (matches)".to_string(),
            Some(name) => format!("no (default is {name})"),
            None => "unknown".to_string(),
        };
        vec![
            format!("state:         {state}"),
            format!("ipv4:          {ipv4}"),
            format!("ipv6:          {ipv6}"),
            format!("default route: {default_route}"),
        ]
    }

    fn keybar(&self) -> String {
        let save = if self.save {
            "[s] save as default: ON"
        } else {
            "[s] save as default: off"
        };
        format!("↑↓ select · Enter confirm · {save} · q cancel")
    }
}

fn draw(frame: &mut Frame, model: &Model) {
    let [title_area, body_area, keybar_area] = Layout::vertical([
        Constraint::Length(1),
        Constraint::Min(3),
        Constraint::Length(1),
    ])
    .areas(frame.area());
    let [list_area, detail_area] =
        Layout::horizontal([Constraint::Percentage(40), Constraint::Percentage(60)])
            .areas(body_area);

    frame.render_widget(
        Paragraph::new("Select VPN interface").style(Style::new().add_modifier(Modifier::BOLD)),
        title_area,
    );

    let items: Vec<ListItem> = model
        .interfaces
        .iter()
        .enumerate()
        .map(|(offset, interface)| {
            let state = if interface.is_up() && interface.is_running() {
                "up"
            } else {
                "down"
            };
            ListItem::new(format!("{}. {} [{state}]", offset + 1, interface.name))
        })
        .collect();
    let mut list_state = ListState::default().with_selected(Some(model.selected));
    frame.render_stateful_widget(
        List::new(items)
            .block(Block::bordered())
            .highlight_style(Style::new().add_modifier(Modifier::REVERSED))
            .highlight_symbol("> "),
        list_area,
        &mut list_state,
    );

    let detail: Vec<Line> = model.detail_lines().into_iter().map(Line::from).collect();
    frame.render_widget(
        Paragraph::new(detail)
            .block(Block::bordered().title(model.selected_interface().name.clone())),
        detail_area,
    );

    frame.render_widget(Paragraph::new(model.keybar()), keybar_area);
}

/// Runs the inline picker over the given interfaces. The caller has already
/// checked that stdin/stdout are a TTY and the list is non-empty.
pub fn quick_pick(interfaces: &[NetworkInterface]) -> Result<QuickPickOutcome> {
    if interfaces.is_empty() {
        return Err(err("no VPN interfaces to select"));
    }
    let default_route = route::default_ipv4_interface().unwrap_or(None);
    let mut model = Model::new(interfaces.to_vec(), default_route);

    let mut guard = TerminalGuard::inline(VIEW_HEIGHT)?;
    let outcome = run_loop(&mut guard, &mut model);
    guard.clear();
    outcome
}

fn run_loop(guard: &mut TerminalGuard, model: &mut Model) -> Result<QuickPickOutcome> {
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
                },
                Event::Resize(..) => {
                    guard.terminal.draw(|frame| draw(frame, model))?;
                }
                _ => {}
            }
        } else {
            next_tick = Instant::now() + TICK;
            if let Ok(interfaces) = vpn_interfaces() {
                let default_route = route::default_ipv4_interface().unwrap_or(None);
                model.refresh(interfaces, default_route);
                guard.terminal.draw(|frame| draw(frame, model))?;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ratatui::Terminal;
    use ratatui::backend::TestBackend;

    fn interface(name: &str, flags: u32, v4: &[&str], peer: &[&str]) -> NetworkInterface {
        NetworkInterface {
            name: name.to_string(),
            flags,
            ipv4_addresses: v4.iter().map(|s| s.to_string()).collect(),
            ipv4_peer_addresses: peer.iter().map(|s| s.to_string()).collect(),
            ipv6_addresses: Vec::new(),
        }
    }

    fn up_flags() -> u32 {
        (libc::IFF_UP | libc::IFF_RUNNING) as u32
    }

    fn sample_model() -> Model {
        Model::new(
            vec![
                interface("utun3", 0, &[], &[]),
                interface("utun5", up_flags(), &["10.7.0.2"], &["10.7.0.1"]),
            ],
            Some("utun5".to_string()),
        )
    }

    fn press(code: KeyCode) -> KeyEvent {
        KeyEvent::new(code, KeyModifiers::NONE)
    }

    #[test]
    fn navigation_wraps_and_selects() {
        let mut model = sample_model();
        assert!(matches!(model.update(press(KeyCode::Down)), Step::Redraw));
        assert_eq!(model.selected, 1);
        assert!(matches!(model.update(press(KeyCode::Down)), Step::Redraw));
        assert_eq!(model.selected, 0);
        assert!(matches!(model.update(press(KeyCode::Up)), Step::Redraw));
        assert_eq!(model.selected, 1);

        match model.update(press(KeyCode::Enter)) {
            Step::Done(QuickPickOutcome::Chosen { name, save }) => {
                assert_eq!(name, "utun5");
                assert!(!save);
            }
            _ => panic!("expected selection"),
        }
    }

    #[test]
    fn save_toggle_and_digit_selection() {
        let mut model = sample_model();
        assert!(matches!(
            model.update(press(KeyCode::Char('s'))),
            Step::Redraw
        ));
        match model.update(press(KeyCode::Char('2'))) {
            Step::Done(QuickPickOutcome::Chosen { name, save }) => {
                assert_eq!(name, "utun5");
                assert!(save);
            }
            _ => panic!("expected digit selection"),
        }
        // Out-of-range digits are ignored.
        let mut model = sample_model();
        assert!(matches!(
            model.update(press(KeyCode::Char('9'))),
            Step::Continue
        ));
    }

    #[test]
    fn cancel_paths() {
        let mut model = sample_model();
        assert!(matches!(
            model.update(press(KeyCode::Esc)),
            Step::Done(QuickPickOutcome::Cancelled)
        ));
        let mut model = sample_model();
        assert!(matches!(
            model.update(press(KeyCode::Char('q'))),
            Step::Done(QuickPickOutcome::Cancelled)
        ));
        let mut model = sample_model();
        let ctrl_c = KeyEvent::new(KeyCode::Char('c'), KeyModifiers::CONTROL);
        assert!(matches!(
            model.update(ctrl_c),
            Step::Done(QuickPickOutcome::Cancelled)
        ));
    }

    #[test]
    fn refresh_keeps_selection_by_name() {
        let mut model = sample_model();
        model.selected = 1; // utun5
        model.refresh(
            vec![
                interface("utun1", up_flags(), &[], &[]),
                interface("utun4", 0, &[], &[]),
                interface("utun5", up_flags(), &["10.7.0.2"], &["10.7.0.1"]),
            ],
            None,
        );
        assert_eq!(model.selected, 2);
        assert_eq!(model.selected_interface().name, "utun5");

        // A vanished selection falls back to the top; an empty refresh is
        // ignored entirely.
        model.refresh(vec![interface("utun9", 0, &[], &[])], None);
        assert_eq!(model.selected, 0);
        model.refresh(Vec::new(), None);
        assert_eq!(model.selected_interface().name, "utun9");
    }

    #[test]
    fn draw_renders_list_detail_and_keybar() {
        let model = sample_model();
        let backend = TestBackend::new(80, 10);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal.draw(|frame| draw(frame, &model)).unwrap();

        let mut rendered = String::new();
        let buffer = terminal.backend().buffer().clone();
        for y in 0..buffer.area.height {
            for x in 0..buffer.area.width {
                rendered.push_str(buffer[(x, y)].symbol());
            }
            rendered.push('\n');
        }

        assert!(rendered.contains("Select VPN interface"));
        assert!(rendered.contains("1. utun3 [down]"));
        assert!(rendered.contains("2. utun5 [up]"));
        assert!(rendered.contains("state:         DOWN"), "{rendered}");
        assert!(rendered.contains("save as default: off"));

        // Selecting the up interface shows its addresses and route match.
        let mut model = sample_model();
        model.selected = 1;
        model.save = true;
        terminal.draw(|frame| draw(frame, &model)).unwrap();
        let buffer = terminal.backend().buffer().clone();
        let mut rendered = String::new();
        for y in 0..buffer.area.height {
            for x in 0..buffer.area.width {
                rendered.push_str(buffer[(x, y)].symbol());
            }
            rendered.push('\n');
        }
        assert!(rendered.contains("10.7.0.2 -> 10.7.0.1"), "{rendered}");
        assert!(rendered.contains("yes (matches)"));
        assert!(rendered.contains("save as default: ON"));
    }
}
