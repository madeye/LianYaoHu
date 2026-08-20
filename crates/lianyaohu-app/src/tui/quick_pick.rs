//! Inline VPN interface picker: a list pane with a live detail pane, drawn in
//! place (no alternate screen), refreshing interface state on a timer so a
//! VPN coming up or down is visible without keypresses.

use std::time::{Duration, Instant};

use lianyaohu_core::Result;
use lianyaohu_core::interfaces::{NetworkInterface, vpn_interfaces};
use lianyaohu_core::route;
use ratatui::Frame;
use ratatui::crossterm::event::{self, Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use ratatui::layout::{Constraint, Layout};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, List, ListItem, ListState, Paragraph};

use super::{TerminalGuard, theme};

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
    egress: route::Ipv4Egress,
}

enum Step {
    Continue,
    Redraw,
    Done(QuickPickOutcome),
}

impl Model {
    /// The picker always appends the synthetic "none" (proxy-only) entry, so
    /// selection works even with no VPN interface up at all.
    fn new(mut interfaces: Vec<NetworkInterface>, egress: route::Ipv4Egress) -> Self {
        interfaces.push(NetworkInterface::proxy_only());
        Self {
            interfaces,
            selected: 0,
            save: false,
            egress,
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

    /// Replaces the interface list with a fresh enumeration (plus the
    /// synthetic "none" entry), keeping the selection pinned to the same
    /// interface name when it still exists.
    fn refresh(&mut self, mut interfaces: Vec<NetworkInterface>, egress: route::Ipv4Egress) {
        interfaces.push(NetworkInterface::proxy_only());
        let current = self.selected_interface().name.clone();
        self.selected = interfaces
            .iter()
            .position(|interface| interface.name == current)
            .unwrap_or(0);
        self.interfaces = interfaces;
        self.egress = egress;
    }

    fn detail_lines(&self) -> Vec<String> {
        super::interface_detail_lines(self.selected_interface(), &self.egress)
    }

    fn keybar(&self) -> Line<'static> {
        let mut line = theme::keybar_line(&[("↑↓", "select"), ("Enter", "confirm")]);
        line.push_span(Span::styled(" · ", theme::dim_style()));
        line.push_span(Span::styled("s", theme::key_style()));
        if self.save {
            line.push_span(Span::styled(" save as default: ON", theme::success_style()));
        } else {
            line.push_span(Span::styled(" save as default: off", theme::dim_style()));
        }
        line.push_span(Span::styled(" · ", theme::dim_style()));
        line.push_span(Span::styled("q", theme::key_style()));
        line.push_span(Span::styled(" cancel", theme::dim_style()));
        line
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
        Paragraph::new(Line::from(vec![
            Span::styled(
                "Select VPN interface",
                Style::new().add_modifier(Modifier::BOLD),
            ),
            Span::styled("  (1-9 picks instantly)", theme::dim_style()),
        ])),
        title_area,
    );

    let items: Vec<ListItem> = model
        .interfaces
        .iter()
        .enumerate()
        .map(|(offset, interface)| {
            let state = if interface.is_proxy_only() {
                Span::styled("[proxy-only]", theme::dim_style())
            } else {
                theme::state_span(interface.is_up() && interface.is_running())
            };
            ListItem::new(Line::from(vec![
                Span::raw(format!("{}. {} ", offset + 1, interface.name)),
                state,
            ]))
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

/// Runs the inline picker over the given interfaces (the synthetic "none"
/// proxy-only entry is always offered, so an empty list is fine). The caller
/// has already checked that stdin/stdout are a TTY.
pub fn quick_pick(interfaces: &[NetworkInterface]) -> Result<QuickPickOutcome> {
    let egress = route::query_ipv4_egress().unwrap_or_default();
    let mut model = Model::new(interfaces.to_vec(), egress);

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
                let egress = route::query_ipv4_egress().unwrap_or_default();
                model.refresh(interfaces, egress);
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

    fn egress_all(name: &str) -> route::Ipv4Egress {
        route::Ipv4Egress {
            default_interfaces: vec![name.to_string()],
            low_half: Some(name.to_string()),
            high_half: Some(name.to_string()),
        }
    }

    fn sample_model() -> Model {
        Model::new(
            vec![
                interface("utun3", 0, &[], &[]),
                interface("utun5", up_flags(), &["10.7.0.2"], &["10.7.0.1"]),
            ],
            egress_all("utun5"),
        )
    }

    fn press(code: KeyCode) -> KeyEvent {
        KeyEvent::new(code, KeyModifiers::NONE)
    }

    #[test]
    fn navigation_wraps_and_selects() {
        // Two real interfaces plus the always-present "none" entry.
        let mut model = sample_model();
        assert_eq!(model.interfaces.len(), 3);
        assert!(matches!(model.update(press(KeyCode::Down)), Step::Redraw));
        assert_eq!(model.selected, 1);
        assert!(matches!(model.update(press(KeyCode::Down)), Step::Redraw));
        assert_eq!(model.selected, 2);
        assert_eq!(model.selected_interface().name, "none");
        assert!(matches!(model.update(press(KeyCode::Down)), Step::Redraw));
        assert_eq!(model.selected, 0);
        assert!(matches!(model.update(press(KeyCode::Up)), Step::Redraw));
        assert_eq!(model.selected, 2);

        model.selected = 1;
        match model.update(press(KeyCode::Enter)) {
            Step::Done(QuickPickOutcome::Chosen { name, save }) => {
                assert_eq!(name, "utun5");
                assert!(!save);
            }
            _ => panic!("expected selection"),
        }
    }

    #[test]
    fn none_entry_selects_proxy_only_mode() {
        let mut model = Model::new(Vec::new(), route::Ipv4Egress::default());
        assert_eq!(model.interfaces.len(), 1);
        match model.update(press(KeyCode::Enter)) {
            Step::Done(QuickPickOutcome::Chosen { name, .. }) => assert_eq!(name, "none"),
            _ => panic!("expected proxy-only selection"),
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
            route::Ipv4Egress::default(),
        );
        assert_eq!(model.selected, 2);
        assert_eq!(model.selected_interface().name, "utun5");

        // A vanished selection falls back to the top; an empty refresh still
        // offers the proxy-only entry.
        model.refresh(vec![interface("utun9", 0, &[], &[])], Default::default());
        assert_eq!(model.selected, 0);
        model.refresh(Vec::new(), Default::default());
        assert_eq!(model.selected_interface().name, "none");
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
        assert!(rendered.contains("3. none [proxy-only]"));
        assert!(rendered.contains("state:        DOWN"), "{rendered}");
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
        assert!(rendered.contains("yes (carries IPv4 egress)"), "{rendered}");
        assert!(rendered.contains("save as default: ON"));
    }
}
