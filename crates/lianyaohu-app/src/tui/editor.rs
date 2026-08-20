//! Full-screen configuration editor (`lyh config` / `lyh setup`).
//!
//! Elm-style: `Editor` is pure state, `update` consumes key events and never
//! touches the terminal, `draw` renders from state — both are unit-tested
//! directly. The run loop owns the terminal through `TerminalGuard`, so the
//! shell is restored on quit and on panic alike.
//!
//! Scope model: every edit lands in either the global draft
//! (`~/.config/lianyaohu/config.toml`) or the project draft
//! (`.lianyaohu.toml`), toggled per session with `s`. The VPN interface is
//! the exception — it is machine-specific, so it always writes to the global
//! draft (project files reject `[defaults]`). Saving the project file also
//! records its hash in the trust store: editing your own project file is
//! consent.

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use lianyaohu_core::config::{self, ConfigFile, PROJECT_FILE_NAME, expand_tilde, trust};
use lianyaohu_core::env_policy::{NO_PROXY_KEYS, NO_PROXY_VALUE, PROXY_ENV_KEYS};
use lianyaohu_core::interfaces::{NetworkInterface, vpn_interfaces};
use lianyaohu_core::policy::{DestRule, LAN4_BLOCKED, LAN6_BLOCKED, lexically_normalized_absolute};
use lianyaohu_core::route;
use lianyaohu_core::{Result, err};
use ratatui::Frame;
use ratatui::crossterm::event::{self, Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Clear, List, ListItem, ListState, Paragraph, Wrap};

use super::{TerminalGuard, theme};

const TICK: Duration = Duration::from_millis(500);

/// Sensitive locations offered as one-key deny toggles.
const SENSITIVE_PRESETS: &[(&str, &str)] = &[
    ("~/.ssh", "SSH keys"),
    ("~/.aws", "AWS credentials"),
    ("~/.gnupg", "GnuPG keys"),
    ("~/.kube", "Kubernetes credentials"),
    ("~/.docker", "Docker credentials"),
    ("~/.netrc", "netrc passwords"),
    ("~/.config/gcloud", "Google Cloud credentials"),
    ("~/Library/Keychains", "macOS keychains"),
];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Scope {
    Global,
    Project,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Screen {
    Home,
    Interface,
    Proxy,
    Network,
    Paths,
    Presets,
    Review,
}

const HOME_MENU: &[(Screen, &str)] = &[
    (Screen::Interface, "VPN interface"),
    (Screen::Proxy, "HTTP proxy"),
    (Screen::Network, "Network rules"),
    (Screen::Paths, "File paths"),
    (Screen::Presets, "Sensitive paths"),
    (Screen::Review, "Review & save"),
];

/// Which list an active text input feeds. Network pane order: allow, deny,
/// lan_allow. Path pane order: writable, read_only. `Proxy` is not a list:
/// it fans out into the standard proxy environment variables.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum InputTarget {
    Network { pane: usize, edit: Option<usize> },
    Path { pane: usize, edit: Option<usize> },
    DenyPath { edit: Option<usize> },
    Proxy,
}

#[derive(Clone, Debug)]
struct InputState {
    target: InputTarget,
    buffer: String,
    cursor: usize,
    error: Option<String>,
    /// Non-error feedback, e.g. the candidate list from an ambiguous Tab
    /// completion.
    hint: Option<String>,
}

impl InputState {
    fn new(target: InputTarget, buffer: String) -> Self {
        Self {
            target,
            cursor: buffer.len(),
            buffer,
            error: None,
            hint: None,
        }
    }
}

/// Readdir-based completion for the path inputs: completes the last component
/// against the (tilde-expanded) parent directory. Returns the new buffer and
/// an optional candidate hint when the match is ambiguous.
fn complete_path(home: &str, buffer: &str) -> Option<(String, Option<String>)> {
    let position = buffer.rfind('/')?;
    let (dir_part, prefix) = buffer.split_at(position + 1);
    let expanded_dir = expand_tilde(dir_part, Path::new(home));
    if !expanded_dir.starts_with('/') {
        return None;
    }
    let entries = std::fs::read_dir(&expanded_dir).ok()?;
    let mut names: Vec<(String, bool)> = entries
        .flatten()
        .filter_map(|entry| {
            let name = entry.file_name().to_str()?.to_string();
            let is_dir = entry.file_type().ok().is_some_and(|kind| kind.is_dir());
            name.starts_with(prefix).then_some((name, is_dir))
        })
        .collect();
    // Shell convention: hidden entries only complete when explicitly asked.
    if !prefix.starts_with('.') {
        names.retain(|(name, _)| !name.starts_with('.'));
    }
    names.sort();
    match names.as_slice() {
        [] => None,
        [(name, is_dir)] => {
            let mut completed = format!("{dir_part}{name}");
            if *is_dir {
                completed.push('/');
            }
            Some((completed, None))
        }
        many => {
            let common = longest_common_prefix(many.iter().map(|(name, _)| name.as_str()));
            let hint = many
                .iter()
                .take(8)
                .map(|(name, _)| name.as_str())
                .collect::<Vec<_>>()
                .join("  ");
            Some((format!("{dir_part}{common}"), Some(hint)))
        }
    }
}

fn longest_common_prefix<'a>(mut names: impl Iterator<Item = &'a str>) -> String {
    let Some(first) = names.next() else {
        return String::new();
    };
    let mut common = first.to_string();
    for name in names {
        while !name.starts_with(&common) {
            common.pop();
        }
    }
    common
}

/// A deleted entry retained for one-shot undo, pinned to the scope and list
/// it came from so a scope switch cannot restore it into the wrong file.
#[derive(Clone, Debug, Eq, PartialEq)]
struct Deleted {
    scope: Scope,
    list: ListRef,
    index: usize,
    entry: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ListRef {
    NetworkAllow,
    NetworkDeny,
    NetworkLanAllow,
    PathWritable,
    PathReadOnly,
    PathDeny,
}

enum Step {
    Continue,
    Redraw,
    Quit,
}

/// Colors the status line: routine feedback stays plain, saves turn green,
/// warnings yellow, failures red.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum StatusKind {
    Info,
    Success,
    Warn,
    Error,
}

struct Editor {
    home_dir: String,
    xdg: Option<String>,
    global_path: PathBuf,
    project_path: PathBuf,
    project_exists: bool,
    global: ConfigFile,
    project: ConfigFile,
    global_on_disk: ConfigFile,
    project_on_disk: ConfigFile,
    scope: Scope,
    screen: Screen,
    menu_selected: usize,
    iface_selected: usize,
    interfaces: Vec<NetworkInterface>,
    egress: route::Ipv4Egress,
    net_pane: usize,
    net_selected: [usize; 3],
    path_pane: usize,
    path_selected: [usize; 2],
    preset_selected: usize,
    input: Option<InputState>,
    status: Option<(StatusKind, String)>,
    review_scroll: u16,
    help: bool,
    confirm_quit: bool,
    undo: Option<Deleted>,
}

impl Editor {
    fn list_mut(&mut self, scope: Scope, list: ListRef) -> &mut Vec<String> {
        let file = match scope {
            Scope::Global => &mut self.global,
            Scope::Project => &mut self.project,
        };
        match list {
            ListRef::NetworkAllow => &mut file.network.allow,
            ListRef::NetworkDeny => &mut file.network.deny,
            ListRef::NetworkLanAllow => &mut file.network.lan_allow,
            ListRef::PathWritable => &mut file.paths.writable,
            ListRef::PathReadOnly => &mut file.paths.read_only,
            ListRef::PathDeny => &mut file.paths.deny,
        }
    }

    fn record_delete(&mut self, list: ListRef, index: usize, entry: String) {
        self.set_status(format!("deleted {entry} — u to undo"));
        self.undo = Some(Deleted {
            scope: self.scope,
            list,
            index,
            entry,
        });
    }

    fn undo_delete(&mut self) -> Step {
        let Some(deleted) = self.undo.take() else {
            return Step::Continue;
        };
        let list = self.list_mut(deleted.scope, deleted.list);
        let index = deleted.index.min(list.len());
        list.insert(index, deleted.entry.clone());
        self.set_status(format!("restored {}", deleted.entry));
        Step::Redraw
    }
    fn scope_draft(&mut self) -> &mut ConfigFile {
        match self.scope {
            Scope::Global => &mut self.global,
            Scope::Project => &mut self.project,
        }
    }

    fn scope_view(&self) -> &ConfigFile {
        match self.scope {
            Scope::Global => &self.global,
            Scope::Project => &self.project,
        }
    }

    fn global_dirty(&self) -> bool {
        self.global != self.global_on_disk
    }

    fn project_dirty(&self) -> bool {
        self.project != self.project_on_disk
    }

    fn dirty(&self) -> bool {
        self.global_dirty() || self.project_dirty()
    }

    fn network_lists(&self) -> [&Vec<String>; 3] {
        let network = &self.scope_view().network;
        [&network.allow, &network.deny, &network.lan_allow]
    }

    fn path_lists(&self) -> [&Vec<String>; 2] {
        let paths = &self.scope_view().paths;
        [&paths.writable, &paths.read_only]
    }

    fn set_status(&mut self, message: impl Into<String>) {
        self.status = Some((StatusKind::Info, message.into()));
    }

    fn set_success(&mut self, message: impl Into<String>) {
        self.status = Some((StatusKind::Success, message.into()));
    }

    fn set_warn(&mut self, message: impl Into<String>) {
        self.status = Some((StatusKind::Warn, message.into()));
    }

    fn set_error(&mut self, message: impl Into<String>) {
        self.status = Some((StatusKind::Error, message.into()));
    }

    /// Test-facing accessor: assertions care about the text, not the color.
    #[cfg(test)]
    fn status_text(&self) -> Option<&str> {
        self.status.as_ref().map(|(_, text)| text.as_str())
    }

    /// The proxy URL currently configured in this scope's `[env]`, if any.
    fn proxy_url(&self) -> Option<String> {
        PROXY_ENV_KEYS
            .iter()
            .find_map(|key| self.scope_view().env.get(*key).cloned())
    }

    fn open_proxy_input(&mut self) {
        self.input = Some(InputState::new(
            InputTarget::Proxy,
            self.proxy_url().unwrap_or_default(),
        ));
    }

    /// Sets or clears the proxy environment variables in the scope draft.
    fn set_proxy(&mut self, url: Option<&str>) {
        let env = &mut self.scope_draft().env;
        match url {
            Some(url) => {
                for key in PROXY_ENV_KEYS {
                    env.insert((*key).to_string(), url.to_string());
                }
                for key in NO_PROXY_KEYS {
                    env.insert((*key).to_string(), NO_PROXY_VALUE.to_string());
                }
            }
            None => {
                for key in PROXY_ENV_KEYS.iter().chain(NO_PROXY_KEYS) {
                    env.remove(*key);
                }
            }
        }
    }

    /// Validates one input buffer for its target; `Ok` value is the
    /// normalized entry actually stored.
    fn validate_entry(&self, target: InputTarget, buffer: &str) -> Result<String> {
        let trimmed = buffer.trim();
        if trimmed.is_empty() && !matches!(target, InputTarget::Proxy) {
            return Err(err("entry is empty"));
        }
        match target {
            // Empty clears the proxy; otherwise scheme://host[:port].
            InputTarget::Proxy => {
                if trimmed.is_empty() {
                    return Ok(String::new());
                }
                lianyaohu_core::env_policy::validate_proxy_url(trimmed)
            }
            InputTarget::Network { pane, .. } => {
                let rule = DestRule::parse(trimmed)?;
                if pane == 2 {
                    let contained = LAN4_BLOCKED
                        .iter()
                        .chain(LAN6_BLOCKED.iter())
                        .any(|lan| lan.contains_network(&rule.net));
                    if !contained {
                        return Err(err("must be inside the blocked LAN ranges"));
                    }
                }
                Ok(rule.to_string())
            }
            InputTarget::Path { .. } | InputTarget::DenyPath { .. } => {
                let expanded = expand_tilde(trimmed, Path::new(&self.home_dir));
                lexically_normalized_absolute(&expanded)?;
                // Store the tilde form the user typed; expansion happens at
                // launch against the running user's home.
                Ok(trimmed.to_string())
            }
        }
    }

    fn commit_input(&mut self) -> Step {
        let Some(input) = self.input.clone() else {
            return Step::Continue;
        };
        match self.validate_entry(input.target, &input.buffer) {
            Err(error) => {
                if let Some(active) = &mut self.input {
                    active.error = Some(error.to_string());
                }
                Step::Redraw
            }
            Ok(entry) => {
                if matches!(input.target, InputTarget::Proxy) {
                    let url = (!entry.is_empty()).then_some(entry.as_str());
                    let cleared = url.is_none();
                    self.set_proxy(url);
                    self.input = None;
                    if cleared {
                        self.set_success("proxy cleared");
                    } else {
                        self.set_success(format!("proxy set to {entry}"));
                    }
                    return Step::Redraw;
                }
                let list: &mut Vec<String> = match input.target {
                    InputTarget::Network { pane, .. } => {
                        let network = &mut self.scope_draft().network;
                        match pane {
                            0 => &mut network.allow,
                            1 => &mut network.deny,
                            _ => &mut network.lan_allow,
                        }
                    }
                    InputTarget::Path { pane: 0, .. } => &mut self.scope_draft().paths.writable,
                    InputTarget::Path { .. } => &mut self.scope_draft().paths.read_only,
                    InputTarget::DenyPath { .. } => &mut self.scope_draft().paths.deny,
                    InputTarget::Proxy => unreachable!("handled above"),
                };
                let edit = match input.target {
                    InputTarget::Network { edit, .. }
                    | InputTarget::Path { edit, .. }
                    | InputTarget::DenyPath { edit } => edit,
                    InputTarget::Proxy => None,
                };
                match edit {
                    Some(index) if index < list.len() => list[index] = entry,
                    _ => {
                        if !list.contains(&entry) {
                            list.push(entry);
                        }
                    }
                }
                self.input = None;
                Step::Redraw
            }
        }
    }

    fn update_input(&mut self, key: KeyEvent) -> Step {
        let Some(input) = &mut self.input else {
            return Step::Continue;
        };
        match key.code {
            KeyCode::Esc => {
                self.input = None;
                Step::Redraw
            }
            KeyCode::Enter => self.commit_input(),
            KeyCode::Tab
                if matches!(
                    input.target,
                    InputTarget::Path { .. } | InputTarget::DenyPath { .. }
                ) =>
            {
                // Disjoint field borrows: `input` borrows self.input, the
                // completion only reads self.home_dir.
                if let Some((completed, hint)) = complete_path(&self.home_dir, &input.buffer) {
                    input.cursor = completed.len();
                    input.buffer = completed;
                    input.error = None;
                    input.hint = hint;
                }
                Step::Redraw
            }
            KeyCode::Backspace => {
                if input.cursor > 0 {
                    input.cursor -= 1;
                    input.buffer.remove(input.cursor);
                    input.error = None;
                    input.hint = None;
                }
                Step::Redraw
            }
            KeyCode::Left => {
                input.cursor = input.cursor.saturating_sub(1);
                Step::Redraw
            }
            KeyCode::Right => {
                input.cursor = (input.cursor + 1).min(input.buffer.len());
                Step::Redraw
            }
            KeyCode::Home => {
                input.cursor = 0;
                Step::Redraw
            }
            KeyCode::End => {
                input.cursor = input.buffer.len();
                Step::Redraw
            }
            KeyCode::Char(character) if key.modifiers.contains(KeyModifiers::CONTROL) => {
                match character {
                    'a' => input.cursor = 0,
                    'e' => input.cursor = input.buffer.len(),
                    // Kill to start of line.
                    'u' => {
                        input.buffer.drain(..input.cursor);
                        input.cursor = 0;
                        input.error = None;
                        input.hint = None;
                    }
                    // Delete the previous word; '/' counts as a boundary so
                    // path components can be trimmed one at a time.
                    'w' => {
                        let boundary = |byte: u8| byte == b' ' || byte == b'/';
                        let mut start = input.cursor;
                        while start > 0 && boundary(input.buffer.as_bytes()[start - 1]) {
                            start -= 1;
                        }
                        while start > 0 && !boundary(input.buffer.as_bytes()[start - 1]) {
                            start -= 1;
                        }
                        input.buffer.drain(start..input.cursor);
                        input.cursor = start;
                        input.error = None;
                        input.hint = None;
                    }
                    _ => return Step::Continue,
                }
                Step::Redraw
            }
            KeyCode::Char(character)
                if !key.modifiers.contains(KeyModifiers::CONTROL) && character.is_ascii() =>
            {
                input.buffer.insert(input.cursor, character);
                input.cursor += 1;
                input.error = None;
                input.hint = None;
                Step::Redraw
            }
            _ => Step::Continue,
        }
    }

    fn update(&mut self, key: KeyEvent) -> Step {
        if key.kind != KeyEventKind::Press {
            return Step::Continue;
        }
        // An active input line captures everything first.
        if self.input.is_some() {
            return self.update_input(key);
        }
        self.status = None;
        if self.help {
            self.help = false;
            return Step::Redraw;
        }
        if key.modifiers.contains(KeyModifiers::CONTROL) {
            return match key.code {
                KeyCode::Char('c') => Step::Quit,
                KeyCode::Char('s') => {
                    self.screen = Screen::Review;
                    self.review_scroll = 0;
                    Step::Redraw
                }
                _ => Step::Continue,
            };
        }
        if key.code == KeyCode::Char('?') {
            self.help = true;
            return Step::Redraw;
        }
        if key.code == KeyCode::Char('s') && self.screen != Screen::Review {
            self.scope = match self.scope {
                Scope::Global => Scope::Project,
                Scope::Project => Scope::Global,
            };
            return Step::Redraw;
        }
        if key.code == KeyCode::Char('u') {
            return self.undo_delete();
        }
        match self.screen {
            Screen::Home => self.update_home(key),
            Screen::Interface => self.update_interface(key),
            Screen::Proxy => self.update_proxy(key),
            Screen::Network => self.update_network(key),
            Screen::Paths => self.update_paths(key),
            Screen::Presets => self.update_presets(key),
            Screen::Review => self.update_review(key),
        }
    }

    fn leave_screen(&mut self) -> Step {
        if self.screen == Screen::Home {
            if self.dirty() && !self.confirm_quit {
                self.confirm_quit = true;
                self.set_warn(
                    "unsaved changes — Esc again to discard, or open Review & save (Ctrl-S)",
                );
                return Step::Redraw;
            }
            return Step::Quit;
        }
        self.screen = Screen::Home;
        Step::Redraw
    }

    fn update_home(&mut self, key: KeyEvent) -> Step {
        match key.code {
            KeyCode::Up | KeyCode::Char('k') => {
                self.menu_selected = self
                    .menu_selected
                    .checked_sub(1)
                    .unwrap_or(HOME_MENU.len() - 1);
                Step::Redraw
            }
            KeyCode::Down | KeyCode::Char('j') => {
                self.menu_selected = (self.menu_selected + 1) % HOME_MENU.len();
                Step::Redraw
            }
            KeyCode::Enter => {
                self.screen = HOME_MENU[self.menu_selected].0;
                self.confirm_quit = false;
                self.review_scroll = 0;
                Step::Redraw
            }
            KeyCode::Char(digit @ '1'..='9') => {
                let index = (digit as u8 - b'1') as usize;
                if index < HOME_MENU.len() {
                    self.menu_selected = index;
                    self.screen = HOME_MENU[index].0;
                    self.confirm_quit = false;
                    self.review_scroll = 0;
                    Step::Redraw
                } else {
                    Step::Continue
                }
            }
            KeyCode::Esc | KeyCode::Char('q') => self.leave_screen(),
            _ => Step::Continue,
        }
    }

    fn update_interface(&mut self, key: KeyEvent) -> Step {
        match key.code {
            KeyCode::Up | KeyCode::Char('k') if !self.interfaces.is_empty() => {
                self.iface_selected = self
                    .iface_selected
                    .checked_sub(1)
                    .unwrap_or(self.interfaces.len() - 1);
                Step::Redraw
            }
            KeyCode::Down | KeyCode::Char('j') if !self.interfaces.is_empty() => {
                self.iface_selected = (self.iface_selected + 1) % self.interfaces.len();
                Step::Redraw
            }
            KeyCode::Enter if !self.interfaces.is_empty() => {
                let selected = &self.interfaces[self.iface_selected];
                let name = selected.name.clone();
                let proxy_only = selected.is_proxy_only();
                // Machine-specific: always the global draft, never the project.
                self.global.defaults.vpn_interface = Some(name.clone());
                if proxy_only && self.proxy_url().is_none() {
                    self.set_success(
                        "default VPN interface set to none (global) — set a proxy URL",
                    );
                    self.open_proxy_input();
                } else {
                    self.set_success(format!("default VPN interface set to {name} (global)"));
                }
                Step::Redraw
            }
            KeyCode::Char('p') => {
                self.open_proxy_input();
                Step::Redraw
            }
            KeyCode::Esc | KeyCode::Char('q') => self.leave_screen(),
            _ => Step::Continue,
        }
    }

    fn update_proxy(&mut self, key: KeyEvent) -> Step {
        match key.code {
            KeyCode::Enter | KeyCode::Char('e') | KeyCode::Char('p') => {
                self.open_proxy_input();
                Step::Redraw
            }
            KeyCode::Char('d') | KeyCode::Delete => {
                if self.proxy_url().is_some() {
                    self.set_proxy(None);
                    self.set_success("proxy cleared");
                }
                Step::Redraw
            }
            KeyCode::Esc | KeyCode::Char('q') => self.leave_screen(),
            _ => Step::Continue,
        }
    }

    fn update_network(&mut self, key: KeyEvent) -> Step {
        let lengths: Vec<usize> = self.network_lists().iter().map(|list| list.len()).collect();
        match key.code {
            KeyCode::Tab | KeyCode::Right | KeyCode::Char('l') => {
                self.net_pane = (self.net_pane + 1) % 3;
                Step::Redraw
            }
            KeyCode::BackTab | KeyCode::Left | KeyCode::Char('h') => {
                self.net_pane = self.net_pane.checked_sub(1).unwrap_or(2);
                Step::Redraw
            }
            KeyCode::Up | KeyCode::Char('k') => {
                let length = lengths[self.net_pane];
                if length > 0 {
                    let selected = &mut self.net_selected[self.net_pane];
                    *selected = selected.checked_sub(1).unwrap_or(length - 1);
                }
                Step::Redraw
            }
            KeyCode::Down | KeyCode::Char('j') => {
                let length = lengths[self.net_pane];
                if length > 0 {
                    let selected = &mut self.net_selected[self.net_pane];
                    *selected = (*selected + 1) % length;
                }
                Step::Redraw
            }
            KeyCode::Char('a') => {
                self.input = Some(InputState::new(
                    InputTarget::Network {
                        pane: self.net_pane,
                        edit: None,
                    },
                    String::new(),
                ));
                Step::Redraw
            }
            KeyCode::Char('e') => {
                let index = self.net_selected[self.net_pane];
                if index < lengths[self.net_pane] {
                    let buffer = self.network_lists()[self.net_pane][index].clone();
                    self.input = Some(InputState::new(
                        InputTarget::Network {
                            pane: self.net_pane,
                            edit: Some(index),
                        },
                        buffer,
                    ));
                }
                Step::Redraw
            }
            KeyCode::Char('d') | KeyCode::Delete => {
                let pane = self.net_pane;
                let index = self.net_selected[pane];
                if index < lengths[pane] {
                    let list_ref = match pane {
                        0 => ListRef::NetworkAllow,
                        1 => ListRef::NetworkDeny,
                        _ => ListRef::NetworkLanAllow,
                    };
                    let scope = self.scope;
                    let list = self.list_mut(scope, list_ref);
                    let entry = list.remove(index);
                    let length = list.len();
                    if self.net_selected[pane] >= length && length > 0 {
                        self.net_selected[pane] = length - 1;
                    }
                    self.record_delete(list_ref, index, entry);
                }
                Step::Redraw
            }
            KeyCode::Char('m') => {
                let network = &mut self.scope_draft().network;
                use lianyaohu_core::policy::NetAction;
                let action = match network.default_action {
                    Some(NetAction::Deny) => None,
                    Some(NetAction::Allow) | None => Some(NetAction::Deny),
                };
                network.default_action = action;
                Step::Redraw
            }
            KeyCode::Char('p') => {
                self.open_proxy_input();
                Step::Redraw
            }
            KeyCode::Esc | KeyCode::Char('q') => self.leave_screen(),
            _ => Step::Continue,
        }
    }

    fn update_paths(&mut self, key: KeyEvent) -> Step {
        let lengths: Vec<usize> = self.path_lists().iter().map(|list| list.len()).collect();
        match key.code {
            KeyCode::Tab
            | KeyCode::BackTab
            | KeyCode::Left
            | KeyCode::Right
            | KeyCode::Char('h')
            | KeyCode::Char('l') => {
                self.path_pane = 1 - self.path_pane;
                Step::Redraw
            }
            KeyCode::Up | KeyCode::Char('k') => {
                let length = lengths[self.path_pane];
                if length > 0 {
                    let selected = &mut self.path_selected[self.path_pane];
                    *selected = selected.checked_sub(1).unwrap_or(length - 1);
                }
                Step::Redraw
            }
            KeyCode::Down | KeyCode::Char('j') => {
                let length = lengths[self.path_pane];
                if length > 0 {
                    let selected = &mut self.path_selected[self.path_pane];
                    *selected = (*selected + 1) % length;
                }
                Step::Redraw
            }
            KeyCode::Char('a') => {
                self.input = Some(InputState::new(
                    InputTarget::Path {
                        pane: self.path_pane,
                        edit: None,
                    },
                    String::new(),
                ));
                Step::Redraw
            }
            KeyCode::Char('e') => {
                let index = self.path_selected[self.path_pane];
                if index < lengths[self.path_pane] {
                    let buffer = self.path_lists()[self.path_pane][index].clone();
                    self.input = Some(InputState::new(
                        InputTarget::Path {
                            pane: self.path_pane,
                            edit: Some(index),
                        },
                        buffer,
                    ));
                }
                Step::Redraw
            }
            KeyCode::Char('d') | KeyCode::Delete => {
                let pane = self.path_pane;
                let index = self.path_selected[pane];
                if index < lengths[pane] {
                    let list_ref = if pane == 0 {
                        ListRef::PathWritable
                    } else {
                        ListRef::PathReadOnly
                    };
                    let scope = self.scope;
                    let list = self.list_mut(scope, list_ref);
                    let entry = list.remove(index);
                    let length = list.len();
                    if self.path_selected[pane] >= length && length > 0 {
                        self.path_selected[pane] = length - 1;
                    }
                    self.record_delete(list_ref, index, entry);
                }
                Step::Redraw
            }
            KeyCode::Char(' ') | KeyCode::Char('n') => {
                let paths = &mut self.scope_draft().paths;
                paths.narrow_home = match paths.narrow_home {
                    Some(true) => None,
                    _ => Some(true),
                };
                Step::Redraw
            }
            KeyCode::Esc | KeyCode::Char('q') => self.leave_screen(),
            _ => Step::Continue,
        }
    }

    /// Presets screen rows: the fixed catalog first, then any custom deny
    /// entries in the current scope.
    fn preset_rows(&self) -> usize {
        SENSITIVE_PRESETS.len() + self.custom_deny_entries().len()
    }

    fn custom_deny_entries(&self) -> Vec<String> {
        self.scope_view()
            .paths
            .deny
            .iter()
            .filter(|entry| {
                !SENSITIVE_PRESETS
                    .iter()
                    .any(|(preset, _)| preset == &entry.as_str())
            })
            .cloned()
            .collect()
    }

    fn update_presets(&mut self, key: KeyEvent) -> Step {
        let rows = self.preset_rows();
        match key.code {
            KeyCode::Up | KeyCode::Char('k') if rows > 0 => {
                self.preset_selected = self.preset_selected.checked_sub(1).unwrap_or(rows - 1);
                Step::Redraw
            }
            KeyCode::Down | KeyCode::Char('j') if rows > 0 => {
                self.preset_selected = (self.preset_selected + 1) % rows;
                Step::Redraw
            }
            KeyCode::Char(' ') | KeyCode::Enter => {
                if self.preset_selected < SENSITIVE_PRESETS.len() {
                    let preset = SENSITIVE_PRESETS[self.preset_selected].0.to_string();
                    let deny = &mut self.scope_draft().paths.deny;
                    if let Some(position) = deny.iter().position(|entry| *entry == preset) {
                        deny.remove(position);
                    } else {
                        deny.push(preset);
                    }
                }
                Step::Redraw
            }
            KeyCode::Char('a') => {
                self.input = Some(InputState::new(
                    InputTarget::DenyPath { edit: None },
                    String::new(),
                ));
                Step::Redraw
            }
            KeyCode::Char('d') | KeyCode::Delete => {
                if self.preset_selected >= SENSITIVE_PRESETS.len() {
                    let custom = self.custom_deny_entries();
                    let index = self.preset_selected - SENSITIVE_PRESETS.len();
                    if let Some(entry) = custom.get(index) {
                        let entry = entry.clone();
                        let scope = self.scope;
                        let deny = self.list_mut(scope, ListRef::PathDeny);
                        if let Some(position) = deny.iter().position(|existing| *existing == entry)
                        {
                            deny.remove(position);
                            self.record_delete(ListRef::PathDeny, position, entry);
                        }
                    }
                    let rows = self.preset_rows();
                    if self.preset_selected >= rows && rows > 0 {
                        self.preset_selected = rows - 1;
                    }
                }
                Step::Redraw
            }
            KeyCode::Esc | KeyCode::Char('q') => self.leave_screen(),
            _ => Step::Continue,
        }
    }

    fn max_review_scroll(&self) -> u16 {
        (review_lines(self).len().saturating_sub(1)) as u16
    }

    fn scroll_review(&mut self, delta: i32) -> Step {
        let scrolled = (i32::from(self.review_scroll) + delta)
            .clamp(0, i32::from(self.max_review_scroll())) as u16;
        self.review_scroll = scrolled;
        Step::Redraw
    }

    fn update_review(&mut self, key: KeyEvent) -> Step {
        match key.code {
            KeyCode::Up | KeyCode::Char('k') => self.scroll_review(-1),
            KeyCode::Down | KeyCode::Char('j') => self.scroll_review(1),
            KeyCode::PageUp => self.scroll_review(-10),
            KeyCode::PageDown => self.scroll_review(10),
            KeyCode::Enter => {
                let mut saved = Vec::new();
                if self.global_dirty() {
                    match self.save_global() {
                        Ok(()) => saved.push("global"),
                        Err(error) => {
                            self.set_error(format!("global save failed: {error}"));
                            return Step::Redraw;
                        }
                    }
                }
                if self.project_dirty() {
                    match self.save_project() {
                        Ok(()) => saved.push("project"),
                        Err(error) => {
                            self.set_error(format!("project save failed: {error}"));
                            return Step::Redraw;
                        }
                    }
                }
                if saved.is_empty() {
                    self.set_status("nothing to save");
                } else {
                    self.set_success(format!("saved: {}", saved.join(" + ")));
                }
                Step::Redraw
            }
            KeyCode::Char('g') => {
                let result = self.save_global();
                match result {
                    Ok(()) => self.set_success("saved global config"),
                    Err(error) => self.set_error(format!("global save failed: {error}")),
                }
                Step::Redraw
            }
            KeyCode::Char('p') => {
                let result = self.save_project();
                match result {
                    Ok(()) => self.set_success("saved project config"),
                    Err(error) => self.set_error(format!("project save failed: {error}")),
                }
                Step::Redraw
            }
            KeyCode::Esc | KeyCode::Char('q') => self.leave_screen(),
            _ => Step::Continue,
        }
    }

    fn save_global(&mut self) -> Result<()> {
        // Validate the draft end-to-end before writing: a config that cannot
        // build a policy must not be saved.
        self.global.sandbox_policy(Path::new(&self.home_dir))?;
        self.global.save(&self.global_path)?;
        self.global_on_disk = self.global.clone();
        Ok(())
    }

    fn save_project(&mut self) -> Result<()> {
        self.project.validate_as_project()?;
        self.project.sandbox_policy(Path::new(&self.home_dir))?;
        self.project.save(&self.project_path)?;
        self.project_on_disk = self.project.clone();
        self.project_exists = true;
        // Editing your own project file is consent: record the saved hash so
        // the next launch does not re-prompt for trust.
        if !self.project.widening_keys().is_empty() {
            let contents = std::fs::read(&self.project_path)?;
            let digest = trust::sha256_hex(&contents);
            if let Some(dir) = self
                .project_path
                .parent()
                .and_then(|parent| parent.canonicalize().ok())
            {
                let store_path = config::trust_store_path(&self.home_dir, self.xdg.as_deref());
                let mut store = trust::TrustStore::load(&store_path)?;
                store.approve(&dir.to_string_lossy(), &digest, Some(crate::unix_now()));
                store.save()?;
            }
        }
        Ok(())
    }

    fn refresh_interfaces(&mut self) {
        // The synthetic "none" (proxy-only) entry is always offered, so the
        // screen works even with no VPN interface up at all.
        let mut interfaces = vpn_interfaces().unwrap_or_default();
        interfaces.push(NetworkInterface::proxy_only());
        let current = self
            .interfaces
            .get(self.iface_selected)
            .map(|interface| interface.name.clone());
        self.iface_selected = current
            .and_then(|name| {
                interfaces
                    .iter()
                    .position(|interface| interface.name == name)
            })
            .unwrap_or(0);
        self.interfaces = interfaces;
        self.egress = route::query_ipv4_egress().unwrap_or_default();
    }
}

// ---------------------------------------------------------------------------
// Rendering
// ---------------------------------------------------------------------------

fn draw(frame: &mut Frame, editor: &Editor) {
    let [title_area, body_area, status_area, keybar_area] = Layout::vertical([
        Constraint::Length(1),
        Constraint::Min(5),
        Constraint::Length(1),
        Constraint::Length(1),
    ])
    .areas(frame.area());

    frame.render_widget(title_line(editor), title_area);

    match editor.screen {
        Screen::Home => draw_home(frame, editor, body_area),
        Screen::Interface => draw_interface(frame, editor, body_area),
        Screen::Proxy => draw_proxy(frame, editor, body_area),
        Screen::Network => draw_network(frame, editor, body_area),
        Screen::Paths => draw_paths(frame, editor, body_area),
        Screen::Presets => draw_presets(frame, editor, body_area),
        Screen::Review => draw_review(frame, editor, body_area),
    }

    if let Some((kind, text)) = &editor.status {
        let style = match kind {
            StatusKind::Info => Style::new(),
            StatusKind::Success => theme::success_style(),
            StatusKind::Warn => theme::warn_style(),
            StatusKind::Error => theme::error_style(),
        };
        frame.render_widget(Paragraph::new(text.clone()).style(style), status_area);
    }
    frame.render_widget(Paragraph::new(keybar(editor)), keybar_area);

    if let Some(input) = &editor.input {
        draw_input_overlay(frame, input, body_area);
    }
    if editor.help {
        draw_help_overlay(frame, body_area);
    }
}

/// Shortens a path for display by folding the home prefix back to `~`.
fn tilde_shorten(path: &Path, home: &str) -> String {
    let display = path.display().to_string();
    match display.strip_prefix(home) {
        Some(rest) if !home.is_empty() && rest.starts_with('/') => format!("~{rest}"),
        _ => display,
    }
}

/// Title bar: app name, colored scope badge, the file that scope edits, and
/// an unsaved marker — everything needed to know where an edit will land.
fn title_line(editor: &Editor) -> Line<'static> {
    let (scope_label, scope_color, target) = match editor.scope {
        Scope::Global => ("global", theme::SCOPE_GLOBAL, &editor.global_path),
        Scope::Project => ("project", theme::SCOPE_PROJECT, &editor.project_path),
    };
    let mut spans = vec![
        Span::styled(
            "LianYaoHu Configuration",
            Style::new().add_modifier(Modifier::BOLD),
        ),
        Span::raw("  "),
        Span::styled(
            format!("[{scope_label}]"),
            Style::new().fg(scope_color).add_modifier(Modifier::BOLD),
        ),
        Span::styled(
            format!(" editing {}", tilde_shorten(target, &editor.home_dir)),
            theme::dim_style(),
        ),
    ];
    if editor.dirty() {
        spans.push(Span::styled("  ● unsaved", theme::warn_style()));
    }
    spans.push(Span::styled("  (s switches scope)", theme::dim_style()));
    Line::from(spans)
}

fn keybar(editor: &Editor) -> Line<'static> {
    if let Some(input) = &editor.input {
        return match input.target {
            InputTarget::Path { .. } | InputTarget::DenyPath { .. } => theme::keybar_line(&[
                ("Enter", "confirm"),
                ("Tab", "complete path"),
                ("Ctrl-U/W", "clear/word"),
                ("Esc", "cancel"),
            ]),
            InputTarget::Network { .. } | InputTarget::Proxy => theme::keybar_line(&[
                ("Enter", "confirm"),
                ("Ctrl-U/W", "clear/word"),
                ("Esc", "cancel"),
            ]),
        };
    }
    match editor.screen {
        Screen::Home => theme::keybar_line(&[
            ("↑↓ 1-6", "select"),
            ("Enter", "open"),
            ("s", "scope"),
            ("Ctrl-S", "review & save"),
            ("q", "quit"),
            ("?", "help"),
        ]),
        Screen::Interface => theme::keybar_line(&[
            ("↑↓", "select"),
            ("Enter", "set default (global)"),
            ("p", "proxy"),
            ("Esc", "back"),
            ("?", "help"),
        ]),
        Screen::Proxy => theme::keybar_line(&[
            ("Enter/e", "edit"),
            ("d", "clear"),
            ("Esc", "back"),
            ("?", "help"),
        ]),
        Screen::Network => theme::keybar_line(&[
            ("Tab ←→", "pane"),
            ("a", "add"),
            ("e", "edit"),
            ("d", "delete"),
            ("u", "undo"),
            ("m", "default"),
            ("p", "proxy"),
            ("Esc", "back"),
        ]),
        Screen::Paths => theme::keybar_line(&[
            ("Tab ←→", "pane"),
            ("a", "add"),
            ("e", "edit"),
            ("d", "delete"),
            ("u", "undo"),
            ("Space", "narrow-home"),
            ("Esc", "back"),
        ]),
        Screen::Presets => theme::keybar_line(&[
            ("↑↓", "select"),
            ("Space", "toggle"),
            ("a", "add custom"),
            ("d", "delete"),
            ("u", "undo"),
            ("Esc", "back"),
        ]),
        Screen::Review => theme::keybar_line(&[
            ("↑↓", "scroll"),
            ("Enter", "save all"),
            ("g", "global only"),
            ("p", "project only"),
            ("Esc", "back"),
        ]),
    }
}

fn draw_home(frame: &mut Frame, editor: &Editor, area: Rect) {
    let summaries = home_summaries(editor);
    let items: Vec<ListItem> = HOME_MENU
        .iter()
        .enumerate()
        .map(|(index, (_, label))| {
            ListItem::new(format!("{}. {label:<18} {}", index + 1, summaries[index]))
        })
        .collect();
    let mut state = ListState::default().with_selected(Some(editor.menu_selected));
    frame.render_stateful_widget(
        List::new(items)
            .block(Block::bordered())
            .highlight_style(Style::new().add_modifier(Modifier::REVERSED))
            .highlight_symbol("> "),
        area,
        &mut state,
    );
}

fn home_summaries(editor: &Editor) -> Vec<String> {
    let view = editor.scope_view();
    HOME_MENU
        .iter()
        .map(|(screen, _)| match screen {
            Screen::Home => String::new(),
            Screen::Interface => editor
                .global
                .defaults
                .vpn_interface
                .clone()
                .map(|name| format!("{name} (global)"))
                .unwrap_or_else(|| "not set — prompted each run".to_string()),
            Screen::Proxy => editor.proxy_url().unwrap_or_else(|| "not set".to_string()),
            Screen::Network => format!(
                "{} allow · {} deny · {} LAN exceptions · default {}",
                view.network.allow.len(),
                view.network.deny.len(),
                view.network.lan_allow.len(),
                match view.network.default_action {
                    Some(lianyaohu_core::policy::NetAction::Deny) => "deny",
                    _ => "allow",
                },
            ),
            Screen::Paths => format!(
                "{} writable · {} read-only · narrow home: {}",
                view.paths.writable.len(),
                view.paths.read_only.len(),
                if view.paths.narrow_home == Some(true) {
                    "on"
                } else {
                    "off"
                }
            ),
            Screen::Presets => format!("{} denied paths", view.paths.deny.len()),
            Screen::Review => {
                let mut changed = Vec::new();
                if editor.global_dirty() {
                    changed.push("global");
                }
                if editor.project_dirty() {
                    changed.push("project");
                }
                if changed.is_empty() {
                    "no pending changes".to_string()
                } else {
                    format!("pending: {}", changed.join(" + "))
                }
            }
        })
        .collect()
}

fn draw_interface(frame: &mut Frame, editor: &Editor, area: Rect) {
    let [list_area, detail_area] =
        Layout::horizontal([Constraint::Percentage(40), Constraint::Percentage(60)]).areas(area);
    let saved = editor.global.defaults.vpn_interface.as_deref();
    let items: Vec<ListItem> = editor
        .interfaces
        .iter()
        .map(|interface| {
            let state = if interface.is_proxy_only() {
                Span::styled("[proxy-only]", theme::dim_style())
            } else {
                theme::state_span(interface.is_up() && interface.is_running())
            };
            let mut line = Line::from(vec![Span::raw(format!("{} ", interface.name)), state]);
            if saved == Some(interface.name.as_str()) {
                line.push_span(Span::styled(" (default)", theme::success_style()));
            }
            ListItem::new(line)
        })
        .collect();
    let mut state = ListState::default().with_selected(Some(editor.iface_selected));
    frame.render_stateful_widget(
        List::new(items)
            .block(Block::bordered().title("Interfaces"))
            .highlight_style(Style::new().add_modifier(Modifier::REVERSED))
            .highlight_symbol("> "),
        list_area,
        &mut state,
    );

    let detail: Vec<Line> = match editor.interfaces.get(editor.iface_selected) {
        Some(interface) => super::interface_detail_lines(interface, &editor.egress)
            .into_iter()
            .map(Line::from)
            .collect(),
        None => vec![Line::from("no active VPN interfaces")],
    };
    let title = editor
        .interfaces
        .get(editor.iface_selected)
        .map(|interface| interface.name.clone())
        .unwrap_or_default();
    frame.render_widget(
        Paragraph::new(detail).block(Block::bordered().title(title)),
        detail_area,
    );
}

fn draw_proxy(frame: &mut Frame, editor: &Editor, area: Rect) {
    let url_line = match editor.proxy_url() {
        Some(url) => Line::from(vec![
            Span::raw("URL  "),
            Span::styled(url, theme::success_style()),
        ]),
        None => Line::from(vec![
            Span::raw("URL  "),
            Span::styled("not set", theme::dim_style()),
        ]),
    };
    let lines = vec![
        url_line,
        Line::from(""),
        Line::from(
            "Sets HTTP_PROXY, HTTPS_PROXY, and ALL_PROXY (both cases) for the launched agent.",
        ),
        Line::from("Empty + Enter clears. Pair with VPN interface \"none\" (proxy-only)"),
        Line::from("or network default DENY so tools that ignore the proxy cannot leak."),
        Line::from(""),
        Line::styled("Enter / e edits · d clears", theme::dim_style()),
    ];
    frame.render_widget(
        Paragraph::new(lines)
            .block(Block::bordered().title("HTTP proxy"))
            .wrap(Wrap { trim: true }),
        area,
    );
}

fn draw_string_list(
    frame: &mut Frame,
    area: Rect,
    title: &str,
    entries: &[String],
    selected: usize,
    focused: bool,
) {
    let items: Vec<ListItem> = if entries.is_empty() {
        vec![ListItem::new(Span::styled(
            "(none — press a to add)",
            theme::dim_style(),
        ))]
    } else {
        entries
            .iter()
            .map(|entry| ListItem::new(entry.clone()))
            .collect()
    };
    let title = format!("{title} ({})", entries.len());
    // The focused pane gets a colored border so Tab focus is visible at a
    // glance, not just a bold weight some terminals barely render.
    let block = if focused {
        Block::bordered()
            .title(title)
            .border_style(Style::new().fg(theme::ACCENT).add_modifier(Modifier::BOLD))
            .title_style(Style::new().fg(theme::ACCENT).add_modifier(Modifier::BOLD))
    } else {
        Block::bordered().title(title)
    };
    let mut state = ListState::default().with_selected(if entries.is_empty() {
        None
    } else {
        Some(selected.min(entries.len() - 1))
    });
    frame.render_stateful_widget(
        List::new(items)
            .block(block)
            .highlight_style(Style::new().add_modifier(Modifier::REVERSED))
            .highlight_symbol("> "),
        area,
        &mut state,
    );
}

fn draw_network(frame: &mut Frame, editor: &Editor, area: Rect) {
    let [note_area, proxy_area, panes_area] = Layout::vertical([
        Constraint::Length(1),
        Constraint::Length(1),
        Constraint::Min(4),
    ])
    .areas(area);
    let default_action = match editor.scope_view().network.default_action {
        Some(lianyaohu_core::policy::NetAction::Deny) => {
            "default: DENY — only allow-listed destinations may leave (m toggles)"
        }
        _ => "default: allow — all non-LAN destinations may leave on the VPN (m toggles)",
    };
    frame.render_widget(Paragraph::new(default_action), note_area);
    let proxy_line = match editor.proxy_url() {
        Some(url) => format!(
            "proxy: {url} — sets HTTP(S)_PROXY/ALL_PROXY for the agent (p edits; pair with DENY \
             for proxy-or-nothing)"
        ),
        None => {
            "proxy: none (p to set — with default DENY this gives proxy-or-nothing)".to_string()
        }
    };
    frame.render_widget(Paragraph::new(proxy_line), proxy_area);

    let [allow_area, deny_area, lan_area] = Layout::horizontal([
        Constraint::Percentage(34),
        Constraint::Percentage(33),
        Constraint::Percentage(33),
    ])
    .areas(panes_area);
    let lists = editor.network_lists();
    draw_string_list(
        frame,
        allow_area,
        "Allow",
        lists[0],
        editor.net_selected[0],
        editor.net_pane == 0,
    );
    draw_string_list(
        frame,
        deny_area,
        "Deny",
        lists[1],
        editor.net_selected[1],
        editor.net_pane == 1,
    );
    draw_string_list(
        frame,
        lan_area,
        "LAN exceptions",
        lists[2],
        editor.net_selected[2],
        editor.net_pane == 2,
    );
}

fn draw_paths(frame: &mut Frame, editor: &Editor, area: Rect) {
    let [toggle_area, panes_area] =
        Layout::vertical([Constraint::Length(1), Constraint::Min(4)]).areas(area);
    let narrow = editor.scope_view().paths.narrow_home == Some(true);
    frame.render_widget(
        Paragraph::new(format!(
            "[{}] narrow HOME — agent writes only to state dirs, cwd, and tmp (Space toggles)",
            if narrow { "x" } else { " " }
        )),
        toggle_area,
    );

    let [writable_area, read_only_area] =
        Layout::horizontal([Constraint::Percentage(50), Constraint::Percentage(50)])
            .areas(panes_area);
    let lists = editor.path_lists();
    draw_string_list(
        frame,
        writable_area,
        "Extra writable",
        lists[0],
        editor.path_selected[0],
        editor.path_pane == 0,
    );
    draw_string_list(
        frame,
        read_only_area,
        "Extra read-only",
        lists[1],
        editor.path_selected[1],
        editor.path_pane == 1,
    );
}

fn draw_presets(frame: &mut Frame, editor: &Editor, area: Rect) {
    let [banner_area, list_area] =
        Layout::vertical([Constraint::Length(1), Constraint::Min(4)]).areas(area);
    let banner = if cfg!(target_os = "linux") {
        "NOTE: Landlock cannot deny inside an allowed tree — deny paths are best-effort on Linux"
    } else {
        "Denied paths are unreadable and unwritable inside the sandbox (seatbelt-enforced)"
    };
    frame.render_widget(Paragraph::new(banner), banner_area);

    let deny = &editor.scope_view().paths.deny;
    let mut items: Vec<ListItem> = SENSITIVE_PRESETS
        .iter()
        .map(|(path, label)| {
            let checked = deny.iter().any(|entry| entry == path);
            ListItem::new(format!(
                "[{}] {path:<22} {label}",
                if checked { "x" } else { " " }
            ))
        })
        .collect();
    for entry in editor.custom_deny_entries() {
        items.push(ListItem::new(format!("[x] {entry:<22} (custom)")));
    }
    let mut state = ListState::default().with_selected(Some(editor.preset_selected));
    frame.render_stateful_widget(
        List::new(items)
            .block(Block::bordered().title("Deny agent access to"))
            .highlight_style(Style::new().add_modifier(Modifier::REVERSED))
            .highlight_symbol("> "),
        list_area,
        &mut state,
    );
}

fn draw_review(frame: &mut Frame, editor: &Editor, area: Rect) {
    let lines = review_lines(editor);
    let title = if lines.len() > usize::from(area.height.saturating_sub(2)) {
        "Review & save (↑↓ to scroll)"
    } else {
        "Review & save"
    };
    frame.render_widget(
        Paragraph::new(lines)
            .block(Block::bordered().title(title))
            .wrap(Wrap { trim: false })
            .scroll((editor.review_scroll, 0)),
        area,
    );
}

fn review_lines(editor: &Editor) -> Vec<Line<'static>> {
    let mut lines: Vec<Line> = Vec::new();
    let global_state = if editor.global_dirty() {
        "modified"
    } else {
        "unchanged"
    };
    lines.push(Line::from(format!(
        "global  {} ({global_state})",
        editor.global_path.display()
    )));
    let project_state = if editor.project_dirty() {
        if editor.project_exists {
            "modified"
        } else {
            "new file"
        }
    } else if editor.project_exists {
        "unchanged"
    } else {
        "not created"
    };
    lines.push(Line::from(format!(
        "project {} ({project_state})",
        editor.project_path.display()
    )));
    lines.push(Line::from(""));
    if editor.project_dirty() && !editor.project.widening_keys().is_empty() {
        lines.push(Line::from(format!(
            "saving the project file also records trust for: {}",
            editor.project.widening_keys().join(", ")
        )));
        lines.push(Line::from(""));
    }
    match editor.global.to_toml() {
        Ok(toml) if editor.global_dirty() => {
            lines.push(Line::styled(
                "--- global after save ---",
                theme::key_style(),
            ));
            lines.extend(toml.lines().map(|line| Line::from(line.to_string())));
        }
        _ => {}
    }
    match editor.project.to_toml() {
        Ok(toml) if editor.project_dirty() => {
            lines.push(Line::styled(
                "--- project after save ---",
                theme::key_style(),
            ));
            lines.extend(toml.lines().map(|line| Line::from(line.to_string())));
        }
        _ => {}
    }
    if !editor.dirty() {
        lines.push(Line::from("no pending changes"));
    }
    lines
}

fn draw_input_overlay(frame: &mut Frame, input: &InputState, body: Rect) {
    let height = 5;
    let area = Rect {
        x: body.x + 2,
        y: body.y + body.height.saturating_sub(height + 1),
        width: body.width.saturating_sub(4),
        height,
    };
    frame.render_widget(Clear, area);
    let title = match input.target {
        InputTarget::Network { pane: 0, edit } => {
            if edit.is_some() {
                "Edit allow rule"
            } else {
                "Add allow rule (ADDR[/PREFIX][:PORT[-PORT]])"
            }
        }
        InputTarget::Network { pane: 1, edit } => {
            if edit.is_some() {
                "Edit deny rule"
            } else {
                "Add deny rule (ADDR[/PREFIX][:PORT[-PORT]])"
            }
        }
        InputTarget::Network { .. } => "LAN exception (must be inside blocked LAN ranges)",
        InputTarget::Path { pane: 0, .. } => "Writable path (absolute or ~/...)",
        InputTarget::Path { .. } => "Read-only path (absolute or ~/...)",
        InputTarget::DenyPath { .. } => "Deny path (absolute or ~/...)",
        InputTarget::Proxy => "Proxy URL (http://host:port or socks5://host:port; empty clears)",
    };
    let mut lines = vec![Line::from(format!("> {}", input.buffer))];
    if let Some(error) = &input.error {
        lines.push(Line::styled(format!("✗ {error}"), theme::error_style()));
    }
    if let Some(hint) = &input.hint {
        lines.push(Line::styled(hint.clone(), theme::dim_style()));
    }
    frame.render_widget(
        Paragraph::new(lines).block(
            Block::bordered()
                .title(title)
                .border_style(Style::new().fg(theme::ACCENT)),
        ),
        area,
    );
    let cursor_x = area.x + 3 + input.cursor as u16;
    frame.set_cursor_position((cursor_x.min(area.x + area.width - 2), area.y + 1));
}

fn draw_help_overlay(frame: &mut Frame, body: Rect) {
    let entries = [
        "s            switch scope (global config vs project .lianyaohu.toml)",
        "Tab / ← →    switch pane on list screens (h/l work too)",
        "a / e / d    add / edit / delete an entry",
        "u            undo the last delete",
        "Space        toggle checkbox (narrow-home, presets)",
        "m            toggle network default allow/deny",
        "p            set/clear the HTTP proxy (HTTP(S)_PROXY/ALL_PROXY);",
        "             also a home-menu item; pair with DENY or VPN \"none\"",
        "Ctrl-S       jump to Review & save (↑↓ scrolls the preview)",
        "Esc / q      back; on Home: quit (asks when unsaved)",
        "",
        "In inputs: Tab completes paths, Ctrl-A/E jump to start/end,",
        "Ctrl-U clears to start, Ctrl-W deletes the previous word.",
        "",
        "Widening entries saved to a project file are trust-pinned",
        "automatically; other users still get a prompt on first launch.",
        "any key closes this help",
    ];
    let width = body.width.saturating_sub(8).min(70);
    let height = body.height.min(entries.len() as u16 + 2);
    let area = Rect {
        x: body.x + (body.width - width) / 2,
        y: body.y + (body.height - height) / 2,
        width,
        height,
    };
    frame.render_widget(Clear, area);
    let lines: Vec<Line> = entries.into_iter().map(Line::from).collect();
    frame.render_widget(
        Paragraph::new(lines).block(Block::bordered().title("Help")),
        area,
    );
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

/// Runs the full-screen configuration editor. Loads the global config and the
/// discovered (or would-be) project file, and saves whatever the user commits
/// on the Review screen.
pub fn run_config_editor(home: &str, xdg: Option<&str>, cwd: &Path) -> Result<()> {
    let global_path = config::global_config_path(home, xdg);
    let global = ConfigFile::load(&global_path)?.unwrap_or_default();
    let (project_path, project_on_disk, project_exists) =
        match config::discover_project(cwd, Path::new(home))? {
            Some((path, file)) => (path, file, true),
            None => (cwd.join(PROJECT_FILE_NAME), ConfigFile::default(), false),
        };

    let mut editor = Editor {
        home_dir: home.to_string(),
        xdg: xdg.map(str::to_string),
        global_path,
        project_path,
        project_exists,
        global: global.clone(),
        project: project_on_disk.clone(),
        global_on_disk: global,
        project_on_disk,
        scope: if project_exists {
            Scope::Project
        } else {
            Scope::Global
        },
        screen: Screen::Home,
        menu_selected: 0,
        iface_selected: 0,
        interfaces: Vec::new(),
        egress: route::Ipv4Egress::default(),
        net_pane: 0,
        net_selected: [0; 3],
        path_pane: 0,
        path_selected: [0; 2],
        preset_selected: 0,
        input: None,
        status: None,
        review_scroll: 0,
        help: false,
        confirm_quit: false,
        undo: None,
    };
    editor.refresh_interfaces();

    let mut guard = TerminalGuard::fullscreen()?;
    let result = run_loop(&mut guard, &mut editor);
    drop(guard);
    result
}

fn run_loop(guard: &mut TerminalGuard, editor: &mut Editor) -> Result<()> {
    let mut next_tick = Instant::now() + TICK;
    guard.terminal.draw(|frame| draw(frame, editor))?;
    loop {
        let timeout = next_tick.saturating_duration_since(Instant::now());
        if event::poll(timeout)? {
            match event::read()? {
                Event::Key(key) => match editor.update(key) {
                    Step::Continue => {}
                    Step::Redraw => {
                        guard.terminal.draw(|frame| draw(frame, editor))?;
                    }
                    Step::Quit => return Ok(()),
                },
                Event::Resize(..) => {
                    guard.terminal.draw(|frame| draw(frame, editor))?;
                }
                _ => {}
            }
        } else {
            next_tick = Instant::now() + TICK;
            if editor.screen == Screen::Interface {
                editor.refresh_interfaces();
                guard.terminal.draw(|frame| draw(frame, editor))?;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ratatui::Terminal;
    use ratatui::backend::TestBackend;

    fn test_editor() -> Editor {
        Editor {
            home_dir: "/Users/me".to_string(),
            xdg: None,
            global_path: PathBuf::from("/Users/me/.config/lianyaohu/config.toml"),
            project_path: PathBuf::from("/Users/me/src/repo/.lianyaohu.toml"),
            project_exists: false,
            global: ConfigFile::default(),
            project: ConfigFile::default(),
            global_on_disk: ConfigFile::default(),
            project_on_disk: ConfigFile::default(),
            scope: Scope::Global,
            screen: Screen::Home,
            menu_selected: 0,
            iface_selected: 0,
            interfaces: vec![NetworkInterface {
                name: "utun5".to_string(),
                flags: (libc::IFF_UP | libc::IFF_RUNNING) as u32,
                ipv4_addresses: vec!["10.7.0.2".to_string()],
                ipv4_peer_addresses: vec!["10.7.0.1".to_string()],
                ipv6_addresses: Vec::new(),
            }],
            egress: route::Ipv4Egress {
                default_interfaces: vec!["utun5".to_string()],
                low_half: Some("utun5".to_string()),
                high_half: Some("utun5".to_string()),
            },
            net_pane: 0,
            net_selected: [0; 3],
            path_pane: 0,
            path_selected: [0; 2],
            preset_selected: 0,
            input: None,
            status: None,
            review_scroll: 0,
            help: false,
            confirm_quit: false,
            undo: None,
        }
    }

    fn press(code: KeyCode) -> KeyEvent {
        KeyEvent::new(code, KeyModifiers::NONE)
    }

    fn type_text(editor: &mut Editor, text: &str) {
        for character in text.chars() {
            editor.update(press(KeyCode::Char(character)));
        }
    }

    fn render(editor: &Editor) -> String {
        let backend = TestBackend::new(100, 24);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal.draw(|frame| draw(frame, editor)).unwrap();
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
    fn home_menu_navigates_to_screens_and_back() {
        let mut editor = test_editor();
        editor.update(press(KeyCode::Char('3')));
        assert_eq!(editor.screen, Screen::Network);
        editor.update(press(KeyCode::Esc));
        assert_eq!(editor.screen, Screen::Home);
        // Selection is sticky: it stayed on Network (index 2), so Down lands
        // on Paths.
        editor.update(press(KeyCode::Down));
        editor.update(press(KeyCode::Enter));
        assert_eq!(editor.screen, Screen::Paths);
    }

    #[test]
    fn quit_requires_confirmation_when_dirty() {
        let mut editor = test_editor();
        editor.global.paths.narrow_home = Some(true);
        assert!(matches!(editor.update(press(KeyCode::Esc)), Step::Redraw));
        assert!(editor.status_text().unwrap_or("").contains("unsaved"));
        assert_eq!(editor.status.as_ref().unwrap().0, StatusKind::Warn);
        assert!(matches!(editor.update(press(KeyCode::Esc)), Step::Quit));

        // A clean editor quits immediately.
        let mut editor = test_editor();
        assert!(matches!(editor.update(press(KeyCode::Esc)), Step::Quit));
    }

    #[test]
    fn scope_toggle_routes_edits_to_the_right_draft() {
        let mut editor = test_editor();
        editor.update(press(KeyCode::Char('4'))); // Paths screen
        editor.update(press(KeyCode::Char(' '))); // narrow home on (global)
        assert_eq!(editor.global.paths.narrow_home, Some(true));
        assert_eq!(editor.project.paths.narrow_home, None);

        editor.update(press(KeyCode::Char('s'))); // switch to project scope
        editor.update(press(KeyCode::Char(' ')));
        assert_eq!(editor.project.paths.narrow_home, Some(true));
    }

    #[test]
    fn network_add_validates_and_stores_canonical_form() {
        let mut editor = test_editor();
        editor.update(press(KeyCode::Char('3'))); // Network
        editor.update(press(KeyCode::Char('a')));
        type_text(&mut editor, "140.82.112.0/20:443");
        editor.update(press(KeyCode::Enter));
        assert_eq!(editor.global.network.allow, ["140.82.112.0/20:443"]);
        assert!(editor.input.is_none());

        // Invalid input keeps the overlay open with an error.
        editor.update(press(KeyCode::Char('a')));
        type_text(&mut editor, "nonsense");
        editor.update(press(KeyCode::Enter));
        let input = editor.input.as_ref().expect("input stays open");
        assert!(input.error.is_some());
        editor.update(press(KeyCode::Esc));
        assert!(editor.input.is_none());
        assert_eq!(editor.global.network.allow.len(), 1);
    }

    #[test]
    fn lan_exception_containment_is_checked_in_the_editor() {
        let mut editor = test_editor();
        editor.update(press(KeyCode::Char('3')));
        editor.update(press(KeyCode::Tab));
        editor.update(press(KeyCode::Tab)); // lan_allow pane
        editor.update(press(KeyCode::Char('a')));
        type_text(&mut editor, "8.8.8.8");
        editor.update(press(KeyCode::Enter));
        assert!(editor.input.as_ref().unwrap().error.is_some());
        // Fix it to something inside the LAN ranges.
        for _ in 0.."8.8.8.8".len() {
            editor.update(press(KeyCode::Backspace));
        }
        type_text(&mut editor, "192.168.1.10:22");
        editor.update(press(KeyCode::Enter));
        assert!(editor.input.is_none());
        assert_eq!(editor.global.network.lan_allow, ["192.168.1.10:22"]);
    }

    #[test]
    fn network_default_action_toggles() {
        use lianyaohu_core::policy::NetAction;
        let mut editor = test_editor();
        editor.update(press(KeyCode::Char('3')));
        editor.update(press(KeyCode::Char('m')));
        assert_eq!(editor.global.network.default_action, Some(NetAction::Deny));
        editor.update(press(KeyCode::Char('m')));
        assert_eq!(editor.global.network.default_action, None);
    }

    #[test]
    fn path_entries_accept_tilde_and_reject_relative() {
        let mut editor = test_editor();
        editor.update(press(KeyCode::Char('4')));
        editor.update(press(KeyCode::Char('a')));
        type_text(&mut editor, "~/models");
        editor.update(press(KeyCode::Enter));
        assert_eq!(editor.global.paths.writable, ["~/models"]);

        editor.update(press(KeyCode::Char('a')));
        type_text(&mut editor, "relative/path");
        editor.update(press(KeyCode::Enter));
        assert!(editor.input.as_ref().unwrap().error.is_some());
        editor.update(press(KeyCode::Esc));

        // Delete removes the entry.
        editor.update(press(KeyCode::Char('d')));
        assert!(editor.global.paths.writable.is_empty());
    }

    #[test]
    fn preset_toggle_adds_and_removes_deny_entries() {
        let mut editor = test_editor();
        editor.update(press(KeyCode::Char('5')));
        editor.update(press(KeyCode::Char(' ')));
        assert_eq!(editor.global.paths.deny, ["~/.ssh"]);
        editor.update(press(KeyCode::Char(' ')));
        assert!(editor.global.paths.deny.is_empty());

        // Custom deny entries append after the catalog and can be deleted.
        editor.update(press(KeyCode::Char('a')));
        type_text(&mut editor, "~/secrets");
        editor.update(press(KeyCode::Enter));
        assert_eq!(editor.global.paths.deny, ["~/secrets"]);
        editor.preset_selected = SENSITIVE_PRESETS.len();
        editor.update(press(KeyCode::Char('d')));
        assert!(editor.global.paths.deny.is_empty());
    }

    #[test]
    fn interface_selection_always_writes_global_defaults() {
        let mut editor = test_editor();
        editor.scope = Scope::Project;
        editor.update(press(KeyCode::Char('1')));
        editor.update(press(KeyCode::Enter));
        assert_eq!(
            editor.global.defaults.vpn_interface.as_deref(),
            Some("utun5")
        );
        assert_eq!(editor.project.defaults, Default::default());
    }

    #[test]
    fn review_save_round_trips_to_disk_and_pins_trust() {
        use std::sync::atomic::{AtomicU32, Ordering};
        static ID: AtomicU32 = AtomicU32::new(0);
        let scratch = std::env::temp_dir().join(format!(
            "lianyaohu-editor-test-{}-{}",
            std::process::id(),
            ID.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(scratch.join("project")).unwrap();

        let mut editor = test_editor();
        editor.home_dir = scratch.to_string_lossy().to_string();
        editor.xdg = Some(scratch.join("xdg").to_string_lossy().to_string());
        editor.global_path = scratch.join("xdg/lianyaohu/config.toml");
        editor.project_path = scratch.join("project/.lianyaohu.toml");

        // Global change + a project widening.
        editor.global.defaults.vpn_interface = Some("utun5".to_string());
        editor.project.paths.writable = vec!["/data/models".to_string()];

        editor.screen = Screen::Review;
        editor.update(press(KeyCode::Enter));
        assert_eq!(editor.status_text(), Some("saved: global + project"));
        assert_eq!(editor.status.as_ref().unwrap().0, StatusKind::Success);
        assert!(!editor.dirty());

        let saved_global = ConfigFile::load(&editor.global_path).unwrap().unwrap();
        assert_eq!(
            saved_global.defaults.vpn_interface.as_deref(),
            Some("utun5")
        );
        let saved_project = ConfigFile::load(&editor.project_path).unwrap().unwrap();
        assert_eq!(saved_project.paths.writable, ["/data/models"]);

        // The saved project hash is trust-pinned.
        let store = trust::TrustStore::load(&config::trust_store_path(
            &editor.home_dir,
            editor.xdg.as_deref(),
        ))
        .unwrap();
        let digest = trust::sha256_hex(&std::fs::read(&editor.project_path).unwrap());
        let dir = editor
            .project_path
            .parent()
            .unwrap()
            .canonicalize()
            .unwrap();
        assert!(store.is_approved(&dir.to_string_lossy(), &digest));

        std::fs::remove_dir_all(&scratch).ok();
    }

    #[test]
    fn http_proxy_home_item_edits_and_clears() {
        let mut editor = test_editor();
        editor.update(press(KeyCode::Char('2')));
        assert_eq!(editor.screen, Screen::Proxy);
        let rendered = render(&editor);
        assert!(rendered.contains("HTTP proxy"));
        assert!(rendered.contains("not set"));

        editor.update(press(KeyCode::Enter));
        type_text(&mut editor, "http://127.0.0.1:7890");
        editor.update(press(KeyCode::Enter));
        assert_eq!(editor.proxy_url().as_deref(), Some("http://127.0.0.1:7890"));
        assert_eq!(
            editor.global.env.get("HTTP_PROXY").map(String::as_str),
            Some("http://127.0.0.1:7890")
        );

        editor.update(press(KeyCode::Char('d')));
        assert!(editor.global.env.is_empty());
        assert_eq!(editor.status_text(), Some("proxy cleared"));
    }

    #[test]
    fn selecting_proxy_only_without_proxy_opens_the_url_input() {
        let mut editor = test_editor();
        editor.interfaces.push(NetworkInterface::proxy_only());
        editor.iface_selected = 1;
        editor.update(press(KeyCode::Char('1')));
        editor.update(press(KeyCode::Enter));
        assert_eq!(
            editor.global.defaults.vpn_interface.as_deref(),
            Some("none")
        );
        let input = editor.input.as_ref().expect("proxy prompt");
        assert_eq!(input.target, InputTarget::Proxy);
        assert!(input.buffer.is_empty());
    }

    #[test]
    fn proxy_url_reads_any_standard_key() {
        let mut editor = test_editor();
        editor
            .global
            .env
            .insert("http_proxy".to_string(), "http://127.0.0.1:9".to_string());
        assert_eq!(editor.proxy_url().as_deref(), Some("http://127.0.0.1:9"));
    }

    #[test]
    fn proxy_input_fans_out_env_vars_and_clears_them() {
        let mut editor = test_editor();
        editor.update(press(KeyCode::Char('3'))); // Network screen
        editor.update(press(KeyCode::Char('p')));
        type_text(&mut editor, "http://127.0.0.1:7890");
        editor.update(press(KeyCode::Enter));
        assert!(editor.input.is_none());
        let env = &editor.global.env;
        for key in PROXY_ENV_KEYS {
            assert_eq!(
                env.get(*key).map(String::as_str),
                Some("http://127.0.0.1:7890")
            );
        }
        assert_eq!(
            env.get("NO_PROXY").map(String::as_str),
            Some(NO_PROXY_VALUE)
        );
        assert_eq!(env.len(), PROXY_ENV_KEYS.len() + NO_PROXY_KEYS.len());

        // Reopening pre-fills the current value; clearing it removes all keys.
        editor.update(press(KeyCode::Char('p')));
        assert_eq!(
            editor.input.as_ref().unwrap().buffer,
            "http://127.0.0.1:7890"
        );
        for _ in 0.."http://127.0.0.1:7890".len() {
            editor.update(press(KeyCode::Backspace));
        }
        editor.update(press(KeyCode::Enter));
        assert!(editor.global.env.is_empty());
        assert_eq!(editor.status_text(), Some("proxy cleared"));
    }

    #[test]
    fn proxy_input_rejects_bad_urls() {
        let mut editor = test_editor();
        editor.update(press(KeyCode::Char('3')));
        for bad in ["127.0.0.1:7890", "ftp://x:1", "http://has space:1"] {
            editor.update(press(KeyCode::Char('p')));
            type_text(&mut editor, bad);
            editor.update(press(KeyCode::Enter));
            assert!(
                editor.input.as_ref().unwrap().error.is_some(),
                "should reject {bad:?}"
            );
            editor.update(press(KeyCode::Esc));
            assert!(editor.global.env.is_empty());
        }
    }

    #[test]
    fn delete_records_undo_and_u_restores_into_the_same_scope() {
        let mut editor = test_editor();
        editor.global.network.allow = vec!["1.1.1.1".to_string(), "9.9.9.9".to_string()];
        editor.update(press(KeyCode::Char('3'))); // Network screen
        editor.update(press(KeyCode::Char('d')));
        assert_eq!(editor.global.network.allow, ["9.9.9.9"]);
        assert!(editor.status_text().unwrap().contains("u to undo"));

        // Even after switching scope, undo restores into the ORIGINAL scope.
        editor.update(press(KeyCode::Char('s')));
        editor.update(press(KeyCode::Char('u')));
        assert_eq!(editor.global.network.allow, ["1.1.1.1", "9.9.9.9"]);
        assert!(editor.project.network.allow.is_empty());
        // Undo is one-shot.
        assert!(matches!(
            editor.update(press(KeyCode::Char('u'))),
            Step::Continue
        ));
    }

    #[test]
    fn tab_completion_extends_path_inputs() {
        use std::sync::atomic::{AtomicU32, Ordering};
        static ID: AtomicU32 = AtomicU32::new(0);
        let scratch = std::env::temp_dir().join(format!(
            "lianyaohu-complete-test-{}-{}",
            std::process::id(),
            ID.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(scratch.join("models")).unwrap();
        std::fs::create_dir_all(scratch.join("moments")).unwrap();
        std::fs::write(scratch.join("notes.txt"), "x").unwrap();

        let mut editor = test_editor();
        editor.home_dir = scratch.to_string_lossy().to_string();
        editor.update(press(KeyCode::Char('4'))); // Paths screen
        editor.update(press(KeyCode::Char('a')));

        // Unique match completes fully and appends '/' for directories.
        type_text(&mut editor, "~/n");
        editor.update(press(KeyCode::Tab));
        assert_eq!(editor.input.as_ref().unwrap().buffer, "~/notes.txt");

        // Ambiguous match extends to the common prefix and offers candidates.
        let mut editor2 = test_editor();
        editor2.home_dir = scratch.to_string_lossy().to_string();
        editor2.update(press(KeyCode::Char('4')));
        editor2.update(press(KeyCode::Char('a')));
        type_text(&mut editor2, "~/m");
        editor2.update(press(KeyCode::Tab));
        let input = editor2.input.as_ref().unwrap();
        assert_eq!(input.buffer, "~/mo");
        assert!(input.hint.as_deref().unwrap().contains("models"));
        assert!(input.hint.as_deref().unwrap().contains("moments"));

        std::fs::remove_dir_all(&scratch).ok();
    }

    #[test]
    fn longest_common_prefix_basics() {
        assert_eq!(
            longest_common_prefix(["models", "moments"].into_iter()),
            "mo"
        );
        assert_eq!(longest_common_prefix(["abc"].into_iter()), "abc");
        assert_eq!(longest_common_prefix(["a", "b"].into_iter()), "");
    }

    #[test]
    fn focused_pane_border_uses_highlight_color() {
        let mut editor = test_editor();
        editor.screen = Screen::Network;
        editor.net_pane = 1; // Deny pane focused

        let backend = TestBackend::new(100, 24);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal.draw(|frame| draw(frame, &editor)).unwrap();
        let buffer = terminal.backend().buffer().clone();

        // Scan only the body rows: the title and keybar carry accent-colored
        // spans of their own by design.
        let cyan_cells: Vec<(u16, u16)> = (1..buffer.area.height - 2)
            .flat_map(|y| (0..buffer.area.width).map(move |x| (x, y)))
            .filter(|&(x, y)| buffer[(x, y)].style().fg == Some(theme::ACCENT))
            .collect();
        assert!(
            !cyan_cells.is_empty(),
            "focused pane border must be highlighted in color"
        );
        // Exactly one of the three panes is highlighted: the cyan cells all
        // fall inside the middle third of the width (the Deny pane).
        let width = buffer.area.width;
        assert!(
            cyan_cells
                .iter()
                .all(|&(x, _)| x >= width / 3 - 1 && x < width / 3 * 2 + 1),
            "only the focused pane may carry the highlight: {cyan_cells:?}"
        );
    }

    #[test]
    fn render_smoke_all_screens() {
        let mut editor = test_editor();
        editor.global.network.allow = vec!["140.82.112.0/20:443".to_string()];
        editor.global.paths.deny = vec!["~/.ssh".to_string(), "~/custom".to_string()];
        editor.global.paths.narrow_home = Some(true);

        editor.screen = Screen::Home;
        let rendered = render(&editor);
        assert!(rendered.contains("VPN interface"));
        assert!(rendered.contains("HTTP proxy"));
        assert!(rendered.contains("Review & save"));
        assert!(rendered.contains("pending: global"));

        editor.screen = Screen::Interface;
        let rendered = render(&editor);
        assert!(rendered.contains("utun5 [up]"));
        assert!(rendered.contains("yes (carries IPv4 egress)"), "{rendered}");

        editor.screen = Screen::Proxy;
        let rendered = render(&editor);
        assert!(rendered.contains("HTTP proxy"));
        assert!(rendered.contains("not set"));
        assert!(rendered.contains("HTTP_PROXY"));

        editor.screen = Screen::Network;
        let rendered = render(&editor);
        assert!(rendered.contains("Allow"));
        assert!(rendered.contains("140.82.112.0/20:443"));
        assert!(rendered.contains("LAN exceptions"));

        editor.screen = Screen::Paths;
        let rendered = render(&editor);
        assert!(rendered.contains("[x] narrow HOME"));
        assert!(rendered.contains("Extra writable"));

        editor.screen = Screen::Presets;
        let rendered = render(&editor);
        assert!(rendered.contains("[x] ~/.ssh"));
        assert!(rendered.contains("(custom)"));

        editor.screen = Screen::Review;
        let rendered = render(&editor);
        assert!(rendered.contains("Review & save"));
        assert!(rendered.contains("--- global after save ---"));

        editor.help = true;
        let rendered = render(&editor);
        assert!(rendered.contains("switch scope"));

        editor.help = false;
        editor.input = Some(InputState {
            target: InputTarget::Network {
                pane: 0,
                edit: None,
            },
            buffer: "1.2.3".to_string(),
            cursor: 5,
            error: Some("invalid".to_string()),
            hint: None,
        });
        let rendered = render(&editor);
        assert!(rendered.contains("Add allow rule"));
        assert!(rendered.contains("✗ invalid"));
    }

    #[test]
    fn input_line_editing_shortcuts() {
        let ctrl = |character| KeyEvent::new(KeyCode::Char(character), KeyModifiers::CONTROL);
        let mut editor = test_editor();
        editor.update(press(KeyCode::Char('4'))); // Paths screen
        editor.update(press(KeyCode::Char('a')));
        type_text(&mut editor, "~/models/llama");

        // Ctrl-W trims one path component at a time.
        editor.update(ctrl('w'));
        assert_eq!(editor.input.as_ref().unwrap().buffer, "~/models/");
        editor.update(ctrl('w'));
        assert_eq!(editor.input.as_ref().unwrap().buffer, "~/");

        // Ctrl-A / Ctrl-E and Home / End move the cursor to the extremes.
        type_text(&mut editor, "data");
        editor.update(ctrl('a'));
        assert_eq!(editor.input.as_ref().unwrap().cursor, 0);
        editor.update(ctrl('e'));
        assert_eq!(editor.input.as_ref().unwrap().cursor, "~/data".len());
        editor.update(press(KeyCode::Home));
        assert_eq!(editor.input.as_ref().unwrap().cursor, 0);
        editor.update(press(KeyCode::End));
        assert_eq!(editor.input.as_ref().unwrap().cursor, "~/data".len());

        // Ctrl-U kills everything before the cursor.
        editor.update(ctrl('u'));
        assert_eq!(editor.input.as_ref().unwrap().buffer, "");
        assert_eq!(editor.input.as_ref().unwrap().cursor, 0);
    }

    #[test]
    fn arrow_keys_and_hl_switch_panes() {
        let mut editor = test_editor();
        editor.update(press(KeyCode::Char('3'))); // Network screen
        editor.update(press(KeyCode::Right));
        assert_eq!(editor.net_pane, 1);
        editor.update(press(KeyCode::Char('l')));
        assert_eq!(editor.net_pane, 2);
        editor.update(press(KeyCode::Char('h')));
        assert_eq!(editor.net_pane, 1);
        editor.update(press(KeyCode::Left));
        assert_eq!(editor.net_pane, 0);

        editor.update(press(KeyCode::Esc));
        editor.update(press(KeyCode::Char('4'))); // Paths screen
        editor.update(press(KeyCode::Right));
        assert_eq!(editor.path_pane, 1);
        editor.update(press(KeyCode::Char('h')));
        assert_eq!(editor.path_pane, 0);
    }

    #[test]
    fn review_scrolls_and_clamps() {
        let mut editor = test_editor();
        // Enough entries that the preview has plenty of lines to scroll.
        editor.global.network.allow = (0..30).map(|index| format!("10.0.0.{index}")).collect();
        editor.update(press(KeyCode::Char('6'))); // Review screen
        assert_eq!(editor.review_scroll, 0);

        editor.update(press(KeyCode::Char('j')));
        assert_eq!(editor.review_scroll, 1);
        editor.update(press(KeyCode::PageDown));
        assert_eq!(editor.review_scroll, 11);
        editor.update(press(KeyCode::Char('k')));
        assert_eq!(editor.review_scroll, 10);
        editor.update(press(KeyCode::PageUp));
        assert_eq!(editor.review_scroll, 0);
        editor.update(press(KeyCode::Up));
        assert_eq!(editor.review_scroll, 0);

        // Scrolling never runs past the last preview line, and re-entering
        // the screen resets it.
        let max = editor.max_review_scroll();
        for _ in 0..500 {
            editor.update(press(KeyCode::PageDown));
        }
        assert_eq!(editor.review_scroll, max);
        editor.update(press(KeyCode::Esc));
        editor.update(press(KeyCode::Char('6')));
        assert_eq!(editor.review_scroll, 0);
    }

    #[test]
    fn empty_lists_hint_at_the_add_key() {
        let mut editor = test_editor();
        editor.screen = Screen::Paths;
        let rendered = render(&editor);
        assert!(rendered.contains("(none — press a to add)"));
        assert!(rendered.contains("Extra writable (0)"));
    }

    #[test]
    fn title_names_the_scope_target_file() {
        let mut editor = test_editor();
        let rendered = render(&editor);
        assert!(rendered.contains("[global]"));
        assert!(rendered.contains("editing ~/.config/lianyaohu/config.toml"));

        editor.scope = Scope::Project;
        editor.global.paths.narrow_home = Some(true);
        let rendered = render(&editor);
        assert!(rendered.contains("[project]"));
        assert!(rendered.contains("editing ~/src/repo/.lianyaohu.toml"));
        assert!(rendered.contains("● unsaved"));
    }
}
