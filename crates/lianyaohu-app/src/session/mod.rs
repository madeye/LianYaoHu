//! Background agent sessions: each `lyh run` forks a small per-session
//! daemon that owns a PTY and a Unix socket, dtach-style. Clients attach to
//! stream the terminal; `Ctrl-g` toggles a zellij-style command mode where
//! `d` detaches, `n`/`p` switch between live sessions, and `w` opens the
//! session picker. One daemon per session keeps every agent in its own
//! sandbox with no shared multiplexer state.

pub mod client;
pub mod daemon;
pub mod protocol;

use std::env;
use std::fs;
use std::path::{Path, PathBuf};

use lianyaohu_core::{Result, err};
use serde::{Deserialize, Serialize};

/// The command-mode toggle key: `Ctrl-g`, zellij-style. Also recognized in
/// its kitty-keyboard-protocol encoding (`ESC [ 103 ; 5 u`), which is what
/// terminals like Ghostty send once the agent enables that protocol.
pub const MODE_KEY: u8 = 0x07;

/// Directory holding one `<name>.sock` + `<name>.json` pair per session.
/// Overridable for tests and unusual setups; sockets need short paths.
pub fn sessions_dir(home: &str) -> PathBuf {
    if let Ok(dir) = env::var("LIANYAOHU_SESSION_DIR") {
        return PathBuf::from(dir);
    }
    let state_home = env::var("XDG_STATE_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|_| Path::new(home).join(".local/state"));
    state_home.join("lianyaohu/sessions")
}

pub fn socket_path(dir: &Path, name: &str) -> PathBuf {
    dir.join(format!("{name}.sock"))
}

pub fn meta_path(dir: &Path, name: &str) -> PathBuf {
    dir.join(format!("{name}.json"))
}

pub fn log_path(dir: &Path, name: &str) -> PathBuf {
    dir.join(format!("{name}.log"))
}

pub fn status_path(dir: &Path, name: &str) -> PathBuf {
    dir.join(format!("{name}.status"))
}

/// Session names become file names; keep them safe and predictable.
pub fn validate_name(name: &str) -> Result<()> {
    if name.is_empty() || name.len() > 64 {
        return Err(err("session name must be 1-64 characters"));
    }
    if !name
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
        || name.starts_with('.')
    {
        return Err(err(
            "session name may only contain letters, digits, '-', '_', '.' (not leading)",
        ));
    }
    Ok(())
}

/// Sanitizes a working-directory basename into a default session name.
pub fn default_name(cwd: &Path) -> String {
    let base: String = cwd
        .file_name()
        .map(|name| name.to_string_lossy().to_string())
        .unwrap_or_default()
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.') {
                c
            } else {
                '-'
            }
        })
        .collect();
    let base = base.trim_matches(|c| c == '-' || c == '.').to_string();
    if base.is_empty() {
        "agent".to_string()
    } else {
        base
    }
}

/// First free name among `base`, `base-2`, `base-3`, ...
pub fn unique_name(dir: &Path, base: &str) -> String {
    if !socket_path(dir, base).exists() && !meta_path(dir, base).exists() {
        return base.to_string();
    }
    for suffix in 2.. {
        let candidate = format!("{base}-{suffix}");
        if !socket_path(dir, &candidate).exists() && !meta_path(dir, &candidate).exists() {
            return candidate;
        }
    }
    unreachable!("suffix search is unbounded")
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SessionMeta {
    pub name: String,
    pub pid: u32,
    pub command: Vec<String>,
    pub cwd: String,
    pub vpn_interface: String,
    pub started_at: u64,
}

impl SessionMeta {
    pub fn save(&self, dir: &Path) -> Result<()> {
        let json = serde_json::to_vec_pretty(self)?;
        fs::write(meta_path(dir, &self.name), json)?;
        Ok(())
    }

    pub fn load(dir: &Path, name: &str) -> Result<Self> {
        let bytes = fs::read(meta_path(dir, name))?;
        Ok(serde_json::from_slice(&bytes)?)
    }
}

/// A session is shown as working while its last PTY output is at most this
/// recent: agents stream continuously while running tools, and a few quiet
/// seconds reliably means they are sitting at a prompt.
pub const ACTIVITY_WINDOW_SECS: u64 = 5;

/// Live activity exported by the daemon as `<name>.status`, separate from
/// the launch-time `<name>.json` so it can be rewritten freely without
/// racing `lyh ls` against the metadata. Absence just means an older daemon.
#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
pub struct SessionStatus {
    /// Unix time of the last PTY output from the agent.
    pub last_output_at: u64,
    /// Currently attached clients.
    pub clients: u32,
}

impl SessionStatus {
    pub fn save(&self, dir: &Path, name: &str) -> Result<()> {
        let json = serde_json::to_vec(self)?;
        fs::write(status_path(dir, name), json)?;
        Ok(())
    }

    pub fn load(dir: &Path, name: &str) -> Result<Self> {
        let bytes = fs::read(status_path(dir, name))?;
        Ok(serde_json::from_slice(&bytes)?)
    }
}

pub(crate) fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Activity {
    Working,
    Idle,
}

/// A missing or unreadable status file classifies as idle rather than
/// erroring, so listings keep working across daemon version skew.
pub fn classify_activity(now: u64, status: Option<&SessionStatus>) -> Activity {
    match status {
        Some(status) if now.saturating_sub(status.last_output_at) <= ACTIVITY_WINDOW_SECS => {
            Activity::Working
        }
        _ => Activity::Idle,
    }
}

/// A live session; attach via `socket_path(dir, &meta.name)`.
pub struct SessionEntry {
    pub meta: SessionMeta,
    pub status: Option<SessionStatus>,
}

fn pid_alive(pid: u32) -> bool {
    if unsafe { libc::kill(pid as libc::pid_t, 0) } == 0 {
        return true;
    }
    // EPERM still proves the pid exists; only ESRCH means it is gone.
    std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM)
}

/// Lists live sessions sorted by name, removing leftovers of dead daemons
/// (crash, SIGKILL) so stale sockets never accumulate.
pub fn list_sessions(dir: &Path) -> Result<Vec<SessionEntry>> {
    let mut entries = Vec::new();
    let read_dir = match fs::read_dir(dir) {
        Ok(read_dir) => read_dir,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(entries),
        Err(error) => return Err(error.into()),
    };
    for item in read_dir.flatten() {
        let path = item.path();
        if path.extension().and_then(|ext| ext.to_str()) != Some("sock") {
            continue;
        }
        let Some(name) = path.file_stem().and_then(|stem| stem.to_str()) else {
            continue;
        };
        match SessionMeta::load(dir, name) {
            Ok(meta) if pid_alive(meta.pid) => {
                let status = SessionStatus::load(dir, name).ok();
                entries.push(SessionEntry { meta, status });
            }
            _ => remove_session_files(dir, name),
        }
    }
    entries.sort_by(|a, b| a.meta.name.cmp(&b.meta.name));
    Ok(entries)
}

pub fn remove_session_files(dir: &Path, name: &str) {
    let _ = fs::remove_file(socket_path(dir, name));
    let _ = fs::remove_file(meta_path(dir, name));
    let _ = fs::remove_file(status_path(dir, name));
}

/// What a keystroke asks the client to do.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum KeyAction {
    /// Send these bytes to the agent.
    Forward(Vec<u8>),
    /// Consumed by the command-mode machinery; send nothing.
    Consumed,
    Detach,
    SwitchNext,
    SwitchPrev,
    /// Detach into the interactive session picker.
    OpenPicker,
}

const ESC: u8 = 0x1b;

/// Longest escape sequence the parser buffers before treating the bytes as
/// ordinary input; real key events are far shorter.
const MAX_SEQ: usize = 32;

/// A decoded kitty-keyboard-protocol `CSI ... u` key event, the encoding
/// terminals such as Ghostty and kitty switch to once the attached agent
/// enables the enhanced keyboard protocol. In that mode `Ctrl-g` arrives as
/// `ESC [ 103 ; 5 u`, never as the legacy `0x07` byte.
enum CsiKey {
    /// `Ctrl-g` (with at most lock modifiers on top).
    ModeKey { press: bool },
    /// An unmodified ASCII key press/repeat.
    Letter(u8),
    /// A key release event (event type 3).
    Release,
    /// A modifier key's own press event (Shift, Ctrl, ...).
    Modifier,
    /// Some other complete escape sequence, `CSI u` or not.
    Other,
}

/// Zellij-style modal keys across reads: `Ctrl-g` enters command mode, where
/// `d` detaches, `n`/`p` switch sessions, `w` opens the session picker, and
/// `g` sends a literal `Ctrl-g` to the agent. `Esc`, `Ctrl-g`, or any other
/// key leaves command mode — the client draws no mode indicator over the
/// agent's screen, so a sticky mode would silently swallow typed text.
///
/// Keys are recognized in both encodings: legacy bytes, and the kitty
/// keyboard protocol's `CSI u` sequences. Release events and modifier-key
/// events (which the protocol reports separately) are swallowed inside
/// command mode instead of cancelling it, so releasing `Ctrl` after
/// `Ctrl-g` does not knock the user out of the mode.
#[derive(Default)]
pub struct ModeParser {
    command_mode: bool,
    /// Partially received escape sequence, held until it can be classified.
    seq: Vec<u8>,
    /// The exact bytes that entered command mode; `g` replays them so the
    /// literal `Ctrl-g` reaches the agent in the encoding it negotiated.
    trigger: Vec<u8>,
}

impl ModeParser {
    pub fn feed(&mut self, byte: u8) -> KeyAction {
        if !self.seq.is_empty() {
            return self.feed_seq(byte);
        }
        if byte == ESC {
            self.seq.push(byte);
            return KeyAction::Consumed;
        }
        if self.command_mode {
            return self.command_key(byte);
        }
        if byte == MODE_KEY {
            self.command_mode = true;
            self.trigger = vec![MODE_KEY];
            return KeyAction::Consumed;
        }
        KeyAction::Forward(vec![byte])
    }

    /// Called at the end of each read burst: a still-incomplete escape
    /// sequence is not going to complete promptly (a bare `Esc` keypress is
    /// the common case), so stop holding it back.
    pub fn flush(&mut self) -> KeyAction {
        if self.seq.is_empty() {
            return KeyAction::Consumed;
        }
        let seq = std::mem::take(&mut self.seq);
        if self.command_mode {
            self.command_mode = false;
            return KeyAction::Consumed;
        }
        KeyAction::Forward(seq)
    }

    fn command_key(&mut self, byte: u8) -> KeyAction {
        self.command_mode = false;
        match byte {
            b'd' => KeyAction::Detach,
            b'n' => KeyAction::SwitchNext,
            b'p' => KeyAction::SwitchPrev,
            b'w' => KeyAction::OpenPicker,
            b'g' => KeyAction::Forward(self.trigger.clone()),
            _ => KeyAction::Consumed,
        }
    }

    fn feed_seq(&mut self, byte: u8) -> KeyAction {
        self.seq.push(byte);
        if self.seq.len() == 2 {
            if byte == b'[' {
                return KeyAction::Consumed;
            }
            // `Esc` followed by an ordinary key (alt-key chord, or a bare
            // escape that a fast typist ran into): not a CSI sequence.
            return self.finish_non_csi();
        }
        if (0x40..=0x7e).contains(&byte) {
            return self.finish_csi();
        }
        if (0x20..=0x3f).contains(&byte) && self.seq.len() < MAX_SEQ {
            return KeyAction::Consumed;
        }
        self.finish_non_csi()
    }

    fn finish_non_csi(&mut self) -> KeyAction {
        let seq = std::mem::take(&mut self.seq);
        if self.command_mode {
            self.command_mode = false;
            return KeyAction::Consumed;
        }
        KeyAction::Forward(seq)
    }

    fn finish_csi(&mut self) -> KeyAction {
        let seq = std::mem::take(&mut self.seq);
        let key = parse_csi_u(&seq);
        if self.command_mode {
            return match key {
                // Releases and modifier presses are protocol noise while the
                // mode is armed; anything else acts or cancels.
                CsiKey::Release | CsiKey::Modifier => KeyAction::Consumed,
                CsiKey::ModeKey { press: true } => {
                    self.command_mode = false;
                    KeyAction::Consumed
                }
                CsiKey::ModeKey { press: false } => KeyAction::Consumed,
                CsiKey::Letter(byte) => self.command_key(byte),
                CsiKey::Other => {
                    self.command_mode = false;
                    KeyAction::Consumed
                }
            };
        }
        match key {
            CsiKey::ModeKey { press: true } => {
                self.command_mode = true;
                self.trigger = seq;
                KeyAction::Consumed
            }
            // Held-key repeats of the toggle must not re-toggle.
            CsiKey::ModeKey { press: false } => KeyAction::Consumed,
            _ => KeyAction::Forward(seq),
        }
    }
}

/// Decodes a complete `ESC [ ... <final>` sequence as a kitty `CSI u` key
/// event: `keycode[:alternates] [; modifiers[:event] [; text]] u`, with
/// modifiers encoded as value − 1 (Ctrl = 4, Caps/Num Lock = 64/128) and
/// event types press/repeat/release = 1/2/3.
fn parse_csi_u(seq: &[u8]) -> CsiKey {
    if seq.last() != Some(&b'u') || seq.len() < 4 {
        return CsiKey::Other;
    }
    let body = &seq[2..seq.len() - 1];
    let mut sections = body.split(|byte| *byte == b';');
    let mut key_fields = sections.next().unwrap_or_default().split(|b| *b == b':');
    let Some(code) = parse_number(key_fields.next().unwrap_or_default()) else {
        return CsiKey::Other;
    };
    let mut mod_fields = sections.next().unwrap_or_default().split(|b| *b == b':');
    let modifiers = parse_number(mod_fields.next().unwrap_or_default())
        .unwrap_or(1)
        .saturating_sub(1);
    let event = parse_number(mod_fields.next().unwrap_or_default()).unwrap_or(1);

    if event == 3 {
        return CsiKey::Release;
    }
    // Kitty functional codepoints for the modifier keys themselves.
    if (57441..=57454).contains(&code) {
        return CsiKey::Modifier;
    }
    let without_locks = modifiers & !(64 | 128);
    if code == u32::from(b'g') && without_locks == 4 {
        return CsiKey::ModeKey { press: event == 1 };
    }
    if code < 128 && without_locks == 0 {
        return CsiKey::Letter(code as u8);
    }
    CsiKey::Other
}

fn parse_number(bytes: &[u8]) -> Option<u32> {
    if bytes.is_empty() || !bytes.iter().all(u8::is_ascii_digit) {
        return None;
    }
    std::str::from_utf8(bytes).ok()?.parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mode_parser_dispatches_commands_and_literals() {
        let mut parser = ModeParser::default();
        assert_eq!(parser.feed(b'a'), KeyAction::Forward(vec![b'a']));
        assert_eq!(parser.feed(MODE_KEY), KeyAction::Consumed);
        assert_eq!(parser.feed(b'd'), KeyAction::Detach);
        assert_eq!(parser.feed(MODE_KEY), KeyAction::Consumed);
        assert_eq!(parser.feed(b'n'), KeyAction::SwitchNext);
        assert_eq!(parser.feed(MODE_KEY), KeyAction::Consumed);
        assert_eq!(parser.feed(b'p'), KeyAction::SwitchPrev);
        assert_eq!(parser.feed(MODE_KEY), KeyAction::Consumed);
        assert_eq!(parser.feed(b'w'), KeyAction::OpenPicker);
        // `g` in command mode sends one literal Ctrl-g.
        assert_eq!(parser.feed(MODE_KEY), KeyAction::Consumed);
        assert_eq!(parser.feed(b'g'), KeyAction::Forward(vec![MODE_KEY]));
        // A doubled Ctrl-g cancels command mode; keys forward again.
        assert_eq!(parser.feed(MODE_KEY), KeyAction::Consumed);
        assert_eq!(parser.feed(MODE_KEY), KeyAction::Consumed);
        assert_eq!(parser.feed(b'd'), KeyAction::Forward(vec![b'd']));
        // Unknown keys leave command mode without reaching the agent.
        assert_eq!(parser.feed(MODE_KEY), KeyAction::Consumed);
        assert_eq!(parser.feed(b'x'), KeyAction::Consumed);
        assert_eq!(parser.feed(b'x'), KeyAction::Forward(vec![b'x']));
    }

    /// Feeds bytes and returns the non-`Consumed` actions in order.
    fn feed_all(parser: &mut ModeParser, bytes: &[u8]) -> Vec<KeyAction> {
        bytes
            .iter()
            .map(|byte| parser.feed(*byte))
            .filter(|action| *action != KeyAction::Consumed)
            .collect()
    }

    #[test]
    fn mode_parser_handles_kitty_protocol_encoding() {
        // Ctrl-g as CSI u (what Ghostty sends under the kitty keyboard
        // protocol) enters command mode; a legacy `d` then detaches.
        let mut parser = ModeParser::default();
        assert!(feed_all(&mut parser, b"\x1b[103;5u").is_empty());
        assert_eq!(parser.feed(b'd'), KeyAction::Detach);

        // With explicit event types: press enters; the key's own release and
        // the Ctrl release are swallowed without cancelling; `w` then acts.
        assert!(feed_all(&mut parser, b"\x1b[103;5:1u").is_empty());
        assert!(feed_all(&mut parser, b"\x1b[103;1:3u").is_empty());
        assert!(feed_all(&mut parser, b"\x1b[57442;1:3u").is_empty());
        assert_eq!(parser.feed(b'w'), KeyAction::OpenPicker);

        // Command keys may themselves arrive CSI-u encoded.
        assert!(feed_all(&mut parser, b"\x1b[103;5u").is_empty());
        assert_eq!(feed_all(&mut parser, b"\x1b[110u"), [KeyAction::SwitchNext]);

        // `g` replays the exact bytes that entered command mode, so the
        // agent receives the literal Ctrl-g in the encoding it negotiated.
        assert!(feed_all(&mut parser, b"\x1b[103;5u").is_empty());
        assert_eq!(
            parser.feed(b'g'),
            KeyAction::Forward(b"\x1b[103;5u".to_vec())
        );

        // An unknown CSI-u press inside command mode cancels it.
        assert!(feed_all(&mut parser, b"\x1b[103;5u").is_empty());
        assert!(feed_all(&mut parser, b"\x1b[97u").is_empty());
        assert_eq!(parser.feed(b'd'), KeyAction::Forward(vec![b'd']));

        // A held toggle repeats (event 2) without re-toggling the mode.
        assert!(feed_all(&mut parser, b"\x1b[103;5:1u").is_empty());
        assert!(feed_all(&mut parser, b"\x1b[103;5:2u").is_empty());
        assert_eq!(parser.feed(b'p'), KeyAction::SwitchPrev);
    }

    #[test]
    fn mode_parser_forwards_unrelated_sequences_untouched() {
        let mut parser = ModeParser::default();
        // Other CSI-u keys (Ctrl-a) and non-u sequences (arrow key, SGR
        // mouse) pass through byte-for-byte.
        for seq in [
            b"\x1b[97;5u".as_slice(),
            b"\x1b[A".as_slice(),
            b"\x1b[<0;33;22M".as_slice(),
        ] {
            assert_eq!(
                feed_all(&mut parser, seq),
                [KeyAction::Forward(seq.to_vec())]
            );
        }
        // Alt-chords come out as Esc plus the key.
        assert_eq!(
            feed_all(&mut parser, b"\x1bx"),
            [KeyAction::Forward(b"\x1bx".to_vec())]
        );
        // A bare Esc is held until the burst ends, then flushed unchanged.
        assert_eq!(parser.feed(0x1b), KeyAction::Consumed);
        assert_eq!(parser.flush(), KeyAction::Forward(vec![0x1b]));
        assert_eq!(parser.flush(), KeyAction::Consumed);
    }

    #[test]
    fn names_are_validated_and_derived_from_cwd() {
        assert!(validate_name("herring-2").is_ok());
        assert!(validate_name("").is_err());
        assert!(validate_name(".hidden").is_err());
        assert!(validate_name("has space").is_err());
        assert!(validate_name("has/slash").is_err());

        assert_eq!(default_name(Path::new("/src/my repo!")), "my-repo");
        assert_eq!(default_name(Path::new("/")), "agent");
    }

    #[test]
    fn unique_name_skips_taken_names() {
        let dir = std::env::temp_dir().join(format!("lyh-session-name-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        assert_eq!(unique_name(&dir, "demo"), "demo");
        fs::write(meta_path(&dir, "demo"), b"{}").unwrap();
        assert_eq!(unique_name(&dir, "demo"), "demo-2");
        fs::write(socket_path(&dir, "demo-2"), b"").unwrap();
        assert_eq!(unique_name(&dir, "demo"), "demo-3");
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn status_round_trips_and_classifies_activity() {
        let dir = std::env::temp_dir().join(format!("lyh-session-status-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();

        let status = SessionStatus {
            last_output_at: 1000,
            clients: 2,
        };
        status.save(&dir, "demo").unwrap();
        let loaded = SessionStatus::load(&dir, "demo").unwrap();
        assert_eq!(loaded.last_output_at, 1000);
        assert_eq!(loaded.clients, 2);

        // Working within the window (inclusive), idle beyond it or unknown.
        assert_eq!(classify_activity(1000, Some(&loaded)), Activity::Working);
        assert_eq!(
            classify_activity(1000 + ACTIVITY_WINDOW_SECS, Some(&loaded)),
            Activity::Working
        );
        assert_eq!(
            classify_activity(1000 + ACTIVITY_WINDOW_SECS + 1, Some(&loaded)),
            Activity::Idle
        );
        assert_eq!(classify_activity(1000, None), Activity::Idle);
        // A clock that ran backwards still reads as working, not a panic.
        assert_eq!(classify_activity(999, Some(&loaded)), Activity::Working);

        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn meta_round_trips_and_stale_sessions_are_cleaned() {
        let dir = std::env::temp_dir().join(format!("lyh-session-meta-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();

        let live = SessionMeta {
            name: "live".to_string(),
            pid: std::process::id(),
            command: vec!["claude".to_string()],
            cwd: "/tmp".to_string(),
            vpn_interface: "utun5".to_string(),
            started_at: 1,
        };
        live.save(&dir).unwrap();
        fs::write(socket_path(&dir, "live"), b"").unwrap();

        // A dead pid marks the session stale; listing reaps its files.
        let stale = SessionMeta {
            pid: 0x7fff_fffe,
            name: "stale".to_string(),
            ..live.clone()
        };
        stale.save(&dir).unwrap();
        fs::write(socket_path(&dir, "stale"), b"").unwrap();

        let sessions = list_sessions(&dir).unwrap();
        assert_eq!(sessions.len(), 1);
        assert_eq!(sessions[0].meta.name, "live");
        assert_eq!(sessions[0].meta.command, ["claude"]);
        assert!(!meta_path(&dir, "stale").exists());
        assert!(!socket_path(&dir, "stale").exists());

        fs::remove_dir_all(&dir).ok();
    }
}
