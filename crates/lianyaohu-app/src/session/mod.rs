//! Background agent sessions: each `lyh run` forks a small per-session
//! daemon that owns a PTY and a Unix socket, dtach-style. Clients attach to
//! stream the terminal, detach with `Ctrl-\ d`, and switch between live
//! sessions with `Ctrl-\ n` / `Ctrl-\ p`. One daemon per session keeps every
//! agent in its own sandbox with no shared multiplexer state.

pub mod client;
pub mod daemon;
pub mod protocol;

use std::env;
use std::fs;
use std::path::{Path, PathBuf};

use lianyaohu_core::{Result, err};
use serde::{Deserialize, Serialize};

/// The detach/switch prefix key: `Ctrl-\`.
pub const PREFIX_KEY: u8 = 0x1c;

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

/// A live session; attach via `socket_path(dir, &meta.name)`.
pub struct SessionEntry {
    pub meta: SessionMeta,
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
            Ok(meta) if pid_alive(meta.pid) => entries.push(SessionEntry { meta }),
            _ => remove_session_files(dir, name),
        }
    }
    entries.sort_by(|a, b| a.meta.name.cmp(&b.meta.name));
    Ok(entries)
}

pub fn remove_session_files(dir: &Path, name: &str) {
    let _ = fs::remove_file(socket_path(dir, name));
    let _ = fs::remove_file(meta_path(dir, name));
}

/// What a prefixed keystroke asks the client to do.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum KeyAction {
    /// Send these bytes to the agent.
    Forward(Vec<u8>),
    /// Waiting for the byte after the prefix; send nothing yet.
    Pending,
    Detach,
    SwitchNext,
    SwitchPrev,
}

/// Tracks the `Ctrl-\` prefix across reads: `Ctrl-\ d` detaches, `n`/`p`
/// switch sessions, a doubled `Ctrl-\` sends the literal byte, and any other
/// follow-up key forwards both bytes unchanged.
#[derive(Default)]
pub struct PrefixParser {
    pending: bool,
}

impl PrefixParser {
    pub fn feed(&mut self, byte: u8) -> KeyAction {
        if self.pending {
            self.pending = false;
            return match byte {
                b'd' => KeyAction::Detach,
                b'n' => KeyAction::SwitchNext,
                b'p' => KeyAction::SwitchPrev,
                PREFIX_KEY => KeyAction::Forward(vec![PREFIX_KEY]),
                other => KeyAction::Forward(vec![PREFIX_KEY, other]),
            };
        }
        if byte == PREFIX_KEY {
            self.pending = true;
            return KeyAction::Pending;
        }
        KeyAction::Forward(vec![byte])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prefix_parser_dispatches_commands_and_literals() {
        let mut parser = PrefixParser::default();
        assert_eq!(parser.feed(b'a'), KeyAction::Forward(vec![b'a']));
        assert_eq!(parser.feed(PREFIX_KEY), KeyAction::Pending);
        assert_eq!(parser.feed(b'd'), KeyAction::Detach);
        assert_eq!(parser.feed(PREFIX_KEY), KeyAction::Pending);
        assert_eq!(parser.feed(b'n'), KeyAction::SwitchNext);
        assert_eq!(parser.feed(PREFIX_KEY), KeyAction::Pending);
        assert_eq!(parser.feed(b'p'), KeyAction::SwitchPrev);
        // Doubled prefix sends one literal Ctrl-\.
        assert_eq!(parser.feed(PREFIX_KEY), KeyAction::Pending);
        assert_eq!(
            parser.feed(PREFIX_KEY),
            KeyAction::Forward(vec![PREFIX_KEY])
        );
        // Unknown follow-ups forward both bytes.
        assert_eq!(parser.feed(PREFIX_KEY), KeyAction::Pending);
        assert_eq!(
            parser.feed(b'x'),
            KeyAction::Forward(vec![PREFIX_KEY, b'x'])
        );
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
