//! Terminal UI: the inline VPN quick-pick and (eventually) the full config
//! editor. Everything here must leave the terminal exactly as it found it —
//! the launcher hands the very same terminal to the agent via SCM_RIGHTS, so
//! a stray raw mode or hidden cursor breaks the agent's own TUI.

mod editor;
pub mod fallback;
mod quick_pick;
mod theme;

use std::io::{self, Stdout};
use std::sync::Once;
use std::sync::atomic::{AtomicBool, Ordering};

use lianyaohu_core::interfaces::NetworkInterface;
use lianyaohu_core::route::Ipv4Egress;
use lianyaohu_core::{Result, err};
use ratatui::crossterm::terminal::{
    EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode,
};
use ratatui::crossterm::{cursor, execute};
use ratatui::prelude::CrosstermBackend;
use ratatui::{Terminal, TerminalOptions, Viewport};

pub use editor::run_config_editor;
pub use quick_pick::{QuickPickOutcome, quick_pick};

pub fn stdin_is_tty() -> bool {
    unsafe { libc::isatty(libc::STDIN_FILENO) == 1 && libc::isatty(libc::STDOUT_FILENO) == 1 }
}

/// Tracks whether the alternate screen is active so the shared restore path
/// (Drop and panic hook alike) knows to leave it.
static ALT_SCREEN: AtomicBool = AtomicBool::new(false);

/// Restores the terminal even when the TUI panics: without this hook a panic
/// mid-draw leaves the user's shell in raw mode with a hidden cursor.
fn install_panic_hook() {
    static HOOK: Once = Once::new();
    HOOK.call_once(|| {
        let previous = std::panic::take_hook();
        std::panic::set_hook(Box::new(move |info| {
            restore_terminal();
            previous(info);
        }));
    });
}

fn restore_terminal() {
    if ALT_SCREEN.swap(false, Ordering::SeqCst) {
        let _ = execute!(io::stdout(), LeaveAlternateScreen);
    }
    let _ = disable_raw_mode();
    let _ = execute!(io::stdout(), cursor::Show);
}

/// Detail-pane lines shared by the quick-pick and the config editor.
pub(crate) fn interface_detail_lines(
    interface: &NetworkInterface,
    egress: &Ipv4Egress,
) -> Vec<String> {
    if interface.is_proxy_only() {
        return vec![
            "Proxy-only: no VPN interface.".to_string(),
            "All direct egress is blocked (loopback only);".to_string(),
            "outbound traffic must use a local proxy,".to_string(),
            "e.g. http://127.0.0.1:7890 — set it under HTTP proxy.".to_string(),
        ];
    }
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
    // Whether this interface carries all IPv4 egress — decided by the same
    // predicate as the launch preflight (`carries_all_ipv4`), so the picker
    // never shows "yes" for a state the launcher would then refuse. In
    // particular, `egress_interface()` alone is not enough: when the two
    // halves of the address space disagree it falls back to the first
    // default-route entry, which may name this very interface even though
    // part of the traffic leaves elsewhere.
    let egress = if egress.carries_all_ipv4(&interface.name) {
        "yes (carries IPv4 egress)".to_string()
    } else {
        match egress.egress_interface() {
            Some(name) if name != interface.name => format!("no (traffic leaves over {name})"),
            Some(_) => "no (IPv4 egress is split)".to_string(),
            None => "unknown".to_string(),
        }
    };
    vec![
        format!("state:        {state}"),
        format!("ipv4:         {ipv4}"),
        format!("ipv6:         {ipv6}"),
        format!("ipv4 egress:  {egress}"),
    ]
}

/// Raw-mode terminal with an inline viewport (no alternate screen, preserving
/// today's draw-in-place picker UX). Drop restores cooked mode and the cursor
/// before the agent inherits the terminal.
pub struct TerminalGuard {
    pub terminal: Terminal<CrosstermBackend<Stdout>>,
}

impl TerminalGuard {
    pub fn inline(height: u16) -> Result<Self> {
        install_panic_hook();
        enable_raw_mode().map_err(|error| err(format!("terminal raw mode: {error}")))?;
        let backend = CrosstermBackend::new(io::stdout());
        let terminal = Terminal::with_options(
            backend,
            TerminalOptions {
                viewport: Viewport::Inline(height),
            },
        )
        .map_err(|error| {
            restore_terminal();
            err(format!("terminal init: {error}"))
        })?;
        Ok(Self { terminal })
    }

    /// Full-screen variant on the alternate screen, for the config editor.
    pub fn fullscreen() -> Result<Self> {
        install_panic_hook();
        enable_raw_mode().map_err(|error| err(format!("terminal raw mode: {error}")))?;
        if let Err(error) = execute!(io::stdout(), EnterAlternateScreen) {
            restore_terminal();
            return Err(err(format!("alternate screen: {error}")));
        }
        ALT_SCREEN.store(true, Ordering::SeqCst);
        let terminal = Terminal::new(CrosstermBackend::new(io::stdout())).map_err(|error| {
            restore_terminal();
            err(format!("terminal init: {error}"))
        })?;
        Ok(Self { terminal })
    }

    /// Clears the inline viewport so the picker leaves no UI residue above the
    /// launched agent.
    pub fn clear(&mut self) {
        let _ = self.terminal.clear();
    }
}

impl Drop for TerminalGuard {
    fn drop(&mut self) {
        restore_terminal();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn utun(name: &str) -> NetworkInterface {
        NetworkInterface {
            name: name.to_string(),
            flags: (libc::IFF_UP | libc::IFF_RUNNING) as u32,
            ipv4_addresses: vec!["10.7.0.2".to_string()],
            ipv4_peer_addresses: vec!["10.7.0.1".to_string()],
            ipv6_addresses: Vec::new(),
        }
    }

    #[test]
    fn split_egress_never_shows_yes_even_when_the_default_entry_matches() {
        // 0.0.0.0/1 leaves over utun4 (which also holds the default route),
        // but 128.0.0.0/1 leaves over en0. The launcher refuses this state,
        // so the detail pane must not claim utun4 carries IPv4 egress —
        // `egress_interface()` alone would fall back to the default-route
        // entry and name utun4 here.
        let egress = Ipv4Egress {
            default_interfaces: vec!["utun4".to_string()],
            low_half: Some("utun4".to_string()),
            high_half: Some("en0".to_string()),
        };
        let lines = interface_detail_lines(&utun("utun4"), &egress).join("\n");
        assert!(!lines.contains("yes"), "{lines}");
        assert!(lines.contains("no (IPv4 egress is split)"), "{lines}");

        // A consistent tunnel still reads "yes", and another candidate reads
        // "no" naming where traffic actually leaves.
        let egress = Ipv4Egress {
            default_interfaces: vec!["en0".to_string()],
            low_half: Some("utun4".to_string()),
            high_half: Some("utun4".to_string()),
        };
        let lines = interface_detail_lines(&utun("utun4"), &egress).join("\n");
        assert!(lines.contains("yes (carries IPv4 egress)"), "{lines}");
        let lines = interface_detail_lines(&utun("utun9"), &egress).join("\n");
        assert!(lines.contains("no (traffic leaves over utun4)"), "{lines}");

        // Nothing known at all reads "unknown".
        let lines = interface_detail_lines(&utun("utun4"), &Ipv4Egress::default()).join("\n");
        assert!(lines.contains("ipv4 egress:  unknown"), "{lines}");
    }
}
