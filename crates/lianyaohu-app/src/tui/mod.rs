//! Terminal UI: the inline VPN quick-pick and (eventually) the full config
//! editor. Everything here must leave the terminal exactly as it found it —
//! the launcher hands the very same terminal to the agent via SCM_RIGHTS, so
//! a stray raw mode or hidden cursor breaks the agent's own TUI.

pub mod fallback;
mod quick_pick;

use std::io::{self, Stdout};
use std::sync::Once;

use lianyaohu_core::{Result, err};
use ratatui::crossterm::terminal::{disable_raw_mode, enable_raw_mode};
use ratatui::crossterm::{cursor, execute};
use ratatui::prelude::CrosstermBackend;
use ratatui::{Terminal, TerminalOptions, Viewport};

pub use quick_pick::{QuickPickOutcome, quick_pick};

pub fn stdin_is_tty() -> bool {
    unsafe { libc::isatty(libc::STDIN_FILENO) == 1 && libc::isatty(libc::STDOUT_FILENO) == 1 }
}

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
    let _ = disable_raw_mode();
    let _ = execute!(io::stdout(), cursor::Show);
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
