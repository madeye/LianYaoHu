//! The attach side: raw-mode passthrough between the user's terminal and a
//! session daemon's socket. `Ctrl-b d` detaches, `Ctrl-b n` / `Ctrl-b p`
//! ask the caller to switch sessions, `Ctrl-b w` asks for the session
//! picker, and window resizes are forwarded so the agent always renders at
//! the attached terminal's size.

use std::io::{Read, Write};
use std::os::fd::{AsRawFd, RawFd};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::time::Duration;

use lianyaohu_core::{Result, err};

use super::protocol::{Decoder, Frame};
use super::{KeyAction, PrefixParser};

/// How the attachment ended; switching is resolved by the caller, which
/// knows the full session list.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AttachOutcome {
    Detached,
    Exited(i32),
    /// The daemon vanished without an exit frame (crash, external kill).
    SessionClosed,
    SwitchNext,
    SwitchPrev,
    /// Detached toward the interactive session picker.
    OpenPicker,
}

/// Restores the caller's termios on drop — the terminal is handed back to
/// the shell exactly as it was, panic or not.
struct RawTerminal {
    original: libc::termios,
}

impl RawTerminal {
    fn enable() -> Result<Self> {
        let mut original = unsafe { std::mem::zeroed::<libc::termios>() };
        if unsafe { libc::tcgetattr(libc::STDIN_FILENO, &mut original) } != 0 {
            return Err(err("stdin is not a terminal"));
        }
        let mut raw = original;
        unsafe {
            libc::cfmakeraw(&mut raw);
            if libc::tcsetattr(libc::STDIN_FILENO, libc::TCSANOW, &raw) != 0 {
                return Err(err(format!(
                    "tcsetattr: {}",
                    std::io::Error::last_os_error()
                )));
            }
        }
        Ok(Self { original })
    }
}

impl Drop for RawTerminal {
    fn drop(&mut self) {
        unsafe {
            libc::tcsetattr(libc::STDIN_FILENO, libc::TCSANOW, &self.original);
        }
    }
}

fn terminal_size() -> (u16, u16) {
    let mut size = libc::winsize {
        ws_row: 0,
        ws_col: 0,
        ws_xpixel: 0,
        ws_ypixel: 0,
    };
    if unsafe { libc::ioctl(libc::STDOUT_FILENO, libc::TIOCGWINSZ, &mut size) } == 0
        && size.ws_row > 0
        && size.ws_col > 0
    {
        (size.ws_row, size.ws_col)
    } else {
        (24, 80)
    }
}

/// Returns the current terminal size for seeding a new session's PTY.
pub fn initial_winsize() -> (u16, u16) {
    terminal_size()
}

fn pollfd(fd: RawFd) -> libc::pollfd {
    libc::pollfd {
        fd,
        events: libc::POLLIN,
        revents: 0,
    }
}

/// Attaches to a session socket until detach, switch, or agent exit.
pub fn attach(socket: &Path, name: &str) -> Result<AttachOutcome> {
    let mut stream = UnixStream::connect(socket)
        .map_err(|error| err(format!("cannot attach to session {name}: {error}")))?;
    stream.set_write_timeout(Some(Duration::from_secs(5)))?;
    unsafe {
        libc::signal(libc::SIGPIPE, libc::SIG_IGN);
    }

    println!("[lyh] attached to {name} — Ctrl-b d detach · Ctrl-b w sessions · Ctrl-b n/p switch");
    let raw = RawTerminal::enable()?;

    let mut size = terminal_size();
    stream.write_all(
        &Frame::Resize {
            rows: size.0,
            cols: size.1,
        }
        .encode(),
    )?;

    let mut parser = PrefixParser::default();
    let mut decoder = Decoder::default();
    let outcome = loop {
        let mut fds = [pollfd(libc::STDIN_FILENO), pollfd(stream.as_raw_fd())];
        let rc = unsafe { libc::poll(fds.as_mut_ptr(), fds.len() as _, 250) };
        if rc < 0 {
            let error = std::io::Error::last_os_error();
            if error.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            break AttachOutcome::Detached;
        }

        // Timeout tick doubles as the resize watcher: no SIGWINCH handler
        // needed, a 250ms poll of TIOCGWINSZ is plenty for a human resize.
        let current = terminal_size();
        if current != size {
            size = current;
            let _ = stream.write_all(
                &Frame::Resize {
                    rows: size.0,
                    cols: size.1,
                }
                .encode(),
            );
        }

        if fds[0].revents & (libc::POLLIN | libc::POLLHUP | libc::POLLERR) != 0 {
            let mut buffer = [0u8; 1024];
            let read =
                unsafe { libc::read(libc::STDIN_FILENO, buffer.as_mut_ptr().cast(), buffer.len()) };
            if read <= 0 {
                break AttachOutcome::Detached;
            }
            let mut forward = Vec::new();
            let mut command = None;
            for byte in &buffer[..read as usize] {
                match parser.feed(*byte) {
                    KeyAction::Forward(mut bytes) => forward.append(&mut bytes),
                    KeyAction::Pending => {}
                    KeyAction::Detach => {
                        command = Some(AttachOutcome::Detached);
                        break;
                    }
                    KeyAction::SwitchNext => {
                        command = Some(AttachOutcome::SwitchNext);
                        break;
                    }
                    KeyAction::SwitchPrev => {
                        command = Some(AttachOutcome::SwitchPrev);
                        break;
                    }
                    KeyAction::OpenPicker => {
                        command = Some(AttachOutcome::OpenPicker);
                        break;
                    }
                }
            }
            if !forward.is_empty() && stream.write_all(&Frame::Input(forward).encode()).is_err() {
                break AttachOutcome::SessionClosed;
            }
            if let Some(outcome) = command {
                break outcome;
            }
        }

        if fds[1].revents & (libc::POLLIN | libc::POLLHUP | libc::POLLERR) != 0 {
            let mut buffer = [0u8; 8192];
            match stream.read(&mut buffer) {
                Ok(0) => break AttachOutcome::SessionClosed,
                Ok(read) => decoder.push(&buffer[..read]),
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(_) => break AttachOutcome::SessionClosed,
            }
            let mut stdout = std::io::stdout().lock();
            let outcome = loop {
                match decoder.next() {
                    Ok(Some(Frame::Output(bytes))) => {
                        if stdout.write_all(&bytes).is_err() {
                            break Some(AttachOutcome::Detached);
                        }
                    }
                    Ok(Some(Frame::Exited(code))) => break Some(AttachOutcome::Exited(code)),
                    Ok(Some(_)) | Err(_) => break Some(AttachOutcome::SessionClosed),
                    Ok(None) => break None,
                }
            };
            let _ = stdout.flush();
            if let Some(outcome) = outcome {
                break outcome;
            }
        }
    };

    drop(raw);
    // Raw mode leaves the cursor mid-line; start the caller's next message
    // cleanly.
    println!();
    Ok(outcome)
}

/// Asks a session daemon to terminate its agent, waiting briefly for the
/// exit notification. Returns the agent's exit code if it was reported.
pub fn kill(socket: &Path, name: &str) -> Result<Option<i32>> {
    let mut stream = UnixStream::connect(socket)
        .map_err(|error| err(format!("cannot reach session {name}: {error}")))?;
    stream.set_write_timeout(Some(Duration::from_secs(5)))?;
    stream.set_read_timeout(Some(Duration::from_secs(10)))?;
    stream.write_all(&Frame::Kill.encode())?;
    let mut decoder = Decoder::default();
    let mut buffer = [0u8; 8192];
    loop {
        match stream.read(&mut buffer) {
            Ok(0) => return Ok(None),
            Ok(read) => decoder.push(&buffer[..read]),
            Err(_) => return Ok(None),
        }
        while let Ok(Some(frame)) = decoder.next() {
            if let Frame::Exited(code) = frame {
                return Ok(Some(code));
            }
        }
    }
}
