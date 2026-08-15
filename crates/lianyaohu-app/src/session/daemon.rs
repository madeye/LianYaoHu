//! The per-session daemon: owns the PTY master and the session socket,
//! pumps agent output to attached clients (keeping a scrollback buffer for
//! replay), and forwards client input, resizes, and kill requests. One
//! daemon per session, dtach-style; it exits when the agent does.

use std::fs::OpenOptions;
use std::io::{Read, Write};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;
use std::time::Duration;

use lianyaohu_core::{Result, err};

use super::protocol::{Decoder, Frame};
use super::remove_session_files;

/// Replayed to a freshly attached client so the screen is not blank before
/// the forced redraw kicks in.
const SCROLLBACK_LIMIT: usize = 128 * 1024;

/// A client that stops draining (SIGSTOP, dead link) must not wedge the
/// daemon; writes that block this long drop the client instead.
const CLIENT_WRITE_TIMEOUT: Duration = Duration::from_secs(5);

/// The running agent as the daemon loop sees it: a pipe that yields the exit
/// code, and a best-effort terminate hook. How the agent was launched
/// (root-helper session or direct sandbox spawn) is the caller's business.
pub struct AgentHandle {
    pub exit_pipe: OwnedFd,
    pub kill: Box<dyn FnMut() + Send>,
}

/// Opens a PTY pair with the given initial size; the master is set
/// non-blocking for the poll loop.
pub fn open_pty(rows: u16, cols: u16) -> Result<(OwnedFd, OwnedFd)> {
    let mut master: libc::c_int = -1;
    let mut slave: libc::c_int = -1;
    let mut size = libc::winsize {
        ws_row: rows,
        ws_col: cols,
        ws_xpixel: 0,
        ws_ypixel: 0,
    };
    // Raw pointer, not `&mut`: Linux libc declares `winp` as `*const winsize`
    // (macOS keeps `*mut`), and a `&mut` argument trips
    // clippy::unnecessary_mut_passed there.
    let winp: *mut libc::winsize = &mut size;
    let rc = unsafe {
        libc::openpty(
            &mut master,
            &mut slave,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            winp,
        )
    };
    if rc != 0 {
        return Err(err(format!("openpty: {}", std::io::Error::last_os_error())));
    }
    let master = unsafe { OwnedFd::from_raw_fd(master) };
    let slave = unsafe { OwnedFd::from_raw_fd(slave) };
    set_nonblocking(master.as_raw_fd())?;
    Ok((master, slave))
}

fn set_nonblocking(fd: RawFd) -> Result<()> {
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 || unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
        return Err(err(format!(
            "fcntl O_NONBLOCK: {}",
            std::io::Error::last_os_error()
        )));
    }
    Ok(())
}

pub fn set_winsize(master: RawFd, rows: u16, cols: u16) {
    let size = libc::winsize {
        ws_row: rows,
        ws_col: cols,
        ws_xpixel: 0,
        ws_ypixel: 0,
    };
    unsafe {
        libc::ioctl(master, libc::TIOCSWINSZ, &size);
    }
}

/// An OS pipe whose write end a waiter thread uses to report the agent's
/// exit code into the poll loop.
pub fn exit_pipe() -> Result<(OwnedFd, OwnedFd)> {
    let mut fds = [0 as libc::c_int; 2];
    if unsafe { libc::pipe(fds.as_mut_ptr()) } != 0 {
        return Err(err(format!("pipe: {}", std::io::Error::last_os_error())));
    }
    Ok(unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) })
}

/// Runs `wait` on a thread and writes its exit code to the pipe. The thread
/// is detached: the daemon exits right after consuming the code.
pub fn spawn_exit_waiter(write_end: OwnedFd, wait: impl FnOnce() -> i32 + Send + 'static) {
    std::thread::spawn(move || {
        let code = wait();
        let bytes = code.to_be_bytes();
        unsafe {
            libc::write(write_end.as_raw_fd(), bytes.as_ptr().cast(), bytes.len());
        }
        drop(write_end);
    });
}

/// Double-forks into a background daemon. Returns `Ok(false)` in the caller
/// (which must not touch the terminal state the daemon inherited) and
/// `Ok(true)` in the daemon, with stdio redirected to `log`.
pub fn daemonize(log: &Path) -> Result<bool> {
    unsafe {
        match libc::fork() {
            -1 => return Err(err(format!("fork: {}", std::io::Error::last_os_error()))),
            0 => {}
            child => {
                // Reap the intermediate child so the daemon is re-parented
                // to init and never becomes our zombie.
                let mut status = 0;
                libc::waitpid(child, &mut status, 0);
                return Ok(false);
            }
        }
        // Intermediate child: leave the caller's session, then fork again so
        // the daemon is not a session leader (it must never accidentally
        // acquire a controlling terminal).
        if libc::setsid() == -1 {
            libc::_exit(1);
        }
        match libc::fork() {
            -1 => libc::_exit(1),
            0 => {}
            _ => libc::_exit(0),
        }
        libc::signal(libc::SIGPIPE, libc::SIG_IGN);
        libc::signal(libc::SIGHUP, libc::SIG_IGN);
    }

    let devnull = OpenOptions::new().read(true).open("/dev/null")?;
    let logfile = OpenOptions::new()
        .create(true)
        .append(true)
        .mode(0o600)
        .open(log)?;
    unsafe {
        libc::dup2(devnull.as_raw_fd(), 0);
        libc::dup2(logfile.as_raw_fd(), 1);
        libc::dup2(logfile.as_raw_fd(), 2);
    }
    Ok(true)
}

struct Client {
    stream: UnixStream,
    decoder: Decoder,
}

/// The daemon event loop. Returns the agent's exit code after cleaning up
/// the session's socket and metadata files.
pub fn run_loop(
    dir: &Path,
    name: &str,
    listener: UnixListener,
    master: OwnedFd,
    mut agent: AgentHandle,
) -> i32 {
    let _ = listener.set_nonblocking(true);
    let mut master = Some(master);
    let mut clients: Vec<Client> = Vec::new();
    let mut scrollback: Vec<u8> = Vec::new();
    let mut current_size: Option<(u16, u16)> = None;
    let mut exit_code: Option<i32> = None;

    while exit_code.is_none() {
        let mut poll_fds: Vec<libc::pollfd> = Vec::with_capacity(3 + clients.len());
        poll_fds.push(pollfd(listener.as_raw_fd()));
        poll_fds.push(pollfd(agent.exit_pipe.as_raw_fd()));
        let master_index = master.as_ref().map(|fd| {
            poll_fds.push(pollfd(fd.as_raw_fd()));
            poll_fds.len() - 1
        });
        let client_base = poll_fds.len();
        for client in &clients {
            poll_fds.push(pollfd(client.stream.as_raw_fd()));
        }

        let rc = unsafe { libc::poll(poll_fds.as_mut_ptr(), poll_fds.len() as _, -1) };
        if rc < 0 {
            let error = std::io::Error::last_os_error();
            if error.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            eprintln!("session {name}: poll failed: {error}");
            break;
        }

        // New attach: replay scrollback; the client's follow-up Resize frame
        // forces a redraw for full-screen agents.
        if readable(&poll_fds[0]) {
            while let Ok((stream, _)) = listener.accept() {
                let _ = stream.set_write_timeout(Some(CLIENT_WRITE_TIMEOUT));
                let mut client = Client {
                    stream,
                    decoder: Decoder::default(),
                };
                let replay = Frame::Output(scrollback.clone()).encode();
                if client.stream.write_all(&replay).is_ok() {
                    clients.push(client);
                }
            }
        }

        if readable(&poll_fds[1]) {
            exit_code = Some(read_exit_code(agent.exit_pipe.as_raw_fd()));
        }

        if let Some(index) = master_index
            && readable(&poll_fds[index])
            && let Some(fd) = &master
        {
            match drain_master(fd.as_raw_fd(), &mut scrollback, &mut clients) {
                MasterState::Open => {}
                MasterState::Closed => master = None,
            }
        }

        // Walk clients back-to-front so dropping one cannot shift the poll
        // indices of those not yet visited.
        for offset in (0..clients.len()).rev() {
            let Some(entry) = poll_fds.get(client_base + offset) else {
                continue;
            };
            if !readable(entry) {
                continue;
            }
            if !service_client(
                &mut clients[offset],
                &mut master,
                &mut current_size,
                &mut agent,
            ) {
                clients.remove(offset);
            }
        }
    }

    let code = exit_code.unwrap_or(1);
    // The agent may have written final output between the last drain and its
    // exit; flush whatever the PTY still holds.
    if let Some(fd) = &master {
        let _ = drain_master(fd.as_raw_fd(), &mut scrollback, &mut clients);
    }
    let farewell = Frame::Exited(code).encode();
    for client in &mut clients {
        let _ = client.stream.write_all(&farewell);
    }
    remove_session_files(dir, name);
    code
}

fn pollfd(fd: RawFd) -> libc::pollfd {
    libc::pollfd {
        fd,
        events: libc::POLLIN,
        revents: 0,
    }
}

fn readable(entry: &libc::pollfd) -> bool {
    entry.revents & (libc::POLLIN | libc::POLLHUP | libc::POLLERR) != 0
}

fn read_exit_code(fd: RawFd) -> i32 {
    let mut bytes = [0u8; 4];
    let read = unsafe { libc::read(fd, bytes.as_mut_ptr().cast(), bytes.len()) };
    if read == bytes.len() as isize {
        i32::from_be_bytes(bytes)
    } else {
        1
    }
}

enum MasterState {
    Open,
    Closed,
}

fn drain_master(fd: RawFd, scrollback: &mut Vec<u8>, clients: &mut Vec<Client>) -> MasterState {
    let mut buffer = [0u8; 8192];
    loop {
        let read = unsafe { libc::read(fd, buffer.as_mut_ptr().cast(), buffer.len()) };
        if read > 0 {
            let chunk = &buffer[..read as usize];
            scrollback.extend_from_slice(chunk);
            if scrollback.len() > SCROLLBACK_LIMIT {
                let excess = scrollback.len() - SCROLLBACK_LIMIT;
                scrollback.drain(..excess);
            }
            broadcast(clients, &Frame::Output(chunk.to_vec()));
            continue;
        }
        if read == 0 {
            return MasterState::Closed;
        }
        let error = std::io::Error::last_os_error();
        return match error.kind() {
            std::io::ErrorKind::WouldBlock => MasterState::Open,
            std::io::ErrorKind::Interrupted => continue,
            // EIO: every slave fd is closed — the agent is gone.
            _ => MasterState::Closed,
        };
    }
}

fn broadcast(clients: &mut Vec<Client>, frame: &Frame) {
    let encoded = frame.encode();
    clients.retain_mut(|client| client.stream.write_all(&encoded).is_ok());
}

/// Reads and applies one batch of frames from a client. Returns `false` when
/// the client should be dropped.
fn service_client(
    client: &mut Client,
    master: &mut Option<OwnedFd>,
    current_size: &mut Option<(u16, u16)>,
    agent: &mut AgentHandle,
) -> bool {
    let mut buffer = [0u8; 4096];
    let read = match client.stream.read(&mut buffer) {
        Ok(0) => return false,
        Ok(read) => read,
        Err(error) if error.kind() == std::io::ErrorKind::Interrupted => return true,
        Err(_) => return false,
    };
    client.decoder.push(&buffer[..read]);
    loop {
        match client.decoder.next() {
            Ok(None) => return true,
            Err(_) => return false,
            Ok(Some(Frame::Input(bytes))) => {
                if let Some(fd) = master {
                    write_master(fd.as_raw_fd(), &bytes);
                }
            }
            Ok(Some(Frame::Resize { rows, cols })) => {
                if let Some(fd) = master {
                    if *current_size == Some((rows, cols)) {
                        // Same size would deliver no SIGWINCH; jiggle it so
                        // full-screen agents repaint for the new attach.
                        set_winsize(fd.as_raw_fd(), rows.saturating_sub(1).max(1), cols);
                    }
                    set_winsize(fd.as_raw_fd(), rows, cols);
                    *current_size = Some((rows, cols));
                }
            }
            Ok(Some(Frame::Kill)) => {
                (agent.kill)();
                // Closing the master hangs up the PTY: agents exit on
                // EOF/SIGHUP even when launched by the root helper, where
                // the daemon has no pid to signal.
                *master = None;
            }
            // Daemon-bound frames only; a client sending daemon→client
            // frames is confused — drop it.
            Ok(Some(Frame::Output(_) | Frame::Exited(_))) => return false,
        }
    }
}

/// Blocking write to the non-blocking master: short waits for a full PTY
/// buffer (large paste), giving up only if the PTY stays wedged.
fn write_master(fd: RawFd, mut bytes: &[u8]) {
    while !bytes.is_empty() {
        let written = unsafe { libc::write(fd, bytes.as_ptr().cast(), bytes.len()) };
        if written > 0 {
            bytes = &bytes[written as usize..];
            continue;
        }
        let error = std::io::Error::last_os_error();
        match error.kind() {
            std::io::ErrorKind::Interrupted => continue,
            std::io::ErrorKind::WouldBlock => {
                let mut entry = libc::pollfd {
                    fd,
                    events: libc::POLLOUT,
                    revents: 0,
                };
                if unsafe { libc::poll(&mut entry, 1, 1000) } <= 0 {
                    return;
                }
            }
            _ => return,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::session::{SessionMeta, meta_path, socket_path};
    use std::fs;
    use std::process::{Command, Stdio};

    fn read_frames(stream: &mut UnixStream, decoder: &mut Decoder) -> Vec<Frame> {
        let mut buffer = [0u8; 4096];
        let mut frames = Vec::new();
        match stream.read(&mut buffer) {
            Ok(read) if read > 0 => decoder.push(&buffer[..read]),
            _ => return frames,
        }
        while let Ok(Some(frame)) = decoder.next() {
            frames.push(frame);
        }
        frames
    }

    /// End-to-end over a real PTY and socket, with a plain (unsandboxed)
    /// `cat` standing in for the agent: attach, echo round-trip, scrollback
    /// replay for a second client, kill, exit notification, file cleanup.
    #[test]
    fn daemon_loop_round_trips_io_and_cleans_up() {
        let dir = std::env::temp_dir().join(format!("lyh-daemon-test-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let name = "t";
        let socket = socket_path(&dir, name);
        let _ = fs::remove_file(&socket);
        let listener = UnixListener::bind(&socket).unwrap();
        SessionMeta {
            name: name.to_string(),
            pid: std::process::id(),
            command: vec!["cat".to_string()],
            cwd: "/".to_string(),
            vpn_interface: "utun0".to_string(),
            started_at: 0,
        }
        .save(&dir)
        .unwrap();

        let (master, slave) = open_pty(24, 80).unwrap();
        let mut child = Command::new("/bin/cat")
            .stdin(Stdio::from(std::fs::File::from(slave.try_clone().unwrap())))
            .stdout(Stdio::from(std::fs::File::from(slave.try_clone().unwrap())))
            .stderr(Stdio::from(std::fs::File::from(slave)))
            .spawn()
            .unwrap();
        let pid = child.id() as libc::pid_t;

        let (exit_read, exit_write) = exit_pipe().unwrap();
        spawn_exit_waiter(exit_write, move || {
            child
                .wait()
                .ok()
                .and_then(|status| status.code())
                .unwrap_or(0)
        });
        let agent = AgentHandle {
            exit_pipe: exit_read,
            kill: Box::new(move || unsafe {
                libc::kill(pid, libc::SIGHUP);
            }),
        };

        let loop_dir = dir.clone();
        let handle = std::thread::spawn(move || run_loop(&loop_dir, "t", listener, master, agent));

        let mut first = UnixStream::connect(&socket).unwrap();
        first
            .set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        let mut first_decoder = Decoder::default();
        first
            .write_all(&Frame::Resize { rows: 24, cols: 80 }.encode())
            .unwrap();
        first
            .write_all(&Frame::Input(b"hello-pty\r".to_vec()).encode())
            .unwrap();

        // The PTY echoes input; wait until it comes back through the daemon.
        let mut seen = Vec::new();
        for _ in 0..50 {
            for frame in read_frames(&mut first, &mut first_decoder) {
                if let Frame::Output(bytes) = frame {
                    seen.extend_from_slice(&bytes);
                }
            }
            if String::from_utf8_lossy(&seen).contains("hello-pty") {
                break;
            }
        }
        assert!(
            String::from_utf8_lossy(&seen).contains("hello-pty"),
            "echo did not round-trip: {seen:?}"
        );

        // A second client gets the scrollback replayed on attach.
        let mut second = UnixStream::connect(&socket).unwrap();
        second
            .set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        let mut second_decoder = Decoder::default();
        let mut replay = Vec::new();
        for _ in 0..50 {
            for frame in read_frames(&mut second, &mut second_decoder) {
                if let Frame::Output(bytes) = frame {
                    replay.extend_from_slice(&bytes);
                }
            }
            if String::from_utf8_lossy(&replay).contains("hello-pty") {
                break;
            }
        }
        assert!(
            String::from_utf8_lossy(&replay).contains("hello-pty"),
            "scrollback was not replayed: {replay:?}"
        );

        // Kill tears the agent down; both clients hear about the exit and
        // the session files disappear.
        first.write_all(&Frame::Kill.encode()).unwrap();
        let mut exited = false;
        for _ in 0..50 {
            if read_frames(&mut first, &mut first_decoder)
                .iter()
                .any(|frame| matches!(frame, Frame::Exited(_)))
            {
                exited = true;
                break;
            }
        }
        assert!(exited, "no exit notification after kill");
        handle.join().unwrap();
        assert!(!socket.exists());
        assert!(!meta_path(&dir, name).exists());

        fs::remove_dir_all(&dir).ok();
    }
}
