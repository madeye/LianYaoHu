use crate::policy::NetworkPolicy;
use crate::{Result, err};
use std::io::{Read, Write};
use std::net::Shutdown;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::{io, mem, ptr};

pub const SOCKET_PATH: &str = "/var/run/lianyaohu-helper.sock";
pub const DAEMON_LABEL: &str = "io.github.madeye.lianyaohu.helper";

pub struct PFHelperClient {
    socket_path: String,
}

impl PFHelperClient {
    pub fn new(socket_path: impl Into<String>) -> Self {
        Self {
            socket_path: socket_path.into(),
        }
    }

    pub fn install(&self, interface_name: &str, network: &NetworkPolicy) -> Result<()> {
        let response = self.send(&install_request(interface_name, network)?)?;
        if response.ok {
            Ok(())
        } else {
            Err(err(response.message))
        }
    }

    pub fn uninstall(&self) -> Result<()> {
        let response = self.send("uninstall\n")?;
        if response.ok {
            Ok(())
        } else {
            Err(err(response.message))
        }
    }

    pub fn status(&self) -> Result<HelperResponse> {
        self.send("status\n")
    }

    /// Probes whether the running helper understands versioned launch specs
    /// with a custom sandbox policy. An old helper answers the unknown verb
    /// with an error line — that error IS the negative signal, so this returns
    /// `Ok(false)` for it and only propagates transport failures.
    pub fn supports_policy(&self) -> Result<bool> {
        self.supports_capability("policy=1")
    }

    /// Probes whether the running helper applies a client-supplied network
    /// policy to `install` requests. A helper that predates this token would
    /// install the default (weaker) rules and report success, so callers with
    /// a non-default policy must not send `install` without checking first.
    pub fn supports_install_policy(&self) -> Result<bool> {
        self.supports_capability("install_policy=1")
    }

    fn supports_capability(&self, token: &str) -> Result<bool> {
        let response = self.send("capabilities\n")?;
        Ok(response.ok
            && response
                .message
                .split_whitespace()
                .any(|candidate| candidate == token))
    }

    pub fn run_session(&self, interface_name: &str, spec_path: &Path) -> Result<i32> {
        self.run_session_with_fds(
            interface_name,
            spec_path,
            [libc::STDIN_FILENO, libc::STDOUT_FILENO, libc::STDERR_FILENO],
        )
    }

    /// Like [`run_session`], but hands the helper an arbitrary stdio triple
    /// instead of this process' own terminal — the background session daemon
    /// passes its PTY slave three times so the agent runs on the session PTY.
    pub fn run_session_with_fds(
        &self,
        interface_name: &str,
        spec_path: &Path,
        stdio: [RawFd; 3],
    ) -> Result<i32> {
        let spec_path = spec_path
            .to_str()
            .ok_or_else(|| err("launch spec path is not valid UTF-8"))?;
        if spec_path.contains(char::is_whitespace) {
            return Err(err("launch spec path cannot contain whitespace"));
        }
        let response =
            self.send_with_fds(&format!("run {interface_name} {spec_path}\n"), &stdio)?;
        if !response.ok {
            return Err(err(response.message));
        }
        let Some(code) = response
            .message
            .strip_prefix("exit ")
            .and_then(|value| value.parse::<i32>().ok())
        else {
            return Err(err(format!(
                "invalid helper run response: {:?}",
                response.message
            )));
        };
        Ok(code)
    }

    fn send(&self, request: &str) -> Result<HelperResponse> {
        let socket_path = if self.socket_path.is_empty() {
            SOCKET_PATH
        } else {
            &self.socket_path
        };
        let mut stream = UnixStream::connect(socket_path)?;
        stream.write_all(request.as_bytes())?;
        stream.shutdown(Shutdown::Write)?;

        let mut response = String::new();
        stream.read_to_string(&mut response)?;
        parse_response(&response)
    }

    fn send_with_fds(&self, request: &str, fds: &[RawFd]) -> Result<HelperResponse> {
        let socket_path = if self.socket_path.is_empty() {
            SOCKET_PATH
        } else {
            &self.socket_path
        };
        let mut stream = UnixStream::connect(socket_path)?;
        send_message_with_fds(&stream, request.as_bytes(), fds)?;
        stream.shutdown(Shutdown::Write)?;

        let mut response = String::new();
        stream.read_to_string(&mut response)?;
        parse_response(&response)
    }
}

#[derive(Debug, Eq, PartialEq)]
pub struct HelperResponse {
    pub ok: bool,
    pub message: String,
}

pub fn parse_response(response: &str) -> Result<HelperResponse> {
    if let Some(message) = response.strip_prefix("ok ") {
        return Ok(HelperResponse {
            ok: true,
            message: message.trim_end().to_string(),
        });
    }
    if let Some(message) = response.strip_prefix("error ") {
        return Ok(HelperResponse {
            ok: false,
            message: message.trim_end().to_string(),
        });
    }
    Err(err(format!("invalid helper response: {response:?}")))
}

/// Builds the wire form of an `install` request. The default policy keeps the
/// legacy single-token form so old and new helpers behave identically; a
/// non-default policy is appended as compact JSON (no whitespace — typed
/// addresses, prefixes, and ports only), which a helper without
/// `install_policy` support rejects rather than silently ignoring.
pub fn install_request(interface_name: &str, network: &NetworkPolicy) -> Result<String> {
    if *network == NetworkPolicy::default() {
        return Ok(format!("install {interface_name}\n"));
    }
    let policy = serde_json::to_string(network)
        .map_err(|error| err(format!("serialize network policy: {error}")))?;
    Ok(format!("install {interface_name} {policy}\n"))
}

pub fn parse_request(line: &str) -> Result<HelperRequest> {
    let trimmed = line.trim();
    if trimmed == "uninstall" {
        return Ok(HelperRequest::Uninstall);
    }
    if trimmed == "status" {
        return Ok(HelperRequest::Status);
    }
    if trimmed == "capabilities" {
        return Ok(HelperRequest::Capabilities);
    }
    if let Some(rest) = trimmed.strip_prefix("install ") {
        let (interface_name, policy_json) = match rest.split_once(' ') {
            Some((interface_name, policy_json)) => (interface_name, Some(policy_json)),
            None => (rest, None),
        };
        if interface_name.is_empty() || interface_name.contains(char::is_whitespace) {
            return Err(err("invalid helper install interface"));
        }
        let network = match policy_json {
            None => NetworkPolicy::default(),
            Some(json) => {
                let network: NetworkPolicy = serde_json::from_str(json).map_err(|error| {
                    err(format!("invalid helper install network policy: {error}"))
                })?;
                // Same grammar, list-cap, and LAN-containment checks as the
                // run-path policy: the sender is untrusted.
                network.validate()?;
                network
            }
        };
        return Ok(HelperRequest::Install {
            interface_name: interface_name.to_string(),
            network,
        });
    }
    if let Some(rest) = trimmed.strip_prefix("run ") {
        let (interface_name, spec_path) = rest
            .split_once(' ')
            .ok_or_else(|| err("invalid helper run request"))?;
        // A relative spec path would resolve against the root daemon's own
        // working directory — never meaningful for a client, so refuse it at
        // parse time.
        if interface_name.is_empty()
            || interface_name.contains(char::is_whitespace)
            || spec_path.is_empty()
            || spec_path.contains(char::is_whitespace)
            || !spec_path.starts_with('/')
        {
            return Err(err("invalid helper run request"));
        }
        return Ok(HelperRequest::Run {
            interface_name: interface_name.to_string(),
            spec_path: spec_path.to_string(),
        });
    }
    Err(err(format!("invalid helper request: {trimmed:?}")))
}

#[derive(Debug, Eq, PartialEq)]
pub enum HelperRequest {
    Install {
        interface_name: String,
        network: NetworkPolicy,
    },
    Run {
        interface_name: String,
        spec_path: String,
    },
    Uninstall,
    Status,
    Capabilities,
}

impl Default for PFHelperClient {
    fn default() -> Self {
        Self {
            socket_path: SOCKET_PATH.to_string(),
        }
    }
}

#[derive(Debug)]
pub struct ReceivedMessage {
    pub message: String,
    pub fds: Vec<OwnedFd>,
}

pub fn send_message_with_fds(stream: &UnixStream, bytes: &[u8], fds: &[RawFd]) -> io::Result<()> {
    if fds.is_empty() {
        let mut stream = stream;
        stream.write_all(bytes)?;
        return Ok(());
    }

    let fd_bytes = mem::size_of_val(fds);
    let mut iov = libc::iovec {
        iov_base: bytes.as_ptr() as *mut libc::c_void,
        iov_len: bytes.len(),
    };
    let mut control = vec![0u8; unsafe { libc::CMSG_SPACE(fd_bytes as _) as usize }];
    let mut msg = unsafe { mem::zeroed::<libc::msghdr>() };
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = control.as_mut_ptr() as *mut libc::c_void;
    msg.msg_controllen = control.len() as _;

    unsafe {
        let header = libc::CMSG_FIRSTHDR(&msg);
        if header.is_null() {
            return Err(io::Error::other("missing control message header"));
        }
        (*header).cmsg_level = libc::SOL_SOCKET;
        (*header).cmsg_type = libc::SCM_RIGHTS;
        (*header).cmsg_len = libc::CMSG_LEN(fd_bytes as _) as _;
        ptr::copy_nonoverlapping(
            fds.as_ptr().cast::<u8>(),
            libc::CMSG_DATA(header).cast::<u8>(),
            fd_bytes,
        );

        let sent = libc::sendmsg(stream.as_raw_fd(), &msg, 0);
        if sent < 0 {
            return Err(io::Error::last_os_error());
        }
        if sent as usize != bytes.len() {
            return Err(io::Error::new(
                io::ErrorKind::WriteZero,
                "partial helper request send",
            ));
        }
    }

    Ok(())
}

pub fn receive_message_with_fds(
    stream: &UnixStream,
    max_bytes: usize,
    max_fds: usize,
) -> io::Result<ReceivedMessage> {
    let mut bytes = vec![0u8; max_bytes];
    let fd_bytes = max_fds * mem::size_of::<RawFd>();
    let mut control = vec![0u8; unsafe { libc::CMSG_SPACE(fd_bytes as _) as usize }];
    let mut iov = libc::iovec {
        iov_base: bytes.as_mut_ptr() as *mut libc::c_void,
        iov_len: bytes.len(),
    };
    let mut msg = unsafe { mem::zeroed::<libc::msghdr>() };
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = control.as_mut_ptr() as *mut libc::c_void;
    msg.msg_controllen = control.len() as _;

    let received = unsafe { libc::recvmsg(stream.as_raw_fd(), &mut msg, 0) };
    if received < 0 {
        return Err(io::Error::last_os_error());
    }
    bytes.truncate(received as usize);

    // recvmsg has already installed any passed descriptors into this process'
    // fd table, so every one of them must be wrapped in OwnedFd BEFORE any
    // validation can bail out; an early return that skips the harvest leaks
    // the fds for the lifetime of the daemon.
    //
    // On a truncated control message the kernel can report the sender's
    // cmsg_len while delivering fewer bytes, so the fd count is clamped to the
    // control data actually received (msg_controllen); trusting cmsg_len alone
    // reads past the buffer and harvests garbage descriptor numbers.
    let mut fds = Vec::new();
    let mut malformed_control = false;
    unsafe {
        let control_start = control.as_ptr() as usize;
        let control_end = control_start + (msg.msg_controllen as usize).min(control.len());
        let mut header = libc::CMSG_FIRSTHDR(&msg);
        while !header.is_null() {
            if (*header).cmsg_level == libc::SOL_SOCKET && (*header).cmsg_type == libc::SCM_RIGHTS {
                if (*header).cmsg_len < libc::CMSG_LEN(0) as _ {
                    malformed_control = true;
                } else {
                    let data_start = libc::CMSG_DATA(header) as usize;
                    let claimed_end = (header as usize).saturating_add((*header).cmsg_len as usize);
                    let data_end = claimed_end.min(control_end);
                    let count = data_end.saturating_sub(data_start) / mem::size_of::<RawFd>();
                    let data = libc::CMSG_DATA(header).cast::<RawFd>();
                    for index in 0..count {
                        fds.push(OwnedFd::from_raw_fd(*data.add(index)));
                    }
                }
            }
            header = libc::CMSG_NXTHDR(&msg, header);
        }
    }

    // Dropping `fds` on these error paths closes everything just harvested.
    if msg.msg_flags & libc::MSG_CTRUNC != 0 {
        return Err(io::Error::other(
            "truncated file descriptors in helper request",
        ));
    }
    if malformed_control {
        return Err(io::Error::other("malformed helper control message"));
    }
    if fds.len() > max_fds {
        return Err(io::Error::other(
            "too many file descriptors in helper request",
        ));
    }

    let message = String::from_utf8(bytes)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    Ok(ReceivedMessage { message, fds })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::{File, OpenOptions};
    use std::io::{Read, Seek, SeekFrom, Write};

    #[test]
    fn parses_helper_requests() {
        assert_eq!(
            parse_request("install utun5\n").unwrap(),
            HelperRequest::Install {
                interface_name: "utun5".to_string(),
                network: NetworkPolicy::default(),
            }
        );
        assert_eq!(
            parse_request("uninstall\n").unwrap(),
            HelperRequest::Uninstall
        );
        assert_eq!(parse_request("status\n").unwrap(), HelperRequest::Status);
        assert_eq!(
            parse_request("run utun5 /tmp/lianyaohu-launch.json\n").unwrap(),
            HelperRequest::Run {
                interface_name: "utun5".to_string(),
                spec_path: "/tmp/lianyaohu-launch.json".to_string()
            }
        );
        assert!(parse_request("install en0").is_ok());
        assert!(parse_request("run utun5 /tmp/has space.json").is_err());
        // Relative spec paths would resolve against the root daemon's cwd.
        assert!(parse_request("run utun5 relative/spec.json").is_err());
        assert!(parse_request("run utun5 spec.json").is_err());
    }

    // Regression test for silent policy widening: an `install` carrying a
    // custom NetworkPolicy must arrive helper-side as exactly the policy the
    // client rendered locally, so the helper-installed rules cannot be weaker
    // than what `--print-firewall` showed.
    #[test]
    fn install_request_round_trips_a_custom_network_policy() {
        use crate::policy::{DestRule, NetAction};

        let network = NetworkPolicy {
            default_action: NetAction::Deny,
            allow: vec![DestRule::parse("140.82.112.0/20:443").unwrap()],
            deny: vec![DestRule::parse("169.254.169.254").unwrap()],
            lan_allow: vec![DestRule::parse("192.168.1.10:22").unwrap()],
        };

        let request = install_request("utun5", &network).unwrap();
        assert_eq!(
            parse_request(&request).unwrap(),
            HelperRequest::Install {
                interface_name: "utun5".to_string(),
                network,
            }
        );

        // The default policy keeps the legacy single-token wire form.
        assert_eq!(
            install_request("utun5", &NetworkPolicy::default()).unwrap(),
            "install utun5\n"
        );
    }

    #[test]
    fn install_request_parsing_rejects_hostile_input() {
        use crate::policy::{DestRule, NetAction};

        // Interface names never contain whitespace; a second token must be a
        // valid policy document, not a stray word.
        assert!(parse_request("install utun 5").is_err());
        assert!(parse_request("install utun5 not-json").is_err());
        assert!(parse_request("install utun5 {\"unknown_field\":1}").is_err());
        // Helper-side re-validation: an uncontained lan_allow entry would
        // bypass the VPN-only guarantee, so it is refused at parse time.
        let hostile = NetworkPolicy {
            default_action: NetAction::Allow,
            allow: Vec::new(),
            deny: Vec::new(),
            lan_allow: vec![DestRule::parse("0.0.0.0/0").unwrap()],
        };
        let json = serde_json::to_string(&hostile).unwrap();
        assert!(parse_request(&format!("install utun5 {json}")).is_err());
    }

    #[test]
    fn parses_helper_responses() {
        assert_eq!(
            parse_response("ok installed\n").unwrap(),
            HelperResponse {
                ok: true,
                message: "installed".to_string()
            }
        );
        assert_eq!(
            parse_response("error denied\n").unwrap(),
            HelperResponse {
                ok: false,
                message: "denied".to_string()
            }
        );
    }

    #[test]
    fn sends_and_receives_file_descriptors() {
        let (left, right) = UnixStream::pair().unwrap();
        let mut file = tempfile_file();
        file.write_all(b"fd-ok").unwrap();
        file.seek(SeekFrom::Start(0)).unwrap();

        send_message_with_fds(&left, b"run test\n", &[file.as_raw_fd()]).unwrap();
        let received = receive_message_with_fds(&right, 1024, 1).unwrap();

        assert_eq!(received.message, "run test\n");
        assert_eq!(received.fds.len(), 1);
        let mut received_file = File::from(received.fds.into_iter().next().unwrap());
        let mut contents = String::new();
        received_file.read_to_string(&mut contents).unwrap();
        assert_eq!(contents, "fd-ok");
    }

    // Regression test for a root-helper fd leak: recvmsg installs passed fds
    // into the process fd table before any validation runs, so rejecting an
    // over-count SCM_RIGHTS message must still close every received fd. Loop
    // past the fd soft limit: if the reject path leaks, the table fills and
    // the error changes (EMFILE from socketpair/recvmsg), failing the assert.
    #[test]
    fn rejected_fd_message_does_not_leak_descriptors() {
        let file = tempfile_file();
        let iterations = (nofile_soft_limit() / 3 + 16).min(100_000);
        for _ in 0..iterations {
            let (left, right) = UnixStream::pair().unwrap();
            send_message_with_fds(&left, b"run test\n", &[file.as_raw_fd(); 4]).unwrap();

            let error = receive_message_with_fds(&right, 1024, 3).unwrap_err();

            assert!(
                error.to_string().contains("file descriptors"),
                "expected fd-count rejection, got: {error}"
            );
        }
    }

    fn nofile_soft_limit() -> u64 {
        let mut limit = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        let rc = unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut limit) };
        assert_eq!(rc, 0);
        limit.rlim_cur
    }

    fn tempfile_file() -> File {
        // Unique per call: tests share one process and run on parallel
        // threads, so a pid-only name lets one test truncate another's
        // still-linked inode.
        static COUNTER: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
        let mut path = std::env::temp_dir();
        path.push(format!(
            "lianyaohu-helper-fd-test-{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ));
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(true)
            .open(&path)
            .unwrap();
        let _ = std::fs::remove_file(path);
        file
    }
}
