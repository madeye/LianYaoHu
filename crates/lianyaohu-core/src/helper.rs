use crate::policy::NetworkPolicy;
use crate::{Result, err};
use std::io::{Read, Write};
use std::net::Shutdown;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::time::{Duration, Instant};
use std::{io, mem, ptr};

pub const SOCKET_PATH: &str = "/var/run/lianyaohu-helper.sock";
pub const DAEMON_LABEL: &str = "io.github.madeye.lianyaohu.helper";

/// Upper bound on one helper request. Sized so that a maximal legal
/// `NetworkPolicy` (`MAX_RULES_PER_LIST` entries in all three lists, long
/// uncompressed IPv6 forms with port ranges) fits with ample headroom — the
/// previous 4 KiB cap silently truncated such requests at `recvmsg` and they
/// died as parse errors. [`receive_message_with_fds`] reports anything larger
/// as a distinct "too large" error instead of parsing a truncated request.
pub const MAX_REQUEST_BYTES: usize = 64 * 1024;

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

/// Reads one newline-terminated helper request plus any SCM_RIGHTS payload.
///
/// A single `recvmsg` on a stream socket may return only part of the request
/// (a short read), and a fixed buffer silently cuts an over-long one — either
/// way a truncated prefix would then be parsed as a *different* request and
/// rejected with a misleading error. This loops until the terminating newline
/// (or EOF) arrives, reassembling segmented delivery, and reports a request
/// that exceeds `max_bytes` before its newline with a distinct "too large"
/// error instead of parsing the truncated prefix.
///
/// Two bounds keep a hostile peer from abusing the loop:
/// - the fd cap is enforced per segment, immediately after each segment's
///   SCM_RIGHTS payload is harvested, so a peer sending many small segments
///   each carrying descriptors cannot make the daemon accumulate fds beyond
///   `max_fds` before the rejection fires (every harvested fd is still closed
///   by the rejection);
/// - `total_timeout` is a wall-clock budget across the WHOLE receive. The
///   caller's per-syscall `SO_RCVTIMEO` restarts on every `recvmsg`, so on
///   its own it lets a peer trickling one byte per almost-timeout pin a
///   worker indefinitely; once the budget is spent the next incomplete
///   segment returns a `TimedOut` error instead of looping again.
pub fn receive_message_with_fds(
    stream: &UnixStream,
    max_bytes: usize,
    max_fds: usize,
    total_timeout: Duration,
) -> io::Result<ReceivedMessage> {
    let start = Instant::now();
    // One spare byte past the cap: filling it proves the request is over the
    // limit (would have been truncated), which is reported explicitly below.
    let mut bytes = vec![0u8; max_bytes + 1];
    let mut total = 0usize;
    let fd_bytes = max_fds * mem::size_of::<RawFd>();
    let mut fds = Vec::new();
    let mut malformed_control = false;
    let mut control_truncated = false;

    loop {
        let mut control = vec![0u8; unsafe { libc::CMSG_SPACE(fd_bytes as _) as usize }];
        let mut iov = libc::iovec {
            iov_base: bytes[total..].as_mut_ptr() as *mut libc::c_void,
            iov_len: bytes.len() - total,
        };
        let mut msg = unsafe { mem::zeroed::<libc::msghdr>() };
        msg.msg_iov = &mut iov;
        msg.msg_iovlen = 1;
        msg.msg_control = control.as_mut_ptr() as *mut libc::c_void;
        msg.msg_controllen = control.len() as _;

        let received = unsafe { libc::recvmsg(stream.as_raw_fd(), &mut msg, 0) };
        if received < 0 {
            // Dropping `fds` closes descriptors harvested from earlier
            // segments.
            return Err(io::Error::last_os_error());
        }

        // recvmsg has already installed any passed descriptors into this
        // process' fd table, so every one of them must be wrapped in OwnedFd
        // BEFORE any validation can bail out; an early return that skips the
        // harvest leaks the fds for the lifetime of the daemon.
        //
        // On a truncated control message the kernel can report the sender's
        // cmsg_len while delivering fewer bytes, so the fd count is clamped to
        // the control data actually received (msg_controllen); trusting
        // cmsg_len alone reads past the buffer and harvests garbage
        // descriptor numbers.
        unsafe {
            let control_start = control.as_ptr() as usize;
            let control_end = control_start + (msg.msg_controllen as usize).min(control.len());
            let mut header = libc::CMSG_FIRSTHDR(&msg);
            while !header.is_null() {
                if (*header).cmsg_level == libc::SOL_SOCKET
                    && (*header).cmsg_type == libc::SCM_RIGHTS
                {
                    if (*header).cmsg_len < libc::CMSG_LEN(0) as _ {
                        malformed_control = true;
                    } else {
                        let data_start = libc::CMSG_DATA(header) as usize;
                        let claimed_end =
                            (header as usize).saturating_add((*header).cmsg_len as usize);
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
        // Enforced here, inside the loop, right after the harvest: checking
        // only after the loop would let a peer sending many small segments
        // each carrying SCM_RIGHTS accumulate thousands of descriptors in the
        // daemon before the rejection fired. Returning drops `fds`, closing
        // everything harvested so far.
        if fds.len() > max_fds {
            return Err(io::Error::other(
                "too many file descriptors in helper request",
            ));
        }
        if msg.msg_flags & libc::MSG_CTRUNC != 0 {
            control_truncated = true;
        }

        if received == 0 {
            // EOF: the peer shut down its write side.
            break;
        }
        let segment_end = total + received as usize;
        let saw_newline = bytes[total..segment_end].contains(&b'\n');
        total = segment_end;
        if saw_newline || total > max_bytes {
            break;
        }
        // Wall-clock deadline before waiting for another segment: the
        // per-syscall receive timeout restarts on every recvmsg, so without
        // this a peer trickling one byte per almost-timeout holds the worker
        // forever. Checked after the completion tests so a request that just
        // finished is never spuriously timed out.
        if start.elapsed() >= total_timeout {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "helper request receive timed out",
            ));
        }
    }
    bytes.truncate(total);

    // Dropping `fds` on these error paths closes everything just harvested.
    if control_truncated {
        return Err(io::Error::other(
            "truncated file descriptors in helper request",
        ));
    }
    if malformed_control {
        return Err(io::Error::other("malformed helper control message"));
    }
    if total > max_bytes {
        return Err(io::Error::other(format!(
            "helper request too large (over {max_bytes} bytes)"
        )));
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

    /// Generous wall-clock budget for tests that must never trip the
    /// deadline: everything here runs over a local socketpair, so anything
    /// close to this is already a failure.
    const RECEIVE_TEST_BUDGET: Duration = Duration::from_secs(30);

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

    // Regression test for the request-size cliff: a policy that is legal
    // under the documented caps (MAX_RULES_PER_LIST entries in all three
    // lists, long uncompressed IPv6 forms with port ranges) serializes well
    // past the old 4 KiB recvmsg buffer, where it was silently truncated and
    // rejected as a parse error. It must fit MAX_REQUEST_BYTES and round-trip
    // losslessly through install_request -> parse_request.
    #[test]
    fn maximal_network_policy_round_trips_through_the_wire_form() {
        use crate::policy::{DestRule, MAX_RULES_PER_LIST, NetAction};

        let rule = |space: &str, index: usize| {
            DestRule::parse(&format!(
                "[{space}:1111:2222:3333:4444:5555:6666:{index:x}]:8000-8100"
            ))
            .unwrap()
        };
        let network = NetworkPolicy {
            default_action: NetAction::Deny,
            allow: (1..=MAX_RULES_PER_LIST).map(|i| rule("2001", i)).collect(),
            deny: (1..=MAX_RULES_PER_LIST).map(|i| rule("2606", i)).collect(),
            // fd00::/8 is inside the fc00::/7 blocked-LAN range, so the
            // containment check accepts these.
            lan_allow: (1..=MAX_RULES_PER_LIST).map(|i| rule("fd00", i)).collect(),
        };
        network.validate().unwrap();

        let request = install_request("utun5", &network).unwrap();
        assert!(
            request.len() > 4096,
            "request no longer exceeds the old 4 KiB cliff ({} bytes); \
             grow the test policy",
            request.len()
        );
        assert!(
            request.len() <= MAX_REQUEST_BYTES,
            "maximal legal request ({} bytes) exceeds MAX_REQUEST_BYTES",
            request.len()
        );
        assert_eq!(
            parse_request(&request).unwrap(),
            HelperRequest::Install {
                interface_name: "utun5".to_string(),
                network,
            }
        );
    }

    // The transport must reassemble a request that arrives across several
    // recvmsg segments instead of parsing a truncated prefix.
    #[test]
    fn segmented_request_is_reassembled_by_the_receiver() {
        let (left, right) = UnixStream::pair().unwrap();
        // Fail fast on regression instead of hanging: a receiver that stops
        // reading mid-request leaves the sender blocked in write_all, so the
        // assert must run (and the receiver side must be dropped) before the
        // join, and a read timeout turns a receiver that never terminates
        // into a visible error rather than a stuck test.
        right
            .set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        let request = format!("install utun5 {}\n", "x".repeat(32 * 1024));
        let sender = std::thread::spawn({
            let request = request.clone();
            move || {
                let mut left = &left;
                let _ = left.write_all(request.as_bytes());
            }
        });

        let received =
            receive_message_with_fds(&right, MAX_REQUEST_BYTES, 3, RECEIVE_TEST_BUDGET).unwrap();
        assert_eq!(received.message, request);
        drop(right);
        sender.join().unwrap();
    }

    // An over-cap request must fail with the distinct "too large" error —
    // never be silently cut at the buffer boundary and parsed as a shorter,
    // different request.
    #[test]
    fn oversized_request_is_rejected_as_too_large_not_truncated() {
        let (left, right) = UnixStream::pair().unwrap();
        // Fail fast on regression: a receiver that never reaches the cap
        // would otherwise block in recvmsg forever once the sender is done.
        right
            .set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        let sender = std::thread::spawn(move || {
            let mut left = &left;
            // No newline: the receiver must hit the cap, not a terminator.
            let payload = vec![b'a'; MAX_REQUEST_BYTES + 2];
            // The receiver may hang up mid-write once it detects the
            // overflow; that error is expected.
            let _ = left.write_all(&payload);
        });

        let error = receive_message_with_fds(&right, MAX_REQUEST_BYTES, 3, RECEIVE_TEST_BUDGET)
            .unwrap_err();
        assert!(
            error.to_string().contains("too large"),
            "expected a too-large rejection, got: {error}"
        );
        drop(right);
        sender.join().unwrap();
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
        let received = receive_message_with_fds(&right, 1024, 1, RECEIVE_TEST_BUDGET).unwrap();

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

            let error = receive_message_with_fds(&right, 1024, 3, RECEIVE_TEST_BUDGET).unwrap_err();

            assert!(
                error.to_string().contains("file descriptors"),
                "expected fd-count rejection, got: {error}"
            );
        }
    }

    // Regression test for cross-segment SCM_RIGHTS accumulation: the fd cap
    // must fire on the first segment that pushes the total over `max_fds`,
    // not after the whole request has been read — otherwise a peer sending
    // many small fd-bearing segments makes the root daemon hold thousands of
    // descriptors before the rejection. The sender stops without a newline
    // and without EOF, so a receiver that keeps looping past the cap hits the
    // 500 ms read timeout and fails the assert below with a WouldBlock-style
    // error instead of hanging the suite.
    #[test]
    fn over_cap_fds_across_segments_are_rejected_on_the_offending_segment() {
        let (left, right) = UnixStream::pair().unwrap();
        right
            .set_read_timeout(Some(Duration::from_millis(500)))
            .unwrap();
        let file = tempfile_file();
        // Four segments of 3 fds each (SCM_RIGHTS is a message boundary, so
        // recvmsg cannot coalesce them): the total of 12 exceeds max_fds = 3
        // on the second segment already.
        for _ in 0..4 {
            send_message_with_fds(&left, b"x", &[file.as_raw_fd(); 3]).unwrap();
        }

        let started = Instant::now();
        let error = receive_message_with_fds(&right, 1024, 3, RECEIVE_TEST_BUDGET).unwrap_err();
        assert!(
            error.to_string().contains("file descriptors"),
            "expected fd-count rejection, got: {error}"
        );
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "over-cap rejection was not prompt"
        );
        drop(left);
    }

    // The wall-clock deadline must bound the whole receive: the per-syscall
    // read timeout restarts on every segment, so it alone cannot stop a peer
    // trickling bytes forever. A zero budget makes the deadline trip
    // deterministically on the first incomplete segment — no real waiting.
    #[test]
    fn receive_deadline_bounds_a_trickling_sender() {
        let (left, right) = UnixStream::pair().unwrap();
        // Fail fast on regression: without the deadline check the receiver
        // would block in recvmsg waiting for a second segment that never
        // comes; the socket timeout turns that into a WouldBlock-style error
        // that fails the TimedOut assert instead of hanging the suite.
        right
            .set_read_timeout(Some(Duration::from_millis(500)))
            .unwrap();
        send_message_with_fds(&left, b"install ", &[]).unwrap();

        let error = receive_message_with_fds(&right, 1024, 3, Duration::ZERO).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        drop(left);
    }

    // The deadline is checked only between segments: a request that completes
    // in one segment must never be spuriously timed out, even with a spent
    // budget.
    #[test]
    fn completed_request_is_not_timed_out_by_the_deadline() {
        let (left, right) = UnixStream::pair().unwrap();
        send_message_with_fds(&left, b"status\n", &[]).unwrap();

        let received = receive_message_with_fds(&right, 1024, 3, Duration::ZERO).unwrap();
        assert_eq!(received.message, "status\n");
        drop(left);
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
