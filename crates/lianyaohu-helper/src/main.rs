use lianyaohu_core::helper::{HelperRequest, SOCKET_PATH, parse_request, receive_message_with_fds};
use lianyaohu_core::interfaces::{utun_interfaces, validate_utun};
use lianyaohu_core::launch::LaunchSpec;
use lianyaohu_core::pf::{
    LIANYAOHU_GROUP_GID, LIANYAOHU_GROUP_NAME, PFRuleSet, parse_enable_token,
};
use lianyaohu_core::{Result, err};
use std::collections::BTreeMap;
use std::ffi::CString;
use std::fs::{self, File};
use std::io::{self, Write};
use std::os::fd::{AsRawFd, OwnedFd};
use std::os::unix::net::{UnixListener, UnixStream};
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::path::Path;
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex, PoisonError};
use std::thread;
use std::time::Duration;

/// A request is a single short line; refuse anything larger so a client
/// cannot exhaust memory by streaming bytes without a newline.
const MAX_REQUEST_BYTES: usize = 4096;

/// Cap how long a single peer may take to send its request / receive its
/// reply, so one stalled client cannot pin a worker forever.
const IO_TIMEOUT: Duration = Duration::from_secs(5);

fn main() {
    if let Err(error) = HelperDaemon::default().run() {
        eprintln!("lianyaohu-helper: {error}");
        std::process::exit(1);
    }
}

#[derive(Clone)]
struct HelperDaemon {
    enable_tokens: Arc<Mutex<BTreeMap<u32, String>>>,
}

impl Default for HelperDaemon {
    fn default() -> Self {
        Self {
            enable_tokens: Arc::new(Mutex::new(BTreeMap::new())),
        }
    }
}

impl HelperDaemon {
    fn run(&self) -> Result<()> {
        if unsafe { libc::geteuid() } != 0 {
            return Err(err("lianyaohu-helper must run as root"));
        }
        ensure_session_group()?;

        let socket_path = Path::new(SOCKET_PATH);
        if let Some(parent) = socket_path.parent() {
            fs::create_dir_all(parent)?;
        }
        let _ = fs::remove_file(socket_path);
        let listener = UnixListener::bind(socket_path)?;
        chmod(socket_path, 0o666)?;
        install_signal_handlers();

        for stream in listener.incoming() {
            match stream {
                // Serve each connection on its own thread so a slow or stalled
                // peer cannot block the others. PF state is shared behind a
                // mutex; pfctl work is infrequent so contention is negligible.
                Ok(stream) => {
                    let daemon = self.clone();
                    thread::spawn(move || daemon.handle(stream));
                }
                Err(error) => eprintln!("accept failed: {error}"),
            }
        }
        Ok(())
    }

    fn handle(&self, mut stream: UnixStream) {
        let _ = stream.set_read_timeout(Some(IO_TIMEOUT));
        let _ = stream.set_write_timeout(Some(IO_TIMEOUT));
        let result = self.handle_inner(&mut stream);
        let response = match result {
            Ok(message) => format!("ok {message}\n"),
            Err(error) => format!("error {error}\n"),
        };
        let _ = stream.write_all(response.as_bytes());
    }

    fn handle_inner(&self, stream: &mut UnixStream) -> Result<String> {
        let peer = peer_credentials(stream)?;
        let received = receive_message_with_fds(stream, MAX_REQUEST_BYTES, 3)?;
        match parse_request(&received.message)? {
            HelperRequest::Install { interface_name } => {
                self.install(peer.uid, &interface_name)?;
                Ok(format!(
                    "installed PF guard for uid {} on {interface_name}",
                    peer.uid
                ))
            }
            HelperRequest::Run {
                interface_name,
                spec_path,
            } => self.run_session(peer, &interface_name, Path::new(&spec_path), received.fds),
            HelperRequest::Uninstall => {
                self.uninstall(peer.uid);
                Ok(format!("uninstalled PF guard for uid {}", peer.uid))
            }
            HelperRequest::Status => {
                if self.tokens().contains_key(&peer.uid) {
                    Ok("installed".to_string())
                } else {
                    Ok("not installed".to_string())
                }
            }
        }
    }

    fn tokens(&self) -> std::sync::MutexGuard<'_, BTreeMap<u32, String>> {
        self.enable_tokens
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }

    fn install(&self, uid: u32, interface_name: &str) -> Result<()> {
        let selected = validated_utun(interface_name)?;
        let rule_set = PFRuleSet::new_user(
            selected.name,
            uid,
            selected.ipv4_peer_addresses.first().cloned(),
        );
        let rules_path = write_rules(&rule_set)?;
        self.install_rule_set(&rule_set, &rules_path)
    }

    fn install_rule_set(&self, rule_set: &PFRuleSet, rules_path: &Path) -> Result<()> {
        run_pf(&["-n", "-f", &rules_path.to_string_lossy()])?;

        // Hold the lock across the pfctl calls: it serializes pfctl (which is
        // not safe to run concurrently) and keeps the enable-token map in sync
        // with PF's enable-reference count.
        let mut tokens = self.tokens();

        // Enable PF at most once per anchor. A repeat install (relaunched agent,
        // concurrent launch) must NOT call `pfctl -E` again, or it leaks an
        // enable reference that uninstall never releases.
        let token = if tokens.contains_key(&rule_set.anchor_key) {
            None
        } else {
            parse_enable_token(&run_pf(&["-E"])?)
        };

        if let Err(error) = run_pf(&[
            "-a",
            &rule_set.anchor_name(),
            "-f",
            &rules_path.to_string_lossy(),
        ]) {
            // Only roll back an enable reference we just acquired; a reused
            // reference belongs to the prior install and must survive.
            if let Some(token) = &token {
                let _ = run_pf(&["-X", token]);
            }
            return Err(error);
        }

        if let Some(token) = token {
            tokens.insert(rule_set.anchor_key, token);
        }
        Ok(())
    }

    fn run_session(
        &self,
        peer: PeerCredentials,
        interface_name: &str,
        spec_path: &Path,
        stdio_fds: Vec<OwnedFd>,
    ) -> Result<String> {
        if stdio_fds.len() != 3 {
            return Err(err(
                "run request must include stdin, stdout, and stderr fds",
            ));
        }

        let spec = LaunchSpec::read_json(spec_path)?;
        ensure_session_group()?;
        let selected = validated_utun(interface_name)?;
        let rule_set = PFRuleSet::new_group(
            selected.name,
            peer.uid,
            LIANYAOHU_GROUP_GID,
            selected.ipv4_peer_addresses.first().cloned(),
        );
        let rules_path = write_rules(&rule_set)?;

        if let Err(error) = self.install_rule_set(&rule_set, &rules_path) {
            let _ = fs::remove_file(rules_path);
            return Err(error);
        }
        let run_result = run_launch_spec(&spec, peer.uid, peer.gid, LIANYAOHU_GROUP_GID, stdio_fds);
        self.uninstall(peer.uid);
        let _ = fs::remove_file(rules_path);

        run_result.map(|code| format!("exit {code}"))
    }

    fn uninstall(&self, uid: u32) {
        let rule_set = PFRuleSet::new_user("utun0", uid, None);
        let mut tokens = self.tokens();
        let _ = run_pf(&["-a", &rule_set.anchor_name(), "-F", "rules"]);
        if let Some(token) = tokens.remove(&uid) {
            let _ = run_pf(&["-X", &token]);
        }
    }
}

#[derive(Clone, Copy)]
struct PeerCredentials {
    uid: u32,
    gid: u32,
}

fn run_launch_spec(
    spec: &LaunchSpec,
    uid: u32,
    primary_gid: u32,
    session_gid: u32,
    mut stdio_fds: Vec<OwnedFd>,
) -> Result<i32> {
    let run_dir = Path::new("/var/run/lianyaohu");
    fs::create_dir_all(run_dir)?;
    chmod(run_dir, 0o755)?;
    let profile_path = run_dir.join(format!("profile-{uid}-{}.sb", std::process::id()));
    fs::write(&profile_path, &spec.sandbox_profile)?;
    chown(
        &profile_path,
        uid as libc::uid_t,
        primary_gid as libc::gid_t,
    )?;
    chmod(&profile_path, 0o400)?;

    let profile_arg = profile_path.to_string_lossy().to_string();
    let stdin = File::from(stdio_fds.remove(0));
    let stdout = File::from(stdio_fds.remove(0));
    let stderr = File::from(stdio_fds.remove(0));

    let mut command = Command::new("/usr/bin/sandbox-exec");
    command
        .arg("-f")
        .arg(profile_arg)
        .args(&spec.command)
        .current_dir(&spec.cwd)
        .env_clear()
        .envs(&spec.environment)
        .stdin(Stdio::from(stdin))
        .stdout(Stdio::from(stdout))
        .stderr(Stdio::from(stderr));

    let supplementary_groups = supplementary_groups_for_uid(uid, primary_gid)?;
    drop_child_credentials(&mut command, uid, session_gid, supplementary_groups);

    let status = command.status();
    let _ = fs::remove_file(&profile_path);
    let status = status?;
    Ok(status
        .code()
        .or_else(|| status.signal().map(|signal| 128 + signal))
        .unwrap_or(1))
}

fn drop_child_credentials(
    command: &mut Command,
    uid: u32,
    gid: u32,
    supplementary_groups: Vec<u32>,
) {
    unsafe {
        command.pre_exec(move || {
            let gid = gid as libc::gid_t;
            let uid = uid as libc::uid_t;
            let groups = supplementary_groups
                .iter()
                .copied()
                .map(|group| group as libc::gid_t)
                .collect::<Vec<_>>();
            if libc::setgroups(groups.len() as _, groups.as_ptr()) != 0 {
                return Err(io::Error::last_os_error());
            }
            if libc::setgid(gid) != 0 {
                return Err(io::Error::last_os_error());
            }
            if libc::setuid(uid) != 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        });
    }
}

fn supplementary_groups_for_uid(uid: u32, primary_gid: u32) -> Result<Vec<u32>> {
    let output = Command::new("/usr/bin/id")
        .args(["-G", &uid.to_string()])
        .output()?;
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    if !output.status.success() {
        return Err(err(format!("id -G {uid} failed: {}", combined.trim())));
    }

    let mut groups = Vec::new();
    for value in combined.split_whitespace() {
        let gid = value
            .parse::<u32>()
            .map_err(|_| err(format!("invalid gid from id -G {uid}: {value}")))?;
        if gid != LIANYAOHU_GROUP_GID && !groups.contains(&gid) {
            groups.push(gid);
        }
    }
    if !groups.contains(&primary_gid) {
        groups.insert(0, primary_gid);
    }
    Ok(groups)
}

fn validated_utun(interface_name: &str) -> Result<lianyaohu_core::interfaces::NetworkInterface> {
    let suffix = interface_name
        .strip_prefix("utun")
        .ok_or_else(|| err(format!("refusing non-utun interface: {interface_name}")))?;
    if suffix.is_empty() || !suffix.chars().all(|ch| ch.is_ascii_digit()) {
        return Err(err(format!(
            "refusing non-utun interface: {interface_name}"
        )));
    }
    let selected = utun_interfaces()?
        .into_iter()
        .find(|interface| interface.name == interface_name)
        .ok_or_else(|| err(format!("{interface_name} is not present")))?;
    validate_utun(&selected)?;
    Ok(selected)
}

fn write_rules(rule_set: &PFRuleSet) -> Result<std::path::PathBuf> {
    let dir = Path::new("/var/run/lianyaohu");
    fs::create_dir_all(dir)?;
    let rules_path = dir.join(format!(
        "rules-{}-{}.pf",
        rule_set.anchor_key, rule_set.interface_name
    ));
    fs::write(&rules_path, rule_set.render())?;
    chmod(&rules_path, 0o600)?;
    Ok(rules_path)
}

fn ensure_session_group() -> Result<()> {
    let groups = list_groups()?;
    let mut found_session_group = None;
    let mut conflicting_group = None;
    for (name, gid) in groups {
        if name == LIANYAOHU_GROUP_NAME {
            found_session_group = Some(gid);
        } else if gid == LIANYAOHU_GROUP_GID {
            conflicting_group = Some(name);
        }
    }

    if let Some(gid) = found_session_group {
        if gid == LIANYAOHU_GROUP_GID {
            return Ok(());
        }
        return Err(err(format!(
            "{LIANYAOHU_GROUP_NAME} has gid {gid}, expected {LIANYAOHU_GROUP_GID}"
        )));
    }

    if let Some(name) = conflicting_group {
        return Err(err(format!(
            "gid {LIANYAOHU_GROUP_GID} is already assigned to group {name}"
        )));
    }

    create_session_group()
}

fn list_groups() -> Result<Vec<(String, u32)>> {
    let output = run_dscl(&[".", "-list", "/Groups", "PrimaryGroupID"])?;
    let mut groups = Vec::new();
    for line in output.lines() {
        let mut fields = line.split_whitespace();
        let Some(name) = fields.next() else {
            continue;
        };
        let Some(gid) = fields.next() else {
            continue;
        };
        if let Ok(gid) = gid.parse::<u32>() {
            groups.push((name.to_string(), gid));
        }
    }
    Ok(groups)
}

fn create_session_group() -> Result<()> {
    let record = format!("/Groups/{LIANYAOHU_GROUP_NAME}");
    let gid = LIANYAOHU_GROUP_GID.to_string();
    let create_result = (|| -> Result<()> {
        run_dscl(&[".", "-create", &record])?;
        run_dscl(&[".", "-create", &record, "PrimaryGroupID", &gid])?;
        run_dscl(&[".", "-create", &record, "Password", "*"])?;
        run_dscl(&[
            ".",
            "-create",
            &record,
            "RealName",
            "LianYaoHu sandbox network group",
        ])?;
        run_dscl(&[".", "-create", &record, "IsHidden", "1"])?;
        Ok(())
    })();

    if let Err(error) = create_result {
        let _ = Command::new("/usr/bin/dscl")
            .args([".", "-delete", &record])
            .output();
        return Err(error);
    }
    Ok(())
}

fn run_dscl(args: &[&str]) -> Result<String> {
    let output = Command::new("/usr/bin/dscl").args(args).output()?;
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    if output.status.success() {
        Ok(combined)
    } else {
        Err(err(format!(
            "dscl {} failed: {}",
            args.join(" "),
            combined.trim()
        )))
    }
}

fn run_pf(args: &[&str]) -> Result<String> {
    let output = Command::new("/sbin/pfctl").args(args).output()?;
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    if output.status.success() {
        Ok(combined)
    } else {
        Err(err(format!(
            "pfctl {} failed: {}",
            args.join(" "),
            combined.trim()
        )))
    }
}

fn peer_credentials(stream: &UnixStream) -> Result<PeerCredentials> {
    let mut uid: libc::uid_t = 0;
    let mut gid: libc::gid_t = 0;
    let rc = unsafe { libc::getpeereid(stream.as_raw_fd(), &mut uid, &mut gid) };
    if rc == 0 {
        Ok(PeerCredentials { uid, gid })
    } else {
        Err(std::io::Error::last_os_error().into())
    }
}

fn chmod(path: &Path, mode: libc::mode_t) -> Result<()> {
    let path = CString::new(path.as_os_str().as_encoded_bytes())?;
    let rc = unsafe { libc::chmod(path.as_ptr(), mode) };
    if rc == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error().into())
    }
}

fn chown(path: &Path, uid: libc::uid_t, gid: libc::gid_t) -> Result<()> {
    let path = CString::new(path.as_os_str().as_encoded_bytes())?;
    let rc = unsafe { libc::chown(path.as_ptr(), uid, gid) };
    if rc == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error().into())
    }
}

fn install_signal_handlers() {
    unsafe {
        libc::signal(
            libc::SIGINT,
            handle_signal as *const () as libc::sighandler_t,
        );
        libc::signal(
            libc::SIGTERM,
            handle_signal as *const () as libc::sighandler_t,
        );
    }
}

extern "C" fn handle_signal(signal: libc::c_int) {
    if let Ok(path) = CString::new(SOCKET_PATH) {
        unsafe {
            libc::unlink(path.as_ptr());
        }
    }
    std::process::exit(128 + signal);
}
