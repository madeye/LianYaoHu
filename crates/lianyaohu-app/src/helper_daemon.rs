use lianyaohu_core::env_policy;
use lianyaohu_core::helper::{HelperRequest, SOCKET_PATH, parse_request, receive_message_with_fds};
#[cfg(target_os = "macos")]
use lianyaohu_core::interfaces::{utun_interfaces, validate_utun};
#[cfg(target_os = "linux")]
use lianyaohu_core::interfaces::{
    validate_vpn_interface as validate_platform_vpn_interface, vpn_interfaces,
};
use lianyaohu_core::launch::LaunchSpec;
#[cfg(target_os = "linux")]
use lianyaohu_core::linux_firewall::{
    LIANYAOHU_GROUP_GID, LIANYAOHU_GROUP_NAME, LinuxFirewallGuard, LinuxFirewallRuleSet,
};
#[cfg(target_os = "linux")]
use lianyaohu_core::linux_sandbox::LinuxSandbox;
#[cfg(target_os = "macos")]
use lianyaohu_core::pf::{
    LIANYAOHU_GROUP_GID, LIANYAOHU_GROUP_NAME, PFRuleSet, parse_enable_token,
};
#[cfg(target_os = "macos")]
use lianyaohu_core::sandbox_profile::SandboxProfile;
use lianyaohu_core::{Result, err};
use std::collections::BTreeMap;
use std::ffi::{CStr, CString};
use std::fs::{self, File};
use std::io::{self, Write};
use std::os::fd::{AsRawFd, OwnedFd};
use std::os::unix::net::{UnixListener, UnixStream};
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::path::Path;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicI32, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;
use std::{mem, ptr, thread};

/// A request is a single short line; refuse anything larger so a client
/// cannot exhaust memory by streaming bytes without a newline.
const MAX_REQUEST_BYTES: usize = 4096;

/// Cap how long a single peer may take to send its request / receive its
/// reply, so one stalled client cannot pin a worker forever.
const IO_TIMEOUT: Duration = Duration::from_secs(5);

/// Upper bound on concurrent worker threads. Run sessions hold a worker for
/// the lifetime of the agent, so the cap must comfortably cover legitimate
/// concurrent sessions while keeping a local flood from pinning unbounded
/// threads and memory.
const MAX_CONCURRENT_CONNECTIONS: usize = 32;

/// Per-UID share of the worker pool. The global cap alone lets one local user
/// pin every slot with long-lived run sessions and starve other users'
/// requests; capping each UID below the global limit keeps slots available
/// for everyone else.
const MAX_CONNECTIONS_PER_UID: usize = 8;

pub fn run() -> Result<()> {
    HelperDaemon::default().run()
}

/// Firewall state for one caller UID. Sessions are reference-counted: a
/// second concurrent launch by the same user on the same interface reuses the
/// installed rules, and the rules come down only when the last session ends.
struct SessionState {
    #[cfg(target_os = "macos")]
    rule_set: PFRuleSet,
    #[cfg(target_os = "linux")]
    rule_set: LinuxFirewallRuleSet,
    refcount: usize,
    #[cfg(target_os = "macos")]
    enable_token: Option<String>,
    #[cfg(target_os = "macos")]
    rules_path: std::path::PathBuf,
}

#[derive(Clone)]
struct HelperDaemon {
    sessions: Arc<Mutex<BTreeMap<u32, SessionState>>>,
    active_connections: Arc<AtomicUsize>,
    uid_connections: Arc<Mutex<BTreeMap<u32, usize>>>,
}

impl Default for HelperDaemon {
    fn default() -> Self {
        Self {
            sessions: Arc::new(Mutex::new(BTreeMap::new())),
            active_connections: Arc::new(AtomicUsize::new(0)),
            uid_connections: Arc::new(Mutex::new(BTreeMap::new())),
        }
    }
}

/// Decrements the active-connection count when a worker finishes, including
/// on panic, so a crashed worker cannot leak a connection slot.
struct ConnectionSlot(Arc<AtomicUsize>);

impl Drop for ConnectionSlot {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::AcqRel);
    }
}

/// One UID's claim on a worker slot; released on drop, including on panic.
struct UidSlot {
    uid_connections: Arc<Mutex<BTreeMap<u32, usize>>>,
    uid: u32,
}

impl UidSlot {
    fn acquire(
        uid_connections: &Arc<Mutex<BTreeMap<u32, usize>>>,
        uid: u32,
        cap: usize,
    ) -> Option<Self> {
        let mut connections = uid_connections
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let count = connections.entry(uid).or_insert(0);
        if *count >= cap {
            return None;
        }
        *count += 1;
        Some(Self {
            uid_connections: uid_connections.clone(),
            uid,
        })
    }
}

impl Drop for UidSlot {
    fn drop(&mut self) {
        let mut connections = self
            .uid_connections
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        if let Some(count) = connections.get_mut(&self.uid) {
            *count -= 1;
            if *count == 0 {
                connections.remove(&self.uid);
            }
        }
    }
}

impl HelperDaemon {
    fn run(&self) -> Result<()> {
        if unsafe { libc::geteuid() } != 0 {
            return Err(err("lianyaohu helper must run as root"));
        }
        ensure_session_group()?;
        // The session map is in-memory, so firewall state installed by a
        // previous helper instance that exited uncleanly (SIGKILL, crash,
        // supervisor restart) would never be reaped. No session is live yet,
        // so anything found now is stale by definition.
        reap_stale_sessions();

        let socket_path = Path::new(SOCKET_PATH);
        if let Some(parent) = socket_path.parent() {
            fs::create_dir_all(parent)?;
        }
        let _ = fs::remove_file(socket_path);
        let listener = UnixListener::bind(socket_path)?;
        chmod(socket_path, 0o666)?;
        install_signal_handlers(self.clone())?;

        for stream in listener.incoming() {
            match stream {
                // Serve each connection on its own thread so a slow or stalled
                // peer cannot block the others. Firewall state is shared behind
                // a mutex; pfctl/iptables work is infrequent so contention is
                // negligible.
                Ok(mut stream) => {
                    if self.active_connections.fetch_add(1, Ordering::AcqRel)
                        >= MAX_CONCURRENT_CONNECTIONS
                    {
                        self.active_connections.fetch_sub(1, Ordering::AcqRel);
                        let _ = stream.set_write_timeout(Some(IO_TIMEOUT));
                        let _ = stream
                            .write_all(b"error helper is at its connection limit; retry shortly\n");
                        continue;
                    }
                    let slot = ConnectionSlot(self.active_connections.clone());
                    let daemon = self.clone();
                    thread::spawn(move || {
                        let _slot = slot;
                        daemon.handle(stream);
                    });
                }
                Err(error) => eprintln!("accept failed: {error}"),
            }
        }
        Ok(())
    }

    fn handle(&self, mut stream: UnixStream) {
        let _ = stream.set_read_timeout(Some(IO_TIMEOUT));
        let _ = stream.set_write_timeout(Some(IO_TIMEOUT));
        let result = peer_credentials(&stream).and_then(|peer| {
            let Some(_uid_slot) =
                UidSlot::acquire(&self.uid_connections, peer.uid, MAX_CONNECTIONS_PER_UID)
            else {
                return Err(err(format!(
                    "uid {} is at its helper connection limit; retry shortly",
                    peer.uid
                )));
            };
            self.handle_inner(&mut stream, peer)
        });
        let response = match result {
            Ok(message) => format!("ok {message}\n"),
            Err(error) => format!("error {error}\n"),
        };
        let _ = stream.write_all(response.as_bytes());
    }

    fn handle_inner(&self, stream: &mut UnixStream, peer: PeerCredentials) -> Result<String> {
        let received = receive_message_with_fds(stream, MAX_REQUEST_BYTES, 3)?;
        match parse_request(&received.message)? {
            HelperRequest::Install { interface_name } => {
                self.install(peer.uid, &interface_name)?;
                Ok(format!(
                    "installed firewall guard for uid {} on {interface_name}",
                    peer.uid
                ))
            }
            HelperRequest::Run {
                interface_name,
                spec_path,
            } => self.run_session(peer, &interface_name, Path::new(&spec_path), received.fds),
            HelperRequest::Uninstall => {
                self.release_session(peer.uid);
                Ok(format!("uninstalled firewall guard for uid {}", peer.uid))
            }
            HelperRequest::Status => {
                if self.lock_sessions().contains_key(&peer.uid) {
                    Ok("installed".to_string())
                } else {
                    Ok("not installed".to_string())
                }
            }
        }
    }

    fn lock_sessions(&self) -> std::sync::MutexGuard<'_, BTreeMap<u32, SessionState>> {
        self.sessions.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn install(&self, uid: u32, interface_name: &str) -> Result<()> {
        let selected = validated_vpn_interface(interface_name)?;

        #[cfg(target_os = "macos")]
        {
            self.acquire_session(PFRuleSet::new_user(
                selected.name,
                uid,
                selected.ipv4_peer_addresses.first().cloned(),
            ))
        }

        #[cfg(target_os = "linux")]
        {
            self.acquire_session(LinuxFirewallRuleSet::new_user(selected.name, uid))
        }
    }

    /// Install firewall rules for this rule set, or join the session that
    /// already holds them. A concurrent session for the same UID must use the
    /// same interface and owner scope: the rules live under one anchor/chain
    /// per UID, so two different scopes cannot both be enforced at once, and
    /// failing closed here beats silently weakening either session.
    #[cfg(target_os = "macos")]
    fn acquire_session(&self, rule_set: PFRuleSet) -> Result<()> {
        // Hold the lock across the pfctl calls: it serializes pfctl (which is
        // not safe to run concurrently) and keeps the session map in sync with
        // PF's enable-reference count.
        let mut sessions = self.lock_sessions();
        if let Some(state) = sessions.get_mut(&rule_set.anchor_key) {
            if state.rule_set.interface_name != rule_set.interface_name
                || state.rule_set.socket_owner != rule_set.socket_owner
            {
                return Err(session_conflict_error(&state.rule_set));
            }
            state.refcount += 1;
            return Ok(());
        }

        let rules_path = write_rules(&rule_set)?;
        if let Err(error) = run_pf(&["-n", "-f", &rules_path.to_string_lossy()]) {
            let _ = fs::remove_file(&rules_path);
            return Err(error);
        }

        let enable_token = match run_pf(&["-E"]) {
            Ok(output) => parse_enable_token(&output),
            Err(error) => {
                let _ = fs::remove_file(&rules_path);
                return Err(error);
            }
        };

        if let Err(error) = run_pf(&[
            "-a",
            &rule_set.anchor_name(),
            "-f",
            &rules_path.to_string_lossy(),
        ]) {
            if let Some(token) = &enable_token {
                let _ = run_pf(&["-X", token]);
            }
            let _ = fs::remove_file(&rules_path);
            return Err(error);
        }

        sessions.insert(
            rule_set.anchor_key,
            SessionState {
                rule_set,
                refcount: 1,
                enable_token,
                rules_path,
            },
        );
        Ok(())
    }

    #[cfg(target_os = "linux")]
    fn acquire_session(&self, rule_set: LinuxFirewallRuleSet) -> Result<()> {
        let mut sessions = self.lock_sessions();
        if let Some(state) = sessions.get_mut(&rule_set.anchor_key) {
            if state.rule_set.interface_name != rule_set.interface_name
                || state.rule_set.socket_owner != rule_set.socket_owner
            {
                return Err(session_conflict_error(&state.rule_set));
            }
            state.refcount += 1;
            return Ok(());
        }

        let mut guard = LinuxFirewallGuard::new_root(rule_set.clone());
        guard.install()?;
        guard.disarm();
        sessions.insert(
            rule_set.anchor_key,
            SessionState {
                rule_set,
                refcount: 1,
            },
        );
        Ok(())
    }

    /// Drop one reference to the UID's session; tear the rules down only when
    /// the last concurrent session ends, so an early-exiting session cannot
    /// strip the firewall out from under a still-running one.
    fn release_session(&self, uid: u32) {
        let mut sessions = self.lock_sessions();
        let Some(state) = sessions.get_mut(&uid) else {
            return;
        };
        state.refcount -= 1;
        if state.refcount > 0 {
            return;
        }
        if let Some(state) = sessions.remove(&uid) {
            teardown_session(&state);
        }
    }

    /// Uninstall every remaining session's firewall state. Used on shutdown
    /// so a stopped helper does not leave rules behind.
    fn teardown_all_sessions(&self) {
        let mut sessions = self.lock_sessions();
        while let Some((_, state)) = sessions.pop_first() {
            teardown_session(&state);
        }
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
        let selected = validated_vpn_interface(interface_name)?;
        let launch = validate_launch(&spec, peer.uid)?;

        #[cfg(target_os = "macos")]
        let rule_set = PFRuleSet::new_group(
            selected.name,
            peer.uid,
            LIANYAOHU_GROUP_GID,
            selected.ipv4_peer_addresses.first().cloned(),
        );
        #[cfg(target_os = "linux")]
        let rule_set =
            LinuxFirewallRuleSet::new_group(selected.name, peer.uid, LIANYAOHU_GROUP_GID);

        self.acquire_session(rule_set)?;
        let run_result =
            run_launch_spec(&launch, peer.uid, peer.gid, LIANYAOHU_GROUP_GID, stdio_fds);
        self.release_session(peer.uid);

        run_result.map(|code| format!("exit {code}"))
    }
}

#[cfg(target_os = "macos")]
fn session_conflict_error(active: &PFRuleSet) -> lianyaohu_core::Error {
    err(format!(
        "uid {} already has an active session on {} ({}); concurrent sessions must use the same \
         interface and scope, or wait for the running session to exit",
        active.anchor_key,
        active.interface_name,
        active.socket_owner.description(),
    ))
}

#[cfg(target_os = "linux")]
fn session_conflict_error(active: &LinuxFirewallRuleSet) -> lianyaohu_core::Error {
    err(format!(
        "uid {} already has an active session on {} ({}); concurrent sessions must use the same \
         interface and scope, or wait for the running session to exit",
        active.anchor_key,
        active.interface_name,
        active.socket_owner.description(),
    ))
}

fn teardown_session(state: &SessionState) {
    #[cfg(target_os = "macos")]
    {
        let _ = run_pf(&["-a", &state.rule_set.anchor_name(), "-F", "rules"]);
        if let Some(token) = &state.enable_token {
            let _ = run_pf(&["-X", token]);
        }
        let _ = fs::remove_file(&state.rules_path);
    }

    #[cfg(target_os = "linux")]
    {
        let mut guard = LinuxFirewallGuard::new_root(state.rule_set.clone());
        guard.uninstall();
    }
}

#[derive(Clone, Copy)]
struct PeerCredentials {
    uid: u32,
    gid: u32,
}

/// Launch inputs the helper has validated itself. The client-supplied spec is
/// untrusted — any local user can connect to the helper socket — so the
/// sandbox policy roots are derived server-side: the home directory comes
/// from the passwd database for the authenticated peer UID, cwd/tmpdir must
/// be real directories (tmpdir owned by the caller), and the environment is
/// re-sanitized with the same policy the client claims to have applied. The
/// client's sandbox_profile text is ignored entirely.
struct ValidatedLaunch {
    command: Vec<String>,
    cwd: String,
    home: String,
    tmpdir: String,
    environment: BTreeMap<String, String>,
}

fn validate_launch(spec: &LaunchSpec, uid: u32) -> Result<ValidatedLaunch> {
    spec.validate()?;
    let home = home_directory_for_uid(uid)?;
    let home = validated_directory("home directory", Path::new(&home), Some(uid))?;
    let cwd = validated_directory("working directory", Path::new(&spec.cwd), None)?;
    let tmpdir = spec
        .environment
        .get("TMPDIR")
        .ok_or_else(|| err("launch environment is missing TMPDIR"))?;
    let tmpdir = validated_directory("temporary directory", Path::new(tmpdir), Some(uid))?;

    // Treat the entire client environment as untrusted extras: privacy and
    // injection blocklists apply, and the sandbox roots are pinned to the
    // values validated above.
    let environment =
        env_policy::sanitize(&BTreeMap::new(), &home, &cwd, &tmpdir, &spec.environment);

    Ok(ValidatedLaunch {
        command: spec.command.clone(),
        cwd,
        home,
        tmpdir,
        environment,
    })
}

fn validated_directory(what: &str, path: &Path, required_owner: Option<u32>) -> Result<String> {
    use std::os::unix::fs::MetadataExt;

    if !path.is_absolute() {
        return Err(err(format!("{what} {} is not absolute", path.display())));
    }
    let canonical = path
        .canonicalize()
        .map_err(|error| err(format!("{what} {}: {error}", path.display())))?;
    if canonical == Path::new("/") {
        return Err(err(format!("{what} must not be the filesystem root")));
    }
    let metadata = fs::metadata(&canonical)?;
    if !metadata.is_dir() {
        return Err(err(format!(
            "{what} {} is not a directory",
            canonical.display()
        )));
    }
    if let Some(owner) = required_owner
        && metadata.uid() != owner
    {
        return Err(err(format!(
            "{what} {} is not owned by uid {owner}",
            canonical.display()
        )));
    }
    canonical
        .to_str()
        .map(ToString::to_string)
        .ok_or_else(|| err(format!("{what} {} is not valid UTF-8", canonical.display())))
}

fn home_directory_for_uid(uid: u32) -> Result<String> {
    let mut buffer_len = 1024usize;
    loop {
        let mut passwd = unsafe { mem::zeroed::<libc::passwd>() };
        let mut buffer = vec![0u8; buffer_len];
        let mut result: *mut libc::passwd = ptr::null_mut();
        let rc = unsafe {
            libc::getpwuid_r(
                uid,
                &mut passwd,
                buffer.as_mut_ptr().cast(),
                buffer.len(),
                &mut result,
            )
        };
        if rc == libc::ERANGE && buffer_len < 1024 * 1024 {
            buffer_len *= 2;
            continue;
        }
        if rc != 0 {
            return Err(io::Error::from_raw_os_error(rc).into());
        }
        if result.is_null() {
            return Err(err(format!("no passwd entry for uid {uid}")));
        }
        let dir = unsafe { CStr::from_ptr(passwd.pw_dir) };
        return Ok(dir
            .to_str()
            .map_err(|_| err(format!("home directory for uid {uid} is not valid UTF-8")))?
            .to_string());
    }
}

#[cfg(target_os = "macos")]
fn run_launch_spec(
    launch: &ValidatedLaunch,
    uid: u32,
    primary_gid: u32,
    session_gid: u32,
    mut stdio_fds: Vec<OwnedFd>,
) -> Result<i32> {
    static LAUNCH_COUNTER: AtomicUsize = AtomicUsize::new(0);

    let run_dir = Path::new("/var/run/lianyaohu");
    fs::create_dir_all(run_dir)?;
    chmod(run_dir, 0o755)?;
    // Unique per launch: two concurrent sessions for one uid must not race on
    // the same profile file.
    let profile_path = run_dir.join(format!(
        "profile-{uid}-{}-{}.sb",
        std::process::id(),
        LAUNCH_COUNTER.fetch_add(1, Ordering::Relaxed)
    ));
    // The profile is rebuilt here from the validated roots; the client's
    // profile text is never consumed.
    let profile = SandboxProfile::new(&launch.home, &launch.cwd, &launch.tmpdir).render();
    fs::write(&profile_path, profile)?;
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

    // Spawn through `launchctl asuser` so the agent joins the caller's Mach
    // bootstrap and audit session. Keychain search lists and unlock state are
    // per-session; launched straight from this LaunchDaemon the agent lands in
    // the system session where the caller's login keychain is invisible, and
    // tools that keep secrets there (claude, gh, git credential helpers)
    // prompt to log in again. `launchctl asuser` keeps uid 0, so the helper
    // re-enters itself via `drop-exec`, which drops credentials inside the
    // caller's session and execs sandbox-exec.
    let helper_exe = std::env::current_exe()?;
    let supplementary_groups = supplementary_groups_for_uid(uid, primary_gid)?;
    let groups_csv = supplementary_groups
        .iter()
        .map(u32::to_string)
        .collect::<Vec<_>>()
        .join(",");

    let mut command = Command::new("/bin/launchctl");
    command
        .arg("asuser")
        .arg(uid.to_string())
        .arg(&helper_exe)
        .arg("drop-exec")
        .arg(uid.to_string())
        .arg(session_gid.to_string())
        .arg(&groups_csv)
        .arg("--")
        .arg("/usr/bin/sandbox-exec")
        .arg("-f")
        .arg(profile_arg)
        .args(&launch.command)
        .current_dir(&launch.cwd)
        .env_clear()
        .envs(&launch.environment)
        .stdin(Stdio::from(stdin))
        .stdout(Stdio::from(stdout))
        .stderr(Stdio::from(stderr));

    let status = command.status();
    let _ = fs::remove_file(&profile_path);
    let status = status?;
    Ok(status
        .code()
        .or_else(|| status.signal().map(|signal| 128 + signal))
        .unwrap_or(1))
}

#[cfg(target_os = "linux")]
fn run_launch_spec(
    launch: &ValidatedLaunch,
    uid: u32,
    primary_gid: u32,
    session_gid: u32,
    mut stdio_fds: Vec<OwnedFd>,
) -> Result<i32> {
    let stdin = File::from(stdio_fds.remove(0));
    let stdout = File::from(stdio_fds.remove(0));
    let stderr = File::from(stdio_fds.remove(0));
    let executable = launch
        .command
        .first()
        .ok_or_else(|| err("launch spec command is empty"))?;
    // Sandbox roots come from the helper-validated launch, not from whatever
    // HOME/TMPDIR the client put in the spec.
    let sandbox = LinuxSandbox::new(&launch.home, &launch.cwd, &launch.tmpdir);

    let mut command = Command::new(executable);
    command
        .args(&launch.command[1..])
        .current_dir(&launch.cwd)
        .env_clear()
        .envs(&launch.environment)
        .stdin(Stdio::from(stdin))
        .stdout(Stdio::from(stdout))
        .stderr(Stdio::from(stderr));

    let supplementary_groups = supplementary_groups_for_uid(uid, primary_gid)?;
    drop_child_credentials(&mut command, uid, session_gid, supplementary_groups);
    apply_child_sandbox(&mut command, sandbox);

    let status = command.status()?;
    Ok(status
        .code()
        .or_else(|| status.signal().map(|signal| 128 + signal))
        .unwrap_or(1))
}

/// Entry point for `lianyaohu drop-exec <uid> <gid> <groups-csv> -- <command...>`.
///
/// Internal trampoline for the macOS launch path: `launchctl asuser` joins the
/// caller's session but keeps uid 0, so the helper re-enters itself with this
/// subcommand to drop credentials and exec the sandboxed agent. It grants
/// nothing to unprivileged callers — setgroups/setgid/setuid fail with EPERM
/// unless the process is already root. On success exec replaces the process
/// and this function never returns.
#[cfg(target_os = "macos")]
pub fn drop_exec(args: &[String]) -> Result<()> {
    let (uid, gid, groups, command) = parse_drop_exec_args(args)?;
    let groups = groups
        .iter()
        .map(|group| *group as libc::gid_t)
        .collect::<Vec<_>>();
    unsafe {
        if libc::setgroups(groups.len() as _, groups.as_ptr()) != 0 {
            return Err(err(format!("setgroups: {}", io::Error::last_os_error())));
        }
        if libc::setgid(gid as libc::gid_t) != 0 {
            return Err(err(format!("setgid {gid}: {}", io::Error::last_os_error())));
        }
        if libc::setuid(uid as libc::uid_t) != 0 {
            return Err(err(format!("setuid {uid}: {}", io::Error::last_os_error())));
        }
        // macOS has no PR_SET_NO_NEW_PRIVS; verify the drop is complete and
        // irreversible before exec'ing the (caller-chosen) command. setuid(uid)
        // from root sets the saved uid too, so regaining root must fail.
        if libc::getuid() != uid as libc::uid_t || libc::geteuid() != uid as libc::uid_t {
            return Err(err("drop-exec: uid drop did not take effect"));
        }
        if libc::getgid() != gid as libc::gid_t || libc::getegid() != gid as libc::gid_t {
            return Err(err("drop-exec: gid drop did not take effect"));
        }
        if uid != 0 && libc::setuid(0) == 0 {
            return Err(err(
                "drop-exec: credential drop is reversible; refusing to exec",
            ));
        }
    }
    let error = Command::new(&command[0]).args(&command[1..]).exec();
    Err(err(format!("exec {}: {error}", command[0])))
}

#[cfg(any(target_os = "macos", test))]
fn parse_drop_exec_args(args: &[String]) -> Result<(u32, u32, Vec<u32>, Vec<String>)> {
    const USAGE: &str = "usage: lianyaohu drop-exec <uid> <gid> <groups-csv> -- <command...>";
    let [uid, gid, groups_csv, separator, command @ ..] = args else {
        return Err(err(USAGE));
    };
    if separator != "--" || command.is_empty() {
        return Err(err(USAGE));
    }
    let uid = uid
        .parse()
        .map_err(|_| err(format!("drop-exec: invalid uid {uid:?}")))?;
    let gid = gid
        .parse()
        .map_err(|_| err(format!("drop-exec: invalid gid {gid:?}")))?;
    let groups = if groups_csv.is_empty() {
        Vec::new()
    } else {
        groups_csv
            .split(',')
            .map(|group| {
                group
                    .parse::<u32>()
                    .map_err(|_| err(format!("drop-exec: invalid group {group:?}")))
            })
            .collect::<Result<Vec<_>>>()?
    };
    Ok((uid, gid, groups, command.to_vec()))
}

#[cfg(target_os = "linux")]
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

#[cfg(target_os = "linux")]
fn apply_child_sandbox(command: &mut Command, sandbox: LinuxSandbox) {
    unsafe {
        command.pre_exec(move || {
            sandbox
                .apply()
                .map_err(|error| io::Error::other(error.to_string()))
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

#[cfg(target_os = "macos")]
fn validated_vpn_interface(
    interface_name: &str,
) -> Result<lianyaohu_core::interfaces::NetworkInterface> {
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

#[cfg(target_os = "linux")]
fn validated_vpn_interface(
    interface_name: &str,
) -> Result<lianyaohu_core::interfaces::NetworkInterface> {
    let selected = vpn_interfaces()?
        .into_iter()
        .find(|interface| interface.name == interface_name)
        .ok_or_else(|| err(format!("{interface_name} is not present")))?;
    validate_platform_vpn_interface(&selected)?;
    Ok(selected)
}

/// Flush firewall state orphaned by a previous helper instance. The PF
/// enable-reference tokens from `pfctl -E` died with the old process and
/// cannot be released, so PF may stay enabled; that is benign (an enabled PF
/// with empty anchors filters nothing extra), unlike stale rules, which keep
/// blocking a user whose session is long gone.
#[cfg(target_os = "macos")]
fn reap_stale_sessions() {
    match run_pf(&["-a", "com.apple", "-s", "Anchors"]) {
        Ok(listing) => {
            for anchor in parse_stale_anchor_listing(&listing) {
                if let Err(error) = run_pf(&["-a", &anchor, "-F", "rules"]) {
                    eprintln!("failed to flush stale PF anchor {anchor}: {error}");
                }
            }
        }
        Err(error) => eprintln!("could not list PF anchors to reap stale sessions: {error}"),
    }
    // Rules and profile files from the previous instance; new launches write
    // fresh ones.
    if let Ok(entries) = fs::read_dir("/var/run/lianyaohu") {
        for entry in entries.flatten() {
            let _ = fs::remove_file(entry.path());
        }
    }
}

#[cfg(target_os = "macos")]
fn parse_stale_anchor_listing(listing: &str) -> Vec<String> {
    listing
        .lines()
        .map(str::trim)
        .filter(|line| line.starts_with("com.apple/lianyaohu-"))
        .map(ToString::to_string)
        .collect()
}

#[cfg(target_os = "linux")]
fn reap_stale_sessions() {
    lianyaohu_core::linux_firewall::reap_stale_chains();
}

#[cfg(target_os = "macos")]
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

#[cfg(target_os = "macos")]
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

#[cfg(target_os = "linux")]
fn ensure_session_group() -> Result<()> {
    if let Some(gid) = group_gid_by_name(LIANYAOHU_GROUP_NAME)? {
        if gid == LIANYAOHU_GROUP_GID {
            return Ok(());
        }
        return Err(err(format!(
            "{LIANYAOHU_GROUP_NAME} has gid {gid}, expected {LIANYAOHU_GROUP_GID}"
        )));
    }

    if let Some(name) = group_name_by_gid(LIANYAOHU_GROUP_GID)? {
        return Err(err(format!(
            "gid {LIANYAOHU_GROUP_GID} is already assigned to group {name}"
        )));
    }

    let gid = LIANYAOHU_GROUP_GID.to_string();
    let output = Command::new("/usr/sbin/groupadd")
        .args(["-g", &gid, LIANYAOHU_GROUP_NAME])
        .output()?;
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    if output.status.success() {
        Ok(())
    } else {
        Err(err(format!("groupadd failed: {}", combined.trim())))
    }
}

#[cfg(target_os = "linux")]
fn group_gid_by_name(name: &str) -> Result<Option<u32>> {
    let output = Command::new("/usr/bin/getent")
        .args(["group", name])
        .output()?;
    if !output.status.success() {
        return Ok(None);
    }
    Ok(parse_group_entry(&String::from_utf8_lossy(&output.stdout)).map(|(_, gid)| gid))
}

#[cfg(target_os = "linux")]
fn group_name_by_gid(gid: u32) -> Result<Option<String>> {
    let output = Command::new("/usr/bin/getent")
        .args(["group", &gid.to_string()])
        .output()?;
    if !output.status.success() {
        return Ok(None);
    }
    Ok(parse_group_entry(&String::from_utf8_lossy(&output.stdout)).map(|(name, _)| name))
}

#[cfg(target_os = "linux")]
fn parse_group_entry(entry: &str) -> Option<(String, u32)> {
    let mut fields = entry.trim().split(':');
    let name = fields.next()?.to_string();
    let _password = fields.next()?;
    let gid = fields.next()?.parse::<u32>().ok()?;
    Some((name, gid))
}

#[cfg(target_os = "macos")]
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

#[cfg(target_os = "macos")]
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

#[cfg(target_os = "macos")]
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

#[cfg(target_os = "macos")]
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
    peer_credentials_inner(stream)
}

#[cfg(target_vendor = "apple")]
fn peer_credentials_inner(stream: &UnixStream) -> Result<PeerCredentials> {
    let mut uid: libc::uid_t = 0;
    let mut gid: libc::gid_t = 0;
    let rc = unsafe { libc::getpeereid(stream.as_raw_fd(), &mut uid, &mut gid) };
    if rc == 0 {
        Ok(PeerCredentials { uid, gid })
    } else {
        Err(std::io::Error::last_os_error().into())
    }
}

#[cfg(target_os = "linux")]
fn peer_credentials_inner(stream: &UnixStream) -> Result<PeerCredentials> {
    let mut credentials = unsafe { std::mem::zeroed::<libc::ucred>() };
    let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    let rc = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            (&mut credentials as *mut libc::ucred).cast(),
            &mut len,
        )
    };
    if rc == 0 {
        Ok(PeerCredentials {
            uid: credentials.uid,
            gid: credentials.gid,
        })
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

#[cfg(target_os = "macos")]
fn chown(path: &Path, uid: libc::uid_t, gid: libc::gid_t) -> Result<()> {
    let path = CString::new(path.as_os_str().as_encoded_bytes())?;
    let rc = unsafe { libc::chown(path.as_ptr(), uid, gid) };
    if rc == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error().into())
    }
}

/// Write end of the shutdown self-pipe. The signal handler's only job is to
/// push the signal number into this pipe; everything else happens on a normal
/// thread where non-async-signal-safe work (unlink, pfctl, exit handlers) is
/// legal.
static SIGNAL_PIPE_WRITE_FD: AtomicI32 = AtomicI32::new(-1);

extern "C" fn handle_signal(signal: libc::c_int) {
    let fd = SIGNAL_PIPE_WRITE_FD.load(Ordering::Relaxed);
    if fd >= 0 {
        let byte = signal as u8;
        unsafe {
            libc::write(fd, ptr::from_ref(&byte).cast(), 1);
        }
    }
}

fn install_signal_handlers(daemon: HelperDaemon) -> Result<()> {
    let mut fds = [0i32; 2];
    if unsafe { libc::pipe(fds.as_mut_ptr()) } != 0 {
        return Err(io::Error::last_os_error().into());
    }
    SIGNAL_PIPE_WRITE_FD.store(fds[1], Ordering::Relaxed);
    let read_fd = fds[0];
    thread::spawn(move || shutdown_on_signal(read_fd, daemon));
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
    Ok(())
}

fn shutdown_on_signal(read_fd: libc::c_int, daemon: HelperDaemon) {
    let mut byte = 0u8;
    loop {
        let received = unsafe { libc::read(read_fd, ptr::from_mut(&mut byte).cast(), 1) };
        if received == 1 {
            break;
        }
        if received < 0 && io::Error::last_os_error().raw_os_error() == Some(libc::EINTR) {
            continue;
        }
        return;
    }
    let _ = fs::remove_file(SOCKET_PATH);
    daemon.teardown_all_sessions();
    std::process::exit(128 + i32::from(byte));
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(values: &[&str]) -> Vec<String> {
        values.iter().map(|value| value.to_string()).collect()
    }

    #[test]
    fn parse_drop_exec_args_accepts_full_form() {
        let (uid, gid, groups, command) =
            parse_drop_exec_args(&args(&["501", "601", "20,12,61", "--", "/bin/echo", "ok"]))
                .unwrap();

        assert_eq!(uid, 501);
        assert_eq!(gid, 601);
        assert_eq!(groups, vec![20, 12, 61]);
        assert_eq!(command, args(&["/bin/echo", "ok"]));
    }

    #[test]
    fn parse_drop_exec_args_accepts_empty_groups() {
        let (_, _, groups, _) =
            parse_drop_exec_args(&args(&["501", "601", "", "--", "/bin/echo"])).unwrap();

        assert!(groups.is_empty());
    }

    #[test]
    fn parse_drop_exec_args_rejects_bad_input() {
        for case in [
            &args(&["501", "601", "20"])[..],
            &args(&["501", "601", "20", "--"]),
            &args(&["501", "601", "20", "/bin/echo"]),
            &args(&["nope", "601", "20", "--", "/bin/echo"]),
            &args(&["501", "nope", "20", "--", "/bin/echo"]),
            &args(&["501", "601", "20,nope", "--", "/bin/echo"]),
        ] {
            assert!(parse_drop_exec_args(case).is_err(), "{case:?}");
        }
    }

    #[test]
    fn uid_slots_cap_per_uid_and_release_on_drop() {
        let connections = Arc::new(Mutex::new(BTreeMap::new()));

        let held = (0..3)
            .map(|_| UidSlot::acquire(&connections, 501, 3).expect("slot under cap"))
            .collect::<Vec<_>>();

        // The capped UID is refused; another UID still gets a slot.
        assert!(UidSlot::acquire(&connections, 501, 3).is_none());
        assert!(UidSlot::acquire(&connections, 502, 3).is_some());

        // Releasing one slot frees capacity for the capped UID again.
        drop(held);
        assert!(UidSlot::acquire(&connections, 501, 3).is_some());
        // Fully released UIDs are removed from the map rather than kept at 0.
        assert!(
            !connections
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .contains_key(&502)
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn stale_anchor_listing_parses_only_lianyaohu_anchors() {
        let listing = "\
  com.apple/250.ApplicationFirewall
  com.apple/lianyaohu-501
  com.apple/lianyaohu-502
  org.example/other
";

        assert_eq!(
            parse_stale_anchor_listing(listing),
            vec![
                "com.apple/lianyaohu-501".to_string(),
                "com.apple/lianyaohu-502".to_string(),
            ]
        );
    }

    #[test]
    fn home_directory_for_current_uid_resolves() {
        let uid = unsafe { libc::getuid() };
        let home = home_directory_for_uid(uid).unwrap();

        assert!(home.starts_with('/'));
        assert!(Path::new(&home).is_dir());
    }

    #[test]
    fn validated_directory_rejects_bad_inputs() {
        assert!(validated_directory("test", Path::new("relative/path"), None).is_err());
        assert!(validated_directory("test", Path::new("/"), None).is_err());
        assert!(validated_directory("test", Path::new("/nonexistent-lianyaohu"), None).is_err());
        // Owned by root, not by an arbitrary high uid.
        assert!(validated_directory("test", Path::new("/usr"), Some(4_000_000)).is_err());
        assert!(validated_directory("test", Path::new("/usr"), None).is_ok());
    }

    // A temporary directory owned by the calling uid, as the launcher's
    // per-launch tmpdir is; the helper rejects a tmpdir the caller does not
    // own, so tests that expect success must supply an owned one rather than
    // the shared, root-owned system temp root.
    fn owned_tmpdir() -> std::path::PathBuf {
        static COUNTER: AtomicUsize = AtomicUsize::new(0);
        let dir = std::env::temp_dir().join(format!(
            "lianyaohu-helper-test-{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn validate_launch_rebuilds_environment_and_ignores_client_profile() {
        let uid = unsafe { libc::getuid() };
        let home = validated_directory(
            "home",
            Path::new(&home_directory_for_uid(uid).unwrap()),
            Some(uid),
        )
        .unwrap();
        let cwd = std::env::current_dir().unwrap();
        let tmpdir = owned_tmpdir();
        let spec = LaunchSpec::new(
            vec!["/bin/echo".to_string(), "ok".to_string()],
            cwd.to_string_lossy().to_string(),
            BTreeMap::from([
                ("TMPDIR".to_string(), tmpdir.to_string_lossy().to_string()),
                ("HOME".to_string(), "/somewhere/forged".to_string()),
                ("LD_PRELOAD".to_string(), "/tmp/evil.so".to_string()),
                (
                    "DYLD_INSERT_LIBRARIES".to_string(),
                    "/tmp/evil.dylib".to_string(),
                ),
                ("MY_AGENT_FLAG".to_string(), "1".to_string()),
            ]),
            "(allow default)",
        );

        let launch = validate_launch(&spec, uid).unwrap();
        let _ = fs::remove_dir_all(&tmpdir);

        // Home comes from the passwd database, not the client environment.
        assert_eq!(launch.home, home);
        assert_eq!(launch.environment.get("HOME"), Some(&home));
        // Injection vectors are stripped even though the client sent them.
        assert!(!launch.environment.contains_key("LD_PRELOAD"));
        assert!(!launch.environment.contains_key("DYLD_INSERT_LIBRARIES"));
        // Benign agent configuration passes through.
        assert_eq!(
            launch.environment.get("MY_AGENT_FLAG").map(String::as_str),
            Some("1")
        );
        assert_eq!(
            launch
                .environment
                .get("LIANYAOHU_SANDBOX")
                .map(String::as_str),
            Some("1")
        );
    }

    #[test]
    fn validate_launch_rejects_forged_tmpdir() {
        let uid = unsafe { libc::getuid() };
        let cwd = std::env::current_dir().unwrap();
        // /usr is not owned by the caller (unless running as root, where the
        // ownership check cannot fail this way; skip there).
        if uid == 0 {
            return;
        }
        let spec = LaunchSpec::new(
            vec!["/bin/echo".to_string()],
            cwd.to_string_lossy().to_string(),
            BTreeMap::from([("TMPDIR".to_string(), "/usr".to_string())]),
            "(version 1)",
        );

        assert!(validate_launch(&spec, uid).is_err());
    }
}
