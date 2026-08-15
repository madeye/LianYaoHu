use lianyaohu_core::env_policy;
use lianyaohu_core::helper::{
    HelperRequest, MAX_REQUEST_BYTES, SOCKET_PATH, parse_request, receive_message_with_fds,
};
#[cfg(target_os = "macos")]
use lianyaohu_core::interfaces::{utun_interfaces, validate_utun};
#[cfg(target_os = "linux")]
use lianyaohu_core::interfaces::{
    validate_vpn_interface as validate_platform_vpn_interface, vpn_interfaces,
};
use lianyaohu_core::launch::{LAUNCH_SPEC_VERSION, LaunchSpec};
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
use lianyaohu_core::policy::{PathPolicy, SandboxPolicy, lexically_normalized_absolute};
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
use std::sync::{Arc, Mutex, OnceLock, PoisonError};
use std::time::Duration;
use std::{mem, ptr, thread};

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
            HelperRequest::Install {
                interface_name,
                network,
            } => {
                self.install(peer.uid, &interface_name, network)?;
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
                self.release_install_session(peer.uid)?;
                Ok(format!("uninstalled firewall guard for uid {}", peer.uid))
            }
            HelperRequest::Status => {
                if self.lock_sessions().contains_key(&peer.uid) {
                    Ok("installed".to_string())
                } else {
                    Ok("not installed".to_string())
                }
            }
            // Capability probe for version negotiation: clients with a
            // non-default sandbox policy require a helper that understands
            // versioned specs, and an old helper answers this verb with an
            // error line — which is exactly the negative signal they need.
            HelperRequest::Capabilities => Ok(format!(
                "policy=1 install_policy=1 spec_version={LAUNCH_SPEC_VERSION}"
            )),
        }
    }

    fn lock_sessions(&self) -> std::sync::MutexGuard<'_, BTreeMap<u32, SessionState>> {
        self.sessions.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn install(
        &self,
        uid: u32,
        interface_name: &str,
        network: lianyaohu_core::policy::NetworkPolicy,
    ) -> Result<()> {
        let selected = validated_vpn_interface(interface_name)?;
        self.acquire_session(install_rule_set(uid, &selected, network))
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
            // Whole-rule-set equality: the rules live under one anchor per
            // UID, so sessions differing in ANY way — interface, owner scope,
            // or network policy — cannot both be enforced at once.
            if state.rule_set != rule_set {
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
            // Whole-rule-set equality: the rules live under one chain per
            // UID, so sessions differing in ANY way — interface, owner scope,
            // or network policy — cannot both be enforced at once.
            if state.rule_set != rule_set {
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

    /// Release one reference to the UID's user-scoped `install` session.
    /// `uninstall` carries no session token — any same-UID process can write
    /// it to the socket — so it must never touch state owned by a live `run`
    /// session: the run path releases its own reference when the agent
    /// exits, and letting an unrelated client decrement that refcount would
    /// strip the group-scoped firewall out from under a still-running agent.
    fn release_install_session(&self, uid: u32) -> Result<()> {
        let mut sessions = self.lock_sessions();
        let Some(state) = sessions.get_mut(&uid) else {
            return Ok(());
        };
        if !state.rule_set.is_user_scoped() {
            return Err(err(format!(
                "uid {uid} has a live helper run session; its firewall rules come down when that \
                 session exits, not via uninstall"
            )));
        }
        state.refcount -= 1;
        if state.refcount > 0 {
            return Ok(());
        }
        if let Some(state) = sessions.remove(&uid) {
            teardown_session(&state);
        }
        Ok(())
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

        // The spec path is client-supplied and this daemon runs as root, so
        // read_json refuses symlinks and non-regular files, requires the file
        // to be owned by the authenticated peer, and runs the open and read
        // on an abandonable reader thread bounded by the same deadline as the
        // socket I/O, so a hostile filesystem cannot pin this worker.
        let spec = LaunchSpec::read_json(spec_path, peer.uid, IO_TIMEOUT)?;
        ensure_session_group()?;
        let selected = validated_vpn_interface(interface_name)?;
        let launch = validate_launch(&spec, peer.uid)?;

        #[cfg(target_os = "macos")]
        let rule_set = PFRuleSet::new_group(
            selected.name,
            peer.uid,
            LIANYAOHU_GROUP_GID,
            selected.ipv4_peer_addresses.first().cloned(),
        )
        .with_network(launch.policy.network.clone());
        #[cfg(target_os = "linux")]
        let rule_set =
            LinuxFirewallRuleSet::new_group(selected.name, peer.uid, LIANYAOHU_GROUP_GID)
                .with_network(launch.policy.network.clone());

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
         interface, scope, and network policy — align the configs, or wait for the running \
         session to exit",
        active.anchor_key,
        active.interface_name,
        active.socket_owner.description(),
    ))
}

#[cfg(target_os = "linux")]
fn session_conflict_error(active: &LinuxFirewallRuleSet) -> lianyaohu_core::Error {
    err(format!(
        "uid {} already has an active session on {} ({}); concurrent sessions must use the same \
         interface, scope, and network policy — align the configs, or wait for the running \
         session to exit",
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
/// be real directories (tmpdir owned by the caller), the environment is
/// re-sanitized with the same policy the client claims to have applied, and
/// the sandbox policy is re-validated field by field (widenings need caller
/// ownership; see validate_policy). The client's sandbox_profile text is
/// ignored entirely.
#[derive(Debug)]
struct ValidatedLaunch {
    command: Vec<String>,
    cwd: String,
    home: String,
    tmpdir: String,
    environment: BTreeMap<String, String>,
    policy: SandboxPolicy,
}

fn validate_launch(spec: &LaunchSpec, uid: u32) -> Result<ValidatedLaunch> {
    spec.validate()?;
    // The command is exec'd through option-parsing wrappers (sandbox-exec on
    // macOS). The `--` separator in run_launch_spec is the primary guard;
    // refusing option-shaped executables here keeps a crafted spec from even
    // reaching a wrapper's argv parser.
    let executable = spec
        .command
        .first()
        .ok_or_else(|| err("launch spec command is empty"))?;
    if executable.is_empty() || executable.starts_with('-') {
        return Err(err(format!(
            "launch spec executable {executable:?} must not be empty or start with '-'"
        )));
    }
    let home = home_directory_for_uid(uid)?;
    let home = validated_directory("home directory", Path::new(&home), Some(uid))?;
    let cwd = validated_directory("working directory", Path::new(&spec.cwd), None)?;
    let tmpdir = spec
        .environment
        .get("TMPDIR")
        .ok_or_else(|| err("launch environment is missing TMPDIR"))?;
    let tmpdir = validated_directory("temporary directory", Path::new(tmpdir), Some(uid))?;
    let policy = validate_policy(spec.policy.as_ref(), uid, &home)?;

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
        policy,
    })
}

/// System prefixes an extra WRITABLE path may never live under, even when the
/// caller somehow owns a directory there. The caller-ownership check is the
/// primary gate; this list is belt and braces for trojanable system surfaces.
const WRITABLE_SYSTEM_DENYLIST: &[&str] = &[
    "/etc",
    "/private/etc",
    "/usr",
    "/bin",
    "/sbin",
    "/System",
    "/Library",
    "/dev",
    "/proc",
    "/sys",
    "/var/run",
    "/private/var/run",
    "/var/db",
    "/private/var/db",
    "/opt/homebrew",
];

fn path_has_prefix(path: &str, prefix: &str) -> bool {
    path == prefix || path.starts_with(&format!("{prefix}/"))
}

/// pw_dir values that are shared system stubs, not private homes: service
/// accounts point at these (`/var/empty` on macOS, `/nonexistent`, `/bin`,
/// and `/usr/sbin` on Debian-family systems). Treating them as home roots
/// would make large system prefixes ungrantable, so they are skipped; every
/// other passwd home counts regardless of uid — a uid-999 system user's real
/// home deserves the same protection as anyone else's.
const SYSTEM_STUB_HOMES: &[&str] = &[
    "/",
    "/bin",
    "/dev",
    "/dev/null",
    "/nonexistent",
    "/private/var/empty",
    "/sbin",
    "/usr/bin",
    "/usr/games",
    "/usr/sbin",
    "/var/empty",
];

/// Directories that are — or contain — user home directories: the standard
/// platform home roots, root's home, plus every user's passwd home (NFS
/// `/export/home/...`, systemd-homed, and other nonstandard layouts).
/// Each root is listed both as written and canonicalized, so a symlinked
/// `/home` or macOS's `/var/root` -> `/private/var/root` cannot dodge the
/// prefix check; the APFS firmlink alias of `/Users` is covered explicitly
/// because canonicalization does not resolve firmlinks.
///
/// The static platform roots are computed once; the passwd walk stays
/// per-request so accounts created while the helper runs are still covered.
/// The tradeoff: each run/policy request re-enumerates passwd behind the
/// process-wide PASSWD_LOCK, so on hosts whose passwd resolves through a
/// slow directory service this serializes concurrent requests. Note getpwent
/// cannot see directory-service accounts at all when enumeration is off
/// (LDAP/AD/Open Directory), so such homes are only covered when they live
/// under one of the static roots.
fn home_directory_roots() -> Vec<String> {
    static STATIC_ROOTS: OnceLock<Vec<String>> = OnceLock::new();
    let mut roots = STATIC_ROOTS
        .get_or_init(|| {
            let statics = [
                "/Users",
                "/home",
                "/root",
                "/var/root",
                "/System/Volumes/Data/Users",
            ];
            let mut roots = Vec::new();
            for root in statics {
                push_home_root_with_canonical(&mut roots, root.to_string());
            }
            roots
        })
        .clone();
    for home in passwd_home_directories() {
        push_home_root_with_canonical(&mut roots, home);
    }
    roots
}

fn push_home_root_with_canonical(roots: &mut Vec<String>, root: String) {
    if let Ok(canonical) = Path::new(&root).canonicalize()
        && let Some(canonical) = canonical.to_str()
    {
        push_home_root(roots, canonical.to_string());
    }
    push_home_root(roots, root);
}

fn push_home_root(roots: &mut Vec<String>, root: String) {
    if root.starts_with('/') && root != "/" && !roots.contains(&root) {
        roots.push(root);
    }
}

fn is_system_stub_home(dir: &str) -> bool {
    SYSTEM_STUB_HOMES.contains(&dir)
}

/// pw_dir of every passwd entry whose home is not a shared system stub.
/// getpwent walks shared static state, so enumeration is serialized.
fn passwd_home_directories() -> Vec<String> {
    static PASSWD_LOCK: Mutex<()> = Mutex::new(());
    let _guard = PASSWD_LOCK.lock().unwrap_or_else(PoisonError::into_inner);
    let mut homes = Vec::new();
    unsafe {
        libc::setpwent();
        loop {
            let entry = libc::getpwent();
            if entry.is_null() {
                break;
            }
            if (*entry).pw_dir.is_null() {
                continue;
            }
            if let Ok(dir) = CStr::from_ptr((*entry).pw_dir).to_str()
                && !is_system_stub_home(dir)
            {
                homes.push(dir.to_string());
            }
        }
        libc::endpwent();
    }
    homes
}

/// True when `canonical` reaches into — or wholly contains — a home-directory
/// tree that is not the caller's own. Both directions matter: a grant at or
/// below a foreign home reads part of it, and a grant ABOVE a home root
/// (`/export/home`, macOS `/System/Volumes/Data`) reads every home below it
/// just the same, because read-only extras render as recursive subpath
/// allows with no counter-deny.
fn inside_foreign_home(canonical: &str, caller_home: &str, home_roots: &[String]) -> bool {
    home_roots.iter().any(|root| {
        // A root at or below the caller's own home is the caller's, never
        // foreign — the caller's home itself must stay grantable.
        if path_has_prefix(root, caller_home) {
            return false;
        }
        (path_has_prefix(canonical, root) && !path_has_prefix(canonical, caller_home))
            || path_has_prefix(root, canonical)
    })
}

/// Re-validates a client-supplied sandbox policy. The network policy and path
/// tightenings (deny entries, narrow-home state dirs) only need grammar and
/// containment checks — worst case the client restricts itself. Widenings are
/// held to the same standard as the launch roots: canonicalized against the
/// real filesystem, and extra writable paths must be owned by the caller and
/// outside system prefixes.
fn validate_policy(
    spec_policy: Option<&SandboxPolicy>,
    uid: u32,
    caller_home: &str,
) -> Result<SandboxPolicy> {
    let Some(policy) = spec_policy else {
        return Ok(SandboxPolicy::default());
    };
    // Grammar, list caps, and lan_allow ⊆ blocked-LAN containment — never
    // trust the client's claim of having validated.
    policy.validate()?;

    let mut writable = Vec::new();
    for entry in &policy.paths.writable {
        let canonical = validated_directory("extra writable path", Path::new(entry), Some(uid))?;
        if WRITABLE_SYSTEM_DENYLIST
            .iter()
            .any(|prefix| path_has_prefix(&canonical, prefix))
        {
            return Err(err(format!(
                "extra writable path {canonical} is inside a protected system prefix"
            )));
        }
        writable.push(canonical);
    }

    let home_roots = home_directory_roots();
    let mut read_only = Vec::new();
    for entry in &policy.paths.read_only {
        let canonical = validated_directory("extra read-only path", Path::new(entry), None)?;
        // Reading other users' homes is exactly what the sandbox exists to
        // prevent; a read-only grant must not reopen it.
        if inside_foreign_home(&canonical, caller_home, &home_roots) {
            return Err(err(format!(
                "extra read-only path {canonical} is inside another user's home directory"
            )));
        }
        read_only.push(canonical);
    }

    // Tightenings: lexical normalization only. Deny targets need not exist
    // (they may be created later) and are never resolved through symlinks —
    // canonicalizing a missing path would fail anyway.
    let deny = policy
        .paths
        .deny
        .iter()
        .map(|entry| lexically_normalized_absolute(entry))
        .collect::<Result<Vec<_>>>()?;

    // Narrow-home state dirs become writable grants, so they are checked
    // against the real filesystem: any entry that resolves through a symlink
    // is refused outright — wherever it points — so ~/.cache can widen
    // narrow-home neither into / nor onto an in-home target like ~/.ssh.
    let agent_state_dirs = policy
        .paths
        .agent_state_dirs
        .iter()
        .map(|entry| validated_state_dir(entry, uid, caller_home))
        .collect::<Result<Vec<_>>>()?;

    Ok(SandboxPolicy {
        network: policy.network.clone(),
        paths: PathPolicy {
            writable,
            read_only,
            deny,
            narrow_home: policy.paths.narrow_home,
            agent_state_dirs,
        },
    })
}

/// Validates a narrow-home state dir entry (relative and `..`-free per
/// `policy.validate`) against the caller's home. The caller's home is already
/// canonical, so the canonical form of `home/entry` can differ from the
/// lexical join only by resolving a symlink — and any symlink involvement is
/// refused outright, never rewritten to its target: under narrow-home a
/// rewrite would convert a state-dir grant into a write grant on the target
/// (e.g. `~/.cache -> ~/.ssh`), and on macOS it would hand seatbelt the
/// redirected target where the symlinked entry was previously inert. This
/// subsumes the escape (`~/.cache -> /`) and home-itself cases, which both
/// involve a symlink. A not-yet-created entry passes through unchanged — it
/// grants nothing until it exists, and on Linux rule installation refuses
/// symlinks again at apply time.
fn validated_state_dir(entry: &str, uid: u32, caller_home: &str) -> Result<String> {
    use std::os::unix::fs::MetadataExt;

    let joined = Path::new(caller_home).join(entry);
    let canonical = match joined.canonicalize() {
        Ok(canonical) => canonical,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(entry.to_string()),
        Err(error) => {
            return Err(err(format!("agent state dir {entry:?}: {error}")));
        }
    };
    if canonical != joined {
        return Err(err(format!(
            "agent state dir {entry:?} resolves through a symlink to {}; symlinked state dirs are refused",
            canonical.display()
        )));
    }
    let metadata = fs::metadata(&canonical)?;
    if metadata.uid() != uid {
        return Err(err(format!(
            "agent state dir {entry:?} is not owned by uid {uid}"
        )));
    }
    Ok(entry.to_string())
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
    // The profile is rebuilt here from the validated roots and the validated
    // policy; the client's profile text is never consumed.
    let profile = SandboxProfile::new(&launch.home, &launch.cwd, &launch.tmpdir)
        .with_paths(launch.policy.paths.clone())
        .render();
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

    let mut command = sandbox_exec_command(
        &helper_exe,
        uid,
        session_gid,
        &groups_csv,
        &profile_arg,
        &launch.command,
    );
    command
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

/// Builds the `launchctl asuser <uid> <helper> drop-exec ... --
/// /usr/bin/sandbox-exec -f <profile> -- <client command...>` argv. Factored
/// out of [`run_launch_spec`] so a unit test can pin the `--` separator
/// between the helper-built profile arguments and the client command: without
/// it a spec command starting with `-p`/`-f` would reach sandbox-exec's
/// option parser and could replace the helper-built profile.
#[cfg(any(target_os = "macos", test))]
fn sandbox_exec_command(
    helper_exe: &Path,
    uid: u32,
    session_gid: u32,
    groups_csv: &str,
    profile_arg: &str,
    client_command: &[String],
) -> Command {
    let mut command = Command::new("/bin/launchctl");
    command
        .arg("asuser")
        .arg(uid.to_string())
        .arg(helper_exe)
        .arg("drop-exec")
        .arg(uid.to_string())
        .arg(session_gid.to_string())
        .arg(groups_csv)
        .arg("--")
        .arg("/usr/bin/sandbox-exec")
        .arg("-f")
        .arg(profile_arg)
        // Terminate sandbox-exec's own option parsing: without this a spec
        // command starting with `-p`/`-f` would be consumed as a sandbox-exec
        // option and could replace the helper-built profile.
        .arg("--")
        .args(client_command);
    command
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
    // HOME/TMPDIR the client put in the spec; same for the path policy.
    let sandbox = LinuxSandbox::new(&launch.home, &launch.cwd, &launch.tmpdir)
        .with_paths(launch.policy.paths.clone());

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

/// Builds the exact rule set an `install` request stores and enforces. The
/// client-supplied policy (already re-validated by `parse_request`) is applied
/// the same way `run_session` applies the launch spec's policy: dropping the
/// `.with_network(network)` here would silently install weaker rules than the
/// client rendered and showed with `--print-firewall` — pinned by
/// `install_stores_the_client_network_policy_in_the_rule_set`.
#[cfg(target_os = "macos")]
fn install_rule_set(
    uid: u32,
    selected: &lianyaohu_core::interfaces::NetworkInterface,
    network: lianyaohu_core::policy::NetworkPolicy,
) -> PFRuleSet {
    PFRuleSet::new_user(
        selected.name.clone(),
        uid,
        selected.ipv4_peer_addresses.first().cloned(),
    )
    .with_network(network)
}

/// See the macOS variant above: this is the stored rule set for `install`,
/// and the client policy must survive into it.
#[cfg(target_os = "linux")]
fn install_rule_set(
    uid: u32,
    selected: &lianyaohu_core::interfaces::NetworkInterface,
    network: lianyaohu_core::policy::NetworkPolicy,
) -> LinuxFirewallRuleSet {
    LinuxFirewallRuleSet::new_user(selected.name.clone(), uid).with_network(network)
}

#[cfg(target_os = "macos")]
fn validated_vpn_interface(
    interface_name: &str,
) -> Result<lianyaohu_core::interfaces::NetworkInterface> {
    // Proxy-only mode has no interface; the rendered rules are strictly
    // tighter (block everything but loopback), so no lookup is needed.
    if interface_name == lianyaohu_core::interfaces::PROXY_ONLY_INTERFACE {
        return Ok(lianyaohu_core::interfaces::NetworkInterface::proxy_only());
    }
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
    if interface_name == lianyaohu_core::interfaces::PROXY_ONLY_INTERFACE {
        return Ok(lianyaohu_core::interfaces::NetworkInterface::proxy_only());
    }
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
    fn proxy_only_interface_is_accepted_without_lookup() {
        let selected = validated_vpn_interface("none").unwrap();
        assert!(selected.is_proxy_only());
        // Everything else keeps the strict platform validation.
        assert!(validated_vpn_interface("en0").is_err());
        assert!(validated_vpn_interface("nonexistent").is_err());
    }

    // Regression test for the silent policy drop at the daemon install site:
    // `HelperDaemon::install` stores exactly `install_rule_set(...)`'s
    // output, so a custom default-deny / lan_allow policy must survive into
    // the stored rule set and its rendered rules. This fails if the
    // `.with_network(network)` in install_rule_set is dropped — the stored
    // set would fall back to the default policy and none of the substrings
    // below would render.
    #[test]
    fn install_stores_the_client_network_policy_in_the_rule_set() {
        use lianyaohu_core::interfaces::NetworkInterface;
        use lianyaohu_core::policy::{DestRule, NetAction, NetworkPolicy};

        let network = NetworkPolicy {
            default_action: NetAction::Deny,
            allow: vec![DestRule::parse("140.82.112.0/20:443").unwrap()],
            deny: vec![DestRule::parse("169.254.169.254").unwrap()],
            lan_allow: vec![DestRule::parse("192.168.1.10:22").unwrap()],
        };
        let selected = NetworkInterface {
            name: "utun5".to_string(),
            flags: 0,
            ipv4_addresses: vec!["10.7.0.2".to_string()],
            ipv4_peer_addresses: vec!["10.7.0.1".to_string()],
            ipv6_addresses: Vec::new(),
        };

        let rule_set = install_rule_set(501, &selected, network.clone());

        // The full policy is stored, not a default that ignores the client's
        // deny/lan_allow lists.
        assert_eq!(rule_set.network, network);
        // `install` sessions must stay user-scoped: `uninstall` may release
        // only user-scoped state.
        assert!(rule_set.is_user_scoped());
        // And the policy's rules actually reach the rendered firewall text.
        let rendered = rule_set.render();
        for needle in ["140.82.112.0/20", "169.254.169.254", "192.168.1.10"] {
            assert!(
                rendered.contains(needle),
                "stored rule set does not render policy rule {needle}:\n{rendered}"
            );
        }
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

    #[cfg(target_os = "macos")]
    fn test_session(rule_set: PFRuleSet, refcount: usize) -> SessionState {
        SessionState {
            rule_set,
            refcount,
            enable_token: None,
            rules_path: std::path::PathBuf::from("/nonexistent-lianyaohu-test-rules"),
        }
    }

    #[cfg(target_os = "linux")]
    fn test_session(rule_set: LinuxFirewallRuleSet, refcount: usize) -> SessionState {
        SessionState { rule_set, refcount }
    }

    // Regression test for #56: `uninstall` is authorized only as "same UID",
    // so it must not decrement the refcount of a live group-scoped `run`
    // session — that would strip the firewall while run_launch_spec is still
    // blocked on the agent.
    #[test]
    fn uninstall_cannot_release_a_live_run_session() {
        let daemon = HelperDaemon::default();
        #[cfg(target_os = "macos")]
        let rule_set = PFRuleSet::new_group("utun9", 501, LIANYAOHU_GROUP_GID, None);
        #[cfg(target_os = "linux")]
        let rule_set = LinuxFirewallRuleSet::new_group("tun9", 501, LIANYAOHU_GROUP_GID);
        daemon
            .lock_sessions()
            .insert(501, test_session(rule_set, 1));

        let error = daemon.release_install_session(501).unwrap_err();

        assert!(
            error.to_string().contains("live helper run session"),
            "{error}"
        );
        // The run session and its refcount are untouched.
        assert_eq!(daemon.lock_sessions().get(&501).unwrap().refcount, 1);
    }

    #[test]
    fn uninstall_releases_install_sessions_by_refcount() {
        let daemon = HelperDaemon::default();
        #[cfg(target_os = "macos")]
        let rule_set = PFRuleSet::new_user("utun9", 501, None);
        #[cfg(target_os = "linux")]
        let rule_set = LinuxFirewallRuleSet::new_user("tun9", 501);
        daemon
            .lock_sessions()
            .insert(501, test_session(rule_set, 2));

        // A second concurrent install still holds a reference: no teardown.
        daemon.release_install_session(501).unwrap();
        assert_eq!(daemon.lock_sessions().get(&501).unwrap().refcount, 1);

        // Unknown UIDs are a no-op rather than an error.
        daemon.release_install_session(4_000_000).unwrap();
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
  com.apple/lianyaohu-user-502
  org.example/other
";

        // Group-scoped and sudo user-scoped anchors are both reaped.
        assert_eq!(
            parse_stale_anchor_listing(listing),
            vec![
                "com.apple/lianyaohu-501".to_string(),
                "com.apple/lianyaohu-user-502".to_string(),
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

    use lianyaohu_core::policy::{DestRule, NetworkPolicy};

    fn base_spec(tmpdir: &Path) -> LaunchSpec {
        LaunchSpec::new(
            vec!["/bin/echo".to_string(), "ok".to_string()],
            std::env::current_dir()
                .unwrap()
                .to_string_lossy()
                .to_string(),
            BTreeMap::from([("TMPDIR".to_string(), tmpdir.to_string_lossy().to_string())]),
            "(version 1)",
        )
    }

    #[test]
    fn validate_launch_rejects_option_shaped_executable() {
        let uid = unsafe { libc::getuid() };
        let tmpdir = owned_tmpdir();

        // A command whose argv[0] parses as a sandbox-exec option must be
        // refused: `-p '(allow default)'` would replace the helper profile.
        for command in [
            vec![
                "-p".to_string(),
                "(allow default)".to_string(),
                "/bin/echo".to_string(),
            ],
            vec!["-f".to_string(), "/tmp/evil.sb".to_string()],
            vec![String::new()],
        ] {
            let mut spec = base_spec(&tmpdir);
            spec.command = command.clone();
            assert!(validate_launch(&spec, uid).is_err(), "{command:?}");
        }

        let _ = fs::remove_dir_all(&tmpdir);
    }

    // sandbox-exec must treat everything after `--` as the command, so an
    // injected `-p '(allow default)'` cannot reach its option parser: with the
    // separator in place the `-p` is exec'd as a (nonexistent) program and the
    // launch fails instead of running under the injected profile.
    #[cfg(target_os = "macos")]
    #[test]
    fn sandbox_exec_separator_stops_option_parsing() {
        if std::env::var_os("CI").is_some() {
            eprintln!("skipping sandbox-exec runtime test in CI");
            return;
        }
        let tmpdir = owned_tmpdir();
        let profile_path = tmpdir.join("permissive.sb");
        fs::write(&profile_path, "(version 1)\n(allow default)\n").unwrap();

        let run = |args: &[&str]| {
            Command::new("/usr/bin/sandbox-exec")
                .arg("-f")
                .arg(&profile_path)
                .args(args)
                .output()
                .unwrap()
        };

        // The separator itself is accepted and the command still runs.
        let plain = run(&["--", "/bin/echo", "ok"]);
        assert!(plain.status.success(), "{plain:?}");

        // The injection attempt fails: `-p` is not a runnable command.
        let injected = run(&["--", "-p", "(allow default)", "/bin/echo"]);
        assert!(!injected.status.success());

        let _ = fs::remove_dir_all(&tmpdir);
    }

    // The built argv itself must carry the separator: the runtime test above
    // self-skips in CI and exercises sandbox-exec directly, so this pins that
    // run_launch_spec's Command keeps `--` between the helper-built `-f
    // <profile>` and the client command — a refactor dropping it would fail
    // here, not only against a live sandbox-exec.
    #[test]
    fn sandbox_exec_argv_terminates_option_parsing_before_client_command() {
        let command = sandbox_exec_command(
            Path::new("/usr/local/bin/lianyaohu"),
            501,
            2_000_000,
            "20,12",
            "/var/run/lianyaohu/profile-501.sb",
            &["-p".to_string(), "(allow default)".to_string()],
        );

        assert_eq!(command.get_program(), "/bin/launchctl");
        let args = command
            .get_args()
            .map(|arg| arg.to_string_lossy().to_string())
            .collect::<Vec<_>>();
        let expected_tail = [
            "/usr/bin/sandbox-exec",
            "-f",
            "/var/run/lianyaohu/profile-501.sb",
            "--",
            "-p",
            "(allow default)",
        ]
        .map(ToString::to_string);
        assert!(args.ends_with(&expected_tail), "{args:?}");
    }

    #[test]
    fn legacy_spec_validates_to_default_policy() {
        let uid = unsafe { libc::getuid() };
        let tmpdir = owned_tmpdir();

        let launch = validate_launch(&base_spec(&tmpdir), uid).unwrap();
        let _ = fs::remove_dir_all(&tmpdir);

        assert!(launch.policy.is_default());
    }

    #[test]
    fn validate_launch_rejects_future_spec_versions() {
        let uid = unsafe { libc::getuid() };
        let tmpdir = owned_tmpdir();
        let mut spec = base_spec(&tmpdir);
        spec.spec_version = LAUNCH_SPEC_VERSION + 1;

        let error = validate_launch(&spec, uid).unwrap_err();
        let _ = fs::remove_dir_all(&tmpdir);

        assert!(
            error.to_string().contains("newer than this helper"),
            "{error}"
        );
    }

    #[test]
    fn validate_policy_accepts_owned_writable_and_rebuilds_canonical_paths() {
        let uid = unsafe { libc::getuid() };
        let caller_home = home_directory_for_uid(uid).unwrap();
        let extra = owned_tmpdir();
        let mut policy = SandboxPolicy::default();
        policy.paths.writable = vec![extra.to_string_lossy().to_string()];
        policy.paths.deny = vec!["/tmp//x/y".to_string()];
        policy.paths.narrow_home = true;

        let validated = validate_policy(Some(&policy), uid, &caller_home).unwrap();
        // The writable extra comes back canonicalized (macOS temp dirs live
        // behind /var -> /private/var).
        let canonical = extra.canonicalize().unwrap();
        let _ = fs::remove_dir_all(&extra);
        assert_eq!(validated.paths.writable, [canonical.to_string_lossy()]);
        // Deny entries are lexically normalized.
        assert_eq!(validated.paths.deny, ["/tmp/x/y"]);
        assert!(validated.paths.narrow_home);
    }

    #[test]
    fn validate_policy_rejects_hostile_paths() {
        let uid = unsafe { libc::getuid() };
        if uid == 0 {
            return;
        }
        let caller_home = home_directory_for_uid(uid).unwrap();

        // Not caller-owned.
        let mut policy = SandboxPolicy::default();
        policy.paths.writable = vec!["/usr".to_string()];
        assert!(validate_policy(Some(&policy), uid, &caller_home).is_err());

        // Caller-owned checks cannot save a protected prefix: simulate by
        // pointing at /etc (fails ownership on the canonical path first, but
        // the denylist also covers it for a root caller).
        let mut policy = SandboxPolicy::default();
        policy.paths.writable = vec!["/etc".to_string()];
        assert!(validate_policy(Some(&policy), uid, &caller_home).is_err());

        // Another user's home is off-limits even read-only.
        let other_home = if cfg!(target_os = "macos") {
            "/Users"
        } else {
            "/home"
        };
        let mut policy = SandboxPolicy::default();
        policy.paths.read_only = vec![other_home.to_string()];
        assert!(validate_policy(Some(&policy), uid, &caller_home).is_err());

        // Homes outside /Users and /home are covered too: root's home lives
        // at /var/root (macOS) or /root (Linux).
        let root_home = if cfg!(target_os = "macos") {
            "/var/root"
        } else {
            "/root"
        };
        let mut policy = SandboxPolicy::default();
        policy.paths.read_only = vec![root_home.to_string()];
        let error = validate_policy(Some(&policy), uid, &caller_home).unwrap_err();
        assert!(error.to_string().contains("another user's home"), "{error}");

        // Absolute agent_state_dirs entries never pass.
        let mut policy = SandboxPolicy::default();
        policy.paths.agent_state_dirs = vec!["/absolute".to_string()];
        assert!(validate_policy(Some(&policy), uid, &caller_home).is_err());

        // Oversized lists are rejected before any filesystem work.
        let mut policy = SandboxPolicy::default();
        policy.paths.deny = (0..=lianyaohu_core::policy::MAX_RULES_PER_LIST)
            .map(|i| format!("/deny/{i}"))
            .collect();
        assert!(validate_policy(Some(&policy), uid, &caller_home).is_err());
    }

    #[test]
    fn home_directory_roots_cover_platform_roots_and_passwd_homes() {
        let roots = home_directory_roots();

        // Never "/" (which would reject every path) and always absolute.
        assert!(
            roots
                .iter()
                .all(|root| root.starts_with('/') && root.as_str() != "/")
        );
        for expected in ["/Users", "/home", "/root", "/var/root"] {
            assert!(roots.contains(&expected.to_string()), "{expected}");
        }
        #[cfg(target_os = "macos")]
        assert!(roots.contains(&"/private/var/root".to_string()));

        // Passwd homes are enumerated with no uid floor, wherever they live.
        let uid = unsafe { libc::getuid() };
        let home = home_directory_for_uid(uid).unwrap();
        if !is_system_stub_home(&home) {
            assert!(roots.contains(&home), "{home} missing from {roots:?}");
        }

        // Service-account stubs never become home roots: treating /var/empty
        // as a home would make most of /var ungrantable on macOS.
        for stub in [
            "/var/empty",
            "/private/var/empty",
            "/nonexistent",
            "/usr/sbin",
        ] {
            assert!(!roots.contains(&stub.to_string()), "{stub}");
        }
    }

    #[test]
    fn foreign_home_check_covers_nonstandard_home_layouts() {
        // Synthetic layout: passwd homes on an NFS export, caller is bob.
        let roots = vec![
            "/Users".to_string(),
            "/home".to_string(),
            "/System/Volumes/Data/Users".to_string(),
            "/export/home/alice".to_string(),
            "/export/home/bob".to_string(),
        ];
        let caller_home = "/export/home/bob";

        assert!(inside_foreign_home(
            "/export/home/alice/docs",
            caller_home,
            &roots
        ));
        assert!(inside_foreign_home(
            "/export/home/alice",
            caller_home,
            &roots
        ));
        assert!(inside_foreign_home("/home/alice", caller_home, &roots));
        // The caller's own home (a passwd home itself) stays grantable.
        assert!(!inside_foreign_home(
            "/export/home/bob/docs",
            caller_home,
            &roots
        ));
        assert!(!inside_foreign_home("/opt/data", caller_home, &roots));
        // A caller homed under a standard root keeps access to their subtree.
        assert!(!inside_foreign_home("/home/bob/x", "/home/bob", &roots));
    }

    // A grant CONTAINING a foreign home grants that home's contents just the
    // same as a grant below it — the read-only rules are recursive with no
    // counter-deny — so parents of home roots are foreign too.
    #[test]
    fn foreign_home_check_rejects_parents_of_home_roots() {
        let roots = vec![
            "/Users".to_string(),
            "/home".to_string(),
            "/System/Volumes/Data/Users".to_string(),
            "/export/home/alice".to_string(),
            "/export/home/bob".to_string(),
        ];
        let caller_home = "/export/home/bob";

        // The issue's NFS example: rejecting /export/home/alice but allowing
        // /export/home would grant alice's home anyway.
        assert!(inside_foreign_home("/export/home", caller_home, &roots));
        assert!(inside_foreign_home("/export", caller_home, &roots));
        // macOS: the firmlinked data volume contains /Users.
        assert!(inside_foreign_home(
            "/System/Volumes/Data",
            caller_home,
            &roots
        ));
        assert!(inside_foreign_home("/Users", caller_home, &roots));
        assert!(inside_foreign_home("/home", caller_home, &roots));

        // The caller's own home and unrelated directories stay grantable,
        // even when the caller's home is itself an enumerated root.
        assert!(!inside_foreign_home(
            "/export/home/bob",
            caller_home,
            &roots
        ));
        assert!(!inside_foreign_home("/opt/data", caller_home, &roots));
        assert!(!inside_foreign_home("/Users/bob", "/Users/bob", &roots));
        assert!(!inside_foreign_home("/Users/bob/src", "/Users/bob", &roots));
    }

    #[test]
    fn state_dirs_refuse_any_symlinked_entry() {
        let uid = unsafe { libc::getuid() };
        let home = owned_tmpdir().canonicalize().unwrap();
        let caller_home = home.to_str().unwrap();

        fs::create_dir_all(home.join("state")).unwrap();
        fs::create_dir_all(home.join("real")).unwrap();
        std::os::unix::fs::symlink(home.join("real"), home.join("inner")).unwrap();
        std::os::unix::fs::symlink(std::env::temp_dir(), home.join("escape")).unwrap();
        std::os::unix::fs::symlink(&home, home.join("self")).unwrap();

        // A real dir keeps its name; a missing one passes through untouched.
        assert_eq!(
            validated_state_dir("state", uid, caller_home).unwrap(),
            "state"
        );
        assert_eq!(
            validated_state_dir("absent", uid, caller_home).unwrap(),
            "absent"
        );
        // A symlink staying inside the home is refused, never rewritten to
        // its target: under narrow-home a rewrite would convert the state
        // grant into a write grant on the target (e.g. ~/.ssh).
        let error = validated_state_dir("inner", uid, caller_home).unwrap_err();
        assert!(error.to_string().contains("symlink"), "{error}");
        // A symlink out of the home (the `~/.cache -> /` escape) is refused...
        let error = validated_state_dir("escape", uid, caller_home).unwrap_err();
        assert!(error.to_string().contains("symlink"), "{error}");
        // ...and so is one resolving to the home itself, which would undo
        // narrow-home entirely.
        assert!(validated_state_dir("self", uid, caller_home).is_err());

        // The same refusal holds end-to-end through policy validation.
        let mut policy = SandboxPolicy::default();
        policy.paths.narrow_home = true;
        policy.paths.agent_state_dirs = vec!["escape".into()];
        assert!(validate_policy(Some(&policy), uid, caller_home).is_err());

        let _ = fs::remove_dir_all(&home);
    }

    #[test]
    fn validate_policy_rejects_lan_allow_outside_blocked_ranges() {
        let uid = unsafe { libc::getuid() };
        let caller_home = home_directory_for_uid(uid).unwrap();
        let policy = SandboxPolicy {
            network: NetworkPolicy {
                lan_allow: vec![DestRule::parse("0.0.0.0/0").unwrap()],
                ..NetworkPolicy::default()
            },
            ..SandboxPolicy::default()
        };

        let error = validate_policy(Some(&policy), uid, &caller_home).unwrap_err();
        assert!(error.to_string().contains("blocked LAN ranges"), "{error}");
    }

    #[test]
    fn capabilities_verb_parses_and_reports_policy_support() {
        assert_eq!(
            lianyaohu_core::helper::parse_request("capabilities\n").unwrap(),
            HelperRequest::Capabilities
        );
    }
}
