//! LianYaoHu (炼妖壶) launcher binary, installed as `lianyaohu` and `lyh`.
//!
//! Runs a code agent inside the platform sandbox with VPN-only egress, and
//! doubles as the root helper daemon (`lianyaohu helper`) and the guided
//! configuration TUI (`lyh config`). See <https://lyh.maxlv.net/> for usage.

mod helper_daemon;
mod session;
mod tui;

use lianyaohu_core::config::{self, ConfigFile, MergedConfig, trust};
use lianyaohu_core::env_policy;
use lianyaohu_core::helper::PFHelperClient;
use lianyaohu_core::interfaces::{
    NetworkInterface, validate_vpn_interface, vpn_interface_description, vpn_interfaces,
};
use lianyaohu_core::launch::LaunchSpec;
#[cfg(target_os = "linux")]
use lianyaohu_core::linux_firewall::{
    LIANYAOHU_GROUP_GID, LinuxFirewallGuard, LinuxFirewallRuleSet,
};
#[cfg(target_os = "linux")]
use lianyaohu_core::linux_sandbox::LinuxSandbox;
#[cfg(target_os = "macos")]
use lianyaohu_core::pf::{LIANYAOHU_GROUP_GID, PFGuard, PFRuleSet};
use lianyaohu_core::policy::SandboxPolicy;
use lianyaohu_core::route;
#[cfg(target_os = "macos")]
use lianyaohu_core::sandbox_profile::SandboxProfile;
use lianyaohu_core::{Result, err};
use std::collections::BTreeMap;
use std::env;
use std::fs;
use std::io::{self, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixListener;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

/// Tri-state flags default to `None` (= "not given on the command line") so
/// config-file defaults can fill them without ever overriding an explicit
/// flag.
#[derive(Debug)]
struct Options {
    cwd: PathBuf,
    vpn_interface: Option<String>,
    command: Vec<String>,
    enforce_pf: Option<bool>,
    helper_group_launch: Option<bool>,
    require_default_route: Option<bool>,
    print_profile: bool,
    print_pf: bool,
    helper_status: bool,
    extra_environment: BTreeMap<String, String>,
    config_path: Option<PathBuf>,
    no_config: bool,
    trust_project: bool,
    no_tui: bool,
    narrow_home: Option<bool>,
    allow_dests: Vec<String>,
    deny_dests: Vec<String>,
    lan_allows: Vec<String>,
    writable_paths: Vec<String>,
    read_only_paths: Vec<String>,
    deny_paths: Vec<String>,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            cwd: env::current_dir().unwrap_or_else(|_| PathBuf::from(".")),
            vpn_interface: None,
            command: Vec::new(),
            enforce_pf: None,
            helper_group_launch: None,
            require_default_route: None,
            print_profile: false,
            print_pf: false,
            helper_status: false,
            extra_environment: BTreeMap::new(),
            config_path: None,
            no_config: false,
            trust_project: false,
            no_tui: false,
            narrow_home: None,
            allow_dests: Vec::new(),
            deny_dests: Vec::new(),
            lan_allows: Vec::new(),
            writable_paths: Vec::new(),
            read_only_paths: Vec::new(),
            deny_paths: Vec::new(),
        }
    }
}

fn main() {
    let program = program_name();
    let args: Vec<String> = env::args().skip(1).collect();

    if args.first().map(String::as_str) == Some("helper") {
        if let Err(error) = helper_daemon::run() {
            eprintln!("{program} helper: {error}");
            std::process::exit(1);
        }
        return;
    }

    // Internal trampoline used by the macOS helper's launch path; on success
    // exec replaces the process, so reaching the error branch is the only way
    // back.
    #[cfg(target_os = "macos")]
    if args.first().map(String::as_str) == Some("drop-exec") {
        if let Err(error) = helper_daemon::drop_exec(&args[1..]) {
            eprintln!("{program} drop-exec: {error}");
        }
        std::process::exit(1);
    }

    // Background session management. As with `config`, an agent literally
    // named like a subcommand can still be launched with `lyh -- <name>`.
    if matches!(
        args.first().map(String::as_str),
        Some("run" | "ls" | "sessions" | "attach" | "kill")
    ) {
        let code = match run_session_cli(&args) {
            Ok(code) => code,
            Err(error) => {
                eprintln!("{program}: {error}");
                1
            }
        };
        std::process::exit(code);
    }

    // `lyh config ...` / `lyh setup`: configuration management. An agent
    // literally named "config" can still be launched with `lyh -- config`.
    if matches!(args.first().map(String::as_str), Some("config" | "setup")) {
        let code = match run_config_command(&args) {
            Ok(code) => code,
            Err(error) => {
                eprintln!("{program} config: {error}");
                1
            }
        };
        std::process::exit(code);
    }

    let code = match run(args) {
        Ok(code) => code,
        Err(error) => {
            eprintln!("{program}: {error}");
            eprintln!("{}", usage(&program));
            2
        }
    };
    std::process::exit(code);
}

// The binary also ships as the `lyh` alias; report whichever name was invoked.
fn program_name() -> String {
    env::args_os()
        .next()
        .map(PathBuf::from)
        .and_then(|path| {
            path.file_name()
                .map(|name| name.to_string_lossy().into_owned())
        })
        .unwrap_or_else(|| "lianyaohu".to_string())
}

fn run(args: Vec<String>) -> Result<i32> {
    let options = parse(args)?;

    if options.helper_status {
        let response = PFHelperClient::default().status()?;
        println!("{}", response.message);
        return Ok(0);
    }

    match prepare(&options)? {
        Prepare::Done(code) => Ok(code),
        Prepare::Ready(prepared) => launch_foreground(*prepared),
    }
}

/// Everything resolved and ready to launch: the command, the sanitized
/// environment, the sandbox profile, and the firewall rule set. Built by
/// [`prepare`], consumed by the foreground launch or a background session.
struct Prepared {
    command: Vec<String>,
    cwd: PathBuf,
    cwd_string: String,
    tmpdir: PathBuf,
    clean_env: BTreeMap<String, String>,
    policy: SandboxPolicy,
    interface: NetworkInterface,
    enforce_pf: bool,
    helper_group_launch: bool,
    #[cfg(target_os = "macos")]
    profile: SandboxProfile,
    #[cfg(target_os = "linux")]
    linux_sandbox: LinuxSandbox,
    #[cfg(target_os = "macos")]
    rule_set: PFRuleSet,
    #[cfg(target_os = "linux")]
    rule_set: LinuxFirewallRuleSet,
}

enum Prepare {
    Ready(Box<Prepared>),
    /// A print-and-exit flag (`--print-profile`, `--print-firewall`) ran.
    Done(i32),
}

/// The whole pre-launch pipeline: layered config, policy, interactive VPN
/// selection, environment sanitizing, sandbox profile, and firewall rules.
/// Interactive prompts happen here, so callers can still daemonize after.
fn prepare(options: &Options) -> Result<Prepare> {
    let home = env::var("HOME").map_err(|_| err("HOME is not set"))?;
    let cwd = options.cwd.canonicalize().unwrap_or(options.cwd.clone());
    let cwd_string = cwd.to_string_lossy().to_string();
    let tmpdir = temporary_directory();

    let merged = load_layered_config(options, &home, &cwd)?;
    let mut effective = merged.file;
    apply_cli_policy(&mut effective, options);

    // Effective settings: CLI flags > project file > global file > defaults.
    let enforce_pf = options
        .enforce_pf
        .unwrap_or_else(|| effective.defaults.firewall.unwrap_or(true));
    let helper_group_launch = options
        .helper_group_launch
        .unwrap_or_else(|| !effective.defaults.shared_user_firewall.unwrap_or(false));
    let require_default_route = options
        .require_default_route
        .unwrap_or_else(|| !effective.defaults.allow_non_default_route.unwrap_or(false));
    let command = if !options.command.is_empty() {
        options.command.clone()
    } else if let Some(command) = effective.defaults.command.clone()
        && !command.is_empty()
    {
        command
    } else {
        if !options.print_profile && !options.print_pf {
            eprintln!(
                "No agent command provided; defaulting to 'claude'. Use -- to pass a different command."
            );
        }
        vec!["claude".to_string()]
    };

    let policy = effective.sandbox_policy(Path::new(&home))?;
    #[cfg(target_os = "linux")]
    if !policy.paths.deny.is_empty() {
        eprintln!(
            "warning: paths.deny is NOT enforced on Linux (Landlock cannot deny inside an allowed tree): {}",
            policy.paths.deny.join(", ")
        );
    }

    // A configured interface that is gone should fall back to selection, not
    // hard-fail like an explicit --vpn flag.
    let config_interface = effective.defaults.vpn_interface.clone();
    let (selected_interface, save_default) = match options.vpn_interface.as_deref() {
        Some(name) => (select_by_name(name)?, false),
        None => match config_interface.as_deref() {
            None => select_interactively(options.no_tui)?,
            Some(name) => match select_by_name(name) {
                Ok(interface) => (interface, false),
                Err(error) => {
                    eprintln!("warning: configured VPN interface {name}: {error}");
                    select_interactively(options.no_tui)?
                }
            },
        },
    };
    if !selected_interface.is_proxy_only() {
        validate_vpn_interface(&selected_interface)?;
    }
    if save_default {
        save_vpn_default(options, &home, &selected_interface.name);
    }

    // Config-file env merges under CLI --env extras (CLI wins per key); both
    // still go through the sanitize block/allow lists.
    let mut extra_environment = effective.env.clone();
    extra_environment.extend(options.extra_environment.clone());

    // Proxy-only mode blocks every direct destination, so a working launch
    // needs a local proxy in the environment — prompt for one if the config
    // and CLI did not provide it. The print-and-exit diagnostics never
    // launch anything, so they skip the requirement.
    if selected_interface.is_proxy_only() && !options.print_pf && !options.print_profile {
        ensure_proxy_configured(&mut extra_environment)?;
        if !policy.network.allow.is_empty() || !policy.network.lan_allow.is_empty() {
            eprintln!(
                "warning: proxy-only mode ignores network.allow/lan_allow rules; only loopback \
                 egress is possible"
            );
        }
    }

    let env_input = env::vars().collect::<BTreeMap<_, _>>();
    let clean_env = env_policy::sanitize(
        &env_input,
        &home,
        &cwd_string,
        &tmpdir.to_string_lossy(),
        &extra_environment,
    );

    #[cfg(target_os = "macos")]
    let profile = SandboxProfile::new(&home, &cwd_string, tmpdir.to_string_lossy())
        .with_paths(policy.paths.clone());
    #[cfg(target_os = "macos")]
    if options.print_profile {
        print!("{}", profile.render());
        return Ok(Prepare::Done(0));
    }
    #[cfg(target_os = "linux")]
    let linux_sandbox =
        LinuxSandbox::from_environment(cwd.clone(), &clean_env)?.with_paths(policy.paths.clone());
    #[cfg(target_os = "linux")]
    if options.print_profile {
        print!("{}", linux_sandbox.render_summary());
        return Ok(Prepare::Done(0));
    }

    let uid = unsafe { libc::getuid() };

    #[cfg(target_os = "macos")]
    let route_gateway = selected_interface.ipv4_peer_addresses.first().cloned();
    #[cfg(target_os = "macos")]
    let rule_set = if helper_group_launch {
        PFRuleSet::new_group(
            selected_interface.name.clone(),
            uid,
            LIANYAOHU_GROUP_GID,
            route_gateway.clone(),
        )
    } else {
        PFRuleSet::new_user(selected_interface.name.clone(), uid, route_gateway.clone())
    }
    .with_network(policy.network.clone());
    #[cfg(target_os = "macos")]
    if options.print_pf {
        print!("{}", rule_set.render());
        return Ok(Prepare::Done(0));
    }

    #[cfg(target_os = "linux")]
    let rule_set = if helper_group_launch {
        LinuxFirewallRuleSet::new_group(selected_interface.name.clone(), uid, LIANYAOHU_GROUP_GID)
    } else {
        LinuxFirewallRuleSet::new_user(selected_interface.name.clone(), uid)
    }
    .with_network(policy.network.clone());
    #[cfg(target_os = "linux")]
    if options.print_pf {
        print!("{}", rule_set.render());
        return Ok(Prepare::Done(0));
    }

    // Proxy-only mode has no VPN interface, so the default-route preflight
    // is meaningless: the firewall blocks direct egress regardless of routes.
    if require_default_route && !selected_interface.is_proxy_only() {
        let default_route = route::default_ipv4_interface()?;
        if default_route.as_deref() != Some(selected_interface.name.as_str()) {
            let default_route_name = default_route.as_deref().unwrap_or("<unknown>");
            #[cfg(target_os = "macos")]
            if enforce_pf && route_gateway.is_some() && PFHelperClient::default().status().is_ok() {
                eprintln!(
                    "note: default IPv4 route uses {default_route_name}; PF route-to will steer agent traffic through {}",
                    selected_interface.name
                );
            } else {
                return Err(err(format!(
                    "default IPv4 route uses {default_route_name}, not selected VPN interface {} \
                     (auto-allow needs the PF guard enabled, a point-to-point IPv4 peer on the utun, \
                     and a reachable root helper; pass --allow-non-default-route to skip this check)",
                    selected_interface.name
                )));
            }
            #[cfg(target_os = "linux")]
            return Err(err(format!(
                "default IPv4 route uses {default_route_name}, not selected VPN interface {} \
                 (Linux firewall support cannot route traffic by itself; configure the VPN as \
                 the default route or pass --allow-non-default-route for diagnostics only)",
                selected_interface.name
            )));
        }
    }

    Ok(Prepare::Ready(Box::new(Prepared {
        command,
        cwd,
        cwd_string,
        tmpdir,
        clean_env,
        policy,
        interface: selected_interface,
        enforce_pf,
        helper_group_launch,
        #[cfg(target_os = "macos")]
        profile,
        #[cfg(target_os = "linux")]
        linux_sandbox,
        rule_set,
    })))
}

fn launch_foreground(prepared: Prepared) -> Result<i32> {
    #[cfg(target_os = "macos")]
    {
        if prepared.enforce_pf && prepared.helper_group_launch {
            return launch_agent_with_session_group(
                &prepared.interface.name,
                &prepared.command,
                &prepared.cwd_string,
                &prepared.tmpdir,
                &prepared.profile,
                &prepared.clean_env,
                &prepared.policy,
            );
        }

        let mut pf_guard = None;
        if prepared.enforce_pf {
            let mut guard = PFGuard::new(prepared.rule_set);
            guard.install()?;
            pf_guard = Some(guard);
        } else {
            eprintln!(
                "warning: PF network guard disabled; relying only on route preflight and process sandbox"
            );
        }

        let status = launch_agent(
            &prepared.command,
            &prepared.cwd,
            &prepared.tmpdir,
            &prepared.profile,
            &prepared.clean_env,
        )?;

        if let Some(mut guard) = pf_guard {
            guard.uninstall();
        }

        Ok(status)
    }

    #[cfg(target_os = "linux")]
    {
        if prepared.enforce_pf && prepared.helper_group_launch {
            return launch_agent_with_session_group(
                &prepared.interface.name,
                &prepared.command,
                &prepared.cwd_string,
                &prepared.tmpdir,
                &prepared.linux_sandbox,
                &prepared.clean_env,
                &prepared.policy,
            );
        }

        let mut firewall_guard = None;
        if prepared.enforce_pf {
            let mut guard = LinuxFirewallGuard::new(prepared.rule_set);
            guard.install()?;
            firewall_guard = Some(guard);
        } else {
            eprintln!(
                "warning: Linux firewall guard disabled; filesystem/process sandbox remains enabled"
            );
        }

        let status = launch_agent(
            &prepared.command,
            &prepared.cwd,
            &prepared.linux_sandbox,
            &prepared.clean_env,
        )?;

        if let Some(mut guard) = firewall_guard {
            guard.uninstall();
        }

        Ok(status)
    }
}

/// `lyh run | ls | attach | kill`: background sessions with attach/detach.
fn run_session_cli(args: &[String]) -> Result<i32> {
    let home = env::var("HOME").map_err(|_| err("HOME is not set"))?;
    let dir = session::sessions_dir(&home);
    match args[0].as_str() {
        "ls" | "sessions" => sessions_ls(&dir),
        "attach" => sessions_attach(&dir, args.get(1).map(String::as_str)),
        "kill" => sessions_kill(&dir, args.get(1).map(String::as_str)),
        "run" => sessions_run(&dir, &args[1..]),
        other => Err(err(format!("unknown session command {other:?}"))),
    }
}

/// `lyh run [--name NAME] [--detached] [launch options] [-- agent ...]`:
/// prepares the sandbox exactly like a foreground launch, then forks a
/// per-session daemon that runs the agent on its own PTY.
fn sessions_run(dir: &Path, args: &[String]) -> Result<i32> {
    let mut name = None;
    let mut detached = false;
    let mut rest = Vec::new();
    let mut index = 0;
    while index < args.len() {
        match args[index].as_str() {
            "--name" => {
                index += 1;
                name = Some(
                    args.get(index)
                        .ok_or_else(|| err("--name requires a session name"))?
                        .clone(),
                );
            }
            "--detached" | "-d" => detached = true,
            // "--" or the first non-flag token starts the agent command;
            // everything after belongs to the agent, not to `run`.
            other if other == "--" || !other.starts_with('-') => {
                rest.extend_from_slice(&args[index..]);
                break;
            }
            _ => rest.push(args[index].clone()),
        }
        index += 1;
    }
    let options = parse(rest)?;
    match prepare(&options)? {
        Prepare::Done(code) => Ok(code),
        Prepare::Ready(prepared) => launch_in_session(*prepared, dir, name, detached),
    }
}

fn launch_in_session(
    prepared: Prepared,
    dir: &Path,
    name: Option<String>,
    detached: bool,
) -> Result<i32> {
    create_private_dir(&dir.to_path_buf())?;
    let name = match name {
        Some(name) => {
            session::validate_name(&name)?;
            if session::socket_path(dir, &name).exists() {
                return Err(err(format!(
                    "session {name} already exists; attach with `lyh attach {name}`"
                )));
            }
            name
        }
        None => session::unique_name(dir, &session::default_name(&prepared.cwd)),
    };
    let socket_path = session::socket_path(dir, &name);
    let listener = UnixListener::bind(&socket_path)
        .map_err(|error| err(format!("{}: {error}", socket_path.display())))?;
    fs::set_permissions(&socket_path, fs::Permissions::from_mode(0o600))?;
    let (rows, cols) = if tui::stdin_is_tty() {
        session::client::initial_winsize()
    } else {
        (24, 80)
    };

    // Helper-path spec (and its policy preflight) is built in the parent so
    // errors still reach the user's terminal.
    let spec = if prepared.enforce_pf && prepared.helper_group_launch {
        #[cfg(target_os = "macos")]
        let rendered = prepared.profile.render();
        #[cfg(target_os = "linux")]
        let rendered = prepared.linux_sandbox.render_summary();
        let spec = lianyaohu_core::launch::LaunchSpec::new(
            prepared.command.clone(),
            prepared.cwd_string.clone(),
            prepared.clean_env.clone(),
            rendered,
        );
        Some(attach_policy(spec, &prepared.policy)?)
    } else {
        None
    };

    // Written by the parent so a concurrent `lyh ls` between fork and the
    // daemon's own metadata write never mistakes the session for stale.
    session::SessionMeta {
        name: name.clone(),
        pid: std::process::id(),
        command: prepared.command.clone(),
        cwd: prepared.cwd_string.clone(),
        vpn_interface: prepared.interface.name.clone(),
        started_at: unix_now(),
    }
    .save(dir)?;

    let log = session::log_path(dir, &name);
    if !session::daemon::daemonize(&log)? {
        drop(listener);
        if detached || !tui::stdin_is_tty() {
            println!("session {name} started; attach with `lyh attach {name}`");
            return Ok(0);
        }
        return attach_loop(dir, name);
    }

    // Daemon from here on: stdio goes to the log file, errors included.
    let code = match run_session_daemon(prepared, dir, &name, listener, spec, (rows, cols)) {
        Ok(code) => code,
        Err(error) => {
            eprintln!("session {name} failed: {error}");
            session::remove_session_files(dir, &name);
            1
        }
    };
    std::process::exit(code);
}

/// Everything the daemon process does: own the PTY, launch the agent onto
/// its slave (root-helper session or direct sandbox spawn), then serve
/// attach clients until the agent exits.
fn run_session_daemon(
    prepared: Prepared,
    dir: &Path,
    name: &str,
    listener: UnixListener,
    spec: Option<lianyaohu_core::launch::LaunchSpec>,
    size: (u16, u16),
) -> Result<i32> {
    use std::os::fd::AsRawFd;

    let (master, slave) = session::daemon::open_pty(size.0, size.1)?;
    session::SessionMeta {
        name: name.to_string(),
        pid: std::process::id(),
        command: prepared.command.clone(),
        cwd: prepared.cwd_string.clone(),
        vpn_interface: prepared.interface.name.clone(),
        started_at: unix_now(),
    }
    .save(dir)?;
    create_private_dir(&prepared.tmpdir)?;
    let (exit_read, exit_write) = session::daemon::exit_pipe()?;

    let agent = if let Some(spec) = spec {
        // Root-helper launch: the helper receives the PTY slave as the
        // agent's stdio triple and reports the exit status when done.
        let spec_path = prepared.tmpdir.join("launch.json");
        spec.write_json(&spec_path)?;
        let interface = prepared.interface.name.clone();
        session::daemon::spawn_exit_waiter(exit_write, move || {
            let fd = slave.as_raw_fd();
            let code = PFHelperClient::default()
                .run_session_with_fds(&interface, &spec_path, [fd, fd, fd])
                .unwrap_or_else(|error| {
                    eprintln!("helper launch failed: {error}");
                    1
                });
            let _ = fs::remove_file(&spec_path);
            drop(slave);
            code
        });
        session::daemon::AgentHandle {
            exit_pipe: exit_read,
            // No pid to signal: the helper owns the agent. Kill works by the
            // daemon closing the PTY master (hangup).
            kill: Box::new(|| {}),
        }
    } else {
        // Direct launch, mirroring the foreground non-helper path but with
        // the PTY slave as the agent's terminal.
        #[cfg(target_os = "macos")]
        let mut guard = prepared.enforce_pf.then(|| PFGuard::new(prepared.rule_set));
        #[cfg(target_os = "linux")]
        let mut guard = prepared
            .enforce_pf
            .then(|| LinuxFirewallGuard::new(prepared.rule_set));
        if let Some(guard) = &mut guard {
            guard.install()?;
        }

        #[cfg(target_os = "macos")]
        let mut command = {
            let profile_path = prepared.tmpdir.join("agent.sb");
            fs::write(&profile_path, prepared.profile.render())?;
            let mut command = Command::new("/usr/bin/sandbox-exec");
            command.arg("-f").arg(&profile_path).args(&prepared.command);
            command
        };
        #[cfg(target_os = "linux")]
        let mut command = {
            let executable = prepared
                .command
                .first()
                .ok_or_else(|| err("agent command is empty"))?;
            let mut command = Command::new(executable);
            command.args(&prepared.command[1..]);
            apply_child_sandbox(&mut command, prepared.linux_sandbox.clone());
            command
        };
        command
            .current_dir(&prepared.cwd)
            .env_clear()
            .envs(&prepared.clean_env)
            .stdin(Stdio::from(fs::File::from(slave.try_clone()?)))
            .stdout(Stdio::from(fs::File::from(slave.try_clone()?)))
            .stderr(Stdio::from(fs::File::from(slave.try_clone()?)));
        // Give the agent the PTY as a proper controlling terminal so job
        // control and SIGWINCH-driven redraws work as in a real terminal.
        // The daemon ignores SIGHUP/SIGPIPE and ignored dispositions survive
        // exec; reset them or the agent becomes unkillable via PTY hangup.
        unsafe {
            command.pre_exec(|| {
                libc::signal(libc::SIGHUP, libc::SIG_DFL);
                libc::signal(libc::SIGPIPE, libc::SIG_DFL);
                libc::setsid();
                libc::ioctl(0, libc::TIOCSCTTY as _, 0);
                Ok(())
            });
        }
        let mut child = command.spawn()?;
        drop(slave);
        let pid = child.id() as libc::pid_t;
        session::daemon::spawn_exit_waiter(exit_write, move || {
            use std::os::unix::process::ExitStatusExt;
            let code = child
                .wait()
                .ok()
                .and_then(|status| {
                    status
                        .code()
                        .or_else(|| status.signal().map(|signal| 128 + signal))
                })
                .unwrap_or(1);
            if let Some(mut guard) = guard {
                guard.uninstall();
            }
            code
        });
        session::daemon::AgentHandle {
            exit_pipe: exit_read,
            kill: Box::new(move || unsafe {
                libc::kill(-pid, libc::SIGHUP);
                libc::kill(pid, libc::SIGHUP);
                libc::kill(-pid, libc::SIGTERM);
                libc::kill(pid, libc::SIGTERM);
            }),
        }
    };

    Ok(session::daemon::run_loop(
        dir, name, listener, master, agent,
    ))
}

/// Attach with client-side session switching: `Ctrl-\ n` / `Ctrl-\ p` hop
/// between live sessions without dropping back to the shell.
fn attach_loop(dir: &Path, mut name: String) -> Result<i32> {
    loop {
        let socket = session::socket_path(dir, &name);
        match session::client::attach(&socket, &name)? {
            session::client::AttachOutcome::Detached => {
                println!("[lyh] detached from {name}; reattach with `lyh attach {name}`");
                return Ok(0);
            }
            session::client::AttachOutcome::Exited(code) => {
                println!("[lyh] session {name} exited with status {code}");
                session::remove_session_files(dir, &name);
                return Ok(code);
            }
            session::client::AttachOutcome::SessionClosed => {
                println!("[lyh] session {name} ended");
                session::remove_session_files(dir, &name);
                return Ok(0);
            }
            outcome @ (session::client::AttachOutcome::SwitchNext
            | session::client::AttachOutcome::SwitchPrev) => {
                let sessions = session::list_sessions(dir)?;
                let names: Vec<String> = sessions
                    .iter()
                    .map(|entry| entry.meta.name.clone())
                    .collect();
                if names.len() <= 1 {
                    println!("[lyh] no other session to switch to");
                    if names.is_empty() {
                        return Ok(0);
                    }
                    continue;
                }
                let position = names.iter().position(|other| *other == name).unwrap_or(0);
                let target = if outcome == session::client::AttachOutcome::SwitchNext {
                    (position + 1) % names.len()
                } else {
                    position.checked_sub(1).unwrap_or(names.len() - 1)
                };
                name = names[target].clone();
            }
        }
    }
}

fn sessions_attach(dir: &Path, name: Option<&str>) -> Result<i32> {
    if !tui::stdin_is_tty() {
        return Err(err("attach requires a terminal"));
    }
    let sessions = session::list_sessions(dir)?;
    let name = match name {
        Some(name) => {
            if !sessions.iter().any(|entry| entry.meta.name == name) {
                return Err(err(format!(
                    "no running session named {name}; `lyh ls` lists sessions"
                )));
            }
            name.to_string()
        }
        // No name: the most recently started session is almost always the
        // one the user means; switching keys reach the rest.
        None => sessions
            .iter()
            .max_by_key(|entry| entry.meta.started_at)
            .map(|entry| entry.meta.name.clone())
            .ok_or_else(|| err("no running sessions; start one with `lyh run`"))?,
    };
    attach_loop(dir, name)
}

fn sessions_ls(dir: &Path) -> Result<i32> {
    let sessions = session::list_sessions(dir)?;
    if sessions.is_empty() {
        println!("no running sessions; start one with `lyh run`");
        return Ok(0);
    }
    println!(
        "{:<20} {:<8} {:<8} {:<8} COMMAND",
        "NAME", "PID", "VPN", "UPTIME"
    );
    let now = unix_now();
    for entry in sessions {
        let uptime = format_uptime(now.saturating_sub(entry.meta.started_at));
        println!(
            "{:<20} {:<8} {:<8} {:<8} {} ({})",
            entry.meta.name,
            entry.meta.pid,
            entry.meta.vpn_interface,
            uptime,
            entry.meta.command.join(" "),
            entry.meta.cwd,
        );
    }
    Ok(0)
}

fn format_uptime(seconds: u64) -> String {
    if seconds >= 3600 {
        format!("{}h{:02}m", seconds / 3600, (seconds % 3600) / 60)
    } else if seconds >= 60 {
        format!("{}m{:02}s", seconds / 60, seconds % 60)
    } else {
        format!("{seconds}s")
    }
}

fn sessions_kill(dir: &Path, name: Option<&str>) -> Result<i32> {
    let name = name.ok_or_else(|| err("kill requires a session name; `lyh ls` lists them"))?;
    let socket = session::socket_path(dir, name);
    if !socket.exists() {
        return Err(err(format!("no session named {name}")));
    }
    match session::client::kill(&socket, name) {
        Ok(Some(code)) => println!("session {name} exited with status {code}"),
        Ok(None) => println!("kill requested; session {name} had not exited yet — check `lyh ls`"),
        Err(_) => {
            session::remove_session_files(dir, name);
            println!("session {name} was already gone; cleaned up its files");
        }
    }
    Ok(0)
}

/// Appends CLI policy flags onto the merged config so one code path builds
/// the final `SandboxPolicy`.
fn apply_cli_policy(file: &mut ConfigFile, options: &Options) {
    file.network.allow.extend(options.allow_dests.clone());
    file.network.deny.extend(options.deny_dests.clone());
    file.network.lan_allow.extend(options.lan_allows.clone());
    file.paths.writable.extend(options.writable_paths.clone());
    file.paths.read_only.extend(options.read_only_paths.clone());
    file.paths.deny.extend(options.deny_paths.clone());
    if options.narrow_home.is_some() {
        file.paths.narrow_home = options.narrow_home;
    }
}

/// Loads the layered configuration and applies the project-file trust policy:
/// tightenings always apply; widenings apply only with a hash-pinned approval
/// (or explicit consent), and are otherwise stripped with a loud warning —
/// never silently widened, and never blocking a scripted run on a prompt.
fn load_layered_config(options: &Options, home: &str, cwd: &Path) -> Result<MergedConfig> {
    let xdg = env::var("XDG_CONFIG_HOME").ok();
    let global_path = options
        .config_path
        .clone()
        .unwrap_or_else(|| config::global_config_path(home, xdg.as_deref()));
    if options.no_config {
        return Ok(config::merge(None, None));
    }

    let global = ConfigFile::load(&global_path)?;
    if global.is_some() && config::loosely_permitted(&global_path) {
        eprintln!(
            "warning: {} is group/world-writable; tighten its permissions (chmod 600)",
            global_path.display()
        );
    }

    let project = match config::discover_project(cwd, Path::new(home))? {
        None => None,
        Some((path, mut file)) => {
            let widenings = file.widening_keys();
            if !widenings.is_empty() {
                let contents = fs::read(&path)?;
                let digest = trust::sha256_hex(&contents);
                let dir = path
                    .parent()
                    .and_then(|parent| parent.canonicalize().ok())
                    .map(|parent| parent.to_string_lossy().to_string())
                    .ok_or_else(|| err(format!("{}: invalid project directory", path.display())))?;
                let store_path = config::trust_store_path(home, xdg.as_deref());
                if config::loosely_permitted(&store_path) {
                    eprintln!(
                        "warning: {} is group/world-writable; a writable trust store defeats hash \
                         pinning (chmod 600)",
                        store_path.display()
                    );
                }
                let mut store = trust::TrustStore::load(&store_path)?;
                if !store.is_approved(&dir, &digest) {
                    let approved_now = options.trust_project
                        || (stdin_is_tty() && prompt_trust(&path, &widenings)?);
                    if approved_now {
                        store.approve(&dir, &digest, Some(unix_now()));
                        store.save()?;
                    } else {
                        let reason = if store.is_stale(&dir, &digest) {
                            "changed since it was last trusted"
                        } else {
                            "not trusted"
                        };
                        eprintln!(
                            "warning: {} is {reason}; applying its restrictions but IGNORING: {}",
                            path.display(),
                            widenings.join(", ")
                        );
                        eprintln!(
                            "         run `lyh config trust` (or pass --trust-project) to approve it"
                        );
                        file.strip_widenings();
                    }
                }
            }
            Some(file)
        }
    };

    Ok(config::merge(global.as_ref(), project.as_ref()))
}

fn stdin_is_tty() -> bool {
    unsafe { libc::isatty(libc::STDIN_FILENO) == 1 && libc::isatty(libc::STDOUT_FILENO) == 1 }
}

fn prompt_trust(path: &Path, widenings: &[&str]) -> Result<bool> {
    eprintln!(
        "{} wants to WIDEN the sandbox with these settings:",
        path.display()
    );
    for key in widenings {
        eprintln!("  - {key}");
    }
    eprint!("Trust this file and apply them? [y/N] ");
    io::stderr().flush()?;
    let mut input = String::new();
    io::stdin().read_line(&mut input)?;
    Ok(matches!(input.trim(), "y" | "Y" | "yes" | "YES"))
}

pub(crate) fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

/// `lyh config [show|path|trust|revoke]` / `lyh setup`. The bare form opens
/// the guided TUI editor on a TTY and falls back to `show` otherwise.
fn run_config_command(args: &[String]) -> Result<i32> {
    let home = env::var("HOME").map_err(|_| err("HOME is not set"))?;
    let xdg = env::var("XDG_CONFIG_HOME").ok();
    let cwd = env::current_dir()?;

    match args.get(1).map(String::as_str) {
        None if tui::stdin_is_tty() => {
            tui::run_config_editor(&home, xdg.as_deref(), &cwd)?;
            Ok(0)
        }
        None | Some("show") => {
            let global_path = config::global_config_path(&home, xdg.as_deref());
            let global = ConfigFile::load(&global_path)?;
            println!(
                "# global: {} ({})",
                global_path.display(),
                if global.is_some() { "loaded" } else { "absent" }
            );
            let project = config::discover_project(&cwd, Path::new(&home))?;
            match &project {
                None => println!("# project: (no {} found)", config::PROJECT_FILE_NAME),
                Some((path, file)) => {
                    println!("# project: {}", path.display());
                    let widenings = file.widening_keys();
                    if !widenings.is_empty() {
                        let digest = trust::sha256_hex(&fs::read(path)?);
                        let dir = path
                            .parent()
                            .and_then(|parent| parent.canonicalize().ok())
                            .map(|parent| parent.to_string_lossy().to_string())
                            .unwrap_or_default();
                        let store = trust::TrustStore::load(&config::trust_store_path(
                            &home,
                            xdg.as_deref(),
                        ))?;
                        if store.is_approved(&dir, &digest) {
                            println!("# project trust: trusted");
                        } else {
                            println!(
                                "# project trust: NOT trusted — {} would be ignored at launch \
                                 (run `lyh config trust`)",
                                widenings.join(", ")
                            );
                        }
                    }
                }
            }
            let merged = config::merge(global.as_ref(), project.as_ref().map(|(_, file)| file));
            for (key, source) in &merged.provenance {
                println!("# source: {key} = {source}");
            }
            print!("{}", merged.file.to_toml()?);
            Ok(0)
        }
        Some("path") => {
            println!(
                "{}",
                config::global_config_path(&home, xdg.as_deref()).display()
            );
            if let Some((path, _)) = config::discover_project(&cwd, Path::new(&home))? {
                println!("{}", path.display());
            }
            Ok(0)
        }
        Some("trust") => config_trust_command(args.get(2), &home, xdg.as_deref(), true),
        Some("revoke") => config_trust_command(args.get(2), &home, xdg.as_deref(), false),
        Some(other) => Err(err(format!(
            "unknown config subcommand {other:?}; expected show, path, trust, or revoke"
        ))),
    }
}

fn config_trust_command(
    dir_arg: Option<&String>,
    home: &str,
    xdg: Option<&str>,
    approve: bool,
) -> Result<i32> {
    let base = match dir_arg {
        Some(dir) => PathBuf::from(dir),
        None => env::current_dir()?,
    };
    let base = base
        .canonicalize()
        .map_err(|error| err(format!("{}: {error}", base.display())))?;
    let (path, _file) = config::discover_project(&base, Path::new(home))?.ok_or_else(|| {
        err(format!(
            "no {} found from {}",
            config::PROJECT_FILE_NAME,
            base.display()
        ))
    })?;
    let dir = path
        .parent()
        .and_then(|parent| parent.canonicalize().ok())
        .map(|parent| parent.to_string_lossy().to_string())
        .ok_or_else(|| err(format!("{}: invalid project directory", path.display())))?;
    let store_path = config::trust_store_path(home, xdg);
    let mut store = trust::TrustStore::load(&store_path)?;
    if approve {
        let digest = trust::sha256_hex(&fs::read(&path)?);
        store.approve(&dir, &digest, Some(unix_now()));
        store.save()?;
        println!("trusted {}", path.display());
    } else if store.revoke(&dir) {
        store.save()?;
        println!("revoked trust for {}", path.display());
    } else {
        println!("no approval recorded for {}", path.display());
    }
    Ok(0)
}

fn parse(args: Vec<String>) -> Result<Options> {
    let mut options = Options::default();
    let mut index = 0;
    while index < args.len() {
        match args[index].as_str() {
            "--" => {
                options.command = args[(index + 1)..].to_vec();
                return Ok(options);
            }
            "--cwd" => {
                index += 1;
                options.cwd = PathBuf::from(
                    args.get(index)
                        .ok_or_else(|| err("--cwd requires a path"))?,
                );
            }
            "--vpn" => {
                index += 1;
                options.vpn_interface = Some(
                    args.get(index)
                        .ok_or_else(|| err("--vpn requires a VPN interface name"))?
                        .clone(),
                );
            }
            "--env" => {
                index += 1;
                let value = args
                    .get(index)
                    .ok_or_else(|| err("--env requires NAME=VALUE"))?;
                let (name, env_value) = value
                    .split_once('=')
                    .ok_or_else(|| err("--env requires NAME=VALUE"))?;
                if name.is_empty() {
                    return Err(err("--env requires NAME=VALUE"));
                }
                options
                    .extra_environment
                    .insert(name.to_string(), env_value.to_string());
            }
            "--no-pf" | "--no-firewall" => options.enforce_pf = Some(false),
            "--shared-user-pf" | "--shared-user-firewall" => {
                options.helper_group_launch = Some(false)
            }
            "--allow-non-default-route" => options.require_default_route = Some(false),
            "--print-profile" => options.print_profile = true,
            "--print-pf" | "--print-firewall" => options.print_pf = true,
            "--helper-status" => options.helper_status = true,
            "--config" => {
                index += 1;
                options.config_path = Some(PathBuf::from(
                    args.get(index)
                        .ok_or_else(|| err("--config requires a path"))?,
                ));
            }
            "--no-config" => options.no_config = true,
            "--trust-project" => options.trust_project = true,
            "--no-tui" => options.no_tui = true,
            "--narrow-home" => options.narrow_home = Some(true),
            "--allow-dest" => {
                index += 1;
                options.allow_dests.push(
                    args.get(index)
                        .ok_or_else(|| err("--allow-dest requires ADDR[/PREFIX][:PORT[-PORT]]"))?
                        .clone(),
                );
            }
            "--deny-dest" => {
                index += 1;
                options.deny_dests.push(
                    args.get(index)
                        .ok_or_else(|| err("--deny-dest requires ADDR[/PREFIX][:PORT[-PORT]]"))?
                        .clone(),
                );
            }
            "--lan-allow" => {
                index += 1;
                options.lan_allows.push(
                    args.get(index)
                        .ok_or_else(|| err("--lan-allow requires ADDR[/PREFIX][:PORT[-PORT]]"))?
                        .clone(),
                );
            }
            "--writable" => {
                index += 1;
                options.writable_paths.push(
                    args.get(index)
                        .ok_or_else(|| err("--writable requires a path"))?
                        .clone(),
                );
            }
            "--read-only" => {
                index += 1;
                options.read_only_paths.push(
                    args.get(index)
                        .ok_or_else(|| err("--read-only requires a path"))?
                        .clone(),
                );
            }
            "--deny-path" => {
                index += 1;
                options.deny_paths.push(
                    args.get(index)
                        .ok_or_else(|| err("--deny-path requires a path"))?
                        .clone(),
                );
            }
            "-h" | "--help" => {
                println!("{}", usage(&program_name()));
                std::process::exit(0);
            }
            other if other.starts_with('-') => return Err(err(format!("unknown option {other}"))),
            _ => {
                options.command = args[index..].to_vec();
                return Ok(options);
            }
        }
        index += 1;
    }
    Ok(options)
}

fn active_interfaces() -> Result<Vec<NetworkInterface>> {
    let interfaces = vpn_interfaces()?;
    if interfaces.is_empty() {
        return Err(err(format!(
            "no supported VPN interfaces found ({}); start the VPN first",
            vpn_interface_description()
        )));
    }
    Ok(interfaces)
}

fn select_by_name(name: &str) -> Result<NetworkInterface> {
    // `--vpn none` / `vpn_interface = "none"`: proxy-only mode, no lookup.
    if name == lianyaohu_core::interfaces::PROXY_ONLY_INTERFACE {
        return Ok(NetworkInterface::proxy_only());
    }
    active_interfaces()?
        .into_iter()
        .find(|interface| interface.name == name)
        .ok_or_else(|| err(format!("{name} was not found among active VPN interfaces")))
}

/// Interactive selection: the ratatui quick-pick on a TTY (unless `--no-tui`),
/// the classic numbered prompt otherwise. Returns the interface and whether
/// the user asked to persist it as the config default. Both pickers offer
/// "none" (proxy-only), so an empty VPN list is still selectable.
fn select_interactively(no_tui: bool) -> Result<(NetworkInterface, bool)> {
    let interfaces = vpn_interfaces()?;
    if tui::stdin_is_tty() && !no_tui {
        match tui::quick_pick(&interfaces)? {
            tui::QuickPickOutcome::Chosen { name, save } => {
                if name == lianyaohu_core::interfaces::PROXY_ONLY_INTERFACE {
                    return Ok((NetworkInterface::proxy_only(), save));
                }
                // The picker refreshes its list live, so the chosen name may
                // postdate our snapshot; re-resolve before trusting it.
                let interface = interfaces
                    .iter()
                    .find(|interface| interface.name == name)
                    .cloned()
                    .or_else(|| {
                        vpn_interfaces()
                            .ok()
                            .and_then(|list| list.into_iter().find(|i| i.name == name))
                    })
                    .ok_or_else(|| err(format!("{name} disappeared during selection")))?;
                Ok((interface, save))
            }
            tui::QuickPickOutcome::Cancelled => Err(err("VPN interface selection cancelled")),
        }
    } else {
        let mut listed = interfaces;
        listed.push(NetworkInterface::proxy_only());
        let index = tui::fallback::select_numbered(&listed)?;
        Ok((listed[index].clone(), false))
    }
}

/// Guarantees the environment carries a proxy for proxy-only mode: keeps a
/// configured proxy as-is, otherwise prompts on a TTY and errors without one.
fn ensure_proxy_configured(environment: &mut BTreeMap<String, String>) -> Result<()> {
    let configured = env_policy::PROXY_ENV_KEYS
        .iter()
        .find_map(|key| environment.get(*key))
        .cloned();
    let url = match configured {
        Some(url) => url,
        None if stdin_is_tty() => prompt_proxy_url()?,
        None => {
            return Err(err(
                "proxy-only mode needs a local proxy: set the proxy in `lyh config` (HTTP \
                 proxy), add [env] HTTPS_PROXY to the config, or pass --env \
                 HTTPS_PROXY=http://127.0.0.1:PORT",
            ));
        }
    };
    if !env_policy::proxy_url_is_loopback(&url) {
        eprintln!(
            "warning: proxy {url} is not on loopback; proxy-only mode blocks every non-loopback \
             destination, so this proxy will be unreachable from the agent"
        );
    }
    env_policy::insert_proxy_env(environment, &url);
    Ok(())
}

fn prompt_proxy_url() -> Result<String> {
    eprintln!(
        "Proxy-only mode: all direct egress is blocked; outbound traffic needs a local proxy."
    );
    loop {
        eprint!("Local proxy URL (e.g. http://127.0.0.1:7890): ");
        io::stderr().flush()?;
        let mut input = String::new();
        if io::stdin().read_line(&mut input)? == 0 {
            return Err(err("proxy-only mode requires a proxy URL"));
        }
        let trimmed = input.trim();
        if trimmed.is_empty() {
            return Err(err("proxy-only mode requires a proxy URL"));
        }
        match env_policy::validate_proxy_url(trimmed) {
            Ok(url) => return Ok(url),
            Err(error) => eprintln!("  invalid proxy URL: {error}"),
        }
    }
}

/// Persists the chosen interface as `[defaults] vpn_interface` in the global
/// config. Failures only warn: not being able to save a preference must never
/// stop a launch.
fn save_vpn_default(options: &Options, home: &str, name: &str) {
    let xdg = env::var("XDG_CONFIG_HOME").ok();
    let path = options
        .config_path
        .clone()
        .unwrap_or_else(|| config::global_config_path(home, xdg.as_deref()));
    let mut file = match ConfigFile::load(&path) {
        Ok(file) => file.unwrap_or_default(),
        Err(error) => {
            eprintln!("warning: not saving default VPN interface: {error}");
            return;
        }
    };
    file.defaults.vpn_interface = Some(name.to_string());
    match file.save(&path) {
        Ok(()) => eprintln!(
            "saved {name} as the default VPN interface in {}",
            path.display()
        ),
        Err(error) => eprintln!("warning: could not save default VPN interface: {error}"),
    }
}

// The launch tree holds the sandbox profile and the launch spec (command,
// environment, credentials); keep it owner-only.
fn create_private_dir(path: &PathBuf) -> Result<()> {
    use std::os::unix::fs::DirBuilderExt;
    fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(path)?;
    Ok(())
}

fn temporary_directory() -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or(0);
    env::temp_dir().join(format!(
        "lianyaohu-{}-{}-{nanos}",
        unsafe { libc::getuid() },
        std::process::id()
    ))
}

#[cfg(target_os = "macos")]
fn launch_agent(
    command: &[String],
    cwd: &PathBuf,
    tmpdir: &PathBuf,
    profile: &SandboxProfile,
    clean_env: &BTreeMap<String, String>,
) -> Result<i32> {
    create_private_dir(tmpdir)?;
    let profile_path = tmpdir.join("agent.sb");
    fs::write(&profile_path, profile.render())?;

    let status = Command::new("/usr/bin/sandbox-exec")
        .arg("-f")
        .arg(&profile_path)
        .args(command)
        .current_dir(cwd)
        .env_clear()
        .envs(clean_env)
        .status()?;

    Ok(status.code().unwrap_or(1))
}

#[cfg(target_os = "linux")]
fn launch_agent(
    command: &[String],
    cwd: &PathBuf,
    sandbox: &LinuxSandbox,
    clean_env: &BTreeMap<String, String>,
) -> Result<i32> {
    let executable = command
        .first()
        .ok_or_else(|| err("agent command is empty"))?;
    let mut child = Command::new(executable);
    child
        .args(&command[1..])
        .current_dir(cwd)
        .env_clear()
        .envs(clean_env);
    apply_child_sandbox(&mut child, sandbox.clone());

    let status = child.status()?;

    Ok(status.code().unwrap_or(1))
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

/// A non-default policy must never be silently half-enforced: probe the helper
/// first, and hard-error when it predates policy support. A default policy
/// skips the probe and ships a legacy spec, so old and new helpers behave
/// identically.
fn attach_policy(spec: LaunchSpec, policy: &SandboxPolicy) -> Result<LaunchSpec> {
    if policy.is_default() {
        return Ok(spec);
    }
    match PFHelperClient::default().supports_policy() {
        Ok(true) => Ok(spec.with_policy(policy.clone())),
        Ok(false) => Err(err(
            "this configuration customizes the sandbox policy, which requires an updated root \
             helper; run scripts/install-helper.sh, or rerun with --no-config to launch with the \
             built-in policy",
        )),
        Err(error) => Err(err(format!("root helper is unreachable: {error}"))),
    }
}

#[cfg(target_os = "macos")]
fn launch_agent_with_session_group(
    interface_name: &str,
    command: &[String],
    cwd: &str,
    tmpdir: &PathBuf,
    profile: &SandboxProfile,
    clean_env: &BTreeMap<String, String>,
    policy: &SandboxPolicy,
) -> Result<i32> {
    create_private_dir(tmpdir)?;
    let spec_path = tmpdir.join("launch.json");
    let spec = LaunchSpec::new(command.to_vec(), cwd, clean_env.clone(), profile.render());
    let spec = attach_policy(spec, policy)?;
    spec.write_json(&spec_path)?;

    let result = PFHelperClient::default()
        .run_session(interface_name, &spec_path)
        .map_err(|error| {
            err(format!(
                "dedicated group isolation requires an updated root helper: {error}. Run scripts/install-helper.sh, or pass --shared-user-pf to use current-UID PF rules."
            ))
        });
    let _ = fs::remove_file(&spec_path);
    result
}

#[cfg(target_os = "linux")]
fn launch_agent_with_session_group(
    interface_name: &str,
    command: &[String],
    cwd: &str,
    tmpdir: &PathBuf,
    sandbox: &LinuxSandbox,
    clean_env: &BTreeMap<String, String>,
    policy: &SandboxPolicy,
) -> Result<i32> {
    create_private_dir(tmpdir)?;
    let spec_path = tmpdir.join("launch.json");
    let spec = LaunchSpec::new(
        command.to_vec(),
        cwd,
        clean_env.clone(),
        sandbox.render_summary(),
    );
    let spec = attach_policy(spec, policy)?;
    spec.write_json(&spec_path)?;

    let result = PFHelperClient::default()
        .run_session(interface_name, &spec_path)
        .map_err(|error| {
            err(format!(
                "dedicated group isolation requires the root helper: {error}. Run scripts/install-helper.sh, or pass --shared-user-firewall to use current-UID firewall rules."
            ))
        });
    let _ = fs::remove_file(&spec_path);
    result
}

fn usage(program: &str) -> String {
    format!(
        r#"usage:
  {program} [options] [-- agent [args...]]
  {program} run [--name NAME] [--detached] [options] [-- agent [args...]]
  {program} attach [NAME]
  {program} ls | sessions
  {program} kill NAME
  {program} config [show|path|trust [DIR]|revoke [DIR]]
  {program} helper

subcommands:
  run                         Launch the agent in a background session on its own PTY, then
                              attach. Detach with Ctrl-\ d; switch sessions with Ctrl-\ n/p;
                              Ctrl-\ Ctrl-\ sends a literal Ctrl-\. Each session gets its own
                              sandbox, so several agents can run side by side.
  attach [NAME]               Reattach to a session (default: the most recently started).
  ls                          List running sessions. Alias: sessions.
  kill NAME                   Terminate a session's agent (hangs up its PTY).
  config show                 Print the effective merged configuration with per-key provenance.
  config path                 Print the config file paths (global, and project if found).
  config trust [DIR]          Approve the project .lianyaohu.toml (hash-pinned, direnv-style).
  config revoke [DIR]         Remove a project file's approval.
  helper                      Run the root firewall helper daemon.

configuration:
  Global defaults live in ~/.config/lianyaohu/config.toml; a project may add
  .lianyaohu.toml (discovered upward from --cwd). Restrictions in a project
  file always apply; anything that WIDENS access (network.allow, lan_allow,
  paths.writable/read_only, agent_state_dirs, [env]) applies only after
  `{program} config trust`. Precedence: flags > project > global.

options:
  --vpn NAME                  Select a VPN interface without prompting
                              (macOS: utun*, Linux: tun* or wg*). `--vpn none` selects
                              proxy-only mode: no VPN, all direct egress blocked (loopback
                              only), outbound traffic through a local proxy — configured
                              via [env] HTTPS_PROXY, --env, or an interactive prompt.
  --cwd PATH                  Working directory exposed to the agent. Defaults to current directory.
  --env NAME=VALUE            Add an environment variable unless it is privacy-blocked or a
                              code-injection vector (LD_*, DYLD_*, PYTHON*, NODE_OPTIONS, ...).
  --config PATH               Use PATH as the global config file.
  --no-config                 Ignore all configuration files for this run.
  --trust-project             Approve the discovered project file without prompting.
  --no-tui                    Never open interactive pickers; use the plain numbered prompt.
  --allow-dest RULE           Allow a destination (ADDR[/PREFIX][:PORT[-PORT]]); repeatable.
                              With [network] default = "deny", only allowed destinations pass.
  --deny-dest RULE            Block a destination; repeatable.
  --lan-allow RULE            Open a hole in the LAN block (rule must be inside the blocked
                              LAN ranges); repeatable.
  --writable PATH             Extra writable path for the agent; repeatable.
  --read-only PATH            Extra read-only path for the agent; repeatable.
  --deny-path PATH            Deny the agent access to PATH (macOS-enforced; warned on Linux);
                              repeatable.
  --narrow-home               Replace the blanket writable $HOME with agent state dirs only.
  --no-firewall               Do not install the firewall guard. Intended for tests and debugging.
                              Alias: --no-pf.
  --shared-user-firewall      Use current-UID firewall rules instead of helper-managed group isolation.
                              Alias: --shared-user-pf.
  --allow-non-default-route   Do not require the system default route to use the selected VPN.
                              On macOS, skipped automatically when the PF guard is enabled, the utun has an
                              IPv4 peer, and the root helper is reachable (PF route-to steers
                              agent traffic through the utun regardless of the default route).
  --helper-status             Query the root firewall helper status for this user.
  --print-profile             Print the generated sandbox profile/summary and exit.
  --print-firewall            Print generated firewall rules and exit. Alias: --print-pf.

default command:
  claude (or [defaults] command from the config file)
"#
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse_args(values: &[&str]) -> Result<Options> {
        parse(values.iter().map(|value| value.to_string()).collect())
    }

    #[test]
    fn proxy_only_mode_requires_or_reuses_a_proxy() {
        // Without a TTY (as in tests) and no configured proxy, launch must
        // fail rather than start an agent with no possible egress.
        let mut environment = BTreeMap::new();
        assert!(ensure_proxy_configured(&mut environment).is_err());

        // A configured proxy is kept and fanned out to all variables.
        let mut environment = BTreeMap::from([(
            "HTTPS_PROXY".to_string(),
            "http://127.0.0.1:7890".to_string(),
        )]);
        ensure_proxy_configured(&mut environment).unwrap();
        assert_eq!(
            environment.get("http_proxy").map(String::as_str),
            Some("http://127.0.0.1:7890")
        );
        assert_eq!(
            environment.get("NO_PROXY").map(String::as_str),
            Some(env_policy::NO_PROXY_VALUE)
        );
    }

    #[test]
    fn select_by_name_resolves_proxy_only_without_lookup() {
        let selected = select_by_name("none").unwrap();
        assert!(selected.is_proxy_only());
    }

    #[test]
    fn parse_leaves_unset_flags_as_none_for_config_defaults() {
        let options = parse_args(&["--", "claude"]).unwrap();

        assert_eq!(options.enforce_pf, None);
        assert_eq!(options.helper_group_launch, None);
        assert_eq!(options.require_default_route, None);
        assert_eq!(options.narrow_home, None);
        assert_eq!(options.command, ["claude"]);
    }

    #[test]
    fn parse_records_explicit_flags() {
        let options = parse_args(&[
            "--no-firewall",
            "--shared-user-firewall",
            "--allow-non-default-route",
            "--narrow-home",
            "--no-config",
            "--trust-project",
            "--no-tui",
            "--config",
            "/tmp/custom.toml",
            "--",
            "codex",
        ])
        .unwrap();

        assert_eq!(options.enforce_pf, Some(false));
        assert_eq!(options.helper_group_launch, Some(false));
        assert_eq!(options.require_default_route, Some(false));
        assert_eq!(options.narrow_home, Some(true));
        assert!(options.no_config);
        assert!(options.trust_project);
        assert!(options.no_tui);
        assert_eq!(options.config_path, Some(PathBuf::from("/tmp/custom.toml")));
        assert_eq!(options.command, ["codex"]);
    }

    #[test]
    fn parse_collects_repeatable_policy_flags() {
        let options = parse_args(&[
            "--allow-dest",
            "1.2.3.0/24:443",
            "--allow-dest",
            "5.6.7.8",
            "--deny-dest",
            "169.254.169.254",
            "--lan-allow",
            "192.168.1.10:22",
            "--writable",
            "/data/models",
            "--read-only",
            "/data/reference",
            "--deny-path",
            "~/.ssh",
        ])
        .unwrap();

        assert_eq!(options.allow_dests, ["1.2.3.0/24:443", "5.6.7.8"]);
        assert_eq!(options.deny_dests, ["169.254.169.254"]);
        assert_eq!(options.lan_allows, ["192.168.1.10:22"]);
        assert_eq!(options.writable_paths, ["/data/models"]);
        assert_eq!(options.read_only_paths, ["/data/reference"]);
        assert_eq!(options.deny_paths, ["~/.ssh"]);
    }

    #[test]
    fn parse_rejects_unknown_flags_and_missing_values() {
        assert!(parse_args(&["--nonsense"]).is_err());
        assert!(parse_args(&["--allow-dest"]).is_err());
        assert!(parse_args(&["--config"]).is_err());
        assert!(parse_args(&["--env", "NOEQUALS"]).is_err());
    }

    #[test]
    fn cli_policy_flags_append_to_merged_config() {
        let mut file =
            ConfigFile::parse("[network]\nallow = [\"9.9.9.9\"]\n\n[paths]\nnarrow_home = false\n")
                .unwrap();
        let options = parse_args(&[
            "--allow-dest",
            "1.2.3.0/24",
            "--deny-path",
            "/secrets",
            "--narrow-home",
        ])
        .unwrap();

        apply_cli_policy(&mut file, &options);

        assert_eq!(file.network.allow, ["9.9.9.9", "1.2.3.0/24"]);
        assert_eq!(file.paths.deny, ["/secrets"]);
        // CLI --narrow-home overrides the config file's false.
        assert_eq!(file.paths.narrow_home, Some(true));

        let policy = file.sandbox_policy(Path::new("/Users/me")).unwrap();
        assert!(policy.paths.narrow_home);
        assert_eq!(policy.network.allow.len(), 2);
    }
}
