mod helper_daemon;

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
use lianyaohu_core::route;
#[cfg(target_os = "macos")]
use lianyaohu_core::sandbox_profile::SandboxProfile;
use lianyaohu_core::{Result, err};
use std::collections::BTreeMap;
use std::env;
use std::fs;
use std::io::{self, Write};
#[cfg(target_os = "linux")]
use std::os::unix::process::CommandExt;
use std::path::PathBuf;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug)]
struct Options {
    cwd: PathBuf,
    vpn_interface: Option<String>,
    command: Vec<String>,
    enforce_pf: bool,
    helper_group_launch: bool,
    require_default_route: bool,
    print_profile: bool,
    print_pf: bool,
    helper_status: bool,
    extra_environment: BTreeMap<String, String>,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            cwd: env::current_dir().unwrap_or_else(|_| PathBuf::from(".")),
            vpn_interface: None,
            command: Vec::new(),
            enforce_pf: true,
            helper_group_launch: true,
            require_default_route: true,
            print_profile: false,
            print_pf: false,
            helper_status: false,
            extra_environment: BTreeMap::new(),
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

    if options.command.is_empty() && !options.print_profile && !options.print_pf {
        eprintln!(
            "No agent command provided; defaulting to 'claude'. Use -- to pass a different command."
        );
    }

    let home = env::var("HOME").map_err(|_| err("HOME is not set"))?;
    let cwd = options.cwd.canonicalize().unwrap_or(options.cwd.clone());
    let cwd_string = cwd.to_string_lossy().to_string();
    let tmpdir = temporary_directory();

    let selected_interface = select_interface(options.vpn_interface.as_deref())?;
    validate_vpn_interface(&selected_interface)?;

    let env_input = env::vars().collect::<BTreeMap<_, _>>();
    let clean_env = env_policy::sanitize(
        &env_input,
        &home,
        &cwd_string,
        &tmpdir.to_string_lossy(),
        &options.extra_environment,
    );

    #[cfg(target_os = "macos")]
    let profile = SandboxProfile::new(&home, &cwd_string, tmpdir.to_string_lossy());
    #[cfg(target_os = "macos")]
    if options.print_profile {
        print!("{}", profile.render());
        return Ok(0);
    }
    #[cfg(target_os = "linux")]
    let linux_sandbox = LinuxSandbox::from_environment(cwd.clone(), &clean_env)?;
    #[cfg(target_os = "linux")]
    if options.print_profile {
        print!("{}", linux_sandbox.render_summary());
        return Ok(0);
    }

    let uid = unsafe { libc::getuid() };

    #[cfg(target_os = "macos")]
    let route_gateway = selected_interface.ipv4_peer_addresses.first().cloned();
    #[cfg(target_os = "macos")]
    let rule_set = if options.helper_group_launch {
        PFRuleSet::new_group(
            selected_interface.name.clone(),
            uid,
            LIANYAOHU_GROUP_GID,
            route_gateway.clone(),
        )
    } else {
        PFRuleSet::new_user(selected_interface.name.clone(), uid, route_gateway.clone())
    };
    #[cfg(target_os = "macos")]
    if options.print_pf {
        print!("{}", rule_set.render());
        return Ok(0);
    }

    #[cfg(target_os = "linux")]
    let rule_set = if options.helper_group_launch {
        LinuxFirewallRuleSet::new_group(selected_interface.name.clone(), uid, LIANYAOHU_GROUP_GID)
    } else {
        LinuxFirewallRuleSet::new_user(selected_interface.name.clone(), uid)
    };
    #[cfg(target_os = "linux")]
    if options.print_pf {
        print!("{}", rule_set.render());
        return Ok(0);
    }

    if options.require_default_route {
        let default_route = route::default_ipv4_interface()?;
        if default_route.as_deref() != Some(selected_interface.name.as_str()) {
            let default_route_name = default_route.as_deref().unwrap_or("<unknown>");
            #[cfg(target_os = "macos")]
            if options.enforce_pf
                && route_gateway.is_some()
                && PFHelperClient::default().status().is_ok()
            {
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

    let command = if options.command.is_empty() {
        vec!["claude".to_string()]
    } else {
        options.command
    };

    #[cfg(target_os = "macos")]
    {
        if options.enforce_pf && options.helper_group_launch {
            return launch_agent_with_session_group(
                &selected_interface.name,
                &command,
                &cwd_string,
                &tmpdir,
                &profile,
                &clean_env,
            );
        }

        let mut pf_guard = None;
        if options.enforce_pf {
            let mut guard = PFGuard::new(rule_set);
            guard.install()?;
            pf_guard = Some(guard);
        } else {
            eprintln!(
                "warning: PF network guard disabled; relying only on route preflight and process sandbox"
            );
        }

        let status = launch_agent(&command, &cwd, &tmpdir, &profile, &clean_env)?;

        if let Some(mut guard) = pf_guard {
            guard.uninstall();
        }

        return Ok(status);
    }

    #[cfg(target_os = "linux")]
    {
        if options.enforce_pf && options.helper_group_launch {
            return launch_agent_with_session_group(
                &selected_interface.name,
                &command,
                &cwd_string,
                &tmpdir,
                &linux_sandbox,
                &clean_env,
            );
        }

        let mut firewall_guard = None;
        if options.enforce_pf {
            let mut guard = LinuxFirewallGuard::new(rule_set);
            guard.install()?;
            firewall_guard = Some(guard);
        } else {
            eprintln!(
                "warning: Linux firewall guard disabled; filesystem/process sandbox remains enabled"
            );
        }

        let status = launch_agent(&command, &cwd, &linux_sandbox, &clean_env)?;

        if let Some(mut guard) = firewall_guard {
            guard.uninstall();
        }

        return Ok(status);
    }

    #[allow(unreachable_code)]
    Err(err("unsupported platform"))
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
            "--no-pf" | "--no-firewall" => options.enforce_pf = false,
            "--shared-user-pf" | "--shared-user-firewall" => options.helper_group_launch = false,
            "--allow-non-default-route" => options.require_default_route = false,
            "--print-profile" => options.print_profile = true,
            "--print-pf" | "--print-firewall" => options.print_pf = true,
            "--helper-status" => options.helper_status = true,
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

fn select_interface(requested: Option<&str>) -> Result<NetworkInterface> {
    let interfaces = vpn_interfaces()?;
    if interfaces.is_empty() {
        return Err(err(format!(
            "no supported VPN interfaces found ({}); start the VPN first",
            vpn_interface_description()
        )));
    }

    if let Some(name) = requested {
        return interfaces
            .into_iter()
            .find(|interface| interface.name == name)
            .ok_or_else(|| err(format!("{name} was not found among active VPN interfaces")));
    }

    let interactive =
        unsafe { libc::isatty(libc::STDIN_FILENO) == 1 && libc::isatty(libc::STDOUT_FILENO) == 1 };
    let selected = if interactive {
        select_interface_interactive(&interfaces)?
    } else {
        select_interface_numbered(&interfaces)?
    };
    Ok(interfaces[selected].clone())
}

fn interface_entry(offset: usize, interface: &NetworkInterface) -> String {
    let state = if interface.is_up() && interface.is_running() {
        "up"
    } else {
        "down"
    };
    format!(
        "{}. {} [{}] {}",
        offset + 1,
        interface.name,
        state,
        interface.address_summary()
    )
}

// Non-TTY fallback (piped stdin, scripts): keep the classic numbered prompt.
fn select_interface_numbered(interfaces: &[NetworkInterface]) -> Result<usize> {
    println!("Select VPN interface ({}):", vpn_interface_description());
    for (offset, interface) in interfaces.iter().enumerate() {
        println!("  {}", interface_entry(offset, interface));
    }
    print!("choice> ");
    io::stdout().flush()?;

    let mut input = String::new();
    io::stdin().read_line(&mut input)?;
    let selected = input.trim().parse::<usize>()?;
    if selected == 0 || selected > interfaces.len() {
        return Err(err("invalid VPN interface selection"));
    }
    Ok(selected - 1)
}

fn select_interface_interactive(interfaces: &[NetworkInterface]) -> Result<usize> {
    println!(
        "Select VPN interface ({}); ↑/↓ to highlight, Enter to confirm, q to cancel:",
        vpn_interface_description()
    );
    let terminal = RawTerminal::enable()?;
    print!("\x1b[?25l");
    let mut selected = 0usize;
    render_interface_menu(interfaces, selected, false)?;
    loop {
        match terminal.read_key()? {
            Key::Up => {
                selected = selected.checked_sub(1).unwrap_or(interfaces.len() - 1);
            }
            Key::Down => selected = (selected + 1) % interfaces.len(),
            Key::Enter => return Ok(selected),
            Key::Digit(digit) if (1..=interfaces.len()).contains(&digit) => {
                render_interface_menu(interfaces, digit - 1, true)?;
                return Ok(digit - 1);
            }
            Key::Cancel => return Err(err("VPN interface selection cancelled")),
            _ => continue,
        }
        render_interface_menu(interfaces, selected, true)?;
    }
}

fn render_interface_menu(
    interfaces: &[NetworkInterface],
    selected: usize,
    redraw: bool,
) -> Result<()> {
    let mut stdout = io::stdout();
    if redraw {
        write!(stdout, "\x1b[{}A", interfaces.len())?;
    }
    for (offset, interface) in interfaces.iter().enumerate() {
        let entry = interface_entry(offset, interface);
        if offset == selected {
            writeln!(stdout, "\r\x1b[2K\x1b[7m> {entry}\x1b[0m")?;
        } else {
            writeln!(stdout, "\r\x1b[2K  {entry}")?;
        }
    }
    stdout.flush()?;
    Ok(())
}

enum Key {
    Up,
    Down,
    Enter,
    Digit(usize),
    Cancel,
    Other,
}

// Puts stdin into raw mode for the picker; Drop restores the terminal and the
// cursor even when selection errors or is cancelled. ISIG is disabled so
// Ctrl-C cancels cleanly through the same path instead of killing the process
// with the terminal still in raw mode.
struct RawTerminal {
    original: libc::termios,
    raw: libc::termios,
}

impl RawTerminal {
    fn enable() -> Result<Self> {
        let mut original = unsafe { std::mem::zeroed::<libc::termios>() };
        if unsafe { libc::tcgetattr(libc::STDIN_FILENO, &mut original) } != 0 {
            return Err(err("failed to read terminal attributes"));
        }
        let mut raw = original;
        raw.c_lflag &= !(libc::ICANON | libc::ECHO | libc::ISIG);
        raw.c_cc[libc::VMIN] = 1;
        raw.c_cc[libc::VTIME] = 0;
        if unsafe { libc::tcsetattr(libc::STDIN_FILENO, libc::TCSANOW, &raw) } != 0 {
            return Err(err("failed to enable terminal raw mode"));
        }
        Ok(Self { original, raw })
    }

    fn read_key(&self) -> Result<Key> {
        let Some(byte) = self.read_byte(true)? else {
            return Err(err("stdin closed during VPN interface selection"));
        };
        Ok(match byte {
            b'\r' | b'\n' => Key::Enter,
            0x03 | b'q' => Key::Cancel,
            byte @ b'1'..=b'9' => Key::Digit(usize::from(byte - b'0')),
            0x1b => {
                let first = self.read_byte(false)?;
                if first.is_none() {
                    // Bare Escape: no continuation bytes arrived.
                    return Ok(Key::Cancel);
                }
                let second = if first == Some(b'[') {
                    self.read_byte(false)?
                } else {
                    None
                };
                match second {
                    Some(b'A') => Key::Up,
                    Some(b'B') => Key::Down,
                    _ => Key::Other,
                }
            }
            _ => Key::Other,
        })
    }

    fn read_byte(&self, blocking: bool) -> Result<Option<u8>> {
        let mut settings = self.raw;
        settings.c_cc[libc::VMIN] = if blocking { 1 } else { 0 };
        settings.c_cc[libc::VTIME] = if blocking { 0 } else { 1 };
        if unsafe { libc::tcsetattr(libc::STDIN_FILENO, libc::TCSANOW, &settings) } != 0 {
            return Err(err("failed to adjust terminal read mode"));
        }
        let mut byte = 0u8;
        loop {
            let count = unsafe {
                libc::read(
                    libc::STDIN_FILENO,
                    std::ptr::from_mut(&mut byte).cast::<libc::c_void>(),
                    1,
                )
            };
            if count == 1 {
                return Ok(Some(byte));
            }
            if count == 0 {
                return Ok(None);
            }
            let error = io::Error::last_os_error();
            if error.raw_os_error() != Some(libc::EINTR) {
                return Err(error.into());
            }
        }
    }
}

impl Drop for RawTerminal {
    fn drop(&mut self) {
        unsafe { libc::tcsetattr(libc::STDIN_FILENO, libc::TCSANOW, &self.original) };
        let mut stdout = io::stdout();
        let _ = write!(stdout, "\x1b[?25h");
        let _ = stdout.flush();
    }
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
    fs::create_dir_all(tmpdir)?;
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

#[cfg(target_os = "macos")]
fn launch_agent_with_session_group(
    interface_name: &str,
    command: &[String],
    cwd: &str,
    tmpdir: &PathBuf,
    profile: &SandboxProfile,
    clean_env: &BTreeMap<String, String>,
) -> Result<i32> {
    fs::create_dir_all(tmpdir)?;
    let spec_path = tmpdir.join("launch.json");
    let spec = LaunchSpec::new(command.to_vec(), cwd, clean_env.clone(), profile.render());
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
) -> Result<i32> {
    fs::create_dir_all(tmpdir)?;
    let spec_path = tmpdir.join("launch.json");
    let spec = LaunchSpec::new(
        command.to_vec(),
        cwd,
        clean_env.clone(),
        sandbox.render_summary(),
    );
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
  {program} helper

subcommands:
  helper                      Run the root firewall helper daemon.

options:
  --vpn NAME                  Select a VPN interface without prompting
                              (macOS: utun*, Linux: tun* or wg*).
  --cwd PATH                  Working directory exposed to the agent. Defaults to current directory.
  --env NAME=VALUE            Add an environment variable unless it is privacy-blocked.
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
  claude
"#
    )
}
