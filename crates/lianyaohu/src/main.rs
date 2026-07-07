use lianyaohu_core::env_policy;
use lianyaohu_core::helper::PFHelperClient;
use lianyaohu_core::interfaces::{NetworkInterface, utun_interfaces, validate_utun};
use lianyaohu_core::launch::LaunchSpec;
use lianyaohu_core::pf::{LIANYAOHU_GROUP_GID, PFGuard, PFRuleSet};
use lianyaohu_core::route;
use lianyaohu_core::sandbox_profile::SandboxProfile;
use lianyaohu_core::{Result, err};
use std::collections::BTreeMap;
use std::env;
use std::fs;
use std::io::{self, Write};
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
    let code = match run() {
        Ok(code) => code,
        Err(error) => {
            eprintln!("lianyaohu: {error}");
            eprintln!("{USAGE}");
            2
        }
    };
    std::process::exit(code);
}

fn run() -> Result<i32> {
    let options = parse(env::args().skip(1).collect())?;

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
    validate_utun(&selected_interface)?;

    let profile = SandboxProfile::new(&home, &cwd_string, tmpdir.to_string_lossy());
    if options.print_profile {
        print!("{}", profile.render());
        return Ok(0);
    }

    let uid = unsafe { libc::getuid() };
    let route_gateway = selected_interface.ipv4_peer_addresses.first().cloned();
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
    if options.print_pf {
        print!("{}", rule_set.render());
        return Ok(0);
    }

    if options.require_default_route {
        let default_route = route::default_ipv4_interface()?;
        if default_route.as_deref() != Some(selected_interface.name.as_str()) {
            return Err(err(format!(
                "default IPv4 route uses {}, not selected VPN interface {}",
                default_route.as_deref().unwrap_or("<unknown>"),
                selected_interface.name
            )));
        }
    }

    let env_input = env::vars().collect::<BTreeMap<_, _>>();
    let clean_env = env_policy::sanitize(
        &env_input,
        &home,
        &cwd_string,
        &tmpdir.to_string_lossy(),
        &options.extra_environment,
    );

    let command = if options.command.is_empty() {
        vec!["claude".to_string()]
    } else {
        options.command
    };

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

    Ok(status)
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
                        .ok_or_else(|| err("--vpn requires a utun interface name"))?
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
            "--no-pf" => options.enforce_pf = false,
            "--shared-user-pf" => options.helper_group_launch = false,
            "--allow-non-default-route" => options.require_default_route = false,
            "--print-profile" => options.print_profile = true,
            "--print-pf" => options.print_pf = true,
            "--helper-status" => options.helper_status = true,
            "-h" | "--help" => {
                println!("{USAGE}");
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
    let interfaces = utun_interfaces()?;
    if interfaces.is_empty() {
        return Err(err("no utun interfaces found; start the VPN first"));
    }

    if let Some(name) = requested {
        return interfaces
            .into_iter()
            .find(|interface| interface.name == name)
            .ok_or_else(|| err(format!("{name} was not found among active utun interfaces")));
    }

    println!("Select VPN utun interface:");
    for (offset, interface) in interfaces.iter().enumerate() {
        let state = if interface.is_up() && interface.is_running() {
            "up"
        } else {
            "down"
        };
        println!(
            "  {}. {} [{}] {}",
            offset + 1,
            interface.name,
            state,
            interface.address_summary()
        );
    }
    print!("choice> ");
    io::stdout().flush()?;

    let mut input = String::new();
    io::stdin().read_line(&mut input)?;
    let selected = input.trim().parse::<usize>()?;
    if selected == 0 || selected > interfaces.len() {
        return Err(err("invalid utun selection"));
    }
    Ok(interfaces[selected - 1].clone())
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
                "dedicated group isolation requires an updated lianyaohu-helper: {error}. Run scripts/install-helper.sh, or pass --shared-user-pf to use current-UID PF rules."
            ))
        });
    let _ = fs::remove_file(&spec_path);
    result
}

const USAGE: &str = r#"usage:
  lianyaohu [options] [-- agent [args...]]

options:
  --vpn NAME                  Select a utun interface without prompting.
  --cwd PATH                  Working directory exposed to the agent. Defaults to current directory.
  --env NAME=VALUE            Add an environment variable unless it is privacy-blocked.
  --no-pf                     Do not install the PF guard. Intended for tests and debugging.
  --shared-user-pf            Use current-UID PF rules instead of helper-managed group isolation.
  --allow-non-default-route   Do not require the system default route to use the selected utun.
  --helper-status             Query the root PF helper status for this user.
  --print-profile             Print the generated sandbox-exec profile and exit.
  --print-pf                  Print the generated PF anchor rules and exit.

default command:
  claude
"#;
