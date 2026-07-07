use lianyaohu_core::helper::{HelperRequest, SOCKET_PATH, parse_request};
use lianyaohu_core::interfaces::{utun_interfaces, validate_utun};
use lianyaohu_core::pf::{PFRuleSet, parse_enable_token};
use lianyaohu_core::{Result, err};
use std::collections::BTreeMap;
use std::ffi::CString;
use std::fs;
use std::io::{BufRead, BufReader, Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;
use std::process::Command;
use std::sync::{Arc, Mutex, PoisonError};
use std::thread;
use std::time::Duration;

/// A request is a single short line; refuse anything larger so a client
/// cannot exhaust memory by streaming bytes without a newline.
const MAX_REQUEST_BYTES: u64 = 256;

/// Cap how long a single peer may take to send its request / receive its
/// reply, so one stalled client cannot pin a worker forever.
const IO_TIMEOUT: Duration = Duration::from_secs(5);

fn main() {
    if let Err(error) = HelperDaemon::default().run() {
        eprintln!("lianyaohu-helper: {error}");
        std::process::exit(1);
    }
}

#[derive(Clone, Default)]
struct HelperDaemon {
    enable_tokens: Arc<Mutex<BTreeMap<u32, String>>>,
}

impl HelperDaemon {
    fn run(&self) -> Result<()> {
        if unsafe { libc::geteuid() } != 0 {
            return Err(err("lianyaohu-helper must run as root"));
        }

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
        let uid = peer_uid(stream)?;
        let mut line = String::new();
        BufReader::new(stream.try_clone()?.take(MAX_REQUEST_BYTES)).read_line(&mut line)?;
        match parse_request(&line)? {
            HelperRequest::Install { interface_name } => {
                self.install(uid, &interface_name)?;
                Ok(format!(
                    "installed PF guard for uid {uid} on {interface_name}"
                ))
            }
            HelperRequest::Uninstall => {
                self.uninstall(uid);
                Ok(format!("uninstalled PF guard for uid {uid}"))
            }
            HelperRequest::Status => {
                if self.tokens().contains_key(&uid) {
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
        let rule_set = PFRuleSet::new(
            selected.name,
            uid,
            selected.ipv4_peer_addresses.first().cloned(),
        );
        let rules_path = write_rules(&rule_set)?;

        run_pf(&["-n", "-f", &rules_path.to_string_lossy()])?;

        // Hold the lock across the pfctl calls: it serializes pfctl (which is
        // not safe to run concurrently) and keeps the enable-token map in sync
        // with PF's enable-reference count.
        let mut tokens = self.tokens();

        // Enable PF at most once per uid. A repeat install (relaunched agent,
        // concurrent launch) must NOT call `pfctl -E` again, or it leaks an
        // enable reference that uninstall never releases.
        let token = if tokens.contains_key(&uid) {
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
            tokens.insert(uid, token);
        }
        Ok(())
    }

    fn uninstall(&self, uid: u32) {
        let rule_set = PFRuleSet::new("utun0", uid, None);
        let mut tokens = self.tokens();
        let _ = run_pf(&["-a", &rule_set.anchor_name(), "-F", "rules"]);
        if let Some(token) = tokens.remove(&uid) {
            let _ = run_pf(&["-X", &token]);
        }
    }
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
        rule_set.uid, rule_set.interface_name
    ));
    fs::write(&rules_path, rule_set.render())?;
    chmod(&rules_path, 0o600)?;
    Ok(rules_path)
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

fn peer_uid(stream: &UnixStream) -> Result<u32> {
    let mut uid: libc::uid_t = 0;
    let mut gid: libc::gid_t = 0;
    let rc = unsafe { libc::getpeereid(stream.as_raw_fd(), &mut uid, &mut gid) };
    if rc == 0 {
        Ok(uid)
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
