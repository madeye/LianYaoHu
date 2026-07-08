pub struct SandboxProfile {
    pub home: String,
    pub cwd: String,
    pub tmpdir: String,
}

impl SandboxProfile {
    pub fn new(home: impl Into<String>, cwd: impl Into<String>, tmpdir: impl Into<String>) -> Self {
        Self {
            home: home.into(),
            cwd: cwd.into(),
            tmpdir: tmpdir.into(),
        }
    }

    pub fn render(&self) -> String {
        let home = scheme_string(&self.home);
        let cwd = scheme_string(&self.cwd);
        let tmpdir = scheme_string(&self.tmpdir);
        let home_global_preferences = scheme_string(&format!(
            "{}/Library/Preferences/.GlobalPreferences.plist",
            self.home
        ));
        let home_by_host_preferences =
            scheme_string(&format!("{}/Library/Preferences/ByHost", self.home));

        format!(
            r#"(version 1)

(deny default)

(deny file-read*
    (literal "/etc/localtime")
    (literal "/private/etc/localtime")
    (literal "/Library/Preferences/.GlobalPreferences.plist")
    (literal "{home_global_preferences}")
    (subpath "{home_by_host_preferences}"))

(deny system-socket)
(deny socket-ioctl)
(deny sysctl-write)
(deny network-inbound)
(deny network-bind)
; Loopback-only listeners: OAuth callback servers (e.g. `claude /login`) and
; dev servers bind an ephemeral localhost port and accept same-machine
; connections. "localhost" matches only the loopback interface, so nothing is
; reachable from the network; the denies above still cover every other address.
(allow network-bind (local ip "localhost:*"))
(allow network-inbound (local ip "localhost:*"))

(allow process*)
(allow signal (target self))

(allow file-read-metadata)
(allow file-read-data (literal "/"))

; libc and language runtimes require basic machine facts: sysconf(3) and
; getpagesize(3) read hw.pagesize via sysctl, and Rust binaries abort during
; startup when that is denied (stack guard-page setup computes a bogus page
; size). Allow the benign machine-description keys Apple's application.sb
; allows; identity surfaces (kern.uuid, hw.serialnumber, ...) stay denied by
; the default-deny.
(allow sysctl-read
    (sysctl-name "hw.activecpu")
    (sysctl-name "hw.busfrequency")
    (sysctl-name "hw.busfrequency_compat")
    (sysctl-name "hw.byteorder")
    (sysctl-name "hw.cacheconfig")
    (sysctl-name "hw.cachelinesize")
    (sysctl-name "hw.cachelinesize_compat")
    (sysctl-name "hw.cpu64bit_capable")
    (sysctl-name "hw.cpufamily")
    (sysctl-name "hw.cpufrequency")
    (sysctl-name "hw.cpufrequency_compat")
    (sysctl-name "hw.cpusubfamily")
    (sysctl-name "hw.cpusubtype")
    (sysctl-name "hw.cputype")
    (sysctl-name "hw.l1dcachesize")
    (sysctl-name "hw.l1dcachesize_compat")
    (sysctl-name "hw.l1icachesize")
    (sysctl-name "hw.l1icachesize_compat")
    (sysctl-name "hw.l2cachesize")
    (sysctl-name "hw.l2cachesize_compat")
    (sysctl-name "hw.l3cachesize")
    (sysctl-name "hw.l3cachesize_compat")
    (sysctl-name "hw.logicalcpu")
    (sysctl-name "hw.logicalcpu_max")
    (sysctl-name "hw.machine")
    (sysctl-name "hw.memsize")
    (sysctl-name "hw.ncpu")
    (sysctl-name "hw.nperflevels")
    (sysctl-name "hw.pagesize")
    (sysctl-name "hw.pagesize_compat")
    (sysctl-name "hw.physicalcpu")
    (sysctl-name "hw.physicalcpu_max")
    (sysctl-name "hw.tbfrequency")
    (sysctl-name "hw.tbfrequency_compat")
    (sysctl-name "hw.vectorunit")
    (sysctl-name-prefix "hw.optional.")
    (sysctl-name-prefix "hw.perflevel")
    (sysctl-name "kern.argmax")
    (sysctl-name "kern.bootargs")
    ; uname(3) reads kern.hostname for the nodename field and fails entirely
    ; when it is denied, breaking Ruby's Etc.uname and therefore Homebrew.
    ; The hostname leaks the machine name; stronger identifiers (kern.uuid)
    ; stay blocked and HOSTNAME is still stripped from the environment.
    (sysctl-name "kern.hostname")
    (sysctl-name "kern.maxfilesperproc")
    (sysctl-name "kern.ngroups")
    (sysctl-name "kern.osproductversion")
    (sysctl-name "kern.osrelease")
    (sysctl-name "kern.ostype")
    (sysctl-name "kern.osvariant_status")
    (sysctl-name "kern.osversion")
    (sysctl-name "kern.safeboot")
    (sysctl-name "kern.secure_kernel")
    (sysctl-name "kern.usrstack64")
    (sysctl-name "kern.version")
    (sysctl-name "security.mac.lockdown_mode_state"))

(allow file-read* file-map-executable
    (subpath "/Applications")
    (subpath "/Library/Apple")
    (subpath "/Library/Developer")
    (subpath "/System")
    (subpath "/bin")
    (subpath "/opt")
    (subpath "/private/etc")
    (subpath "/sbin")
    (subpath "/usr"))

; $HOME is writable so agents can maintain their own state (~/.claude,
; ~/.codex, credential and cache files). The identity-surface denials above
; still win over this allow. /opt/homebrew is writable so agents can
; brew install the tools they need.
(allow file-read* file-write* file-map-executable
    (subpath "{home}")
    (subpath "{cwd}")
    (subpath "{tmpdir}")
    (subpath "/opt/homebrew"))

; /dev/fd is how bash implements process substitution (/dev/fd/62); Homebrew
; uses it on every run.
(allow file-read* file-write*
    (literal "/dev/null")
    (literal "/dev/random")
    (literal "/dev/urandom")
    (literal "/dev/zero")
    (subpath "/dev/fd")
    (subpath "/private/tmp")
    (subpath "/tmp"))

; Bun/JavaScriptCore initializes ICU timezone data during startup. With TZ=UTC,
; it still reads the versioned UTC zoneinfo and ICU timezone bundle; allow only
; those UTC data files while keeping localtime and preference-based timezone
; identity blocked above.
(allow file-read*
    (regex #"^/var/db/timezone/tz/[^/]+/zoneinfo/UTC$")
    (regex #"^/private/var/db/timezone/tz/[^/]+/zoneinfo/UTC$")
    (regex #"^/var/db/timezone/tz/[^/]+/zoneinfo/posixrules$")
    (regex #"^/private/var/db/timezone/tz/[^/]+/zoneinfo/posixrules$")
    (regex #"^/var/db/timezone/tz/[^/]+/icutz/[^/]+\.dat$")
    (regex #"^/private/var/db/timezone/tz/[^/]+/icutz/[^/]+\.dat$"))

; TUI agents (codex, fish, claude) put the terminal into raw mode with
; tcsetattr and open /dev/tty; both need ioctl access to the pty devices.
; pseudo-tty lets agents allocate nested ptys for interactive subprocesses.
(allow file-read* file-write* file-ioctl
    (literal "/dev/tty")
    (literal "/dev/ptmx")
    (regex #"^/dev/ttys[0-9]+$"))
(allow pseudo-tty)

; TLS: Security.framework loads root CA certificates and trust settings by
; talking to securityd/trustd over XPC and reading the keychain databases.
; Without this, Rust agents (rustls-native-certs) see zero root CAs
; ("No keychain is available") and cannot validate any TLS connection.
(allow mach-lookup
    (global-name "com.apple.SecurityServer")
    (global-name "com.apple.trustd")
    (global-name "com.apple.trustd.agent"))

; getpwuid/getpwnam and group membership resolve through opendirectoryd;
; Homebrew (Ruby Dir.home) and many tools look up the current user.
(allow mach-lookup
    (global-name "com.apple.system.opendirectoryd.libinfo")
    (global-name "com.apple.system.opendirectoryd.membership"))
(allow file-read*
    (subpath "/Library/Keychains")
    (subpath "/private/var/db/mds"))

; /usr/bin/git is an xcrun shim that refuses to run unless it can read the
; Xcode license-acceptance state.
(allow file-read*
    (literal "/Library/Preferences/com.apple.dt.Xcode.plist"))

(allow network-outbound
    (remote tcp "*:*")
    (remote udp "*:*")
    (remote unix-socket (path-literal "/private/var/run/mDNSResponder")))
"#
        )
    }
}

pub fn scheme_string(value: &str) -> String {
    value.replace('\\', "\\\\").replace('"', "\\\"")
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(target_os = "macos")]
    use crate::env_policy;
    #[cfg(target_os = "macos")]
    use std::collections::BTreeMap;
    #[cfg(target_os = "macos")]
    use std::fs;
    #[cfg(target_os = "macos")]
    use std::process::Command;
    #[cfg(target_os = "macos")]
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn profile_allows_home_and_cwd_writable_but_denies_identity_surfaces() {
        let profile =
            SandboxProfile::new("/Users/example", "/Users/example/project", "/tmp/lyh").render();

        assert!(profile.contains(
            r#"(allow file-read* file-write* file-map-executable
    (subpath "/Users/example")
    (subpath "/Users/example/project")
    (subpath "/tmp/lyh")
    (subpath "/opt/homebrew"))"#
        ));
        assert!(profile.contains("(deny system-socket)"));
        assert!(profile.contains("(deny socket-ioctl)"));
        assert!(profile.contains("(deny network-inbound)"));
        assert!(profile.contains("(deny network-bind)"));
        assert!(profile.contains(r#"(allow network-bind (local ip "localhost:*"))"#));
        assert!(profile.contains(r#"(allow network-inbound (local ip "localhost:*"))"#));
        assert!(profile.contains(r#"(sysctl-name "security.mac.lockdown_mode_state")"#));
        assert!(profile.contains(r#"(sysctl-name "kern.ngroups")"#));
        assert!(profile.contains(r#"(sysctl-name "hw.pagesize")"#));
        assert!(profile.contains(r#"(sysctl-name-prefix "hw.optional.")"#));
        assert!(profile.contains(r#"(regex #"^/dev/ttys[0-9]+$")"#));
        assert!(profile.contains("(allow pseudo-tty)"));
        assert!(profile.contains(r#"(global-name "com.apple.SecurityServer")"#));
        assert!(profile.contains(r#"(global-name "com.apple.trustd.agent")"#));
        assert!(profile.contains(r#"(subpath "/Library/Keychains")"#));
        assert!(profile.contains(r#"(sysctl-name "kern.hostname")"#));
        assert!(!profile.contains(r#"(sysctl-name "kern.uuid")"#));
        assert!(profile.contains(r#"(subpath "/opt/homebrew")"#));
        assert!(profile.contains(r#"(subpath "/dev/fd")"#));
        assert!(profile.contains(r#"(global-name "com.apple.system.opendirectoryd.libinfo")"#));
        assert!(profile.contains("/private/etc/localtime"));
        assert!(profile.contains("zoneinfo/UTC"));
        assert!(!profile.contains(r#"(subpath "/private/var/db/timezone")"#));
        assert!(profile.contains(r#"(remote tcp "*:*")"#));
        assert!(profile.contains(r#"(remote udp "*:*")"#));
    }

    #[test]
    fn escapes_scheme_strings() {
        assert_eq!(scheme_string(r#"/tmp/a"b\c"#), r#"/tmp/a\"b\\c"#);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn generated_profile_can_launch_simple_tool() {
        if skip_sandbox_runtime_tests_in_ci() {
            return;
        }

        let result = run_in_sandbox(&["/bin/echo", "ok"]);

        assert_eq!(result.status, 0);
        assert!(result.output.contains("ok"));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn generated_profile_can_start_rust_runtime() {
        if skip_sandbox_runtime_tests_in_ci() {
            return;
        }

        // Rust start-up installs a main-stack guard page sized by
        // sysconf(_SC_PAGESIZE), which reads hw.pagesize via sysctl. When the
        // profile denies it, every Rust agent aborts before main with
        // "failed to allocate a guard page". The test executable itself is a
        // Rust binary, so running it inside the sandbox exercises that path.
        let result = run_in_sandbox_with_tmpdir(|tmpdir| {
            let probe = tmpdir.join("rust-runtime-probe");
            fs::copy(std::env::current_exe().unwrap(), &probe).unwrap();
            vec![probe.to_string_lossy().to_string(), "--list".to_string()]
        });

        assert_eq!(result.status, 0, "rust probe failed: {}", result.output);
    }

    // Trivially passes when run directly; its real purpose is to be re-run
    // inside sandbox-exec by generated_profile_allows_localhost_bind, where it
    // exercises the loopback network-bind/network-inbound allows.
    #[test]
    fn localhost_bind_probe() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        assert_ne!(listener.local_addr().unwrap().port(), 0);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn generated_profile_allows_localhost_bind() {
        if skip_sandbox_runtime_tests_in_ci() {
            return;
        }

        // OAuth logins (`claude /login`) start a localhost callback server on
        // an ephemeral port; without the loopback allows the bind fails with
        // EPERM. Re-run this test binary inside the sandbox, filtered to the
        // probe test above, so the bind happens under the generated profile.
        let result = run_in_sandbox_with_tmpdir(|tmpdir| {
            let probe = tmpdir.join("localhost-bind-probe");
            fs::copy(std::env::current_exe().unwrap(), &probe).unwrap();
            vec![
                probe.to_string_lossy().to_string(),
                "tests::localhost_bind_probe".to_string(),
                "--exact".to_string(),
            ]
        });

        assert_eq!(result.status, 0, "localhost bind probe: {}", result.output);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn generated_profile_allows_root_ca_access() {
        if skip_sandbox_runtime_tests_in_ci() {
            return;
        }

        // TLS stacks load root CAs through Security.framework, which needs
        // securityd/trustd XPC access; without it agents see zero root CAs
        // ("No keychain is available") and cannot validate TLS connections.
        let result = run_in_sandbox(&[
            "/usr/bin/security",
            "find-certificate",
            "-a",
            "/System/Library/Keychains/SystemRootCertificates.keychain",
        ]);

        assert_eq!(result.status, 0, "{}", result.output);
        assert!(result.output.contains("labl"));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn generated_profile_allows_utc_timezone_data() {
        if skip_sandbox_runtime_tests_in_ci() {
            return;
        }

        let Some(utc_path) = find_utc_timezone_file() else {
            eprintln!("skipping UTC timezone sandbox test; no macOS timezone DB found");
            return;
        };
        let utc_path = utc_path.to_string_lossy().to_string();
        let result = run_in_sandbox(&["/bin/cat", &utc_path]);

        assert_eq!(result.status, 0, "cat {utc_path}: {}", result.output);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn generated_profile_allows_tty_raw_mode() {
        if skip_sandbox_runtime_tests_in_ci() {
            return;
        }

        // TUI agents enable raw mode via tcsetattr on the terminal; without
        // tty device + file-ioctl access the sandbox returns EPERM and agents
        // die with "Operation not permitted". stty -f opens the pty slave and
        // calls tcsetattr, exercising the same path.
        let mut master: libc::c_int = 0;
        let mut slave: libc::c_int = 0;
        let mut name = [0 as libc::c_char; 128];
        let rc = unsafe {
            libc::openpty(
                &mut master,
                &mut slave,
                name.as_mut_ptr(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            )
        };
        assert_eq!(rc, 0);
        let slave_name = unsafe { std::ffi::CStr::from_ptr(name.as_ptr()) }
            .to_string_lossy()
            .to_string();

        let result = run_in_sandbox(&["/bin/stty", "-f", &slave_name, "raw"]);

        unsafe {
            libc::close(slave);
            libc::close(master);
        }
        assert_eq!(
            result.status, 0,
            "stty raw on {slave_name}: {}",
            result.output
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn generated_profile_allows_home_write() {
        if skip_sandbox_runtime_tests_in_ci() {
            return;
        }

        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let marker = std::path::PathBuf::from(std::env::var("HOME").unwrap())
            .join(format!(".lianyaohu-write-test-{nanos}"));

        let result = run_in_sandbox(&["/usr/bin/touch", &marker.to_string_lossy()]);

        let written = marker.exists();
        let _ = fs::remove_file(&marker);
        assert_eq!(result.status, 0, "{}", result.output);
        assert!(written);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn generated_profile_blocks_host_uuid_sysctl() {
        if skip_sandbox_runtime_tests_in_ci() {
            return;
        }

        let result = run_in_sandbox(&["/usr/sbin/sysctl", "-n", "kern.uuid"]);

        assert_ne!(result.status, 0);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn generated_profile_allows_uname() {
        if skip_sandbox_runtime_tests_in_ci() {
            return;
        }

        // uname(3) reads kern.hostname among other sysctls and fails entirely
        // when any of them is denied; Ruby's Etc.uname (and thus Homebrew)
        // raises on that failure.
        let result = run_in_sandbox(&["/usr/bin/uname", "-a"]);

        assert_eq!(result.status, 0, "{}", result.output);
        assert!(result.output.contains("Darwin"));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn generated_profile_blocks_timezone_file() {
        if skip_sandbox_runtime_tests_in_ci() {
            return;
        }

        let result = run_in_sandbox(&["/bin/cat", "/private/etc/localtime"]);

        assert_ne!(result.status, 0);
    }

    #[cfg(target_os = "macos")]
    struct SandboxRun {
        status: i32,
        output: String,
    }

    #[cfg(target_os = "macos")]
    fn skip_sandbox_runtime_tests_in_ci() -> bool {
        if std::env::var_os("CI").is_some() {
            eprintln!("skipping sandbox-exec runtime test in CI");
            true
        } else {
            false
        }
    }

    #[cfg(target_os = "macos")]
    fn run_in_sandbox(command: &[&str]) -> SandboxRun {
        let command: Vec<String> = command.iter().map(|arg| arg.to_string()).collect();
        run_in_sandbox_with_tmpdir(|_| command)
    }

    #[cfg(target_os = "macos")]
    fn find_utc_timezone_file() -> Option<std::path::PathBuf> {
        let timezone_root = std::path::Path::new("/private/var/db/timezone/tz");
        let entries = fs::read_dir(timezone_root).ok()?;
        for entry in entries.flatten() {
            let path = entry.path().join("zoneinfo/UTC");
            if path.is_file() {
                return Some(path);
            }
        }
        None
    }

    #[cfg(target_os = "macos")]
    fn run_in_sandbox_with_tmpdir(
        build_command: impl FnOnce(&std::path::Path) -> Vec<String>,
    ) -> SandboxRun {
        let cwd = std::env::current_dir().unwrap();
        let home = std::env::var("HOME").unwrap();
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let tmpdir = std::env::temp_dir().join(format!("lianyaohu-test-{nanos}"));
        fs::create_dir_all(&tmpdir).unwrap();
        let command = build_command(&tmpdir);
        let profile = SandboxProfile::new(&home, cwd.to_string_lossy(), tmpdir.to_string_lossy());
        let profile_path = tmpdir.join("profile.sb");
        fs::write(&profile_path, profile.render()).unwrap();

        let input_env = std::env::vars().collect::<BTreeMap<_, _>>();
        let clean_env = env_policy::sanitize(
            &input_env,
            &home,
            &cwd.to_string_lossy(),
            &tmpdir.to_string_lossy(),
            &BTreeMap::new(),
        );

        let output = Command::new("/usr/bin/sandbox-exec")
            .arg("-f")
            .arg(&profile_path)
            .args(command)
            .current_dir(&cwd)
            .env_clear()
            .envs(clean_env)
            .output()
            .unwrap();

        let _ = fs::remove_dir_all(&tmpdir);
        SandboxRun {
            status: output.status.code().unwrap_or(1),
            output: format!(
                "{}{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            ),
        }
    }
}
