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
    (literal "/var/db/timezone")
    (subpath "/var/db/timezone")
    (literal "/private/var/db/timezone")
    (subpath "/private/var/db/timezone")
    (literal "/Library/Preferences/.GlobalPreferences.plist")
    (literal "{home_global_preferences}")
    (subpath "{home_by_host_preferences}"))

(deny system-socket)
(deny socket-ioctl)
(deny sysctl-write)
(deny network-inbound)
(deny network-bind)

(allow process*)
(allow signal (target self))

(allow file-read-metadata)
(allow file-read-data (literal "/"))

(allow sysctl-read
    (sysctl-name "security.mac.lockdown_mode_state")
    (sysctl-name "kern.bootargs")
    (sysctl-name "kern.ngroups"))

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

(allow file-read* file-map-executable
    (subpath "{home}"))

(allow file-read* file-write* file-map-executable
    (subpath "{cwd}")
    (subpath "{tmpdir}"))

(allow file-read* file-write*
    (literal "/dev/null")
    (literal "/dev/random")
    (literal "/dev/urandom")
    (literal "/dev/zero")
    (subpath "/private/tmp")
    (subpath "/tmp"))

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
    use crate::env_policy;
    use std::collections::BTreeMap;
    use std::fs;
    use std::process::Command;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn profile_allows_home_read_only_and_cwd_writable_but_denies_identity_surfaces() {
        let profile =
            SandboxProfile::new("/Users/example", "/Users/example/project", "/tmp/lyh").render();

        assert!(profile.contains(
            r#"(allow file-read* file-map-executable
    (subpath "/Users/example"))"#
        ));
        assert!(!profile.contains(
            r#"(allow file-read* file-write* file-map-executable
    (subpath "/Users/example"))"#
        ));
        assert!(profile.contains(
            r#"(allow file-read* file-write* file-map-executable
    (subpath "/Users/example/project")
    (subpath "/tmp/lyh"))"#
        ));
        assert!(profile.contains("(deny system-socket)"));
        assert!(profile.contains("(deny socket-ioctl)"));
        assert!(profile.contains("(deny network-inbound)"));
        assert!(profile.contains("(deny network-bind)"));
        assert!(profile.contains(r#"(sysctl-name "security.mac.lockdown_mode_state")"#));
        assert!(profile.contains(r#"(sysctl-name "kern.ngroups")"#));
        assert!(profile.contains("/private/etc/localtime"));
        assert!(profile.contains("/private/var/db/timezone"));
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
    fn generated_profile_blocks_host_sysctl() {
        if skip_sandbox_runtime_tests_in_ci() {
            return;
        }

        let result = run_in_sandbox(&["/usr/sbin/sysctl", "-n", "kern.hostname"]);

        assert_ne!(result.status, 0);
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
        let cwd = std::env::current_dir().unwrap();
        let home = std::env::var("HOME").unwrap();
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let tmpdir = std::env::temp_dir().join(format!("lianyaohu-test-{nanos}"));
        fs::create_dir_all(&tmpdir).unwrap();
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
