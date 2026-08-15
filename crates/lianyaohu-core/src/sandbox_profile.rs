use crate::policy::PathPolicy;

pub struct SandboxProfile {
    pub home: String,
    pub cwd: String,
    pub tmpdir: String,
    pub paths: PathPolicy,
}

impl SandboxProfile {
    pub fn new(home: impl Into<String>, cwd: impl Into<String>, tmpdir: impl Into<String>) -> Self {
        Self {
            home: home.into(),
            cwd: cwd.into(),
            tmpdir: tmpdir.into(),
            paths: PathPolicy::default(),
        }
    }

    pub fn with_paths(mut self, paths: PathPolicy) -> Self {
        self.paths = paths;
        self
    }

    pub fn render(&self) -> String {
        let home_write_section = self.home_write_section();
        let user_sections = self.user_sections();

        format!(
            r#"(version 1)

(deny default)

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

{home_write_section}

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

; The timezone-database deny and its UTC-only carve-out are emitted in the
; user sections at the end of the profile, AFTER any user read-only allows —
; seatbelt is last-match-wins, so emitting them here would let a
; `paths.read_only` extra covering the tree re-open it.

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
{user_sections}"#
        )
    }

    /// The writable-roots allow block. In default mode this must render
    /// byte-identical to the historical fixed block; extra writable paths from
    /// the user policy are appended inside the same allow.
    fn home_write_section(&self) -> String {
        let home = scheme_string(&self.home);
        let cwd = scheme_string(&self.cwd);
        let tmpdir = scheme_string(&self.tmpdir);
        let mut extras = String::new();
        for path in &self.paths.writable {
            extras.push_str(&format!("\n    (subpath \"{}\")", scheme_string(path)));
        }

        if self.paths.narrow_home {
            // Both (literal ...) and (subpath ...) are emitted per state entry
            // so file entries like `.claude.json` match without stat-ing.
            let mut state = String::new();
            for entry in &self.paths.agent_state_dirs {
                let path = scheme_string(&format!("{}/{}", self.home, entry));
                state.push_str(&format!(
                    "\n    (literal \"{path}\")\n    (subpath \"{path}\")"
                ));
            }
            format!(
                r#"; Narrow-home mode: $HOME stays readable and executable so dotfiles and
; installed tooling keep working, but only agent state locations (plus the
; working directory and the launch tmpdir) are writable. /opt/homebrew is
; writable so agents can brew install the tools they need.
(allow file-read* file-map-executable
    (subpath "{home}"))
(allow file-read* file-write* file-map-executable{state}
    (subpath "{cwd}")
    (subpath "{tmpdir}")
    (subpath "/opt/homebrew"){extras})"#
            )
        } else {
            format!(
                r#"; $HOME is writable so agents can maintain their own state (~/.claude,
; ~/.codex, credential and cache files). Seatbelt is last-match-wins, so the
; identity-surface denials emitted after this allow carve the timezone
; preference files back out of it. /opt/homebrew is writable so agents can
; brew install the tools they need.
(allow file-read* file-write* file-map-executable
    (subpath "{home}")
    (subpath "{cwd}")
    (subpath "{tmpdir}")
    (subpath "/opt/homebrew"){extras})"#
            )
        }
    }

    /// User-policy blocks plus the identity/timezone denials, appended after
    /// everything else. Seatbelt is last-match-wins, so the ordering here is
    /// load-bearing: the user's read-only allows render first, then the
    /// timezone-database deny with its UTC-only carve-out and the identity
    /// deny block (so a `paths.read_only` entry covering the timezone tree or
    /// the identity paths cannot re-allow them), and the user `paths.deny`
    /// block stays the very last rules in the profile so it overrides every
    /// allow above, including the writable roots.
    fn user_sections(&self) -> String {
        let home_global_preferences = scheme_string(&format!(
            "{}/Library/Preferences/.GlobalPreferences.plist",
            self.home
        ));
        let home_by_host_preferences =
            scheme_string(&format!("{}/Library/Preferences/ByHost", self.home));
        let mut out = String::new();
        if !self.paths.read_only.is_empty() {
            out.push_str("\n; Extra read-only paths from the user policy.\n(allow file-read*");
            for path in &self.paths.read_only {
                out.push_str(&format!("\n    (subpath \"{}\")", scheme_string(path)));
            }
            out.push_str(")\n");
        }
        out.push_str(
            "\n; The timezone database is denied wholesale, AFTER any user read-only\n\
             ; allows above (so a read-only extra covering the tree cannot re-open\n\
             ; it) and BEFORE the UTC-only allow below. Seatbelt is last-match-wins,\n\
             ; so the later allow carves the UTC data files back out while every\n\
             ; other zone file — including the real zone file that the\n\
             ; /etc/localtime symlink resolves to before rule matching — is denied\n\
             ; by an explicit rule instead of being blocked only incidentally by\n\
             ; not matching any allow.\n\
             (deny file-read*\n    \
             (subpath \"/var/db/timezone\")\n    \
             (subpath \"/private/var/db/timezone\"))\n\
             \n\
             ; Bun/JavaScriptCore initializes ICU timezone data during startup. With\n\
             ; TZ=UTC, it still reads the versioned UTC zoneinfo and ICU timezone\n\
             ; bundle; allow only those UTC data files. Preference-based timezone\n\
             ; identity stays blocked by the identity deny block just below.\n\
             (allow file-read*\n    \
             (regex #\"^/var/db/timezone/tz/[^/]+/zoneinfo/UTC$\")\n    \
             (regex #\"^/private/var/db/timezone/tz/[^/]+/zoneinfo/UTC$\")\n    \
             (regex #\"^/var/db/timezone/tz/[^/]+/zoneinfo/posixrules$\")\n    \
             (regex #\"^/private/var/db/timezone/tz/[^/]+/zoneinfo/posixrules$\")\n    \
             (regex #\"^/var/db/timezone/tz/[^/]+/icutz/[^/]+\\.dat$\")\n    \
             (regex #\"^/private/var/db/timezone/tz/[^/]+/icutz/[^/]+\\.dat$\"))\n",
        );
        out.push_str(&format!(
            "\n; Timezone/identity denials. Seatbelt is last-match-wins, so these must\n\
             ; come AFTER the $HOME writable allow, the /private/etc read allow, and\n\
             ; any user read-only allows above, or those allows override them. Only\n\
             ; the user paths.deny block may follow.\n\
             (deny file-read* file-write*\n    \
             (literal \"/etc/localtime\")\n    \
             (literal \"/private/etc/localtime\")\n    \
             (literal \"/Library/Preferences/.GlobalPreferences.plist\")\n    \
             (literal \"{home_global_preferences}\")\n    \
             (subpath \"{home_by_host_preferences}\"))\n"
        ));
        if !self.paths.deny.is_empty() {
            out.push_str(
                "\n; Denied paths from the user policy. Seatbelt is last-match-wins, so\n\
                 ; these must remain the final rules to override every allow above.\n\
                 (deny file-read* file-write*",
            );
            for path in &self.paths.deny {
                let path = scheme_string(path);
                out.push_str(&format!(
                    "\n    (literal \"{path}\")\n    (subpath \"{path}\")"
                ));
            }
            out.push_str(")\n");
        }
        out
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
    use std::sync::atomic::{AtomicU64, Ordering};

    // Tests run on parallel threads; naming scratch paths by wall-clock
    // timestamp lets two tests collide on the same nanosecond and delete each
    // other's files mid-run (flaky "execvp: No such file or directory").
    // A per-process counter is unique by construction.
    #[cfg(target_os = "macos")]
    fn unique_test_id() -> u64 {
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        COUNTER.fetch_add(1, Ordering::Relaxed)
    }

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
        assert!(!profile.contains(r#"(sysctl-name "kern.bootargs")"#));
        assert!(profile.contains(r#"(subpath "/opt/homebrew")"#));
        assert!(profile.contains(r#"(subpath "/dev/fd")"#));
        assert!(profile.contains(r#"(global-name "com.apple.system.opendirectoryd.libinfo")"#));
        assert!(profile.contains("/private/etc/localtime"));
        assert!(profile.contains("zoneinfo/UTC"));
        // The timezone database must be explicitly denied, never allowed
        // wholesale; only the UTC data files are carved back out.
        assert!(profile.contains(
            "(deny file-read*\n    (subpath \"/var/db/timezone\")\n    (subpath \"/private/var/db/timezone\"))"
        ));
        assert!(!profile.contains("(allow file-read*\n    (subpath \"/var/db/timezone\")"));
        assert!(profile.contains(r#"(remote tcp "*:*")"#));
        assert!(profile.contains(r#"(remote udp "*:*")"#));
    }

    #[test]
    fn escapes_scheme_strings() {
        assert_eq!(scheme_string(r#"/tmp/a"b\c"#), r#"/tmp/a\"b\\c"#);
    }

    #[test]
    fn default_policy_renders_without_user_sections() {
        let profile =
            SandboxProfile::new("/Users/example", "/Users/example/project", "/tmp/lyh").render();

        // The default policy must not introduce any generated markers; combined
        // with the exact writable-block assertion above, this pins the default
        // render to the historical profile.
        assert!(!profile.contains("user policy"));
        assert!(!profile.contains("Narrow-home"));
        assert!(profile.ends_with("(subpath \"/Users/example/Library/Preferences/ByHost\"))\n"));
    }

    #[test]
    fn identity_denials_come_after_home_and_etc_allows() {
        let profile =
            SandboxProfile::new("/Users/example", "/Users/example/project", "/tmp/lyh").render();

        // Seatbelt is last-match-wins: if the timezone/identity denials sit
        // before the blanket $HOME write allow or the /private/etc read allow,
        // those allows silently override them and the denials are dead rules.
        let deny_block = r#"(deny file-read* file-write*
    (literal "/etc/localtime")
    (literal "/private/etc/localtime")
    (literal "/Library/Preferences/.GlobalPreferences.plist")
    (literal "/Users/example/Library/Preferences/.GlobalPreferences.plist")
    (subpath "/Users/example/Library/Preferences/ByHost"))"#;
        let deny_at = profile.find(deny_block).expect("identity deny block");
        let home_allow_at = profile
            .find("(subpath \"/Users/example\")")
            .expect("home allow");
        let etc_allow_at = profile
            .find("(subpath \"/private/etc\")")
            .expect("/private/etc allow");
        assert!(
            deny_at > home_allow_at,
            "identity denials before home allow"
        );
        assert!(deny_at > etc_allow_at, "identity denials before /etc allow");
    }

    #[test]
    fn zoneinfo_deny_comes_before_utc_allow() {
        let profile =
            SandboxProfile::new("/Users/example", "/Users/example/project", "/tmp/lyh").render();

        // Seatbelt is last-match-wins: the wholesale timezone-database deny
        // must precede the UTC-only allow so the allow carves the UTC data
        // files back out while everything else in the tree stays explicitly
        // denied (including the resolved target of the /etc/localtime
        // symlink, which would otherwise be blocked only incidentally).
        let deny_at = profile
            .find("(deny file-read*\n    (subpath \"/var/db/timezone\")")
            .expect("zoneinfo tree deny");
        let utc_allow_at = profile
            .find(r##"(regex #"^/var/db/timezone/tz/[^/]+/zoneinfo/UTC$")"##)
            .expect("UTC allow");
        assert!(
            deny_at < utc_allow_at,
            "zoneinfo deny must precede the UTC allow or it kills the UTC carve-out"
        );
    }

    #[test]
    fn identity_denials_render_between_user_read_only_allow_and_user_deny() {
        let paths = PathPolicy {
            read_only: vec!["/Users/example/Library/Preferences".into()],
            deny: vec!["/Users/example/.ssh".into()],
            ..PathPolicy::default()
        };
        let profile = SandboxProfile::new("/Users/example", "/Users/example/project", "/tmp/lyh")
            .with_paths(paths)
            .render();

        // Seatbelt is last-match-wins: a paths.read_only allow covering the
        // identity paths must render BEFORE the identity deny block or it
        // re-allows the identity plists; the user paths.deny block must stay
        // the very last rules in the profile.
        let read_only_allow_at = profile
            .find("(subpath \"/Users/example/Library/Preferences\")")
            .expect("user read_only allow");
        let identity_deny_at = profile
            .find("(literal \"/Users/example/Library/Preferences/.GlobalPreferences.plist\")")
            .expect("identity deny");
        let user_deny_at = profile
            .find("(literal \"/Users/example/.ssh\")")
            .expect("user deny");
        assert!(
            read_only_allow_at < identity_deny_at,
            "identity denials must come after the user read_only allow"
        );
        assert!(
            identity_deny_at < user_deny_at,
            "user paths.deny must remain the very last rules"
        );
    }

    #[test]
    fn zoneinfo_deny_renders_after_user_read_only_allow_and_before_user_deny() {
        let paths = PathPolicy {
            read_only: vec!["/private/var/db/timezone".into()],
            deny: vec!["/Users/example/.ssh".into()],
            ..PathPolicy::default()
        };
        let profile = SandboxProfile::new("/Users/example", "/Users/example/project", "/tmp/lyh")
            .with_paths(paths)
            .render();

        // Seatbelt is last-match-wins: a paths.read_only extra covering the
        // timezone database must render BEFORE the zoneinfo deny or it
        // re-opens the whole tree (and with it the resolved target of the
        // /etc/localtime symlink). The UTC carve-out must immediately follow
        // the deny so UTC data stays readable, and the user paths.deny block
        // must stay the very last rules.
        let read_only_allow_at = profile
            .find("(allow file-read*\n    (subpath \"/private/var/db/timezone\"))")
            .expect("user read_only allow");
        let zoneinfo_deny_at = profile
            .find("(deny file-read*\n    (subpath \"/var/db/timezone\")")
            .expect("zoneinfo tree deny");
        let utc_allow_at = profile
            .find(r##"(regex #"^/var/db/timezone/tz/[^/]+/zoneinfo/UTC$")"##)
            .expect("UTC allow");
        let user_deny_at = profile
            .find("(literal \"/Users/example/.ssh\")")
            .expect("user deny");
        assert!(
            read_only_allow_at < zoneinfo_deny_at,
            "zoneinfo deny must come after the user read_only allow"
        );
        assert!(
            zoneinfo_deny_at < utc_allow_at,
            "UTC carve-out must follow the zoneinfo deny or the deny kills it"
        );
        assert!(
            utc_allow_at < user_deny_at,
            "user paths.deny must remain the very last rules"
        );
    }

    #[test]
    fn user_deny_paths_stay_last_after_identity_denials() {
        let paths = PathPolicy {
            deny: vec!["/Users/example/.ssh".into()],
            ..PathPolicy::default()
        };
        let profile = SandboxProfile::new("/Users/example", "/Users/example/project", "/tmp/lyh")
            .with_paths(paths)
            .render();

        let identity_deny_at = profile
            .find("(literal \"/Users/example/Library/Preferences/.GlobalPreferences.plist\")")
            .expect("identity deny");
        let user_deny_at = profile
            .find("(literal \"/Users/example/.ssh\")")
            .expect("user deny");
        assert!(
            user_deny_at > identity_deny_at,
            "user paths.deny must remain the very last rules"
        );
    }

    #[test]
    fn extra_paths_render_in_policy_order() {
        let paths = PathPolicy {
            writable: vec!["/Volumes/DATA/models".into()],
            read_only: vec!["/Volumes/DATA/reference".into()],
            deny: vec!["/Users/example/.ssh".into(), "/Users/example/.aws".into()],
            ..PathPolicy::default()
        };
        let profile = SandboxProfile::new("/Users/example", "/Users/example/project", "/tmp/lyh")
            .with_paths(paths)
            .render();

        // Extra writable paths join the existing writable allow.
        assert!(profile.contains(
            r#"(allow file-read* file-write* file-map-executable
    (subpath "/Users/example")
    (subpath "/Users/example/project")
    (subpath "/tmp/lyh")
    (subpath "/opt/homebrew")
    (subpath "/Volumes/DATA/models"))"#
        ));
        assert!(profile.contains(
            r#"(allow file-read*
    (subpath "/Volumes/DATA/reference"))"#
        ));
        // Deny rules cover read and write, and are the FINAL rules in the
        // profile — seatbelt is last-match-wins, so anything after them would
        // override the denial.
        let deny_block = r#"(deny file-read* file-write*
    (literal "/Users/example/.ssh")
    (subpath "/Users/example/.ssh")
    (literal "/Users/example/.aws")
    (subpath "/Users/example/.aws"))"#;
        assert!(profile.contains(deny_block));
        let deny_at = profile.find(deny_block).unwrap();
        let outbound_at = profile.find("(allow network-outbound").unwrap();
        assert!(deny_at > outbound_at, "deny block must come last");
        assert!(profile.trim_end().ends_with(deny_block));
    }

    #[test]
    fn narrow_home_grants_state_dirs_not_home() {
        let paths = PathPolicy {
            narrow_home: true,
            agent_state_dirs: vec![".claude".into(), ".claude.json".into()],
            ..PathPolicy::default()
        };
        let profile = SandboxProfile::new("/Users/example", "/Users/example/project", "/tmp/lyh")
            .with_paths(paths)
            .render();

        // Home is readable/executable but no longer blanket-writable.
        assert!(profile.contains(
            r#"(allow file-read* file-map-executable
    (subpath "/Users/example"))"#
        ));
        assert!(!profile.contains(
            r#"(allow file-read* file-write* file-map-executable
    (subpath "/Users/example")
"#
        ));
        // State entries are writable as both literal (files) and subpath.
        assert!(profile.contains(r#"(literal "/Users/example/.claude.json")"#));
        assert!(profile.contains(r#"(subpath "/Users/example/.claude")"#));
        assert!(profile.contains(r#"(subpath "/Users/example/project")"#));
        assert!(profile.contains(r#"(subpath "/opt/homebrew")"#));
    }

    #[test]
    fn user_paths_are_scheme_escaped() {
        let paths = PathPolicy {
            writable: vec![r#"/tmp/a"b\c"#.into()],
            deny: vec![r#"/tmp/d"e"#.into()],
            ..PathPolicy::default()
        };
        let profile = SandboxProfile::new("/Users/example", "/Users/example/project", "/tmp/lyh")
            .with_paths(paths)
            .render();

        assert!(profile.contains(r#"(subpath "/tmp/a\"b\\c")"#));
        assert!(profile.contains(r#"(subpath "/tmp/d\"e")"#));
        assert!(!profile.contains(r#"a"b"#));
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

        let marker = std::path::PathBuf::from(std::env::var("HOME").unwrap()).join(format!(
            ".lianyaohu-write-test-{}-{}",
            std::process::id(),
            unique_test_id()
        ));

        let result = run_in_sandbox(&["/usr/bin/touch", &marker.to_string_lossy()]);

        let written = marker.exists();
        let _ = fs::remove_file(&marker);
        assert_eq!(result.status, 0, "{}", result.output);
        assert!(written);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn generated_profile_blocks_setuid_exec() {
        if skip_sandbox_runtime_tests_in_ci() {
            return;
        }

        // macOS has no PR_SET_NO_NEW_PRIVS, but Seatbelt refuses to exec
        // setuid/setgid binaries from a sandboxed process, so a sandboxed
        // agent cannot escalate through setuid-root helpers. This pins that
        // behavior: if it ever regresses, the launch path needs an explicit
        // privilege-transition lock.
        let result = run_in_sandbox(&["/usr/bin/sudo", "-n", "true"]);

        assert_ne!(result.status, 0, "setuid exec unexpectedly succeeded");
        assert!(
            result.output.contains("Operation not permitted"),
            "expected exec of setuid binary to be denied by the sandbox: {}",
            result.output
        );
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
    #[test]
    fn generated_profile_blocks_home_timezone_preferences() {
        if skip_sandbox_runtime_tests_in_ci() {
            return;
        }

        // The $HOME copies of the timezone/identity preferences sit inside the
        // blanket-writable home. Seatbelt is last-match-wins, so the identity
        // denials must be emitted after the home allow or the allow silently
        // wins; this pins the runtime behavior with a scratch home.
        let (root, home, tmpdir) = scratch_home_layout();
        let prefs = home.join("Library/Preferences");
        fs::create_dir_all(prefs.join("ByHost")).unwrap();
        fs::write(prefs.join(".GlobalPreferences.plist"), "identity").unwrap();
        fs::write(prefs.join("ByHost/com.apple.example.plist"), "identity").unwrap();
        fs::write(home.join("readable"), "fine").unwrap();
        let cwd = std::env::current_dir().unwrap();
        let profile = SandboxProfile::new(
            home.to_string_lossy(),
            cwd.to_string_lossy(),
            tmpdir.to_string_lossy(),
        );

        let global_prefs = run_profile(
            &profile,
            &tmpdir,
            vec![
                "/bin/cat".into(),
                prefs
                    .join(".GlobalPreferences.plist")
                    .to_string_lossy()
                    .into(),
            ],
        );
        let by_host = run_profile(
            &profile,
            &tmpdir,
            vec![
                "/bin/cat".into(),
                prefs
                    .join("ByHost/com.apple.example.plist")
                    .to_string_lossy()
                    .into(),
            ],
        );
        let write_attempt = run_profile(
            &profile,
            &tmpdir,
            vec![
                "/usr/bin/touch".into(),
                prefs.join("ByHost/planted.plist").to_string_lossy().into(),
            ],
        );
        let control = run_profile(
            &profile,
            &tmpdir,
            vec![
                "/bin/cat".into(),
                home.join("readable").to_string_lossy().into(),
            ],
        );

        let planted = prefs.join("ByHost/planted.plist").exists();
        let _ = fs::remove_dir_all(&root);
        assert_ne!(
            global_prefs.status, 0,
            "$HOME .GlobalPreferences.plist was readable despite the deny"
        );
        assert_ne!(
            by_host.status, 0,
            "$HOME Library/Preferences/ByHost was readable despite the deny"
        );
        assert_ne!(
            write_attempt.status, 0,
            "$HOME Library/Preferences/ByHost was writable despite the deny"
        );
        assert!(!planted);
        assert_eq!(control.status, 0, "control read failed: {}", control.output);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn read_only_extra_cannot_reallow_identity_preferences() {
        if skip_sandbox_runtime_tests_in_ci() {
            return;
        }

        // A user paths.read_only grant covering ~/Library/Preferences renders
        // as an (allow file-read* ...) in the user sections. Seatbelt is
        // last-match-wins, so if the identity deny block rendered before that
        // allow, the allow would silently re-open the identity plists. This
        // pins the runtime behavior: the identity files stay denied while the
        // rest of the granted subtree reads fine.
        let (root, home, tmpdir) = scratch_home_layout();
        let prefs = home.join("Library/Preferences");
        fs::create_dir_all(prefs.join("ByHost")).unwrap();
        fs::write(prefs.join(".GlobalPreferences.plist"), "identity").unwrap();
        fs::write(prefs.join("ByHost/com.apple.example.plist"), "identity").unwrap();
        fs::write(prefs.join("com.example.app.plist"), "fine").unwrap();
        let cwd = std::env::current_dir().unwrap();
        let paths = PathPolicy {
            read_only: vec![prefs.to_string_lossy().into()],
            ..PathPolicy::default()
        };
        let profile = SandboxProfile::new(
            home.to_string_lossy(),
            cwd.to_string_lossy(),
            tmpdir.to_string_lossy(),
        )
        .with_paths(paths);

        let global_prefs = run_profile(
            &profile,
            &tmpdir,
            vec![
                "/bin/cat".into(),
                prefs
                    .join(".GlobalPreferences.plist")
                    .to_string_lossy()
                    .into(),
            ],
        );
        let by_host = run_profile(
            &profile,
            &tmpdir,
            vec![
                "/bin/cat".into(),
                prefs
                    .join("ByHost/com.apple.example.plist")
                    .to_string_lossy()
                    .into(),
            ],
        );
        let control = run_profile(
            &profile,
            &tmpdir,
            vec![
                "/bin/cat".into(),
                prefs.join("com.example.app.plist").to_string_lossy().into(),
            ],
        );

        let _ = fs::remove_dir_all(&root);
        assert_ne!(
            global_prefs.status, 0,
            "paths.read_only re-allowed $HOME .GlobalPreferences.plist"
        );
        assert_ne!(
            by_host.status, 0,
            "paths.read_only re-allowed $HOME Library/Preferences/ByHost"
        );
        assert_eq!(
            control.status, 0,
            "control read under the read_only grant failed: {}",
            control.output
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn read_only_extra_cannot_reallow_timezone_database() {
        if skip_sandbox_runtime_tests_in_ci() {
            return;
        }

        // A user paths.read_only grant covering /private/var/db/timezone
        // renders as an (allow file-read* ...) in the user sections. Seatbelt
        // is last-match-wins, so if the zoneinfo deny rendered before that
        // allow, the allow would silently re-open the timezone database — and
        // with it /etc/localtime, whose symlink target resolves into the tree
        // before rule matching. This pins the runtime behavior: the tree and
        // /etc/localtime stay denied while the UTC carve-out keeps working.
        let (root, home, tmpdir) = scratch_home_layout();
        let cwd = std::env::current_dir().unwrap();
        let paths = PathPolicy {
            read_only: vec!["/private/var/db/timezone".into()],
            ..PathPolicy::default()
        };
        let profile = SandboxProfile::new(
            home.to_string_lossy(),
            cwd.to_string_lossy(),
            tmpdir.to_string_lossy(),
        )
        .with_paths(paths);

        // The host's configured zone target. Skip the localtime probes on the
        // (unusual) host whose local zone IS one of the carved-out UTC data
        // files, where a successful read is the intended behavior.
        let zone_target = fs::read_link("/etc/localtime")
            .map(|target| target.to_string_lossy().to_string())
            .ok()
            .filter(|target| !target.ends_with("/UTC") && !target.ends_with("/posixrules"));
        let localtime = zone_target.as_ref().map(|_| {
            run_profile(
                &profile,
                &tmpdir,
                vec!["/bin/cat".into(), "/etc/localtime".into()],
            )
        });
        let resolved_zone = zone_target
            .as_ref()
            .map(|target| run_profile(&profile, &tmpdir, vec!["/bin/cat".into(), target.clone()]));
        let utc = find_utc_timezone_file().map(|path| {
            run_profile(
                &profile,
                &tmpdir,
                vec!["/bin/cat".into(), path.to_string_lossy().into()],
            )
        });

        let _ = fs::remove_dir_all(&root);
        if zone_target.is_none() {
            eprintln!("skipping localtime probes; /etc/localtime is not a non-UTC symlink");
        }
        if let Some(localtime) = localtime {
            assert_ne!(
                localtime.status, 0,
                "paths.read_only over the timezone DB re-allowed /etc/localtime"
            );
        }
        if let Some(resolved_zone) = resolved_zone {
            assert_ne!(
                resolved_zone.status, 0,
                "paths.read_only over the timezone DB re-allowed the zoneinfo target"
            );
        }
        if let Some(utc) = utc {
            assert_eq!(
                utc.status, 0,
                "UTC carve-out broken under a timezone read_only extra: {}",
                utc.output
            );
        }
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
        let tmpdir = std::env::temp_dir().join(format!(
            "lianyaohu-test-{}-{}",
            std::process::id(),
            unique_test_id()
        ));
        fs::create_dir_all(&tmpdir).unwrap();
        let command = build_command(&tmpdir);
        let profile = SandboxProfile::new(&home, cwd.to_string_lossy(), tmpdir.to_string_lossy());
        let result = run_profile(&profile, &tmpdir, command);
        let _ = fs::remove_dir_all(&tmpdir);
        result
    }

    // Runs a command under an arbitrary profile; the caller owns tmpdir
    // creation and cleanup. The child's environment is sanitized against the
    // profile's own home/cwd/tmpdir so runtime tests can use a scratch home.
    #[cfg(target_os = "macos")]
    fn run_profile(
        profile: &SandboxProfile,
        tmpdir: &std::path::Path,
        command: Vec<String>,
    ) -> SandboxRun {
        let profile_path = tmpdir.join(format!("profile-{}.sb", unique_test_id()));
        fs::write(&profile_path, profile.render()).unwrap();

        let input_env = std::env::vars().collect::<BTreeMap<_, _>>();
        let clean_env = env_policy::sanitize(
            &input_env,
            &profile.home,
            &profile.cwd,
            &tmpdir.to_string_lossy(),
            &BTreeMap::new(),
        );

        let output = Command::new("/usr/bin/sandbox-exec")
            .arg("-f")
            .arg(&profile_path)
            .args(command)
            .current_dir(&profile.cwd)
            .env_clear()
            .envs(clean_env)
            .output()
            .unwrap();

        SandboxRun {
            status: output.status.code().unwrap_or(1),
            output: format!(
                "{}{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            ),
        }
    }

    // Scratch layout for policy runtime tests: home and the launch tmpdir must
    // be SIBLINGS — if home lived inside the granted tmpdir, the tmpdir's
    // writable subpath rule would make home writable and mask the behavior
    // under test.
    #[cfg(target_os = "macos")]
    fn scratch_home_layout() -> (std::path::PathBuf, std::path::PathBuf, std::path::PathBuf) {
        let root = std::env::temp_dir().join(format!(
            "lianyaohu-policy-test-{}-{}",
            std::process::id(),
            unique_test_id()
        ));
        fs::create_dir_all(&root).unwrap();
        // Seatbelt matches canonical vnode paths, and macOS temp dirs live
        // behind the /var -> /private/var symlink; production paths are always
        // canonicalized (helper validated_directory), so mirror that here.
        let root = root.canonicalize().unwrap();
        let home = root.join("home");
        let tmpdir = root.join("tmp");
        fs::create_dir_all(&home).unwrap();
        fs::create_dir_all(&tmpdir).unwrap();
        (root, home, tmpdir)
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn narrow_home_profile_restricts_home_writes() {
        if skip_sandbox_runtime_tests_in_ci() {
            return;
        }

        let (root, home, tmpdir) = scratch_home_layout();
        fs::create_dir_all(home.join(".claude")).unwrap();
        let cwd = std::env::current_dir().unwrap();
        let paths = PathPolicy {
            narrow_home: true,
            agent_state_dirs: vec![".claude".into()],
            ..PathPolicy::default()
        };
        let profile = SandboxProfile::new(
            home.to_string_lossy(),
            cwd.to_string_lossy(),
            tmpdir.to_string_lossy(),
        )
        .with_paths(paths);

        let blocked = home.join("blocked");
        let denied = run_profile(
            &profile,
            &tmpdir,
            vec!["/usr/bin/touch".into(), blocked.to_string_lossy().into()],
        );
        let allowed_target = home.join(".claude").join("ok");
        let allowed = run_profile(
            &profile,
            &tmpdir,
            vec![
                "/usr/bin/touch".into(),
                allowed_target.to_string_lossy().into(),
            ],
        );

        let blocked_exists = blocked.exists();
        let allowed_exists = allowed_target.exists();
        let _ = fs::remove_dir_all(&root);
        assert_ne!(denied.status, 0, "write outside state dirs must fail");
        assert!(!blocked_exists);
        assert_eq!(
            allowed.status, 0,
            "state dir write failed: {}",
            allowed.output
        );
        assert!(allowed_exists);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn deny_paths_block_reads_inside_writable_home() {
        if skip_sandbox_runtime_tests_in_ci() {
            return;
        }

        let (root, home, tmpdir) = scratch_home_layout();
        let ssh_dir = home.join(".ssh");
        fs::create_dir_all(&ssh_dir).unwrap();
        fs::write(ssh_dir.join("secret"), "key material").unwrap();
        fs::write(home.join("readable"), "fine").unwrap();
        let cwd = std::env::current_dir().unwrap();
        let paths = PathPolicy {
            deny: vec![ssh_dir.to_string_lossy().into()],
            ..PathPolicy::default()
        };
        let profile = SandboxProfile::new(
            home.to_string_lossy(),
            cwd.to_string_lossy(),
            tmpdir.to_string_lossy(),
        )
        .with_paths(paths);

        let denied = run_profile(
            &profile,
            &tmpdir,
            vec![
                "/bin/cat".into(),
                ssh_dir.join("secret").to_string_lossy().into(),
            ],
        );
        let allowed = run_profile(
            &profile,
            &tmpdir,
            vec![
                "/bin/cat".into(),
                home.join("readable").to_string_lossy().into(),
            ],
        );

        let _ = fs::remove_dir_all(&root);
        assert_ne!(
            denied.status, 0,
            "deny path was readable despite writable home"
        );
        assert_eq!(allowed.status, 0, "control read failed: {}", allowed.output);
    }
}
