use std::collections::BTreeMap;

pub const DEFAULT_PATH: &str = "/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin";

const ALLOWED_EXACT: &[&str] = &[
    "ANTHROPIC_API_KEY",
    "ANTHROPIC_AUTH_TOKEN",
    "ANTHROPIC_BASE_URL",
    "ANTHROPIC_MODEL",
    "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC",
    "CLAUDE_CODE_MAX_OUTPUT_TOKENS",
    "CLAUDE_CONFIG_DIR",
    "CODEX_HOME",
    "CODEX_MODEL",
    "COLORTERM",
    "GEMINI_API_KEY",
    "GITHUB_TOKEN",
    "GIT_ASKPASS",
    "HOME",
    "LANG",
    "LC_ALL",
    "LOGNAME",
    "NO_COLOR",
    "OPENAI_API_KEY",
    "OPENAI_BASE_URL",
    "OPENAI_MODEL",
    "PATH",
    "PWD",
    "SHELL",
    "TERM",
    "TMPDIR",
    "USER",
];

const ALLOWED_PREFIXES: &[&str] = &[
    "ANTHROPIC_",
    "CLAUDE_",
    "CODEX_",
    "GEMINI_",
    "GIT_",
    "LC_",
    "OPENAI_",
];

const BLOCKED_EXACT: &[&str] = &[
    "__CF_USER_TEXT_ENCODING",
    "APPLE_PUBSUB_SOCKET_RENDER",
    "BASH_ENV",
    "DISPLAY",
    "ENV",
    "HOST",
    "HOSTNAME",
    "IFS",
    "ITERM_SESSION_ID",
    "LAUNCHINSTANCEID",
    "NODE_OPTIONS",
    "NODE_PATH",
    "REMOTEHOST",
    "RUBYLIB",
    "RUBYOPT",
    "SECURITYSESSIONID",
    "SHELLOPTS",
    "SSH_AUTH_SOCK",
    "SSH_CLIENT",
    "SSH_CONNECTION",
    "SSH_TTY",
    "TZ",
    "XPC_FLAGS",
    "XPC_SERVICE_NAME",
    "ZDOTDIR",
];

// Families that change what code a process loads or executes at startup
// (dynamic-loader preloads, interpreter startup files, exported shell
// functions). Allowing them through --env would let a caller plant code in
// every process the agent starts, so they are blocked even as extras.
const BLOCKED_PREFIXES: &[&str] = &[
    "BASH_FUNC",
    "DYLD_",
    "GLIBC_",
    "LD_",
    "PERL5",
    "PYTHON",
    "SSH_",
    "XPC_",
];

const BLOCKED_SUBSTRINGS: &[&str] = &[
    "AIRPORT",
    "BSSID",
    "COMPUTERNAME",
    "HOST_MAC",
    "LOCAL_IP",
    "MACADDR",
    "MAC_ADDRESS",
    "MAC_ADDR",
    "SERIAL",
    "TIMEZONE",
    "TIME_ZONE",
    "WIFI",
];

const FIXED_SANDBOX_ENV: &[&str] = &["HOME", "PWD", "TMPDIR", "TZ", "LIANYAOHU_SANDBOX"];

pub fn sanitize(
    input: &BTreeMap<String, String>,
    home: &str,
    cwd: &str,
    tmpdir: &str,
    extra: &BTreeMap<String, String>,
) -> BTreeMap<String, String> {
    let mut output = BTreeMap::new();

    for (key, value) in input {
        if is_allowed(key) {
            output.insert(key.clone(), value.clone());
        }
    }

    output.insert("HOME".to_string(), home.to_string());
    output.insert("PWD".to_string(), cwd.to_string());
    output.insert("TMPDIR".to_string(), tmpdir.to_string());
    output.insert(
        "PATH".to_string(),
        input
            .get("PATH")
            .filter(|value| !value.is_empty())
            .cloned()
            .unwrap_or_else(|| DEFAULT_PATH.to_string()),
    );
    output.insert(
        "TERM".to_string(),
        input
            .get("TERM")
            .cloned()
            .unwrap_or_else(|| "xterm-256color".to_string()),
    );
    output.insert("TZ".to_string(), "UTC".to_string());
    output.insert("LIANYAOHU_SANDBOX".to_string(), "1".to_string());

    for (key, value) in extra {
        if !is_blocked(key) && !is_fixed_sandbox_env(key) {
            output.insert(key.clone(), value.clone());
        }
    }

    output
}

pub fn is_allowed(key: &str) -> bool {
    if is_blocked(key) {
        return false;
    }
    ALLOWED_EXACT.contains(&key)
        || ALLOWED_PREFIXES
            .iter()
            .any(|prefix| key.starts_with(prefix))
}

pub fn is_blocked(key: &str) -> bool {
    let upper = key.to_ascii_uppercase();
    BLOCKED_EXACT.contains(&upper.as_str())
        || BLOCKED_PREFIXES
            .iter()
            .any(|prefix| upper.starts_with(prefix))
        || BLOCKED_SUBSTRINGS
            .iter()
            .any(|needle| upper.contains(needle))
}

fn is_fixed_sandbox_env(key: &str) -> bool {
    FIXED_SANDBOX_ENV.contains(&key)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn drops_host_and_network_identity_environment() {
        let input = BTreeMap::from([
            ("PATH".to_string(), "/usr/bin".to_string()),
            ("TERM".to_string(), "xterm".to_string()),
            ("TZ".to_string(), "Asia/Singapore".to_string()),
            ("HOSTNAME".to_string(), "workstation.local".to_string()),
            ("HOST_MAC_ADDR".to_string(), "aa:bb:cc:dd:ee:ff".to_string()),
            ("OPENAI_API_KEY".to_string(), "test-openai".to_string()),
            (
                "ANTHROPIC_API_KEY".to_string(),
                "test-anthropic".to_string(),
            ),
            (
                "SSH_AUTH_SOCK".to_string(),
                "/private/tmp/socket".to_string(),
            ),
        ]);

        let output = sanitize(
            &input,
            "/Users/example",
            "/Users/example/project",
            "/tmp/lianyaohu",
            &BTreeMap::new(),
        );

        assert_eq!(output.get("PATH").map(String::as_str), Some("/usr/bin"));
        assert_eq!(output.get("TERM").map(String::as_str), Some("xterm"));
        assert_eq!(output.get("TZ").map(String::as_str), Some("UTC"));
        assert!(!output.contains_key("HOSTNAME"));
        assert!(!output.contains_key("HOST_MAC_ADDR"));
        assert!(!output.contains_key("SSH_AUTH_SOCK"));
        assert_eq!(
            output.get("OPENAI_API_KEY").map(String::as_str),
            Some("test-openai")
        );
        assert_eq!(
            output.get("ANTHROPIC_API_KEY").map(String::as_str),
            Some("test-anthropic")
        );
    }

    #[test]
    fn extra_environment_cannot_reintroduce_blocked_values() {
        let extra = BTreeMap::from([
            ("MAC_ADDRESS".to_string(), "aa:bb:cc:dd:ee:ff".to_string()),
            (
                "CLAUDE_CONFIG_DIR".to_string(),
                "/Users/example/.claude".to_string(),
            ),
        ]);

        let output = sanitize(
            &BTreeMap::new(),
            "/Users/example",
            "/Users/example/project",
            "/tmp/lianyaohu",
            &extra,
        );

        assert!(!output.contains_key("MAC_ADDRESS"));
        assert_eq!(
            output.get("CLAUDE_CONFIG_DIR").map(String::as_str),
            Some("/Users/example/.claude")
        );
    }

    #[test]
    fn extra_environment_cannot_inject_loader_or_runtime_knobs() {
        let injection_keys = [
            "LD_PRELOAD",
            "LD_LIBRARY_PATH",
            "DYLD_INSERT_LIBRARIES",
            "DYLD_LIBRARY_PATH",
            "NODE_OPTIONS",
            "NODE_PATH",
            "PYTHONPATH",
            "PYTHONSTARTUP",
            "PYTHONHOME",
            "PERL5OPT",
            "PERL5LIB",
            "RUBYOPT",
            "RUBYLIB",
            "BASH_ENV",
            "ENV",
            "SHELLOPTS",
            "ZDOTDIR",
            "IFS",
            "GLIBC_TUNABLES",
            "BASH_FUNC_ls%%",
            "ld_preload",
        ];
        let extra = injection_keys
            .iter()
            .map(|key| (key.to_string(), "injected".to_string()))
            .collect::<BTreeMap<_, _>>();

        let output = sanitize(
            &extra.clone(),
            "/Users/example",
            "/Users/example/project",
            "/tmp/lianyaohu",
            &extra,
        );

        for key in injection_keys {
            assert!(!output.contains_key(key), "{key} should be blocked");
        }
    }

    #[test]
    fn extra_environment_still_admits_agent_configuration() {
        let extra = BTreeMap::from([
            ("NODE_ENV".to_string(), "production".to_string()),
            ("MY_AGENT_FLAG".to_string(), "1".to_string()),
            (
                "ANTHROPIC_API_KEY".to_string(),
                "test-anthropic".to_string(),
            ),
        ]);

        let output = sanitize(
            &BTreeMap::new(),
            "/Users/example",
            "/Users/example/project",
            "/tmp/lianyaohu",
            &extra,
        );

        assert_eq!(
            output.get("NODE_ENV").map(String::as_str),
            Some("production")
        );
        assert_eq!(output.get("MY_AGENT_FLAG").map(String::as_str), Some("1"));
        assert_eq!(
            output.get("ANTHROPIC_API_KEY").map(String::as_str),
            Some("test-anthropic")
        );
    }

    #[test]
    fn extra_environment_cannot_override_sandbox_roots() {
        let extra = BTreeMap::from([
            ("HOME".to_string(), "/".to_string()),
            ("PWD".to_string(), "/".to_string()),
            ("TMPDIR".to_string(), "/".to_string()),
            ("TZ".to_string(), "Asia/Singapore".to_string()),
            ("LIANYAOHU_SANDBOX".to_string(), "0".to_string()),
        ]);

        let output = sanitize(
            &BTreeMap::new(),
            "/Users/example",
            "/Users/example/project",
            "/tmp/lianyaohu",
            &extra,
        );

        assert_eq!(
            output.get("HOME").map(String::as_str),
            Some("/Users/example")
        );
        assert_eq!(
            output.get("PWD").map(String::as_str),
            Some("/Users/example/project")
        );
        assert_eq!(
            output.get("TMPDIR").map(String::as_str),
            Some("/tmp/lianyaohu")
        );
        assert_eq!(output.get("TZ").map(String::as_str), Some("UTC"));
        assert_eq!(
            output.get("LIANYAOHU_SANDBOX").map(String::as_str),
            Some("1")
        );
    }
}
