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
    "DISPLAY",
    "HOST",
    "HOSTNAME",
    "ITERM_SESSION_ID",
    "LAUNCHINSTANCEID",
    "REMOTEHOST",
    "SECURITYSESSIONID",
    "SSH_AUTH_SOCK",
    "SSH_CLIENT",
    "SSH_CONNECTION",
    "SSH_TTY",
    "TZ",
    "XPC_FLAGS",
    "XPC_SERVICE_NAME",
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
        if !is_blocked(key) {
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
        || upper.starts_with("XPC_")
        || upper.starts_with("SSH_")
        || BLOCKED_SUBSTRINGS
            .iter()
            .any(|needle| upper.contains(needle))
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
}
