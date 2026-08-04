//! Layered TOML configuration.
//!
//! Two files feed a run: the global `~/.config/lianyaohu/config.toml`
//! (machine-level defaults) and an optional per-project `.lianyaohu.toml`
//! discovered by walking upward from the working directory. The project file
//! lives inside a checkout, so it is treated as attacker-influenced: policy
//! *tightenings* apply automatically, while *widenings* require a hash-pinned
//! approval recorded in `trusted.toml` (see [`trust`]).
//!
//! Precedence: CLI flags > project file > global file > built-in defaults.
//! The CLI layer is applied by the app after [`merge`].

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::policy::{
    DestRule, NetAction, NetworkPolicy, PathPolicy, SandboxPolicy, default_agent_state_dirs,
};
use crate::{Result, err};

/// Name of the per-project configuration file.
pub const PROJECT_FILE_NAME: &str = ".lianyaohu.toml";
/// Cap on a configuration file's size; a policy file has no business being big.
pub const MAX_CONFIG_LEN: u64 = 256 * 1024;

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct ConfigFile {
    pub defaults: DefaultsSection,
    pub env: BTreeMap<String, String>,
    pub network: NetworkSection,
    pub paths: PathsSection,
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct DefaultsSection {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vpn_interface: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub firewall: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub shared_user_firewall: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub allow_non_default_route: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub command: Option<Vec<String>>,
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct NetworkSection {
    /// `default = "allow" | "deny"`.
    #[serde(rename = "default", skip_serializing_if = "Option::is_none")]
    pub default_action: Option<NetAction>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub allow: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub deny: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub lan_allow: Vec<String>,
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct PathsSection {
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub writable: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub read_only: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub deny: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub narrow_home: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub agent_state_dirs: Option<Vec<String>>,
}

impl ConfigFile {
    pub fn parse(text: &str) -> Result<Self> {
        toml::from_str(text).map_err(|error| err(format!("invalid configuration: {error}")))
    }

    /// Reads and parses a config file; `Ok(None)` when the file is absent.
    pub fn load(path: &Path) -> Result<Option<Self>> {
        let text = match fs::read_to_string(path) {
            Ok(text) => text,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(err(format!("{}: {error}", path.display()))),
        };
        if text.len() as u64 > MAX_CONFIG_LEN {
            return Err(err(format!(
                "{}: configuration file exceeds {MAX_CONFIG_LEN} bytes",
                path.display()
            )));
        }
        let config =
            Self::parse(&text).map_err(|error| err(format!("{}: {error}", path.display())))?;
        Ok(Some(config))
    }

    pub fn to_toml(&self) -> Result<String> {
        toml::to_string_pretty(self).map_err(|error| err(error.to_string()))
    }

    /// Rejects sections that make no sense in a per-project file: `[defaults]`
    /// holds machine-specific knobs (the VPN interface, firewall toggles) that
    /// do not belong in a repository checkout.
    pub fn validate_as_project(&self) -> Result<()> {
        if self.defaults != DefaultsSection::default() {
            return Err(err(format!(
                "{PROJECT_FILE_NAME} must not contain a [defaults] section"
            )));
        }
        Ok(())
    }

    /// Keys whose presence *widens* the sandbox relative to the built-in
    /// policy. These require trust approval when they come from a project
    /// file. `[env]` is included because environment variables can redirect
    /// credentials (e.g. `ANTHROPIC_BASE_URL`).
    pub fn widening_keys(&self) -> Vec<&'static str> {
        let mut keys = Vec::new();
        if !self.network.allow.is_empty() {
            keys.push("network.allow");
        }
        if !self.network.lan_allow.is_empty() {
            keys.push("network.lan_allow");
        }
        if !self.paths.writable.is_empty() {
            keys.push("paths.writable");
        }
        if !self.paths.read_only.is_empty() {
            keys.push("paths.read_only");
        }
        if self.paths.agent_state_dirs.is_some() {
            keys.push("paths.agent_state_dirs");
        }
        if !self.env.is_empty() {
            keys.push("env");
        }
        keys
    }

    /// Removes every widening key, keeping only tightenings. Used for
    /// unapproved project files in non-interactive runs: we never silently
    /// widen, and we never block a scripted run on a prompt.
    pub fn strip_widenings(&mut self) {
        self.network.allow.clear();
        self.network.lan_allow.clear();
        self.paths.writable.clear();
        self.paths.read_only.clear();
        self.paths.agent_state_dirs = None;
        self.env.clear();
    }

    /// Builds the typed, validated policy from this (already merged) config.
    /// `home` is the caller's home directory, used for `~` expansion — this
    /// runs client-side only; the helper receives the expanded policy and
    /// re-validates it.
    pub fn sandbox_policy(&self, home: &Path) -> Result<SandboxPolicy> {
        let network = NetworkPolicy {
            default_action: self.network.default_action.unwrap_or_default(),
            allow: parse_rules("network.allow", &self.network.allow)?,
            deny: parse_rules("network.deny", &self.network.deny)?,
            lan_allow: parse_rules("network.lan_allow", &self.network.lan_allow)?,
        };
        let paths = PathPolicy {
            writable: expand_paths("paths.writable", &self.paths.writable, home)?,
            read_only: expand_paths("paths.read_only", &self.paths.read_only, home)?,
            deny: expand_paths("paths.deny", &self.paths.deny, home)?,
            narrow_home: self.paths.narrow_home.unwrap_or(false),
            agent_state_dirs: self
                .paths
                .agent_state_dirs
                .clone()
                .unwrap_or_else(default_agent_state_dirs),
        };
        let policy = SandboxPolicy { network, paths };
        policy.validate()?;
        Ok(policy)
    }
}

fn parse_rules(key: &str, entries: &[String]) -> Result<Vec<DestRule>> {
    entries
        .iter()
        .map(|entry| DestRule::parse(entry).map_err(|error| err(format!("{key}: {error}"))))
        .collect()
}

fn expand_paths(key: &str, entries: &[String], home: &Path) -> Result<Vec<String>> {
    entries
        .iter()
        .map(|entry| {
            let expanded = expand_tilde(entry, home);
            crate::policy::lexically_normalized_absolute(&expanded)
                .map_err(|error| err(format!("{key} entry {entry:?}: {error}")))
        })
        .collect()
}

/// Expands a leading `~` or `~/` against the caller's home directory. Other
/// users' homes (`~name`) are intentionally not supported.
pub fn expand_tilde(entry: &str, home: &Path) -> String {
    if entry == "~" {
        return home.to_string_lossy().into_owned();
    }
    if let Some(rest) = entry.strip_prefix("~/") {
        return format!("{}/{rest}", home.to_string_lossy());
    }
    entry.to_string()
}

/// Where a merged value came from, for `lyh config show` provenance output.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Source {
    Default,
    Global,
    Project,
    Cli,
}

impl std::fmt::Display for Source {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let text = match self {
            Self::Default => "default",
            Self::Global => "global",
            Self::Project => "project",
            Self::Cli => "cli",
        };
        f.write_str(text)
    }
}

#[derive(Clone, Debug)]
pub struct MergedConfig {
    pub file: ConfigFile,
    /// Provenance per key (scalar keys, plus list keys mapped to the layer
    /// that contributed last).
    pub provenance: BTreeMap<String, Source>,
}

/// Merges global and project layers. Lists concatenate (global first,
/// deduplicated); scalars from the project override the global value;
/// `[defaults]` comes from the global file only (project files reject it).
pub fn merge(global: Option<&ConfigFile>, project: Option<&ConfigFile>) -> MergedConfig {
    let mut provenance = BTreeMap::new();
    let mut file = ConfigFile::default();

    if let Some(global) = global {
        file = global.clone();
        record_layer(&mut provenance, global, Source::Global);
    }
    if let Some(project) = project {
        record_layer(&mut provenance, project, Source::Project);
        for (key, value) in &project.env {
            file.env.insert(key.clone(), value.clone());
        }
        if project.network.default_action.is_some() {
            file.network.default_action = project.network.default_action;
        }
        append_unique(&mut file.network.allow, &project.network.allow);
        append_unique(&mut file.network.deny, &project.network.deny);
        append_unique(&mut file.network.lan_allow, &project.network.lan_allow);
        append_unique(&mut file.paths.writable, &project.paths.writable);
        append_unique(&mut file.paths.read_only, &project.paths.read_only);
        append_unique(&mut file.paths.deny, &project.paths.deny);
        if project.paths.narrow_home.is_some() {
            file.paths.narrow_home = project.paths.narrow_home;
        }
        if project.paths.agent_state_dirs.is_some() {
            file.paths.agent_state_dirs = project.paths.agent_state_dirs.clone();
        }
    }

    MergedConfig { file, provenance }
}

fn append_unique(target: &mut Vec<String>, extra: &[String]) {
    for entry in extra {
        if !target.contains(entry) {
            target.push(entry.clone());
        }
    }
}

fn record_layer(provenance: &mut BTreeMap<String, Source>, layer: &ConfigFile, source: Source) {
    let mut set = |key: &str, present: bool| {
        if present {
            provenance.insert(key.to_string(), source);
        }
    };
    set(
        "defaults.vpn_interface",
        layer.defaults.vpn_interface.is_some(),
    );
    set("defaults.firewall", layer.defaults.firewall.is_some());
    set(
        "defaults.shared_user_firewall",
        layer.defaults.shared_user_firewall.is_some(),
    );
    set(
        "defaults.allow_non_default_route",
        layer.defaults.allow_non_default_route.is_some(),
    );
    set("defaults.command", layer.defaults.command.is_some());
    set("env", !layer.env.is_empty());
    set("network.default", layer.network.default_action.is_some());
    set("network.allow", !layer.network.allow.is_empty());
    set("network.deny", !layer.network.deny.is_empty());
    set("network.lan_allow", !layer.network.lan_allow.is_empty());
    set("paths.writable", !layer.paths.writable.is_empty());
    set("paths.read_only", !layer.paths.read_only.is_empty());
    set("paths.deny", !layer.paths.deny.is_empty());
    set("paths.narrow_home", layer.paths.narrow_home.is_some());
    set(
        "paths.agent_state_dirs",
        layer.paths.agent_state_dirs.is_some(),
    );
}

/// `$XDG_CONFIG_HOME/lianyaohu` or `~/.config/lianyaohu`, from the given
/// environment view (pass the caller's real env; the sanitized child env drops
/// XDG variables).
pub fn config_dir(env_home: &str, xdg_config_home: Option<&str>) -> PathBuf {
    match xdg_config_home {
        Some(dir) if !dir.is_empty() => PathBuf::from(dir).join("lianyaohu"),
        _ => PathBuf::from(env_home).join(".config").join("lianyaohu"),
    }
}

pub fn global_config_path(env_home: &str, xdg_config_home: Option<&str>) -> PathBuf {
    config_dir(env_home, xdg_config_home).join("config.toml")
}

pub fn trust_store_path(env_home: &str, xdg_config_home: Option<&str>) -> PathBuf {
    config_dir(env_home, xdg_config_home).join("trusted.toml")
}

/// Walks upward from `cwd` looking for [`PROJECT_FILE_NAME`], stopping after
/// checking the caller's home directory or the filesystem root. Returns the
/// file's path and parsed contents.
pub fn discover_project(cwd: &Path, home: &Path) -> Result<Option<(PathBuf, ConfigFile)>> {
    let mut dir = cwd;
    loop {
        let candidate = dir.join(PROJECT_FILE_NAME);
        if candidate.is_file() {
            let config = ConfigFile::load(&candidate)?
                .ok_or_else(|| err(format!("{}: unreadable", candidate.display())))?;
            config
                .validate_as_project()
                .map_err(|error| err(format!("{}: {error}", candidate.display())))?;
            return Ok(Some((candidate, config)));
        }
        if dir == home {
            return Ok(None);
        }
        match dir.parent() {
            Some(parent) => dir = parent,
            None => return Ok(None),
        }
    }
}

/// True when the file's permissions let anyone but the owner write it — a
/// group/world-writable config or trust store defeats the whole model.
pub fn loosely_permitted(path: &Path) -> bool {
    use std::os::unix::fs::MetadataExt;
    fs::metadata(path).is_ok_and(|metadata| metadata.mode() & 0o022 != 0)
}

pub mod trust {
    //! Hash-pinned approvals for per-project config files, in the style of
    //! `direnv allow`: an approval records the canonical project directory and
    //! the SHA-256 of the file contents it applies to. Any edit to the file
    //! invalidates the approval.

    use std::fs;
    use std::path::{Path, PathBuf};

    use serde::{Deserialize, Serialize};
    use sha2::{Digest, Sha256};

    use crate::{Result, err};

    #[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
    #[serde(default, deny_unknown_fields)]
    struct TrustDoc {
        #[serde(skip_serializing_if = "Vec::is_empty")]
        approvals: Vec<Approval>,
    }

    #[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
    #[serde(deny_unknown_fields)]
    pub struct Approval {
        /// Canonicalized directory containing the project file.
        pub path: String,
        /// Hex SHA-256 of the approved file contents.
        pub sha256: String,
        /// Unix timestamp (seconds) of the approval, informational only.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub approved_at: Option<u64>,
    }

    #[derive(Clone, Debug)]
    pub struct TrustStore {
        path: PathBuf,
        doc: TrustDoc,
    }

    impl TrustStore {
        /// Loads the store; a missing file is an empty store.
        pub fn load(path: &Path) -> Result<Self> {
            let doc = match fs::read_to_string(path) {
                Ok(text) => toml::from_str(&text)
                    .map_err(|error| err(format!("{}: {error}", path.display())))?,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => TrustDoc::default(),
                Err(error) => return Err(err(format!("{}: {error}", path.display()))),
            };
            Ok(Self {
                path: path.to_path_buf(),
                doc,
            })
        }

        pub fn is_approved(&self, project_dir: &str, sha256: &str) -> bool {
            self.doc
                .approvals
                .iter()
                .any(|approval| approval.path == project_dir && approval.sha256 == sha256)
        }

        /// True when the directory has an approval whose hash no longer
        /// matches, i.e. the file changed since approval.
        pub fn is_stale(&self, project_dir: &str, sha256: &str) -> bool {
            self.doc
                .approvals
                .iter()
                .any(|approval| approval.path == project_dir && approval.sha256 != sha256)
        }

        /// Records (or replaces) the approval for a project directory.
        pub fn approve(&mut self, project_dir: &str, sha256: &str, approved_at: Option<u64>) {
            self.doc
                .approvals
                .retain(|approval| approval.path != project_dir);
            self.doc.approvals.push(Approval {
                path: project_dir.to_string(),
                sha256: sha256.to_string(),
                approved_at,
            });
        }

        /// Removes any approval for the directory; returns whether one existed.
        pub fn revoke(&mut self, project_dir: &str) -> bool {
            let before = self.doc.approvals.len();
            self.doc
                .approvals
                .retain(|approval| approval.path != project_dir);
            self.doc.approvals.len() != before
        }

        pub fn approvals(&self) -> &[Approval] {
            &self.doc.approvals
        }

        /// Writes the store with owner-only permissions.
        pub fn save(&self) -> Result<()> {
            use std::io::Write;
            use std::os::unix::fs::OpenOptionsExt;

            if let Some(parent) = self.path.parent() {
                fs::create_dir_all(parent)
                    .map_err(|error| err(format!("{}: {error}", parent.display())))?;
            }
            let text = toml::to_string_pretty(&self.doc).map_err(|error| err(error.to_string()))?;
            let mut file = fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .mode(0o600)
                .open(&self.path)
                .map_err(|error| err(format!("{}: {error}", self.path.display())))?;
            file.write_all(text.as_bytes())
                .map_err(|error| err(format!("{}: {error}", self.path.display())))?;
            Ok(())
        }
    }

    pub fn sha256_hex(bytes: &[u8]) -> String {
        let digest = Sha256::digest(bytes);
        let mut text = String::with_capacity(digest.len() * 2);
        for byte in digest {
            use std::fmt::Write;
            let _ = write!(text, "{byte:02x}");
        }
        text
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU32, Ordering};

    const SAMPLE: &str = r#"
[defaults]
vpn_interface = "utun5"
firewall = true
allow_non_default_route = false
command = ["claude"]

[env]
SOME_VAR = "1"

[network]
default = "deny"
allow = ["140.82.112.0/20", "151.101.0.1:443"]
deny = ["169.254.169.254"]
lan_allow = ["192.168.1.10:22"]

[paths]
writable = ["/Volumes/DATA/models"]
read_only = ["/Volumes/DATA/reference"]
deny = ["~/.ssh", "~/.aws"]
narrow_home = true
agent_state_dirs = [".claude", ".config"]
"#;

    static TEST_ID: AtomicU32 = AtomicU32::new(0);

    fn scratch_dir(label: &str) -> PathBuf {
        let id = TEST_ID.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!(
            "lianyaohu-config-test-{label}-{}-{id}",
            std::process::id()
        ));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn parses_the_full_schema() {
        let config = ConfigFile::parse(SAMPLE).unwrap();
        assert_eq!(config.defaults.vpn_interface.as_deref(), Some("utun5"));
        assert_eq!(
            config.defaults.command.as_deref(),
            Some(&["claude".to_string()][..])
        );
        assert_eq!(config.network.default_action, Some(NetAction::Deny));
        assert_eq!(config.network.allow.len(), 2);
        assert_eq!(config.paths.narrow_home, Some(true));
        assert_eq!(config.env.get("SOME_VAR").map(String::as_str), Some("1"));
    }

    #[test]
    fn unknown_keys_are_hard_errors() {
        for text in [
            "[paths]\nnarow_home = true\n",
            "[network]\nalow = []\n",
            "[nonsense]\nx = 1\n",
            "[defaults]\nvpn = \"utun5\"\n",
        ] {
            assert!(ConfigFile::parse(text).is_err(), "should reject {text:?}");
        }
    }

    #[test]
    fn toml_round_trip() {
        let config = ConfigFile::parse(SAMPLE).unwrap();
        let text = config.to_toml().unwrap();
        assert_eq!(ConfigFile::parse(&text).unwrap(), config);
    }

    #[test]
    fn project_files_reject_defaults_section() {
        let config = ConfigFile::parse("[defaults]\nvpn_interface = \"utun5\"\n").unwrap();
        assert!(config.validate_as_project().is_err());
        let config = ConfigFile::parse("[paths]\nnarrow_home = true\n").unwrap();
        config.validate_as_project().unwrap();
    }

    #[test]
    fn widening_detection_and_strip() {
        let mut config = ConfigFile::parse(SAMPLE).unwrap();
        assert_eq!(
            config.widening_keys(),
            [
                "network.allow",
                "network.lan_allow",
                "paths.writable",
                "paths.read_only",
                "paths.agent_state_dirs",
                "env"
            ]
        );
        config.strip_widenings();
        assert!(config.widening_keys().is_empty());
        // Tightenings survive the strip.
        assert_eq!(config.network.default_action, Some(NetAction::Deny));
        assert_eq!(config.network.deny, ["169.254.169.254"]);
        assert_eq!(config.paths.deny.len(), 2);
        assert_eq!(config.paths.narrow_home, Some(true));
    }

    #[test]
    fn merge_precedence() {
        let global = ConfigFile::parse(
            r#"
[defaults]
vpn_interface = "utun5"

[network]
default = "allow"
allow = ["1.2.3.0/24"]

[paths]
writable = ["/data/one"]
narrow_home = false
"#,
        )
        .unwrap();
        let project = ConfigFile::parse(
            r#"
[network]
default = "deny"
allow = ["1.2.3.0/24", "5.6.7.0/24"]

[paths]
writable = ["/data/two"]
narrow_home = true
"#,
        )
        .unwrap();

        let merged = merge(Some(&global), Some(&project));
        assert_eq!(merged.file.defaults.vpn_interface.as_deref(), Some("utun5"));
        assert_eq!(merged.file.network.default_action, Some(NetAction::Deny));
        // Lists concatenate with dedup, global entries first.
        assert_eq!(merged.file.network.allow, ["1.2.3.0/24", "5.6.7.0/24"]);
        assert_eq!(merged.file.paths.writable, ["/data/one", "/data/two"]);
        assert_eq!(merged.file.paths.narrow_home, Some(true));
        assert_eq!(
            merged.provenance.get("defaults.vpn_interface"),
            Some(&Source::Global)
        );
        assert_eq!(
            merged.provenance.get("network.default"),
            Some(&Source::Project)
        );

        let global_only = merge(Some(&global), None);
        assert_eq!(global_only.file, global);
        let empty = merge(None, None);
        assert_eq!(empty.file, ConfigFile::default());
    }

    #[test]
    fn sandbox_policy_expands_and_validates() {
        let config = ConfigFile::parse(SAMPLE).unwrap();
        let policy = config.sandbox_policy(Path::new("/Users/me")).unwrap();
        assert_eq!(policy.network.default_action, NetAction::Deny);
        assert_eq!(policy.network.allow.len(), 2);
        assert_eq!(policy.paths.deny, ["/Users/me/.ssh", "/Users/me/.aws"]);
        assert!(policy.paths.narrow_home);
        assert_eq!(policy.paths.agent_state_dirs, [".claude", ".config"]);

        // Missing agent_state_dirs falls back to the default set.
        let config = ConfigFile::parse("[paths]\nnarrow_home = true\n").unwrap();
        let policy = config.sandbox_policy(Path::new("/Users/me")).unwrap();
        assert_eq!(policy.paths.agent_state_dirs, default_agent_state_dirs());

        // Invalid destination entries are rejected with the key name.
        let config = ConfigFile::parse("[network]\nallow = [\"nonsense\"]\n").unwrap();
        let error = config.sandbox_policy(Path::new("/Users/me")).unwrap_err();
        assert!(error.to_string().contains("network.allow"), "{error}");

        // lan_allow containment is enforced at build time.
        let config = ConfigFile::parse("[network]\nlan_allow = [\"0.0.0.0/0\"]\n").unwrap();
        assert!(config.sandbox_policy(Path::new("/Users/me")).is_err());
    }

    #[test]
    fn tilde_expansion() {
        let home = Path::new("/Users/me");
        assert_eq!(expand_tilde("~", home), "/Users/me");
        assert_eq!(expand_tilde("~/.ssh", home), "/Users/me/.ssh");
        assert_eq!(expand_tilde("/abs", home), "/abs");
        assert_eq!(expand_tilde("~other/x", home), "~other/x");
    }

    #[test]
    fn discovery_walks_upward_and_stops_at_home() {
        let root = scratch_dir("discover");
        let home = root.join("home");
        let project = home.join("src").join("repo");
        let nested = project.join("a").join("b");
        fs::create_dir_all(&nested).unwrap();
        fs::write(
            project.join(PROJECT_FILE_NAME),
            "[paths]\nnarrow_home = true\n",
        )
        .unwrap();

        let (path, config) = discover_project(&nested, &home).unwrap().unwrap();
        assert_eq!(path, project.join(PROJECT_FILE_NAME));
        assert_eq!(config.paths.narrow_home, Some(true));

        // A file above $HOME is never picked up.
        fs::write(
            root.join(PROJECT_FILE_NAME),
            "[paths]\nnarrow_home = true\n",
        )
        .unwrap();
        let sibling = home.join("elsewhere");
        fs::create_dir_all(&sibling).unwrap();
        assert!(discover_project(&sibling, &home).unwrap().is_none());

        // A project file with [defaults] is rejected during discovery.
        fs::write(
            project.join(PROJECT_FILE_NAME),
            "[defaults]\nvpn_interface = \"utun5\"\n",
        )
        .unwrap();
        assert!(discover_project(&nested, &home).is_err());

        fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn config_paths_respect_xdg() {
        assert_eq!(
            global_config_path("/Users/me", None),
            PathBuf::from("/Users/me/.config/lianyaohu/config.toml")
        );
        assert_eq!(
            global_config_path("/Users/me", Some("/custom/xdg")),
            PathBuf::from("/custom/xdg/lianyaohu/config.toml")
        );
        assert_eq!(
            trust_store_path("/Users/me", Some("")),
            PathBuf::from("/Users/me/.config/lianyaohu/trusted.toml")
        );
    }

    #[test]
    fn trust_store_round_trip() {
        let dir = scratch_dir("trust");
        let store_path = dir.join("trusted.toml");
        let contents = b"[paths]\nnarrow_home = true\n";
        let digest = trust::sha256_hex(contents);

        let mut store = trust::TrustStore::load(&store_path).unwrap();
        assert!(!store.is_approved("/Users/me/src/repo", &digest));
        store.approve("/Users/me/src/repo", &digest, Some(1_754_265_600));
        store.save().unwrap();

        let store = trust::TrustStore::load(&store_path).unwrap();
        assert!(store.is_approved("/Users/me/src/repo", &digest));
        // An edited file no longer matches, and reads as stale.
        let other = trust::sha256_hex(b"[paths]\nnarrow_home = false\n");
        assert!(!store.is_approved("/Users/me/src/repo", &other));
        assert!(store.is_stale("/Users/me/src/repo", &other));

        let mut store = store;
        assert!(store.revoke("/Users/me/src/repo"));
        assert!(!store.revoke("/Users/me/src/repo"));
        store.save().unwrap();
        let store = trust::TrustStore::load(&store_path).unwrap();
        assert!(store.approvals().is_empty());

        // Owner-only permissions on the saved store.
        use std::os::unix::fs::MetadataExt;
        let mode = fs::metadata(&store_path).unwrap().mode() & 0o777;
        assert_eq!(mode, 0o600);

        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn sha256_matches_known_vector() {
        assert_eq!(
            trust::sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }
}
