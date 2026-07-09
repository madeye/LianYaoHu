use crate::helper::PFHelperClient;
use crate::{Result, err};
use std::fs;
use std::io;
use std::process::Command;

pub const LIANYAOHU_GROUP_NAME: &str = "_lianyaohu";
pub const LIANYAOHU_GROUP_GID: u32 = 2_000_000;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PFRuleSet {
    pub interface_name: String,
    pub anchor_key: u32,
    pub socket_owner: SocketOwner,
    pub route_ipv4_gateway: Option<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SocketOwner {
    User(u32),
    /// Match both the socket's UID and its GID. The session GID alone is
    /// shared by every helper-run session on the machine, so matching the
    /// caller's UID too keeps one user's rules from capturing another user's
    /// agent traffic.
    UserAndGroup(u32, u32),
}

impl SocketOwner {
    pub fn clause(self) -> String {
        match self {
            Self::User(uid) => format!("user {uid}"),
            Self::UserAndGroup(uid, gid) => format!("user {uid} group {gid}"),
        }
    }

    pub fn description(self) -> String {
        match self {
            Self::User(uid) => format!("uid {uid}"),
            Self::UserAndGroup(uid, gid) => format!("uid {uid} gid {gid}"),
        }
    }
}

impl PFRuleSet {
    pub fn new_user(
        interface_name: impl Into<String>,
        uid: u32,
        route_ipv4_gateway: Option<String>,
    ) -> Self {
        Self {
            interface_name: interface_name.into(),
            anchor_key: uid,
            socket_owner: SocketOwner::User(uid),
            route_ipv4_gateway,
        }
    }

    pub fn new_group(
        interface_name: impl Into<String>,
        anchor_uid: u32,
        gid: u32,
        route_ipv4_gateway: Option<String>,
    ) -> Self {
        Self {
            interface_name: interface_name.into(),
            anchor_key: anchor_uid,
            socket_owner: SocketOwner::UserAndGroup(anchor_uid, gid),
            route_ipv4_gateway,
        }
    }

    pub fn anchor_name(&self) -> String {
        format!("com.apple/lianyaohu-{}", self.anchor_key)
    }

    pub fn render(&self) -> String {
        let owner = self.socket_owner.clause();
        let route_rule = self.route_ipv4_gateway.as_ref().map_or_else(
            || {
                "# No IPv4 route-to rule: selected utun has no point-to-point IPv4 peer."
                    .to_string()
            },
            |gateway| {
                format!(
                    "pass out quick on ! {} route-to ({} {}) inet proto {{ tcp udp }} from any to any {} keep state",
                    self.interface_name, self.interface_name, gateway, owner
                )
            },
        );

        format!(
            r#"# LianYaoHu agent network guard.
# Scope: TCP/UDP sockets owned by {owner_description}.
# Raw/route/system sockets are denied by the process sandbox profile.

lianyaohu_lan4 = "{{ 0.0.0.0/8, 10.0.0.0/8, 100.64.0.0/10, 169.254.0.0/16, 172.16.0.0/12, 192.168.0.0/16, 224.0.0.0/4, 240.0.0.0/4 }}"
lianyaohu_lan6 = "{{ ::/128, fe80::/10, fc00::/7, ff00::/8 }}"

pass out quick on lo0 proto {{ tcp udp }} from any to any {owner} keep state

block return out quick proto {{ tcp udp }} from any to $lianyaohu_lan4 {owner}
block return out quick inet6 proto {{ tcp udp }} from any to $lianyaohu_lan6 {owner}

{route_rule}
block return out quick on ! {interface_name} proto {{ tcp udp }} from any to any {owner}
pass out quick on {interface_name} proto {{ tcp udp }} from any to any {owner} keep state
"#,
            owner_description = self.socket_owner.description(),
            owner = owner,
            interface_name = self.interface_name
        )
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Backend {
    Helper,
    Sudo,
}

pub struct PFGuard {
    rule_set: PFRuleSet,
    enable_token: Option<String>,
    backend: Option<Backend>,
    installed: bool,
    rules_path: Option<std::path::PathBuf>,
}

impl PFGuard {
    pub fn new(rule_set: PFRuleSet) -> Self {
        Self {
            rule_set,
            enable_token: None,
            backend: None,
            installed: false,
            rules_path: None,
        }
    }

    pub fn install(&mut self) -> Result<()> {
        match PFHelperClient::default().install(&self.rule_set.interface_name) {
            Ok(()) => {
                self.backend = Some(Backend::Helper);
                self.installed = true;
                return Ok(());
            }
            Err(error) if helper_unavailable(error.as_ref()) => {}
            Err(error) => return Err(err(format!("PF helper refused request: {error}"))),
        }

        let dir = std::env::temp_dir().join("lianyaohu-pf");
        fs::create_dir_all(&dir)?;
        let rules_path = dir.join(format!(
            "rules-{}-{}.pf",
            self.rule_set.anchor_key, self.rule_set.interface_name
        ));
        fs::write(&rules_path, self.rule_set.render())?;
        self.rules_path = Some(rules_path.clone());

        // Validate the ruleset before touching PF's enable state, mirroring the
        // helper path, so a malformed ruleset can't leave PF toggled on.
        run_sudo_pf(&["-n", "-f", &rules_path.to_string_lossy()])?;

        let enable_output = run_sudo_pf(&["-E"])?;
        let token = parse_enable_token(&enable_output);
        if let Err(error) = run_sudo_pf(&[
            "-a",
            &self.rule_set.anchor_name(),
            "-f",
            &rules_path.to_string_lossy(),
        ]) {
            if let Some(token) = &token {
                let _ = run_sudo_pf(&["-X", token]);
            }
            let _ = fs::remove_file(&rules_path);
            self.rules_path = None;
            return Err(error);
        }

        self.enable_token = token;
        self.backend = Some(Backend::Sudo);
        self.installed = true;
        Ok(())
    }

    pub fn uninstall(&mut self) {
        if !self.installed {
            return;
        }

        match self.backend {
            Some(Backend::Helper) => {
                let _ = PFHelperClient::default().uninstall();
            }
            Some(Backend::Sudo) => {
                let _ = run_sudo_pf(&["-a", &self.rule_set.anchor_name(), "-F", "rules"]);
                if let Some(token) = &self.enable_token {
                    let _ = run_sudo_pf(&["-X", token]);
                }
            }
            None => {}
        }

        if let Some(rules_path) = self.rules_path.take() {
            let _ = fs::remove_file(rules_path);
        }

        self.installed = false;
        self.backend = None;
    }
}

impl Drop for PFGuard {
    fn drop(&mut self) {
        self.uninstall();
    }
}

pub fn parse_enable_token(output: &str) -> Option<String> {
    output
        .split_whitespace()
        .last()
        .filter(|token| token.chars().all(|ch| ch.is_ascii_digit()))
        .map(ToString::to_string)
}

fn helper_unavailable(error: &(dyn std::error::Error + Send + Sync + 'static)) -> bool {
    if let Some(io_error) = error.downcast_ref::<io::Error>() {
        return matches!(
            io_error.kind(),
            io::ErrorKind::NotFound | io::ErrorKind::ConnectionRefused
        );
    }
    false
}

fn run_sudo_pf(args: &[&str]) -> Result<String> {
    let output = Command::new("/usr/bin/sudo")
        .arg("/sbin/pfctl")
        .args(args)
        .output()?;
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    if output.status.success() {
        Ok(combined)
    } else {
        Err(err(format!("pfctl failed: {}", combined.trim())))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_rules_block_lan_and_non_selected_interfaces() {
        let rules =
            PFRuleSet::new_group("utun4", 501, 2_000_000, Some("10.9.0.1".to_string())).render();

        // Session rules must match the caller's UID as well as the shared
        // session GID; a group-only match would let one user's rules capture
        // another user's agent traffic.
        assert!(rules.contains(
            "pass out quick on lo0 proto { tcp udp } from any to any user 501 group 2000000 keep state"
        ));
        assert!(rules.contains("10.0.0.0/8"));
        assert!(rules.contains("172.16.0.0/12"));
        assert!(rules.contains("192.168.0.0/16"));
        assert!(rules.contains("fc00::/7"));
        assert!(rules.contains("to $lianyaohu_lan4 user 501 group 2000000"));
        assert!(rules.contains("to $lianyaohu_lan6 user 501 group 2000000"));
        assert!(rules.contains("pass out quick on ! utun4 route-to (utun4 10.9.0.1) inet proto { tcp udp } from any to any user 501 group 2000000 keep state"));
        assert!(rules.contains(
            "block return out quick on ! utun4 proto { tcp udp } from any to any user 501 group 2000000"
        ));
        assert!(rules.contains(
            "pass out quick on utun4 proto { tcp udp } from any to any user 501 group 2000000 keep state"
        ));
        assert!(rules.contains("# Scope: TCP/UDP sockets owned by uid 501 gid 2000000."));
    }

    #[test]
    fn generated_rules_can_scope_to_user_for_fallback() {
        let rules = PFRuleSet::new_user("utun4", 501, Some("10.9.0.1".to_string())).render();

        assert!(rules.contains("# Scope: TCP/UDP sockets owned by uid 501."));
        assert!(rules.contains(
            "pass out quick on lo0 proto { tcp udp } from any to any user 501 keep state"
        ));
        assert!(rules.contains("to $lianyaohu_lan4 user 501"));
    }

    #[test]
    fn generated_rules_can_omit_route_to_when_no_peer_exists() {
        let rules = PFRuleSet::new_group("utun4", 501, 2_000_000, None).render();

        assert!(rules.contains("No IPv4 route-to rule"));
        assert!(!rules.contains("route-to (utun4"));
    }

    #[test]
    fn parses_pf_enable_token() {
        assert_eq!(
            parse_enable_token("Token : 12345\n").as_deref(),
            Some("12345")
        );
        assert_eq!(parse_enable_token("pf enabled\n"), None);
    }
}
