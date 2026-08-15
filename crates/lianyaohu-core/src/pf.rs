use crate::helper::PFHelperClient;
use crate::policy::{DestRule, IpNetwork, LAN4_BLOCKED, LAN6_BLOCKED, NetAction, NetworkPolicy};
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
    pub network: NetworkPolicy,
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
            network: NetworkPolicy::default(),
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
            network: NetworkPolicy::default(),
        }
    }

    pub fn with_network(mut self, network: NetworkPolicy) -> Self {
        self.network = network;
        self
    }

    pub fn anchor_name(&self) -> String {
        // User- and group-scoped rule sets must never share an anchor: the
        // sudo fallback loads and flushes its anchor wholesale, and with a
        // shared name that would replace or strip a live helper session's
        // group-scoped rules. Both names stay under `com.apple/lianyaohu-`
        // so the helper's stale-anchor reaper covers them.
        match self.socket_owner {
            SocketOwner::User(_) => format!("com.apple/lianyaohu-user-{}", self.anchor_key),
            SocketOwner::UserAndGroup(..) => format!("com.apple/lianyaohu-{}", self.anchor_key),
        }
    }

    /// Proxy-only mode: no VPN interface at all; only loopback egress (the
    /// local proxy) may pass.
    pub fn is_proxy_only(&self) -> bool {
        self.interface_name == crate::interfaces::PROXY_ONLY_INTERFACE
    }

    /// True for the current-UID fallback scope (`install`); false for the
    /// group-scoped rules a helper `run` session installs.
    pub fn is_user_scoped(&self) -> bool {
        matches!(self.socket_owner, SocketOwner::User(_))
    }

    pub fn render(&self) -> String {
        let owner = self.socket_owner.clause();
        let lan4 = LAN4_BLOCKED
            .iter()
            .map(IpNetwork::cidr)
            .collect::<Vec<_>>()
            .join(", ");
        let lan6 = LAN6_BLOCKED
            .iter()
            .map(IpNetwork::cidr)
            .collect::<Vec<_>>()
            .join(", ");
        let lan_allow_section = self.lan_allow_section(&owner);
        let deny_section = self.deny_section(&owner);
        let tail_section = self.tail_section(&owner);

        // Every rule uses `quick`, so pf is first-match-wins here: LAN
        // exceptions must precede the LAN blocks, and user denies must precede
        // every pass that could match the same destination.
        format!(
            r#"# LianYaoHu agent network guard.
# Scope: TCP/UDP sockets owned by {owner_description}.
# Raw/route/system sockets are denied by the process sandbox profile.

lianyaohu_lan4 = "{{ {lan4} }}"
lianyaohu_lan6 = "{{ {lan6} }}"

pass out quick on lo0 proto {{ tcp udp }} from any to any {owner} keep state

{lan_allow_section}block return out quick proto {{ tcp udp }} from any to $lianyaohu_lan4 {owner}
block return out quick inet6 proto {{ tcp udp }} from any to $lianyaohu_lan6 {owner}

{deny_section}{tail_section}"#,
            owner_description = self.socket_owner.description(),
            owner = owner,
        )
    }

    /// LAN exceptions rendered ahead of the LAN blocks. Empty for the default
    /// policy so the rendered rules stay byte-identical to the historical
    /// output.
    fn lan_allow_section(&self, owner: &str) -> String {
        // Proxy-only mode is strict: nothing but loopback leaves, so LAN
        // exceptions configured for VPN launches do not apply.
        if self.network.lan_allow.is_empty() || self.is_proxy_only() {
            return String::new();
        }
        let mut out = String::from(
            "# LAN exceptions from the user policy; they must precede the LAN blocks.\n",
        );
        for rule in &self.network.lan_allow {
            out.push_str(&format!(
                "pass out quick {} {owner} keep state\n",
                destination_clause(rule)
            ));
        }
        out.push('\n');
        out
    }

    /// User deny rules, after the LAN blocks and before any pass rule that
    /// could match the same destination.
    fn deny_section(&self, owner: &str) -> String {
        if self.network.deny.is_empty() {
            return String::new();
        }
        let mut out = String::from("# Denied destinations from the user policy.\n");
        for rule in &self.network.deny {
            out.push_str(&format!(
                "block return out quick {} {owner}\n",
                destination_clause(rule)
            ));
        }
        out.push('\n');
        out
    }

    /// The final interface-restriction rules. In default-allow mode this is
    /// the historical route-to / block / pass tail; in default-deny mode only
    /// allow-listed destinations may leave, and only on the selected
    /// interface.
    fn tail_section(&self, owner: &str) -> String {
        if self.is_proxy_only() {
            return format!(
                "# Proxy-only mode: no VPN interface. Only the loopback pass above\n\
                 # (the local proxy) lets traffic out; everything else is blocked.\n\
                 block return out quick proto {{ tcp udp }} from any to any {owner}\n"
            );
        }
        match self.network.default_action {
            NetAction::Allow => {
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
                    "{route_rule}\nblock return out quick on ! {iface} proto {{ tcp udp }} from any to any {owner}\npass out quick on {iface} proto {{ tcp udp }} from any to any {owner} keep state\n",
                    iface = self.interface_name
                )
            }
            NetAction::Deny => {
                let mut out = String::from(
                    "# Default-deny mode: only allow-listed destinations may leave, and only\n# on the selected interface.\n",
                );
                for rule in &self.network.allow {
                    out.push_str(&format!(
                        "pass out quick on {} {} {owner} keep state\n",
                        self.interface_name,
                        destination_clause(rule)
                    ));
                    if rule.net.is_ipv4()
                        && let Some(gateway) = &self.route_ipv4_gateway
                    {
                        out.push_str(&format!(
                            "pass out quick on ! {iface} route-to ({iface} {gateway}) {clause} {owner} keep state\n",
                            iface = self.interface_name,
                            clause = destination_clause(rule)
                        ));
                    }
                }
                out.push_str(&format!(
                    "block return out quick proto {{ tcp udp }} from any to any {owner}\n"
                ));
                out
            }
        }
    }
}

/// Renders a typed destination as a pf match clause. Only `Display` of typed
/// addresses/prefixes/ports reaches the rule text — the pf config file is
/// parsed by pfctl, so raw user strings must never be interpolated here.
fn destination_clause(rule: &DestRule) -> String {
    let family = if rule.net.is_ipv4() { "inet" } else { "inet6" };
    let mut clause = format!("{family} proto {{ tcp udp }} from any to {}", rule.net);
    if let Some(spec) = rule.port_spec() {
        clause.push_str(&format!(" port {spec}"));
    }
    clause
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
        if self.try_helper_install()? {
            self.backend = Some(Backend::Helper);
            self.installed = true;
            return Ok(());
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

    /// Asks the helper to install this rule set. `Ok(true)` means the helper
    /// holds the rules; `Ok(false)` means the caller must use the sudo
    /// fallback, which renders the full rule set itself. A non-default
    /// network policy is negotiated first: a helper that predates
    /// install-time policies would install the default (weaker) rules and
    /// report success — exactly the silent partial enforcement the run path's
    /// capability probe exists to prevent — so such a helper is skipped in
    /// favor of sudo rather than trusted with the install.
    fn try_helper_install(&self) -> Result<bool> {
        let client = PFHelperClient::default();
        if self.rule_set.network != NetworkPolicy::default() {
            match client.supports_install_policy() {
                Ok(true) => {}
                Ok(false) => {
                    eprintln!(
                        "note: the installed root helper predates install-time network policies; \
                         applying the custom policy through sudo pfctl instead"
                    );
                    return Ok(false);
                }
                Err(error) if helper_unavailable(error.as_ref()) => return Ok(false),
                Err(error) => return Err(err(format!("PF helper refused request: {error}"))),
            }
        }
        match client.install(&self.rule_set.interface_name, &self.rule_set.network) {
            Ok(()) => Ok(true),
            Err(error) if helper_unavailable(error.as_ref()) => Ok(false),
            Err(error) => Err(err(format!("PF helper refused request: {error}"))),
        }
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
    fn proxy_only_rules_allow_loopback_and_block_everything_else() {
        use crate::policy::{DestRule, NetworkPolicy};
        let rules = PFRuleSet::new_group("none", 501, 2_000_000, None)
            .with_network(NetworkPolicy {
                allow: vec![DestRule::parse("1.2.3.4").unwrap()],
                lan_allow: vec![DestRule::parse("192.168.1.10:22").unwrap()],
                ..NetworkPolicy::default()
            })
            .render();

        assert!(rules.contains(
            "pass out quick on lo0 proto { tcp udp } from any to any user 501 group 2000000 keep state"
        ));
        assert!(rules.contains(
            "block return out quick proto { tcp udp } from any to any user 501 group 2000000"
        ));
        // No interface rules, no route-to, and no pass rules for allow or
        // LAN-exception destinations: proxy-only is loopback or nothing.
        assert!(!rules.contains("route-to"));
        assert!(!rules.contains("on none"));
        assert!(!rules.contains("1.2.3.4"));
        assert!(!rules.contains("192.168.1.10"));
        assert!(rules.contains("# Proxy-only mode"));
    }

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

    // Regression test for #58: the sudo fallback loads and flushes its anchor
    // wholesale, so the user-scoped rule set must own an anchor distinct from
    // the helper's group-scoped anchor for the same uid.
    #[test]
    fn user_scope_anchor_is_distinct_from_group_anchor() {
        let user = PFRuleSet::new_user("utun4", 501, None);
        let group = PFRuleSet::new_group("utun4", 501, 2_000_000, None);

        assert_eq!(user.anchor_name(), "com.apple/lianyaohu-user-501");
        assert_eq!(group.anchor_name(), "com.apple/lianyaohu-501");
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

    fn policy(entries: &[(&str, &str)]) -> NetworkPolicy {
        let mut network = NetworkPolicy::default();
        for (list, entry) in entries {
            let rule = DestRule::parse(entry).unwrap();
            match *list {
                "allow" => network.allow.push(rule),
                "deny" => network.deny.push(rule),
                "lan_allow" => network.lan_allow.push(rule),
                other => panic!("unknown list {other}"),
            }
        }
        network
    }

    #[test]
    fn default_network_policy_renders_identically_to_legacy() {
        let plain = PFRuleSet::new_group("utun4", 501, 2_000_000, Some("10.9.0.1".into())).render();
        let with_default = PFRuleSet::new_group("utun4", 501, 2_000_000, Some("10.9.0.1".into()))
            .with_network(NetworkPolicy::default())
            .render();
        assert_eq!(plain, with_default);
        assert!(!plain.contains("user policy"));
        assert!(!plain.contains("Default-deny"));
    }

    #[test]
    fn lan_exceptions_precede_lan_blocks_and_denies_precede_passes() {
        let rules = PFRuleSet::new_group("utun4", 501, 2_000_000, None)
            .with_network(policy(&[
                ("lan_allow", "192.168.1.10:22"),
                ("deny", "1.2.3.0/24:8000-8100"),
                ("deny", "[2001:db8::]/32"),
            ]))
            .render();

        let lan_allow = "pass out quick inet proto { tcp udp } from any to 192.168.1.10 port 22 user 501 group 2000000 keep state";
        let lan_block = "block return out quick proto { tcp udp } from any to $lianyaohu_lan4 user 501 group 2000000";
        let deny4 = "block return out quick inet proto { tcp udp } from any to 1.2.3.0/24 port 8000:8100 user 501 group 2000000";
        let deny6 = "block return out quick inet6 proto { tcp udp } from any to 2001:db8::/32 user 501 group 2000000";
        let pass = "pass out quick on utun4 proto { tcp udp } from any to any user 501 group 2000000 keep state";
        for line in [lan_allow, lan_block, deny4, deny6, pass] {
            assert!(rules.contains(line), "missing: {line}\n{rules}");
        }
        // pf rules here all use `quick`, so first match wins: exceptions
        // before blocks, denies before passes.
        assert!(rules.find(lan_allow).unwrap() < rules.find(lan_block).unwrap());
        assert!(rules.find(lan_block).unwrap() < rules.find(deny4).unwrap());
        assert!(rules.find(deny6).unwrap() < rules.find(pass).unwrap());
    }

    // Regression test for #54: an `install` via the helper must enforce the
    // same rules the sudo fallback renders — a helper-side reconstruction of
    // the wire policy has to produce byte-identical PF rules, custom
    // default-deny/deny/lan_allow entries included.
    #[test]
    fn helper_install_renders_the_same_rules_as_the_sudo_path() {
        use crate::helper::{HelperRequest, install_request, parse_request};

        let mut network = policy(&[
            ("allow", "140.82.112.0/20:443"),
            ("deny", "169.254.169.254"),
            ("lan_allow", "192.168.1.10:22"),
        ]);
        network.default_action = NetAction::Deny;
        let sudo_rules = PFRuleSet::new_user("utun4", 501, Some("10.9.0.1".into()))
            .with_network(network.clone());

        let request = install_request("utun4", &network).unwrap();
        let HelperRequest::Install {
            interface_name,
            network: received,
        } = parse_request(&request).unwrap()
        else {
            panic!("expected an install request");
        };
        let helper_rules = PFRuleSet::new_user(interface_name, 501, Some("10.9.0.1".into()))
            .with_network(received);

        assert_eq!(sudo_rules.render(), helper_rules.render());
    }

    #[test]
    fn default_deny_mode_replaces_blanket_pass() {
        let mut network = policy(&[
            ("allow", "140.82.112.0/20:443"),
            ("allow", "[2606:50c0::]/32"),
        ]);
        network.default_action = NetAction::Deny;
        let rules = PFRuleSet::new_group("utun4", 501, 2_000_000, Some("10.9.0.1".into()))
            .with_network(network)
            .render();

        assert!(!rules.contains(
            "pass out quick on utun4 proto { tcp udp } from any to any user 501 group 2000000 keep state"
        ));
        assert!(rules.contains(
            "pass out quick on utun4 inet proto { tcp udp } from any to 140.82.112.0/20 port 443 user 501 group 2000000 keep state"
        ));
        // v4 allow entries also get a route-to pass when the utun has a
        // point-to-point gateway; v6 entries do not (the gateway is IPv4).
        assert!(rules.contains(
            "pass out quick on ! utun4 route-to (utun4 10.9.0.1) inet proto { tcp udp } from any to 140.82.112.0/20 port 443 user 501 group 2000000 keep state"
        ));
        assert!(rules.contains(
            "pass out quick on utun4 inet6 proto { tcp udp } from any to 2606:50c0::/32 user 501 group 2000000 keep state"
        ));
        assert!(!rules.contains("route-to (utun4 10.9.0.1) inet6"));
        // Terminal block closes the anchor.
        assert!(rules.trim_end().ends_with(
            "block return out quick proto { tcp udp } from any to any user 501 group 2000000"
        ));
    }
}
