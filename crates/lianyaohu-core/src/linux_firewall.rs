use crate::policy::{DestRule, IpNetwork, LAN4_BLOCKED, LAN6_BLOCKED, NetAction, NetworkPolicy};
use crate::{Result, err};
use std::path::Path;
use std::process::Command;

pub const LIANYAOHU_GROUP_NAME: &str = "_lianyaohu";
pub const LIANYAOHU_GROUP_GID: u32 = 2_000_000;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LinuxFirewallRuleSet {
    pub interface_name: String,
    pub anchor_key: u32,
    pub socket_owner: LinuxSocketOwner,
    pub network: NetworkPolicy,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LinuxSocketOwner {
    User(u32),
    /// Match both the socket's UID and its GID. The session GID alone is
    /// shared by every helper-run session on the machine, so matching the
    /// caller's UID too keeps one user's rules from capturing another user's
    /// agent traffic.
    UserAndGroup(u32, u32),
}

impl LinuxSocketOwner {
    pub fn clause(self) -> Vec<(&'static str, String)> {
        match self {
            Self::User(uid) => vec![("--uid-owner", uid.to_string())],
            Self::UserAndGroup(uid, gid) => vec![
                ("--uid-owner", uid.to_string()),
                ("--gid-owner", gid.to_string()),
            ],
        }
    }

    pub fn description(self) -> String {
        match self {
            Self::User(uid) => format!("uid {uid}"),
            Self::UserAndGroup(uid, gid) => format!("uid {uid} gid {gid}"),
        }
    }
}

impl LinuxFirewallRuleSet {
    pub fn new_user(interface_name: impl Into<String>, uid: u32) -> Self {
        Self {
            interface_name: interface_name.into(),
            anchor_key: uid,
            socket_owner: LinuxSocketOwner::User(uid),
            network: NetworkPolicy::default(),
        }
    }

    pub fn new_group(interface_name: impl Into<String>, anchor_uid: u32, gid: u32) -> Self {
        Self {
            interface_name: interface_name.into(),
            anchor_key: anchor_uid,
            socket_owner: LinuxSocketOwner::UserAndGroup(anchor_uid, gid),
            network: NetworkPolicy::default(),
        }
    }

    pub fn with_network(mut self, network: NetworkPolicy) -> Self {
        self.network = network;
        self
    }

    pub fn chain_name(&self) -> String {
        format!("LYH-{}", self.anchor_key)
    }

    pub fn render(&self) -> String {
        let mut lines = vec![
            "# LianYaoHu Linux network guard.".to_string(),
            format!(
                "# Scope: packets owned by {}.",
                self.socket_owner.description()
            ),
        ];
        for family in [IpFamily::V4, IpFamily::V6] {
            for command in self.setup_commands(family) {
                lines.push(format!("{} {}", family.program_name(), command.join(" ")));
            }
        }
        lines.join("\n") + "\n"
    }

    fn owner_match_args(&self) -> Vec<String> {
        let mut args = vec!["-m".to_string(), "owner".to_string()];
        for (flag, value) in self.socket_owner.clause() {
            args.push(flag.to_string());
            args.push(value);
        }
        args
    }

    fn setup_commands(&self, family: IpFamily) -> Vec<Vec<String>> {
        let chain = self.chain_name();
        let lan_blocked: &[IpNetwork] = match family {
            IpFamily::V4 => &LAN4_BLOCKED,
            IpFamily::V6 => &LAN6_BLOCKED,
        };
        let family_rules = |rules: &[DestRule]| -> Vec<DestRule> {
            rules
                .iter()
                .filter(|rule| rule.net.is_ipv4() == matches!(family, IpFamily::V4))
                .cloned()
                .collect()
        };

        let args =
            |parts: &[&str]| -> Vec<String> { parts.iter().map(ToString::to_string).collect() };

        let mut commands = vec![
            args(&["-w", "-N", &chain]),
            args(&["-w", "-F", &chain]),
            args(&["-w", "-A", &chain, "-o", "lo", "-j", "RETURN"]),
        ];
        // Rule order inside the chain is first-match-wins: LAN exceptions
        // must precede the LAN REJECTs, and user denies must precede any
        // RETURN that could match the same destination.
        for rule in family_rules(&self.network.lan_allow) {
            commands.extend(self.destination_commands(&chain, &rule, None, "RETURN"));
        }
        for lan in lan_blocked {
            commands.push(args(&[
                "-w",
                "-A",
                &chain,
                "-d",
                &lan.cidr(),
                "-j",
                "REJECT",
            ]));
        }
        for rule in family_rules(&self.network.deny) {
            commands.extend(self.destination_commands(&chain, &rule, None, "REJECT"));
        }
        match self.network.default_action {
            NetAction::Allow => {
                commands.push(args(&[
                    "-w",
                    "-A",
                    &chain,
                    "-o",
                    &self.interface_name,
                    "-j",
                    "RETURN",
                ]));
            }
            NetAction::Deny => {
                // Only allow-listed destinations may leave, and only on the
                // selected interface; everything else falls through to the
                // terminal REJECT.
                for rule in family_rules(&self.network.allow) {
                    commands.extend(self.destination_commands(
                        &chain,
                        &rule,
                        Some(&self.interface_name),
                        "RETURN",
                    ));
                }
            }
        }
        commands.push(args(&["-w", "-A", &chain, "-j", "REJECT"]));

        let mut jump = vec![
            "-w".to_string(),
            "-I".to_string(),
            "OUTPUT".to_string(),
            "1".to_string(),
        ];
        jump.extend(self.owner_match_args());
        jump.extend(["-j".to_string(), chain]);
        commands.push(jump);

        commands
    }

    /// Builds the `-A` command(s) for one typed destination rule. Rules with a
    /// port spec expand to a tcp and a udp command because `--dport` requires
    /// a protocol match. Arguments stay argv vectors end to end — no shell —
    /// and only `Display` of typed values reaches them.
    fn destination_commands(
        &self,
        chain: &str,
        rule: &DestRule,
        out_interface: Option<&str>,
        target: &str,
    ) -> Vec<Vec<String>> {
        let mut base = vec!["-w".to_string(), "-A".to_string(), chain.to_string()];
        if let Some(interface) = out_interface {
            base.extend(["-o".to_string(), interface.to_string()]);
        }
        base.extend(["-d".to_string(), rule.net.cidr()]);
        match rule.port_spec() {
            None => {
                base.extend(["-j".to_string(), target.to_string()]);
                vec![base]
            }
            Some(spec) => ["tcp", "udp"]
                .into_iter()
                .map(|proto| {
                    let mut command = base.clone();
                    command.extend([
                        "-p".to_string(),
                        proto.to_string(),
                        "--dport".to_string(),
                        spec.clone(),
                        "-j".to_string(),
                        target.to_string(),
                    ]);
                    command
                })
                .collect(),
        }
    }

    fn cleanup_commands(&self) -> Vec<(IpFamily, Vec<String>)> {
        let chain = self.chain_name();
        let mut delete_jump = vec!["-w".to_string(), "-D".to_string(), "OUTPUT".to_string()];
        delete_jump.extend(self.owner_match_args());
        delete_jump.extend(["-j".to_string(), chain.clone()]);
        [IpFamily::V4, IpFamily::V6]
            .into_iter()
            .flat_map(|family| {
                [
                    delete_jump.clone(),
                    vec!["-w".to_string(), "-F".to_string(), chain.clone()],
                    vec!["-w".to_string(), "-X".to_string(), chain.clone()],
                ]
                .into_iter()
                .map(move |command| (family, command))
            })
            .collect()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum IpFamily {
    V4,
    V6,
}

impl IpFamily {
    fn program_name(self) -> &'static str {
        match self {
            Self::V4 => "iptables",
            Self::V6 => "ip6tables",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Privilege {
    Root,
    Sudo,
}

pub struct LinuxFirewallGuard {
    rule_set: LinuxFirewallRuleSet,
    privilege: Privilege,
    installed: bool,
}

impl LinuxFirewallGuard {
    pub fn new(rule_set: LinuxFirewallRuleSet) -> Self {
        Self {
            rule_set,
            privilege: Privilege::Sudo,
            installed: false,
        }
    }

    pub fn new_root(rule_set: LinuxFirewallRuleSet) -> Self {
        Self {
            rule_set,
            privilege: Privilege::Root,
            installed: false,
        }
    }

    pub fn install(&mut self) -> Result<()> {
        self.cleanup();
        for family in [IpFamily::V4, IpFamily::V6] {
            for command in self.rule_set.setup_commands(family) {
                if let Err(error) = run_firewall_command(self.privilege, family, &command) {
                    self.cleanup();
                    return Err(error);
                }
            }
        }
        self.installed = true;
        Ok(())
    }

    pub fn uninstall(&mut self) {
        self.cleanup();
        self.installed = false;
    }

    fn cleanup(&mut self) {
        for (family, command) in self.rule_set.cleanup_commands() {
            let _ = run_firewall_command(self.privilege, family, &command);
        }
    }

    pub fn disarm(&mut self) {
        self.installed = false;
    }
}

impl Drop for LinuxFirewallGuard {
    fn drop(&mut self) {
        if self.installed {
            self.uninstall();
        }
    }
}

/// Remove `LYH-*` chains and their OUTPUT jumps left behind by a helper that
/// exited uncleanly (SIGKILL, crash, systemd restart): the session map lives
/// in memory, so a restarted helper would otherwise never reap rules whose
/// sessions no longer exist. Must run as root, before the daemon starts
/// serving, while no live session owns any chain.
pub fn reap_stale_chains() {
    for family in [IpFamily::V4, IpFamily::V6] {
        let listing = match run_firewall_command(
            Privilege::Root,
            family,
            &["-w".to_string(), "-S".to_string()],
        ) {
            Ok(listing) => listing,
            // ip6tables may be missing entirely; nothing to reap there.
            Err(_) => continue,
        };
        let (jumps, chains) = parse_stale_chain_listing(&listing);
        for jump in jumps {
            let mut command = vec!["-w".to_string(), "-D".to_string()];
            command.extend(jump);
            let _ = run_firewall_command(Privilege::Root, family, &command);
        }
        for chain in chains {
            let _ = run_firewall_command(
                Privilege::Root,
                family,
                &["-w".to_string(), "-F".to_string(), chain.clone()],
            );
            let _ = run_firewall_command(
                Privilege::Root,
                family,
                &["-w".to_string(), "-X".to_string(), chain],
            );
        }
    }
}

/// Parse `iptables -S` output into the jump rules targeting `LYH-*` chains
/// (as replayable argument lists, minus the `-A`) and the `LYH-*` chain names.
fn parse_stale_chain_listing(listing: &str) -> (Vec<Vec<String>>, Vec<String>) {
    let mut jumps = Vec::new();
    let mut chains = Vec::new();
    for line in listing.lines() {
        let tokens = line.split_whitespace().collect::<Vec<_>>();
        match tokens.as_slice() {
            ["-N", chain] if chain.starts_with("LYH-") => chains.push((*chain).to_string()),
            ["-A", rest @ ..] => {
                let targets_lyh_chain = rest.len() >= 2
                    && rest[rest.len() - 2] == "-j"
                    && rest[rest.len() - 1].starts_with("LYH-");
                if targets_lyh_chain {
                    jumps.push(tokens[1..].iter().map(ToString::to_string).collect());
                }
            }
            _ => {}
        }
    }
    (jumps, chains)
}

fn run_firewall_command(privilege: Privilege, family: IpFamily, args: &[String]) -> Result<String> {
    let program = firewall_program(family);
    let output = match privilege {
        Privilege::Root => Command::new(program).args(args).output()?,
        Privilege::Sudo => Command::new("/usr/bin/sudo")
            .arg(program)
            .args(args)
            .output()?,
    };
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    if output.status.success() {
        Ok(combined)
    } else {
        Err(err(format!(
            "{} {} failed: {}",
            family.program_name(),
            args.join(" "),
            combined.trim()
        )))
    }
}

fn firewall_program(family: IpFamily) -> &'static str {
    match family {
        IpFamily::V4 => {
            if Path::new("/usr/sbin/iptables").exists() {
                "/usr/sbin/iptables"
            } else if Path::new("/sbin/iptables").exists() {
                "/sbin/iptables"
            } else {
                "iptables"
            }
        }
        IpFamily::V6 => {
            if Path::new("/usr/sbin/ip6tables").exists() {
                "/usr/sbin/ip6tables"
            } else if Path::new("/sbin/ip6tables").exists() {
                "/sbin/ip6tables"
            } else {
                "ip6tables"
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_rules_block_lan_and_non_selected_interfaces() {
        let rules = LinuxFirewallRuleSet::new_group("tun0", 1000, 2_000_000).render();

        // Session rules must match the caller's UID as well as the shared
        // session GID; a group-only match would let one user's rules capture
        // another user's agent traffic.
        assert!(rules.contains("# Scope: packets owned by uid 1000 gid 2000000."));
        assert!(rules.contains("iptables -w -A LYH-1000 -o lo -j RETURN"));
        assert!(rules.contains("iptables -w -A LYH-1000 -d 10.0.0.0/8 -j REJECT"));
        assert!(rules.contains("iptables -w -A LYH-1000 -o tun0 -j RETURN"));
        assert!(rules.contains("iptables -w -A LYH-1000 -j REJECT"));
        assert!(rules.contains(
            "iptables -w -I OUTPUT 1 -m owner --uid-owner 1000 --gid-owner 2000000 -j LYH-1000"
        ));
        assert!(rules.contains("ip6tables -w -A LYH-1000 -d fc00::/7 -j REJECT"));
    }

    #[test]
    fn stale_chain_listing_parses_jumps_and_chains() {
        let listing = "\
-P OUTPUT ACCEPT
-N DOCKER-USER
-N LYH-1000
-N LYH-1001
-A OUTPUT -m owner --uid-owner 1000 --gid-owner 2000000 -j LYH-1000
-A OUTPUT -m owner --uid-owner 1001 -j LYH-1001
-A OUTPUT -j DOCKER-USER
-A LYH-1000 -o lo -j RETURN
-A LYH-1000 -d 10.0.0.0/8 -j REJECT
";

        let (jumps, chains) = parse_stale_chain_listing(listing);

        assert_eq!(chains, vec!["LYH-1000".to_string(), "LYH-1001".to_string()]);
        assert_eq!(
            jumps,
            vec![
                vec![
                    "OUTPUT".to_string(),
                    "-m".to_string(),
                    "owner".to_string(),
                    "--uid-owner".to_string(),
                    "1000".to_string(),
                    "--gid-owner".to_string(),
                    "2000000".to_string(),
                    "-j".to_string(),
                    "LYH-1000".to_string(),
                ],
                vec![
                    "OUTPUT".to_string(),
                    "-m".to_string(),
                    "owner".to_string(),
                    "--uid-owner".to_string(),
                    "1001".to_string(),
                    "-j".to_string(),
                    "LYH-1001".to_string(),
                ],
            ]
        );
    }

    #[test]
    fn generated_rules_can_scope_to_user_for_fallback() {
        let rules = LinuxFirewallRuleSet::new_user("wg0", 1000).render();

        assert!(rules.contains("# Scope: packets owned by uid 1000."));
        assert!(rules.contains("iptables -w -I OUTPUT 1 -m owner --uid-owner 1000 -j LYH-1000"));
        assert!(rules.contains("iptables -w -A LYH-1000 -o wg0 -j RETURN"));
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
    fn lan_exceptions_precede_lan_blocks_and_denies_precede_interface_return() {
        let rules = LinuxFirewallRuleSet::new_group("tun0", 1000, 2_000_000)
            .with_network(policy(&[
                ("lan_allow", "192.168.1.10:22"),
                ("deny", "169.254.169.254"),
            ]))
            .render();

        let lan_allow_tcp =
            "iptables -w -A LYH-1000 -d 192.168.1.10/32 -p tcp --dport 22 -j RETURN";
        let lan_allow_udp =
            "iptables -w -A LYH-1000 -d 192.168.1.10/32 -p udp --dport 22 -j RETURN";
        let lan_block = "iptables -w -A LYH-1000 -d 192.168.0.0/16 -j REJECT";
        let deny = "iptables -w -A LYH-1000 -d 169.254.169.254/32 -j REJECT";
        let interface_return = "iptables -w -A LYH-1000 -o tun0 -j RETURN";
        for line in [
            lan_allow_tcp,
            lan_allow_udp,
            lan_block,
            deny,
            interface_return,
        ] {
            assert!(rules.contains(line), "missing: {line}\n{rules}");
        }
        // First-match-wins ordering inside the chain.
        assert!(rules.find(lan_allow_tcp).unwrap() < rules.find(lan_block).unwrap());
        assert!(rules.find(lan_block).unwrap() < rules.find(deny).unwrap());
        assert!(rules.find(deny).unwrap() < rules.find(interface_return).unwrap());
        // The LAN-block REJECT for 169.254.0.0/16 also precedes the deny; the
        // specific deny entry still renders for non-LAN metadata addresses.
    }

    #[test]
    fn default_deny_mode_scopes_returns_to_allow_list() {
        let mut network = policy(&[("allow", "140.82.112.0/20:443"), ("allow", "1.1.1.1")]);
        network.default_action = NetAction::Deny;
        let rules = LinuxFirewallRuleSet::new_group("tun0", 1000, 2_000_000)
            .with_network(network)
            .render();

        // No blanket interface RETURN in deny mode.
        assert!(!rules.contains("iptables -w -A LYH-1000 -o tun0 -j RETURN\n"));
        assert!(rules.contains(
            "iptables -w -A LYH-1000 -o tun0 -d 140.82.112.0/20 -p tcp --dport 443 -j RETURN"
        ));
        assert!(rules.contains(
            "iptables -w -A LYH-1000 -o tun0 -d 140.82.112.0/20 -p udp --dport 443 -j RETURN"
        ));
        assert!(rules.contains("iptables -w -A LYH-1000 -o tun0 -d 1.1.1.1/32 -j RETURN"));
        // Terminal REJECT still closes the chain.
        assert!(rules.contains("iptables -w -A LYH-1000 -j REJECT"));
    }

    #[test]
    fn rules_route_to_matching_family_program() {
        let rules = LinuxFirewallRuleSet::new_group("tun0", 1000, 2_000_000)
            .with_network(policy(&[
                ("deny", "10.99.0.0/16:8000-8100"),
                ("deny", "[2001:db8::]/32:443"),
            ]))
            .render();

        assert!(rules.contains(
            "iptables -w -A LYH-1000 -d 10.99.0.0/16 -p tcp --dport 8000:8100 -j REJECT"
        ));
        assert!(
            rules
                .contains("ip6tables -w -A LYH-1000 -d 2001:db8::/32 -p tcp --dport 443 -j REJECT")
        );
        // v4 rules never reach ip6tables and vice versa.
        assert!(!rules.contains("ip6tables -w -A LYH-1000 -d 10.99.0.0/16"));
        assert!(!rules.contains("iptables -w -A LYH-1000 -d 2001:db8::/32"));
    }

    #[test]
    fn default_network_policy_renders_identically_to_legacy() {
        let plain = LinuxFirewallRuleSet::new_group("tun0", 1000, 2_000_000).render();
        let with_default = LinuxFirewallRuleSet::new_group("tun0", 1000, 2_000_000)
            .with_network(NetworkPolicy::default())
            .render();
        assert_eq!(plain, with_default);
        assert!(!plain.contains("--dport"));
    }
}
