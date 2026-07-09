use crate::{Result, err};
use std::path::Path;
use std::process::Command;

pub const LIANYAOHU_GROUP_NAME: &str = "_lianyaohu";
pub const LIANYAOHU_GROUP_GID: u32 = 2_000_000;

const LAN4_CIDRS: &[&str] = &[
    "0.0.0.0/8",
    "10.0.0.0/8",
    "100.64.0.0/10",
    "169.254.0.0/16",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "224.0.0.0/4",
    "240.0.0.0/4",
];

const LAN6_CIDRS: &[&str] = &["::/128", "fe80::/10", "fc00::/7", "ff00::/8"];

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LinuxFirewallRuleSet {
    pub interface_name: String,
    pub anchor_key: u32,
    pub socket_owner: LinuxSocketOwner,
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
        }
    }

    pub fn new_group(interface_name: impl Into<String>, anchor_uid: u32, gid: u32) -> Self {
        Self {
            interface_name: interface_name.into(),
            anchor_key: anchor_uid,
            socket_owner: LinuxSocketOwner::UserAndGroup(anchor_uid, gid),
        }
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
        let mut commands = Vec::new();
        let chain = self.chain_name();
        let cidrs = match family {
            IpFamily::V4 => LAN4_CIDRS,
            IpFamily::V6 => LAN6_CIDRS,
        };

        commands.push(vec!["-w", "-N", &chain]);
        commands.push(vec!["-w", "-F", &chain]);
        commands.push(vec!["-w", "-A", &chain, "-o", "lo", "-j", "RETURN"]);
        for cidr in cidrs {
            commands.push(vec!["-w", "-A", &chain, "-d", cidr, "-j", "REJECT"]);
        }
        commands.push(vec![
            "-w",
            "-A",
            &chain,
            "-o",
            &self.interface_name,
            "-j",
            "RETURN",
        ]);
        commands.push(vec!["-w", "-A", &chain, "-j", "REJECT"]);

        let mut commands = commands
            .into_iter()
            .map(|command| {
                command
                    .into_iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();

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
}
