//! Typed sandbox policy shared by the launcher client and the root helper.
//!
//! Everything here is parsed into typed values (`IpAddr`, prefix, port) before
//! any rendering happens: PF rules are text fed to `pfctl -f`, so raw
//! user-supplied strings must never reach a rule template. Serialization uses
//! the same canonical string grammar in both TOML config files and the JSON
//! launch spec, and the helper re-validates every field it receives.

use std::fmt;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::str::FromStr;

use serde::de::Error as _;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::{Result, err};

/// Upper bound on entries per rule list; keeps the rendered PF/iptables rule
/// sets (and the launch spec) small even though the spec cap alone would allow
/// far more.
pub const MAX_RULES_PER_LIST: usize = 64;
/// Upper bound on a single rule or path entry, in bytes.
pub const MAX_RULE_LEN: usize = 1024;

/// IPv4 ranges blocked as "LAN" by the network guard on both platforms.
pub const LAN4_BLOCKED: [IpNetwork; 8] = [
    IpNetwork::v4(Ipv4Addr::new(0, 0, 0, 0), 8),
    IpNetwork::v4(Ipv4Addr::new(10, 0, 0, 0), 8),
    IpNetwork::v4(Ipv4Addr::new(100, 64, 0, 0), 10),
    IpNetwork::v4(Ipv4Addr::new(169, 254, 0, 0), 16),
    IpNetwork::v4(Ipv4Addr::new(172, 16, 0, 0), 12),
    IpNetwork::v4(Ipv4Addr::new(192, 168, 0, 0), 16),
    IpNetwork::v4(Ipv4Addr::new(224, 0, 0, 0), 4),
    IpNetwork::v4(Ipv4Addr::new(240, 0, 0, 0), 4),
];

/// IPv6 ranges blocked as "LAN" by the network guard on both platforms.
pub const LAN6_BLOCKED: [IpNetwork; 4] = [
    IpNetwork::v6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 0), 128),
    IpNetwork::v6(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 0), 10),
    IpNetwork::v6(Ipv6Addr::new(0xfc00, 0, 0, 0, 0, 0, 0, 0), 7),
    IpNetwork::v6(Ipv6Addr::new(0xff00, 0, 0, 0, 0, 0, 0, 0), 8),
];

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct SandboxPolicy {
    pub network: NetworkPolicy,
    pub paths: PathPolicy,
}

impl SandboxPolicy {
    /// True when the policy matches the built-in defaults, i.e. rendering it
    /// must produce byte-identical profiles and firewall rules to a build
    /// without any policy support.
    pub fn is_default(&self) -> bool {
        *self == Self::default()
    }

    pub fn validate(&self) -> Result<()> {
        self.network.validate()?;
        self.paths.validate()
    }
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum NetAction {
    #[default]
    Allow,
    Deny,
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct NetworkPolicy {
    pub default_action: NetAction,
    pub allow: Vec<DestRule>,
    pub deny: Vec<DestRule>,
    pub lan_allow: Vec<DestRule>,
}

impl NetworkPolicy {
    pub fn validate(&self) -> Result<()> {
        for (name, list) in [
            ("network.allow", &self.allow),
            ("network.deny", &self.deny),
            ("network.lan_allow", &self.lan_allow),
        ] {
            if list.len() > MAX_RULES_PER_LIST {
                return Err(err(format!(
                    "{name} has {} entries; the maximum is {MAX_RULES_PER_LIST}",
                    list.len()
                )));
            }
        }
        // A lan_allow entry outside the blocked LAN ranges would insert a pass
        // rule ahead of the interface restriction and bypass the VPN-only
        // guarantee entirely, so containment is mandatory.
        for rule in &self.lan_allow {
            let contained = LAN4_BLOCKED
                .iter()
                .chain(LAN6_BLOCKED.iter())
                .any(|lan| lan.contains_network(&rule.net));
            if !contained {
                return Err(err(format!(
                    "network.lan_allow entry {rule} is not within the blocked LAN ranges"
                )));
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct PathPolicy {
    /// Extra writable subpaths (absolute, tilde-expanded by the client).
    pub writable: Vec<String>,
    /// Extra read-only subpaths (absolute, tilde-expanded by the client).
    pub read_only: Vec<String>,
    /// Subpaths the agent must not read or write. Enforced by seatbelt on
    /// macOS; Landlock cannot express deny-inside-allow, so on Linux these are
    /// reported as unenforced.
    pub deny: Vec<String>,
    /// When set, the blanket writable-$HOME grant is replaced by per-entry
    /// grants for `agent_state_dirs` (plus cwd and the launch tmpdir); $HOME
    /// itself stays readable.
    pub narrow_home: bool,
    /// HOME-relative entries kept writable in narrow-home mode.
    pub agent_state_dirs: Vec<String>,
}

impl Default for PathPolicy {
    fn default() -> Self {
        Self {
            writable: Vec::new(),
            read_only: Vec::new(),
            deny: Vec::new(),
            narrow_home: false,
            agent_state_dirs: default_agent_state_dirs(),
        }
    }
}

/// HOME-relative locations agents commonly need writable: agent state, config
/// and cache roots, and package-manager caches.
pub fn default_agent_state_dirs() -> Vec<String> {
    [
        ".claude",
        ".claude.json",
        ".codex",
        ".gemini",
        ".config",
        ".cache",
        ".local",
        ".npm",
    ]
    .into_iter()
    .map(str::to_string)
    .collect()
}

impl PathPolicy {
    pub fn validate(&self) -> Result<()> {
        for (name, list) in [
            ("paths.writable", &self.writable),
            ("paths.read_only", &self.read_only),
            ("paths.deny", &self.deny),
            ("paths.agent_state_dirs", &self.agent_state_dirs),
        ] {
            if list.len() > MAX_RULES_PER_LIST {
                return Err(err(format!(
                    "{name} has {} entries; the maximum is {MAX_RULES_PER_LIST}",
                    list.len()
                )));
            }
            for entry in list {
                if entry.len() > MAX_RULE_LEN {
                    return Err(err(format!(
                        "{name} entry is longer than {MAX_RULE_LEN} bytes"
                    )));
                }
                if entry.contains('\0') {
                    return Err(err(format!("{name} entry contains a NUL byte")));
                }
            }
        }
        for (name, list) in [
            ("paths.writable", &self.writable),
            ("paths.read_only", &self.read_only),
            ("paths.deny", &self.deny),
        ] {
            for entry in list {
                lexically_normalized_absolute(entry)
                    .map_err(|error| err(format!("{name} entry {entry:?}: {error}")))?;
            }
        }
        for entry in &self.agent_state_dirs {
            validate_home_relative(entry)
                .map_err(|error| err(format!("paths.agent_state_dirs entry {entry:?}: {error}")))?;
        }
        Ok(())
    }
}

/// Lexical-only normalization of an absolute path: no filesystem access, so it
/// is safe for paths that do not exist yet (deny targets). Rejects relative
/// paths, `.`/`..` components, and empty components beyond the leading slash.
pub fn lexically_normalized_absolute(path: &str) -> Result<String> {
    if !path.starts_with('/') {
        return Err(err("path is not absolute"));
    }
    let mut components = Vec::new();
    for component in path.split('/').skip(1) {
        match component {
            "" => continue,
            "." | ".." => {
                return Err(err("path must not contain `.` or `..` components"));
            }
            other => components.push(other),
        }
    }
    if components.is_empty() {
        return Err(err("path must not be the filesystem root"));
    }
    Ok(format!("/{}", components.join("/")))
}

fn validate_home_relative(entry: &str) -> Result<()> {
    if entry.is_empty() {
        return Err(err("entry is empty"));
    }
    if entry.starts_with('/') {
        return Err(err("entry must be relative to the home directory"));
    }
    for component in entry.split('/') {
        match component {
            "" => return Err(err("entry contains an empty component")),
            "." | ".." => {
                return Err(err("entry must not contain `.` or `..` components"));
            }
            _ => {}
        }
    }
    Ok(())
}

/// An IPv4 or IPv6 network in canonical form: the address never has host bits
/// set beyond the prefix.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IpNetwork {
    V4 { addr: Ipv4Addr, prefix: u8 },
    V6 { addr: Ipv6Addr, prefix: u8 },
}

impl IpNetwork {
    pub const fn v4(addr: Ipv4Addr, prefix: u8) -> Self {
        Self::V4 { addr, prefix }
    }

    pub const fn v6(addr: Ipv6Addr, prefix: u8) -> Self {
        Self::V6 { addr, prefix }
    }

    pub fn is_ipv4(&self) -> bool {
        matches!(self, Self::V4 { .. })
    }

    pub fn prefix(&self) -> u8 {
        match self {
            Self::V4 { prefix, .. } | Self::V6 { prefix, .. } => *prefix,
        }
    }

    /// Always-explicit `addr/prefix` form, for firewall rule rendering where
    /// a bare address would be ambiguous (e.g. `::/128` vs `::`).
    pub fn cidr(&self) -> String {
        match self {
            Self::V4 { addr, prefix } => format!("{addr}/{prefix}"),
            Self::V6 { addr, prefix } => format!("{addr}/{prefix}"),
        }
    }

    /// True when `other` is fully contained in `self` (same family only).
    pub fn contains_network(&self, other: &IpNetwork) -> bool {
        match (self, other) {
            (Self::V4 { addr, prefix }, Self::V4 { addr: b, prefix: q }) => {
                q >= prefix && mask_v4(*b, *prefix) == *addr
            }
            (Self::V6 { addr, prefix }, Self::V6 { addr: b, prefix: q }) => {
                q >= prefix && mask_v6(*b, *prefix) == *addr
            }
            _ => false,
        }
    }
}

impl fmt::Display for IpNetwork {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::V4 { addr, prefix } if *prefix == 32 => write!(f, "{addr}"),
            Self::V4 { addr, prefix } => write!(f, "{addr}/{prefix}"),
            Self::V6 { addr, prefix } if *prefix == 128 => write!(f, "{addr}"),
            Self::V6 { addr, prefix } => write!(f, "{addr}/{prefix}"),
        }
    }
}

fn mask_v4(addr: Ipv4Addr, prefix: u8) -> Ipv4Addr {
    let mask = if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - u32::from(prefix))
    };
    Ipv4Addr::from(u32::from(addr) & mask)
}

fn mask_v6(addr: Ipv6Addr, prefix: u8) -> Ipv6Addr {
    let mask = if prefix == 0 {
        0
    } else {
        u128::MAX << (128 - u32::from(prefix))
    };
    Ipv6Addr::from(u128::from(addr) & mask)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PortRange {
    pub start: u16,
    pub end: u16,
}

impl fmt::Display for PortRange {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.start == self.end {
            write!(f, "{}", self.start)
        } else {
            write!(f, "{}-{}", self.start, self.end)
        }
    }
}

/// A destination rule: `ADDR[/PREFIX][:PORT[-PORT]]`.
///
/// IPv6 with a port requires brackets around the address, with the optional
/// prefix after the closing bracket: `[2606:50c0::]/32:443`. Note that an
/// unbracketed entry like `::1:443` is a *valid IPv6 address* (`0:0:…:1:443`),
/// not "port 443 on ::1" — the bracket requirement exists precisely because
/// the colon is ambiguous. DNS hostnames are rejected by design — the helper
/// would otherwise resolve untrusted names as root, and name resolution is
/// itself a TOCTOU against the firewall.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DestRule {
    pub net: IpNetwork,
    pub ports: Option<PortRange>,
}

impl DestRule {
    pub fn parse(entry: &str) -> Result<Self> {
        entry.parse()
    }

    /// Port clause spec shared by pf and iptables: `443` or `8000:8100`.
    /// `None` when the rule matches all ports.
    pub fn port_spec(&self) -> Option<String> {
        self.ports.map(|ports| {
            if ports.start == ports.end {
                ports.start.to_string()
            } else {
                format!("{}:{}", ports.start, ports.end)
            }
        })
    }
}

impl fmt::Display for DestRule {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match (&self.net, &self.ports) {
            (net, None) => write!(f, "{net}"),
            (IpNetwork::V4 { .. }, Some(ports)) => write!(f, "{}:{ports}", self.net),
            (IpNetwork::V6 { addr, prefix }, Some(ports)) => {
                if *prefix == 128 {
                    write!(f, "[{addr}]:{ports}")
                } else {
                    write!(f, "[{addr}]/{prefix}:{ports}")
                }
            }
        }
    }
}

impl FromStr for DestRule {
    type Err = crate::Error;

    fn from_str(entry: &str) -> Result<Self> {
        if entry.is_empty() {
            return Err(err("destination rule is empty"));
        }
        if entry.len() > MAX_RULE_LEN {
            return Err(err(format!(
                "destination rule is longer than {MAX_RULE_LEN} bytes"
            )));
        }
        if entry.chars().any(|c| !c.is_ascii_graphic()) {
            return Err(err(format!(
                "destination rule {entry:?} contains whitespace or non-printable characters"
            )));
        }

        if let Some(rest) = entry.strip_prefix('[') {
            // Bracketed IPv6: [addr][/prefix][:ports]
            let (addr_text, tail) = rest
                .split_once(']')
                .ok_or_else(|| err(format!("destination rule {entry:?} has an unclosed `[`")))?;
            let addr: Ipv6Addr = addr_text.parse().map_err(|_| {
                err(format!(
                    "destination rule {entry:?} has an invalid IPv6 address"
                ))
            })?;
            let (prefix_text, ports_text) = split_prefix_and_ports(tail)?;
            let prefix = parse_prefix(prefix_text, 128, entry)?;
            let net = canonical_v6(addr, prefix, entry)?;
            let ports = ports_text
                .map(|text| parse_ports(text, entry))
                .transpose()?;
            return Ok(Self { net, ports });
        }

        // Unbracketed: 0 colons => IPv4; 1 colon => IPv4 with ports;
        // 2+ colons => IPv6 without ports. (IPv4-mapped IPv6 like
        // ::ffff:1.2.3.4 contains at least two colons, so this is unambiguous.)
        match entry.matches(':').count() {
            0 => {
                let (addr_text, prefix_text) = split_slash(entry);
                let addr: Ipv4Addr = addr_text.parse().map_err(|_| {
                    err(format!(
                        "destination rule {entry:?} has an invalid IPv4 address"
                    ))
                })?;
                let prefix = parse_prefix(prefix_text, 32, entry)?;
                let net = canonical_v4(addr, prefix, entry)?;
                Ok(Self { net, ports: None })
            }
            1 => {
                let (head, ports_text) = entry.split_once(':').expect("one colon");
                let (addr_text, prefix_text) = split_slash(head);
                let addr: Ipv4Addr = addr_text.parse().map_err(|_| {
                    err(format!(
                        "destination rule {entry:?} has an invalid IPv4 address"
                    ))
                })?;
                let prefix = parse_prefix(prefix_text, 32, entry)?;
                let net = canonical_v4(addr, prefix, entry)?;
                let ports = Some(parse_ports(ports_text, entry)?);
                Ok(Self { net, ports })
            }
            _ => {
                let (addr_text, prefix_text) = split_slash(entry);
                let addr: Ipv6Addr = addr_text.parse().map_err(|_| {
                    err(format!(
                        "destination rule {entry:?} has an invalid IPv6 address \
                         (use [addr]:port for an IPv6 destination with a port)"
                    ))
                })?;
                let prefix = parse_prefix(prefix_text, 128, entry)?;
                let net = canonical_v6(addr, prefix, entry)?;
                Ok(Self { net, ports: None })
            }
        }
    }
}

fn split_slash(text: &str) -> (&str, Option<&str>) {
    match text.split_once('/') {
        Some((head, tail)) => (head, Some(tail)),
        None => (text, None),
    }
}

/// Splits the text after a bracketed address (`]...`) into optional `/prefix`
/// and optional `:ports` parts.
fn split_prefix_and_ports(tail: &str) -> Result<(Option<&str>, Option<&str>)> {
    if tail.is_empty() {
        return Ok((None, None));
    }
    if let Some(rest) = tail.strip_prefix('/') {
        match rest.split_once(':') {
            Some((prefix, ports)) => Ok((Some(prefix), Some(ports))),
            None => Ok((Some(rest), None)),
        }
    } else if let Some(ports) = tail.strip_prefix(':') {
        Ok((None, Some(ports)))
    } else {
        Err(err(format!(
            "unexpected text {tail:?} after the bracketed address"
        )))
    }
}

fn parse_prefix(text: Option<&str>, max: u8, entry: &str) -> Result<u8> {
    match text {
        None => Ok(max),
        Some(text) => {
            let prefix: u8 = text.parse().map_err(|_| {
                err(format!(
                    "destination rule {entry:?} has an invalid prefix length"
                ))
            })?;
            if prefix > max {
                return Err(err(format!(
                    "destination rule {entry:?} prefix length exceeds /{max}"
                )));
            }
            Ok(prefix)
        }
    }
}

fn parse_ports(text: &str, entry: &str) -> Result<PortRange> {
    let (start_text, end_text) = match text.split_once('-') {
        Some((start, end)) => (start, end),
        None => (text, text),
    };
    let start: u16 = start_text
        .parse()
        .map_err(|_| err(format!("destination rule {entry:?} has an invalid port")))?;
    let end: u16 = end_text
        .parse()
        .map_err(|_| err(format!("destination rule {entry:?} has an invalid port")))?;
    if start == 0 || end == 0 {
        return Err(err(format!(
            "destination rule {entry:?}: port 0 is not valid"
        )));
    }
    if start > end {
        return Err(err(format!(
            "destination rule {entry:?} has a reversed port range"
        )));
    }
    Ok(PortRange { start, end })
}

fn canonical_v4(addr: Ipv4Addr, prefix: u8, entry: &str) -> Result<IpNetwork> {
    if mask_v4(addr, prefix) != addr {
        return Err(err(format!(
            "destination rule {entry:?} has host bits set beyond /{prefix}"
        )));
    }
    Ok(IpNetwork::V4 { addr, prefix })
}

fn canonical_v6(addr: Ipv6Addr, prefix: u8, entry: &str) -> Result<IpNetwork> {
    if mask_v6(addr, prefix) != addr {
        return Err(err(format!(
            "destination rule {entry:?} has host bits set beyond /{prefix}"
        )));
    }
    Ok(IpNetwork::V6 { addr, prefix })
}

impl Serialize for DestRule {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for DestRule {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        let text = String::deserialize(deserializer)?;
        text.parse().map_err(D::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rule(entry: &str) -> DestRule {
        DestRule::parse(entry).expect(entry)
    }

    #[test]
    fn parses_ipv4_forms() {
        assert_eq!(
            rule("1.2.3.4"),
            DestRule {
                net: IpNetwork::v4(Ipv4Addr::new(1, 2, 3, 4), 32),
                ports: None
            }
        );
        assert_eq!(
            rule("140.82.112.0/20"),
            DestRule {
                net: IpNetwork::v4(Ipv4Addr::new(140, 82, 112, 0), 20),
                ports: None
            }
        );
        assert_eq!(
            rule("151.101.0.1:443"),
            DestRule {
                net: IpNetwork::v4(Ipv4Addr::new(151, 101, 0, 1), 32),
                ports: Some(PortRange {
                    start: 443,
                    end: 443
                })
            }
        );
        assert_eq!(
            rule("10.99.0.0/16:8000-8100"),
            DestRule {
                net: IpNetwork::v4(Ipv4Addr::new(10, 99, 0, 0), 16),
                ports: Some(PortRange {
                    start: 8000,
                    end: 8100
                })
            }
        );
    }

    #[test]
    fn parses_ipv6_forms() {
        assert_eq!(
            rule("::1"),
            DestRule {
                net: IpNetwork::v6(Ipv6Addr::LOCALHOST, 128),
                ports: None
            }
        );
        assert_eq!(
            rule("2001:db8::/32"),
            DestRule {
                net: IpNetwork::v6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0), 32),
                ports: None
            }
        );
        assert_eq!(
            rule("[::1]:443"),
            DestRule {
                net: IpNetwork::v6(Ipv6Addr::LOCALHOST, 128),
                ports: Some(PortRange {
                    start: 443,
                    end: 443
                })
            }
        );
        assert_eq!(
            rule("[2606:50c0::]/32:443"),
            DestRule {
                net: IpNetwork::v6(Ipv6Addr::new(0x2606, 0x50c0, 0, 0, 0, 0, 0, 0), 32),
                ports: Some(PortRange {
                    start: 443,
                    end: 443
                })
            }
        );
        // IPv4-mapped IPv6 stays IPv6 (two or more colons).
        assert!(matches!(rule("::ffff:1.2.3.4").net, IpNetwork::V6 { .. }));
        // The classic footgun: this is the ADDRESS 0:0:…:1:443, not a port —
        // ports on IPv6 require brackets.
        assert_eq!(rule("::1:443").ports, None);
    }

    #[test]
    fn rejects_invalid_rules() {
        for entry in [
            "",
            "example.com",
            "example.com:443",
            "1.2.3.4/33",
            "2001:db8::/129",
            "1.2.3.4:0",
            "1.2.3.4:70000",
            "1.2.3.4:443-80",
            "1.2.3.5/24",        // host bits set
            "2001:db8::1/32",    // host bits set
            "[::1]443",          // missing separator after bracket
            "[::1",              // unclosed bracket
            "1.2.3.4 ",          // whitespace
            "{1.2.3.4}",         // pf list braces
            "1.2.3.4\"",         // quote
            "1.2.3.4:443 label", // trailing text
        ] {
            assert!(DestRule::parse(entry).is_err(), "should reject {entry:?}");
        }
    }

    #[test]
    fn display_round_trips_canonical_forms() {
        for entry in [
            "1.2.3.4",
            "140.82.112.0/20",
            "151.101.0.1:443",
            "10.99.0.0/16:8000-8100",
            "::1",
            "2001:db8::/32",
            "[::1]:443",
            "[2606:50c0::]/32:443",
        ] {
            let parsed = rule(entry);
            assert_eq!(parsed.to_string(), entry);
            assert_eq!(rule(&parsed.to_string()), parsed);
        }
    }

    #[test]
    fn serde_uses_the_string_grammar() {
        let parsed: Vec<DestRule> =
            serde_json::from_str(r#"["1.2.3.0/24:443", "[::1]:8080"]"#).unwrap();
        assert_eq!(parsed[0], rule("1.2.3.0/24:443"));
        assert_eq!(parsed[1], rule("[::1]:8080"));
        let text = serde_json::to_string(&parsed).unwrap();
        assert_eq!(text, r#"["1.2.3.0/24:443","[::1]:8080"]"#);
        assert!(serde_json::from_str::<DestRule>(r#""nonsense""#).is_err());
    }

    #[test]
    fn network_containment() {
        let lan = rule("192.168.0.0/16");
        assert!(lan.net.contains_network(&rule("192.168.1.10").net));
        assert!(lan.net.contains_network(&rule("192.168.4.0/24").net));
        assert!(!lan.net.contains_network(&rule("192.169.0.0/16").net));
        assert!(!lan.net.contains_network(&rule("10.0.0.1").net));
        assert!(!lan.net.contains_network(&rule("[fe80::1]:22").net));
        let v6 = rule("fc00::/7");
        assert!(v6.net.contains_network(&rule("fd12:3456::1").net));
        assert!(!v6.net.contains_network(&rule("fe80::1").net));
    }

    #[test]
    fn lan_allow_must_stay_inside_blocked_ranges() {
        let ok = NetworkPolicy {
            lan_allow: vec![
                rule("192.168.1.10:22"),
                rule("10.0.0.0/24"),
                rule("fe80::1"),
            ],
            ..NetworkPolicy::default()
        };
        ok.validate().unwrap();

        for entry in ["0.0.0.0/0", "8.8.8.8", "2606:50c0::/32", "192.0.2.1"] {
            let bad = NetworkPolicy {
                lan_allow: vec![rule(entry)],
                ..NetworkPolicy::default()
            };
            assert!(
                bad.validate().is_err(),
                "lan_allow {entry:?} must be rejected"
            );
        }
    }

    #[test]
    fn list_caps_are_enforced() {
        let policy = NetworkPolicy {
            allow: (0..=MAX_RULES_PER_LIST)
                .map(|i| rule(&format!("1.2.{}.0/24", i % 256)))
                .collect(),
            ..NetworkPolicy::default()
        };
        assert!(policy.validate().is_err());

        let paths = PathPolicy {
            writable: (0..=MAX_RULES_PER_LIST)
                .map(|i| format!("/data/{i}"))
                .collect(),
            ..PathPolicy::default()
        };
        assert!(paths.validate().is_err());
    }

    #[test]
    fn path_policy_validation() {
        let ok = PathPolicy {
            writable: vec!["/Volumes/DATA/models".into()],
            read_only: vec!["/Volumes/DATA/reference".into()],
            deny: vec!["/Users/me/.ssh".into()],
            narrow_home: true,
            agent_state_dirs: vec![".claude".into(), ".config/agent".into()],
        };
        ok.validate().unwrap();

        for bad in [
            PathPolicy {
                writable: vec!["relative/path".into()],
                ..PathPolicy::default()
            },
            PathPolicy {
                deny: vec!["/tmp/../etc".into()],
                ..PathPolicy::default()
            },
            PathPolicy {
                writable: vec!["/".into()],
                ..PathPolicy::default()
            },
            PathPolicy {
                agent_state_dirs: vec!["/absolute".into()],
                ..PathPolicy::default()
            },
            PathPolicy {
                agent_state_dirs: vec!["../escape".into()],
                ..PathPolicy::default()
            },
            PathPolicy {
                agent_state_dirs: vec!["".into()],
                ..PathPolicy::default()
            },
        ] {
            assert!(bad.validate().is_err(), "should reject {bad:?}");
        }
    }

    #[test]
    fn lexical_normalization() {
        assert_eq!(
            lexically_normalized_absolute("/a//b/./c")
                .unwrap_err()
                .to_string(),
            "path must not contain `.` or `..` components"
        );
        assert_eq!(lexically_normalized_absolute("//a//b/").unwrap(), "/a/b");
        assert!(lexically_normalized_absolute("relative").is_err());
        assert!(lexically_normalized_absolute("/").is_err());
        assert!(lexically_normalized_absolute("/a/../b").is_err());
    }

    #[test]
    fn default_policy_is_default() {
        assert!(SandboxPolicy::default().is_default());
        let mut custom = SandboxPolicy::default();
        custom.paths.narrow_home = true;
        assert!(!custom.is_default());
        custom.validate().unwrap();
    }

    #[test]
    fn policy_json_round_trip_and_unknown_field_rejection() {
        let mut policy = SandboxPolicy::default();
        policy.network.default_action = NetAction::Deny;
        policy.network.allow.push(rule("140.82.112.0/20:443"));
        policy.network.lan_allow.push(rule("192.168.1.10:22"));
        policy.paths.writable.push("/Volumes/DATA/models".into());
        policy.paths.narrow_home = true;

        let json = serde_json::to_string(&policy).unwrap();
        let back: SandboxPolicy = serde_json::from_str(&json).unwrap();
        assert_eq!(back, policy);

        // Unknown fields fail closed: a newer client's policy must not be
        // silently half-applied by an older helper.
        assert!(
            serde_json::from_str::<SandboxPolicy>(r#"{"network":{"future_knob":true}}"#).is_err()
        );

        // A missing policy section deserializes to defaults.
        let empty: SandboxPolicy = serde_json::from_str("{}").unwrap();
        assert!(empty.is_default());
    }

    #[test]
    fn blocked_lan_constants_match_the_firewall_literals() {
        let rendered4: Vec<String> = LAN4_BLOCKED.iter().map(IpNetwork::cidr).collect();
        assert_eq!(
            rendered4,
            [
                "0.0.0.0/8",
                "10.0.0.0/8",
                "100.64.0.0/10",
                "169.254.0.0/16",
                "172.16.0.0/12",
                "192.168.0.0/16",
                "224.0.0.0/4",
                "240.0.0.0/4"
            ]
        );
        let rendered6: Vec<String> = LAN6_BLOCKED.iter().map(IpNetwork::cidr).collect();
        assert_eq!(rendered6, ["::/128", "fe80::/10", "fc00::/7", "ff00::/8"]);
    }
}
