//! Where unbound IPv4 traffic actually leaves the host.
//!
//! The launcher refuses to start unless the selected VPN carries *all* IPv4
//! egress, so this module has to answer that question and not a weaker one.
//! Probing the route to a single well-known address (the old `1.1.1.1` probe)
//! was not good enough: a split-tunnel VPN that installs a host route for its
//! resolver makes that probe answer `utunN` while the system default route is
//! still `en0`, and the preflight passed while DNS leaked.
//!
//! Instead we ask two questions:
//!
//! 1. Which interfaces hold an unscoped IPv4 default route (`0.0.0.0/0`)?
//!    That is the routing-table fact the security model talks about, and it
//!    is what the UI shows.
//! 2. Which interface does the kernel pick for each half of the address
//!    space, `0.0.0.0/1` and `128.0.0.0/1`? Both halves resolving to the
//!    selected VPN is the actual invariant we need — it is true for a plain
//!    default route through the tunnel, it is also true for the common
//!    "def1" split (`0.0.0.0/1` + `128.0.0.0/1` through the tunnel, physical
//!    default route left in place), and no single-host route can satisfy it.

use crate::Result;
use std::process::Command;

/// Representative addresses for the two halves of the IPv4 space. Neither is
/// a destination a VPN would pin with a host route, unlike public resolver
/// addresses such as `1.1.1.1`.
const LOW_HALF_PROBE: &str = "0.0.0.1";
const HIGH_HALF_PROBE: &str = "128.0.0.1";

/// The routing table's answer for unbound IPv4 traffic.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Ipv4Egress {
    /// Interfaces holding an unscoped default route (`0.0.0.0/0`), in table
    /// order. Interface-scoped defaults (macOS `IFSCOPE`) are excluded: they
    /// only apply to sockets already bound to that interface.
    pub default_interfaces: Vec<String>,
    /// Interface the kernel picks for the low half of the address space.
    pub low_half: Option<String>,
    /// Interface the kernel picks for the high half of the address space.
    pub high_half: Option<String>,
}

impl Ipv4Egress {
    /// True when every unbound IPv4 destination — not merely one probe
    /// address — leaves over `interface`. Host or prefix routes that pin a
    /// *specific* destination elsewhere are still possible; the firewall
    /// rules are the defense for those.
    pub fn carries_all_ipv4(&self, interface: &str) -> bool {
        self.low_half.as_deref() == Some(interface) && self.high_half.as_deref() == Some(interface)
    }

    /// The interface unbound traffic uses, for display. Falls back to the
    /// first default-route entry when the two halves disagree (a partially
    /// split routing table), and is `None` when nothing could be determined.
    pub fn egress_interface(&self) -> Option<&str> {
        match (self.low_half.as_deref(), self.high_half.as_deref()) {
            (Some(low), Some(high)) if low == high => Some(low),
            _ => self.default_interfaces.first().map(String::as_str),
        }
    }

    /// One-line diagnostic naming what the routing table really says.
    pub fn describe(&self) -> String {
        let name = |value: &Option<String>| value.as_deref().unwrap_or("<unknown>").to_string();
        let mut parts = vec![format!(
            "0.0.0.0/1 -> {}, 128.0.0.0/1 -> {}",
            name(&self.low_half),
            name(&self.high_half)
        )];
        parts.push(if self.default_interfaces.is_empty() {
            "no default route".to_string()
        } else {
            format!("default route -> {}", self.default_interfaces.join(", "))
        });
        parts.join("; ")
    }
}

// ---------------------------------------------------------------------------
// Parsers (pure, so they can be unit-tested without touching the kernel)
// ---------------------------------------------------------------------------

/// Interface reported by macOS `route -n get <destination>`.
pub fn parse_route_get_interface(output: &str) -> Option<String> {
    output.lines().find_map(|line| {
        let (key, value) = line.split_once(':')?;
        if key.trim() == "interface" {
            Some(value.trim().to_string())
        } else {
            None
        }
    })
}

/// Interfaces of the unscoped default routes in macOS `netstat -rn -f inet`
/// output. Rows look like:
///
/// ```text
/// Destination        Gateway            Flags               Netif Expire
/// default            192.168.0.1        UGScg                 en1
/// default            link#22            UCSg                utun4
/// default            192.168.0.1        UGScIg                en1
/// ```
///
/// The third row carries the `I` (`RTF_IFSCOPE`) flag: it is scoped to `en1`
/// and is not used by unbound sockets, so it is skipped.
pub fn parse_netstat_default_interfaces(output: &str) -> Vec<String> {
    let mut interfaces: Vec<String> = Vec::new();
    for line in output.lines() {
        let fields: Vec<&str> = line.split_whitespace().collect();
        let [destination, _gateway, flags, netif, ..] = fields.as_slice() else {
            continue;
        };
        if *destination != "default" || flags.contains('I') {
            continue;
        }
        let netif = (*netif).to_string();
        if !interfaces.contains(&netif) {
            interfaces.push(netif);
        }
    }
    interfaces
}

/// Interface reported by Linux `ip route get <destination>`.
pub fn parse_ip_route_get_interface(output: &str) -> Option<String> {
    let mut tokens = output.split_whitespace();
    while let Some(token) = tokens.next() {
        if token == "dev" {
            return tokens.next().map(ToString::to_string);
        }
    }
    None
}

/// Interfaces named by Linux `ip -4 route show default`, including every leg
/// of a multipath (`nexthop ... dev ...`) default route.
pub fn parse_ip_route_show_default_interfaces(output: &str) -> Vec<String> {
    let mut interfaces: Vec<String> = Vec::new();
    let mut tokens = output.split_whitespace();
    while let Some(token) = tokens.next() {
        if token != "dev" {
            continue;
        }
        let Some(name) = tokens.next() else { break };
        if !interfaces.contains(&name.to_string()) {
            interfaces.push(name.to_string());
        }
    }
    interfaces
}

// ---------------------------------------------------------------------------
// Platform queries
// ---------------------------------------------------------------------------

#[cfg(target_os = "macos")]
fn route_get_interface(destination: &str) -> Option<String> {
    let output = Command::new("/sbin/route")
        .args(["-n", "get", destination])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    parse_route_get_interface(&String::from_utf8_lossy(&output.stdout))
}

#[cfg(target_os = "macos")]
pub fn query_ipv4_egress() -> Result<Ipv4Egress> {
    let default_interfaces = Command::new("/usr/sbin/netstat")
        .args(["-rn", "-f", "inet"])
        .output()
        .ok()
        .filter(|output| output.status.success())
        .map(|output| parse_netstat_default_interfaces(&String::from_utf8_lossy(&output.stdout)))
        .unwrap_or_default();
    Ok(Ipv4Egress {
        default_interfaces,
        low_half: route_get_interface(LOW_HALF_PROBE),
        high_half: route_get_interface(HIGH_HALF_PROBE),
    })
}

#[cfg(target_os = "linux")]
fn ip_output(args: &[&str]) -> Option<String> {
    for ip in ["/sbin/ip", "/usr/sbin/ip", "/usr/bin/ip", "ip"] {
        let Ok(output) = Command::new(ip).args(args).output() else {
            continue;
        };
        if output.status.success() {
            return Some(String::from_utf8_lossy(&output.stdout).into_owned());
        }
    }
    None
}

#[cfg(target_os = "linux")]
pub fn query_ipv4_egress() -> Result<Ipv4Egress> {
    let default_interfaces = ip_output(&["-4", "route", "show", "default"])
        .as_deref()
        .map(parse_ip_route_show_default_interfaces)
        .unwrap_or_default();
    let probe = |destination: &str| {
        ip_output(&["-4", "route", "get", destination])
            .as_deref()
            .and_then(parse_ip_route_get_interface)
    };
    Ok(Ipv4Egress {
        default_interfaces,
        low_half: probe(LOW_HALF_PROBE),
        high_half: probe(HIGH_HALF_PROBE),
    })
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
pub fn query_ipv4_egress() -> Result<Ipv4Egress> {
    Ok(Ipv4Egress::default())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_route_get_interface() {
        let output = r#"
   route to: 0.0.0.1
destination: default
       mask: default
    gateway: 10.0.0.1
  interface: utun5
"#;
        assert_eq!(parse_route_get_interface(output).as_deref(), Some("utun5"));
    }

    #[test]
    fn parses_linux_ip_route_get_interface() {
        let output = "0.0.0.1 via 10.0.2.2 dev eth0 src 10.0.2.15 uid 501\n    cache\n";
        assert_eq!(
            parse_ip_route_get_interface(output).as_deref(),
            Some("eth0")
        );
    }

    #[test]
    fn parses_macos_default_routes_and_skips_scoped_ones() {
        let output = "\
Routing tables

Internet:
Destination        Gateway            Flags               Netif Expire
default            link#22            UCSg                utun4
default            192.168.0.1        UGScIg                en0
default            192.168.0.1        UGScg                 en0
127                127.0.0.1          UCS                   lo0
1.1.1.1/32         link#22            UCSg                utun4
";
        // The IFSCOPE ("I") row is skipped; the remaining defaults keep table
        // order; the 1.1.1.1 host route is not a default route.
        assert_eq!(
            parse_netstat_default_interfaces(output),
            vec!["utun4".to_string(), "en0".to_string()]
        );
    }

    #[test]
    fn parses_linux_default_routes_including_multipath() {
        let single = "default via 192.168.1.1 dev eth0 proto dhcp metric 100\n";
        assert_eq!(
            parse_ip_route_show_default_interfaces(single),
            vec!["eth0".to_string()]
        );

        let multipath = "\
default proto static
\tnexthop via 10.0.0.1 dev eth0 weight 1
\tnexthop via 10.0.1.1 dev wg0 weight 1
";
        assert_eq!(
            parse_ip_route_show_default_interfaces(multipath),
            vec!["eth0".to_string(), "wg0".to_string()]
        );
    }

    #[test]
    fn host_route_for_a_resolver_does_not_satisfy_the_check() {
        // The bug this replaces: a VPN pinning 1.1.1.1 to utun5 while the
        // default route stays on en0. Both halves of the address space still
        // resolve to en0, so the tunnel does not carry IPv4 egress.
        let egress = Ipv4Egress {
            default_interfaces: vec!["en0".to_string()],
            low_half: Some("en0".to_string()),
            high_half: Some("en0".to_string()),
        };
        assert!(!egress.carries_all_ipv4("utun5"));
        assert!(egress.carries_all_ipv4("en0"));
        assert_eq!(egress.egress_interface(), Some("en0"));
    }

    #[test]
    fn split_default_tunnel_carries_all_traffic() {
        // OpenVPN-style "def1": 0.0.0.0/1 + 128.0.0.0/1 through the tunnel,
        // the physical default route left untouched.
        let egress = Ipv4Egress {
            default_interfaces: vec!["en0".to_string()],
            low_half: Some("utun4".to_string()),
            high_half: Some("utun4".to_string()),
        };
        assert!(egress.carries_all_ipv4("utun4"));
        assert!(!egress.carries_all_ipv4("en0"));
        assert_eq!(egress.egress_interface(), Some("utun4"));
    }

    #[test]
    fn half_split_between_interfaces_fails_for_both() {
        // Only one of the two /1 routes survived a VPN restart: half of the
        // address space still leaves over en0.
        let egress = Ipv4Egress {
            default_interfaces: vec!["en0".to_string()],
            low_half: Some("utun4".to_string()),
            high_half: Some("en0".to_string()),
        };
        assert!(!egress.carries_all_ipv4("utun4"));
        assert!(!egress.carries_all_ipv4("en0"));
        // Display falls back to the routing table's default route.
        assert_eq!(egress.egress_interface(), Some("en0"));
        assert!(egress.describe().contains("128.0.0.0/1 -> en0"));
    }

    #[test]
    fn unknown_routing_state_fails_closed() {
        let egress = Ipv4Egress::default();
        assert!(!egress.carries_all_ipv4("utun4"));
        assert_eq!(egress.egress_interface(), None);
        assert!(egress.describe().contains("no default route"));
    }

    #[test]
    fn queries_the_live_routing_table_without_error() {
        // Smoke test: the platform query must not fail on a normal host, and
        // whatever it reports must be self-consistent. (No assertion about
        // *which* interface: CI runners and containers vary.)
        let egress = query_ipv4_egress().unwrap();
        let _ = egress.describe();
        if let Some(interface) = egress.egress_interface().map(ToString::to_string) {
            assert_eq!(
                egress.carries_all_ipv4(&interface),
                egress.low_half == egress.high_half && egress.low_half.is_some()
            );
        }
    }
}
