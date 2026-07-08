use crate::Result;
use std::process::Command;

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

pub fn parse_ip_route_get_interface(output: &str) -> Option<String> {
    let mut tokens = output.split_whitespace();
    while let Some(token) = tokens.next() {
        if token == "dev" {
            return tokens.next().map(ToString::to_string);
        }
    }
    None
}

#[cfg(target_os = "macos")]
pub fn default_ipv4_interface() -> Result<Option<String>> {
    let output = Command::new("/sbin/route")
        .args(["-n", "get", "1.1.1.1"])
        .output()?;
    if !output.status.success() {
        return Ok(None);
    }
    Ok(parse_route_get_interface(&String::from_utf8_lossy(
        &output.stdout,
    )))
}

#[cfg(target_os = "linux")]
pub fn default_ipv4_interface() -> Result<Option<String>> {
    for ip in ["/sbin/ip", "/usr/sbin/ip", "/usr/bin/ip", "ip"] {
        let Ok(output) = Command::new(ip).args(["route", "get", "1.1.1.1"]).output() else {
            continue;
        };
        if output.status.success() {
            return Ok(parse_ip_route_get_interface(&String::from_utf8_lossy(
                &output.stdout,
            )));
        }
    }
    Ok(None)
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
pub fn default_ipv4_interface() -> Result<Option<String>> {
    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_route_get_interface() {
        let output = r#"
   route to: 1.1.1.1
destination: default
       mask: default
    gateway: 10.0.0.1
  interface: utun5
"#;
        assert_eq!(parse_route_get_interface(output).as_deref(), Some("utun5"));
    }

    #[test]
    fn parses_linux_ip_route_get_interface() {
        let output = "1.1.1.1 via 10.0.2.2 dev eth0 src 10.0.2.15 uid 501\n    cache\n";
        assert_eq!(
            parse_ip_route_get_interface(output).as_deref(),
            Some("eth0")
        );
    }
}
