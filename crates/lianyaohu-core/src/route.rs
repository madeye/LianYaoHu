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
}
