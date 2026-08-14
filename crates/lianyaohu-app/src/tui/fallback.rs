//! Non-TTY fallback (piped stdin, scripts, `--no-tui`): the classic numbered
//! prompt, unchanged behavior from the pre-TUI launcher.

use std::io::{self, Write};

use lianyaohu_core::interfaces::{NetworkInterface, vpn_interface_description};
use lianyaohu_core::{Result, err};

pub fn interface_entry(offset: usize, interface: &NetworkInterface) -> String {
    if interface.is_proxy_only() {
        return format!(
            "{}. none — proxy-only (block all direct egress; outbound via a local proxy)",
            offset + 1
        );
    }
    let state = if interface.is_up() && interface.is_running() {
        "up"
    } else {
        "down"
    };
    format!(
        "{}. {} [{}] {}",
        offset + 1,
        interface.name,
        state,
        interface.address_summary()
    )
}

pub fn select_numbered(interfaces: &[NetworkInterface]) -> Result<usize> {
    println!("Select VPN interface ({}):", vpn_interface_description());
    for (offset, interface) in interfaces.iter().enumerate() {
        println!("  {}", interface_entry(offset, interface));
    }
    print!("choice> ");
    io::stdout().flush()?;

    let mut input = String::new();
    io::stdin().read_line(&mut input)?;
    parse_choice(&input, interfaces.len())
}

pub fn parse_choice(input: &str, count: usize) -> Result<usize> {
    let selected = input.trim().parse::<usize>()?;
    if selected == 0 || selected > count {
        return Err(err("invalid VPN interface selection"));
    }
    Ok(selected - 1)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_choice_is_one_based_and_bounded() {
        assert_eq!(parse_choice("1\n", 3).unwrap(), 0);
        assert_eq!(parse_choice(" 3 ", 3).unwrap(), 2);
        assert!(parse_choice("0", 3).is_err());
        assert!(parse_choice("4", 3).is_err());
        assert!(parse_choice("nope", 3).is_err());
        assert!(parse_choice("", 3).is_err());
    }
}
