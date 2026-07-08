use crate::{Result, err};
use std::collections::BTreeMap;
use std::ffi::CStr;
use std::ptr;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NetworkInterface {
    pub name: String,
    pub flags: u32,
    pub ipv4_addresses: Vec<String>,
    pub ipv4_peer_addresses: Vec<String>,
    pub ipv6_addresses: Vec<String>,
}

impl NetworkInterface {
    pub fn is_up(&self) -> bool {
        self.flags & libc::IFF_UP as u32 != 0
    }

    pub fn is_running(&self) -> bool {
        self.flags & libc::IFF_RUNNING as u32 != 0
    }

    pub fn is_utun(&self) -> bool {
        self.name.starts_with("utun")
    }

    pub fn is_linux_tunnel(&self) -> bool {
        self.name.starts_with("tun") || self.name.starts_with("wg")
    }

    pub fn is_supported_vpn(&self) -> bool {
        #[cfg(target_os = "macos")]
        {
            self.is_utun()
        }
        #[cfg(target_os = "linux")]
        {
            self.is_linux_tunnel()
        }
        #[cfg(not(any(target_os = "macos", target_os = "linux")))]
        {
            false
        }
    }

    pub fn address_summary(&self) -> String {
        let mut addresses = Vec::new();
        for address in &self.ipv4_addresses {
            if let Some(peer) = self.ipv4_peer_addresses.first() {
                addresses.push(format!("{address}->{peer}"));
            } else {
                addresses.push(address.clone());
            }
        }
        addresses.extend(self.ipv6_addresses.iter().cloned());
        if addresses.is_empty() {
            "no addresses".to_string()
        } else {
            addresses.join(", ")
        }
    }
}

#[derive(Default)]
struct InterfaceBuilder {
    flags: u32,
    ipv4: Vec<String>,
    ipv4_peers: Vec<String>,
    ipv6: Vec<String>,
}

pub fn all_interfaces() -> Result<Vec<NetworkInterface>> {
    let mut addrs: *mut libc::ifaddrs = ptr::null_mut();
    let rc = unsafe { libc::getifaddrs(&mut addrs) };
    if rc != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    let _guard = IfAddrsGuard(addrs);

    let mut builders: BTreeMap<String, InterfaceBuilder> = BTreeMap::new();
    let mut cursor = addrs;
    while !cursor.is_null() {
        let item = unsafe { &*cursor };
        let name = unsafe { CStr::from_ptr(item.ifa_name) }
            .to_string_lossy()
            .to_string();
        let builder = builders.entry(name).or_default();
        builder.flags |= item.ifa_flags;

        if !item.ifa_addr.is_null() {
            let family = unsafe { (*item.ifa_addr).sa_family as i32 };
            match family {
                libc::AF_INET => {
                    if let Some(host) = numeric_host(item.ifa_addr) {
                        push_unique(&mut builder.ipv4, host);
                    }
                    let peer_addr = point_to_point_destination(item);
                    if item.ifa_flags & libc::IFF_POINTOPOINT as u32 != 0
                        && !peer_addr.is_null()
                        && let Some(peer) = numeric_host(peer_addr)
                    {
                        push_unique(&mut builder.ipv4_peers, peer);
                    }
                }
                libc::AF_INET6 => {
                    if let Some(host) = numeric_host(item.ifa_addr) {
                        push_unique(&mut builder.ipv6, host);
                    }
                }
                _ => {}
            }
        }

        cursor = item.ifa_next;
    }

    Ok(builders
        .into_iter()
        .map(|(name, mut builder)| {
            builder.ipv4.sort();
            builder.ipv4_peers.sort();
            builder.ipv6.sort();
            NetworkInterface {
                name,
                flags: builder.flags,
                ipv4_addresses: builder.ipv4,
                ipv4_peer_addresses: builder.ipv4_peers,
                ipv6_addresses: builder.ipv6,
            }
        })
        .collect())
}

pub fn utun_interfaces() -> Result<Vec<NetworkInterface>> {
    Ok(all_interfaces()?
        .into_iter()
        .filter(NetworkInterface::is_utun)
        .collect())
}

pub fn vpn_interfaces() -> Result<Vec<NetworkInterface>> {
    Ok(all_interfaces()?
        .into_iter()
        .filter(NetworkInterface::is_supported_vpn)
        .collect())
}

pub fn validate_utun(interface: &NetworkInterface) -> Result<()> {
    if !interface.is_utun() {
        return Err(err(format!("{} is not a utun interface", interface.name)));
    }
    if !interface.is_up() || !interface.is_running() {
        return Err(err(format!("{} is not up/running", interface.name)));
    }
    if interface.ipv4_addresses.is_empty() && interface.ipv6_addresses.is_empty() {
        return Err(err(format!(
            "{} has no IPv4 or IPv6 address",
            interface.name
        )));
    }
    Ok(())
}

pub fn validate_vpn_interface(interface: &NetworkInterface) -> Result<()> {
    if !interface.is_supported_vpn() {
        return Err(err(format!(
            "{} is not a supported VPN interface ({})",
            interface.name,
            vpn_interface_description()
        )));
    }
    validate_addressed_up_interface(interface)
}

pub fn vpn_interface_description() -> &'static str {
    #[cfg(target_os = "macos")]
    {
        "utun*"
    }
    #[cfg(target_os = "linux")]
    {
        "tun* or wg*"
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        "unsupported platform"
    }
}

fn validate_addressed_up_interface(interface: &NetworkInterface) -> Result<()> {
    let require_running = cfg!(not(target_os = "linux"));
    if !interface.is_up() || (require_running && !interface.is_running()) {
        #[cfg(target_os = "linux")]
        let state = "up";
        #[cfg(not(target_os = "linux"))]
        let state = "up/running";
        return Err(err(format!("{} is not {state}", interface.name)));
    }
    if interface.ipv4_addresses.is_empty() && interface.ipv6_addresses.is_empty() {
        return Err(err(format!(
            "{} has no IPv4 or IPv6 address",
            interface.name
        )));
    }
    Ok(())
}

fn push_unique(values: &mut Vec<String>, value: String) {
    if !values.contains(&value) {
        values.push(value);
    }
}

fn numeric_host(addr: *const libc::sockaddr) -> Option<String> {
    let mut host = [0 as libc::c_char; libc::NI_MAXHOST as usize];
    let len = sockaddr_len(addr)?;
    let rc = unsafe {
        libc::getnameinfo(
            addr,
            len,
            host.as_mut_ptr(),
            host.len() as libc::socklen_t,
            ptr::null_mut(),
            0,
            libc::NI_NUMERICHOST,
        )
    };
    if rc != 0 {
        return None;
    }
    Some(
        unsafe { CStr::from_ptr(host.as_ptr()) }
            .to_string_lossy()
            .to_string(),
    )
}

fn sockaddr_len(addr: *const libc::sockaddr) -> Option<libc::socklen_t> {
    if addr.is_null() {
        return None;
    }
    #[cfg(target_vendor = "apple")]
    {
        Some(unsafe { (*addr).sa_len as libc::socklen_t })
    }
    #[cfg(not(target_vendor = "apple"))]
    {
        match unsafe { (*addr).sa_family as i32 } {
            libc::AF_INET => Some(std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t),
            libc::AF_INET6 => Some(std::mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t),
            _ => None,
        }
    }
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn point_to_point_destination(item: &libc::ifaddrs) -> *const libc::sockaddr {
    item.ifa_ifu
}

#[cfg(not(any(target_os = "linux", target_os = "android")))]
fn point_to_point_destination(item: &libc::ifaddrs) -> *const libc::sockaddr {
    item.ifa_dstaddr
}

struct IfAddrsGuard(*mut libc::ifaddrs);

impl Drop for IfAddrsGuard {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe { libc::freeifaddrs(self.0) };
        }
    }
}
