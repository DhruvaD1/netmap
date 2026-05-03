//! reverse dns hostname lookup

use std::net::{IpAddr, Ipv4Addr};

pub fn reverse(ip: Ipv4Addr) -> Option<String> {
    let name = dns_lookup::lookup_addr(&IpAddr::V4(ip)).ok()?;
    if name.is_empty() || name == ip.to_string() {
        return None;
    }
    Some(name)
}
