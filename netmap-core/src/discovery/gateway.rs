//! default gateway detection via /proc/net/route

use std::net::Ipv4Addr;

pub fn default_gateway() -> Option<Ipv4Addr> {
    let data = std::fs::read_to_string("/proc/net/route").ok()?;

    for line in data.lines().skip(1) {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() < 3 {
            continue;
        }
        if fields[1] != "00000000" {
            continue;
        }

        let hex = fields[2];
        if hex.len() != 8 {
            continue;
        }

        let bytes: Option<Vec<u8>> = (0..4)
            .map(|i| u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).ok())
            .collect();

        if let Some(b) = bytes {
            return Some(Ipv4Addr::new(b[3], b[2], b[1], b[0]));
        }
    }
    None
}
