//! mac address vendor lookup via the ieee oui database

use std::collections::HashMap;
use std::path::Path;

pub struct OuiDatabase {
    entries: HashMap<[u8; 3], String>,
}

impl OuiDatabase {
    pub fn load(path: &Path) -> Result<Self, Box<dyn std::error::Error>> {
        let mut entries = HashMap::new();
        let data = std::fs::read_to_string(path)?;

        for line in data.lines().skip(1) {
            let parts: Vec<&str> = line.splitn(2, ',').collect();
            if parts.len() != 2 {
                continue;
            }

            let prefix = parts[0].trim();
            let vendor = parts[1].trim().to_string();

            if let Some(bytes) = parse_mac_prefix(prefix) {
                entries.insert(bytes, vendor);
            }
        }

        Ok(Self { entries })
    }

    pub fn lookup(&self, mac: &pnet::util::MacAddr) -> Option<&str> {
        let bytes = [mac.0, mac.1, mac.2];
        self.entries.get(&bytes).map(|s| s.as_str())
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }
}

fn parse_mac_prefix(s: &str) -> Option<[u8; 3]> {
    let parts: Vec<&str> = s.split(':').collect();
    if parts.len() != 3 {
        return None;
    }
    Some([
        u8::from_str_radix(parts[0], 16).ok()?,
        u8::from_str_radix(parts[1], 16).ok()?,
        u8::from_str_radix(parts[2], 16).ok()?,
    ])
}
