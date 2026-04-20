//! network device representation

use chrono::{DateTime, Utc};
use pnet::util::MacAddr;
use std::net::Ipv4Addr;
use uuid::Uuid;

#[derive(Debug, Clone)]
pub struct Device {
    pub id: Uuid,
    pub ip: Ipv4Addr,
    pub mac: MacAddr,
    pub hostname: Option<String>,
    pub vendor: Option<String>,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
}

impl Device {
    pub fn new(ip: Ipv4Addr, mac: MacAddr) -> Self {
        let now = Utc::now();
        Self {
            id: Uuid::new_v4(),
            ip,
            mac,
            hostname: None,
            vendor: None,
            first_seen: now,
            last_seen: now,
        }
    }
}
