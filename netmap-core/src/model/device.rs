//! network device representation

use crate::model::os::OsFingerprint;
use crate::model::port::PortInfo;
use chrono::{DateTime, Utc};
use pnet::util::MacAddr;
use std::net::Ipv4Addr;
use std::time::Duration;
use uuid::Uuid;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeviceType {
    Router,
    Server,
    Workstation,
    IoT,
    Printer,
    Unknown,
}

#[derive(Debug, Clone)]
pub struct Device {
    pub id: Uuid,
    pub ip: Ipv4Addr,
    pub mac: Option<MacAddr>,
    pub hostname: Option<String>,
    pub vendor: Option<String>,
    pub rtt: Option<Duration>,
    pub ttl: Option<u8>,
    pub os: Option<OsFingerprint>,
    pub device_type: DeviceType,
    pub open_ports: Vec<PortInfo>,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
}

impl Device {
    pub fn new(ip: Ipv4Addr, mac: MacAddr) -> Self {
        let now = Utc::now();
        Self {
            id: Uuid::new_v4(),
            ip,
            mac: Some(mac),
            hostname: None,
            vendor: None,
            rtt: None,
            ttl: None,
            os: None,
            device_type: DeviceType::Unknown,
            open_ports: vec![],
            first_seen: now,
            last_seen: now,
        }
    }

    pub fn from_ip(ip: Ipv4Addr) -> Self {
        let now = Utc::now();
        Self {
            id: Uuid::new_v4(),
            ip,
            mac: None,
            hostname: None,
            vendor: None,
            rtt: None,
            ttl: None,
            os: None,
            device_type: DeviceType::Unknown,
            open_ports: vec![],
            first_seen: now,
            last_seen: now,
        }
    }
}
