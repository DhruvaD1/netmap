//! fingerprint pipeline - chains mac vendor, port scan, service id, reverse dns

use crate::fingerprint::{dns_resolve, mac_vendor::OuiDatabase, port_scan, service_id};
use crate::model::device::{Device, DeviceType};
use rayon::prelude::*;
use std::time::Duration;

pub struct PipelineConfig {
    pub ports: Vec<u16>,
    pub port_timeout: Duration,
    pub service_id: bool,
    pub reverse_dns: bool,
}

impl Default for PipelineConfig {
    fn default() -> Self {
        Self {
            ports: port_scan::COMMON_PORTS.to_vec(),
            port_timeout: Duration::from_millis(800),
            service_id: true,
            reverse_dns: true,
        }
    }
}

pub fn fingerprint(device: &mut Device, oui_db: Option<&OuiDatabase>, config: &PipelineConfig) {
    if let (Some(mac), Some(db)) = (device.mac, oui_db) {
        if device.vendor.is_none() {
            device.vendor = db.lookup(&mac).map(String::from);
        }
    }

    if config.reverse_dns && device.hostname.is_none() {
        device.hostname = dns_resolve::reverse(device.ip);
    }

    let mut ports = port_scan::scan(device.ip, &config.ports, config.port_timeout);

    if config.service_id {
        ports.par_iter_mut().for_each(|p| {
            p.service = service_id::identify(device.ip, p.port, config.port_timeout);
        });
    }

    device.open_ports = ports;
    device.device_type = infer_type(device);
}

fn infer_type(d: &Device) -> DeviceType {
    let has_port = |port: u16| d.open_ports.iter().any(|p| p.port == port);

    if has_port(631) {
        return DeviceType::Printer;
    }
    if has_port(53) && (has_port(80) || has_port(443)) {
        return DeviceType::Router;
    }
    if has_port(22) && has_port(80) {
        return DeviceType::Server;
    }
    if let Some(v) = d.vendor.as_deref() {
        let v = v.to_lowercase();
        if v.contains("espressif") || v.contains("raspberry pi") {
            return DeviceType::IoT;
        }
        if v.contains("cisco") || v.contains("juniper") || v.contains("aruba") || v.contains("ubiquiti") || v.contains("tp-link") || v.contains("netgear") {
            return DeviceType::Router;
        }
        if v.contains("apple") || v.contains("dell") || v.contains("lenovo") || v.contains("hewlett") {
            return DeviceType::Workstation;
        }
    }
    DeviceType::Unknown
}

pub fn fingerprint_all(
    devices: &mut [Device],
    oui_db: Option<&OuiDatabase>,
    config: &PipelineConfig,
) {
    devices.par_iter_mut().for_each(|d| {
        fingerprint(d, oui_db, config);
    });
}
