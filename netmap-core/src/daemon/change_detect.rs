//! diff two topologies and produce events

use crate::model::events::EventKind;
use crate::model::topology::Topology;
use std::collections::{HashMap, HashSet};
use std::net::Ipv4Addr;

pub fn diff(old: &Topology, new: &Topology) -> Vec<EventKind> {
    let old_map: HashMap<Ipv4Addr, _> = old.devices.iter().map(|d| (d.ip, d)).collect();
    let new_map: HashMap<Ipv4Addr, _> = new.devices.iter().map(|d| (d.ip, d)).collect();

    let mut events = Vec::new();

    for (ip, d) in &new_map {
        if !old_map.contains_key(ip) {
            events.push(EventKind::DeviceAdded {
                ip: *ip,
                vendor: d.vendor.clone(),
            });
        }
    }

    for ip in old_map.keys() {
        if !new_map.contains_key(ip) {
            events.push(EventKind::DeviceRemoved { ip: *ip });
        }
    }

    for (ip, new_d) in &new_map {
        if let Some(old_d) = old_map.get(ip) {
            let old_ports: HashSet<u16> = old_d.open_ports.iter().map(|p| p.port).collect();
            let new_ports: HashSet<u16> = new_d.open_ports.iter().map(|p| p.port).collect();

            for port in new_ports.difference(&old_ports) {
                events.push(EventKind::PortOpened {
                    ip: *ip,
                    port: *port,
                });
            }
            for port in old_ports.difference(&new_ports) {
                events.push(EventKind::PortClosed {
                    ip: *ip,
                    port: *port,
                });
            }
        }
    }

    events
}
