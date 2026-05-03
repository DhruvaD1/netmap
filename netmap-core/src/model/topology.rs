//! topology graph with force-directed layout

use crate::model::device::{Device, DeviceType};
use crate::model::link::{Link, LinkType};
use std::collections::HashMap;
use std::net::Ipv4Addr;
use uuid::Uuid;

pub struct Topology {
    pub devices: Vec<Device>,
    pub links: Vec<Link>,
    pub gateway: Option<Uuid>,
    pub positions: HashMap<Uuid, (f64, f64)>,
}

impl Topology {
    pub fn empty() -> Self {
        Self {
            devices: vec![],
            links: vec![],
            gateway: None,
            positions: HashMap::new(),
        }
    }

    pub fn build(
        mut devices: Vec<Device>,
        gateway_ip: Option<Ipv4Addr>,
        upstream_hops: Vec<Ipv4Addr>,
    ) -> Self {
        let gateway_id = gateway_ip.and_then(|ip| devices.iter().find(|d| d.ip == ip).map(|d| d.id));

        let mut links = Vec::new();
        if let Some(gw) = gateway_id {
            for d in &devices {
                if d.id != gw {
                    links.push(Link {
                        source: gw,
                        target: d.id,
                        link_type: LinkType::Direct,
                    });
                }
            }
        }

        let mut prev_id = gateway_id;
        for hop_ip in upstream_hops {
            let existing = devices.iter().find(|d| d.ip == hop_ip).map(|d| d.id);
            let hop_id = match existing {
                Some(id) => id,
                None => {
                    let mut hop = Device::from_ip(hop_ip);
                    hop.device_type = DeviceType::Router;
                    let id = hop.id;
                    devices.push(hop);
                    id
                }
            };

            if let Some(prev) = prev_id {
                if prev != hop_id {
                    links.push(Link {
                        source: prev,
                        target: hop_id,
                        link_type: LinkType::Routed,
                    });
                }
            }
            prev_id = Some(hop_id);
        }

        let positions = force_directed_layout(&devices, &links, 140);

        Self {
            devices,
            links,
            gateway: gateway_id,
            positions,
        }
    }
}

fn force_directed_layout(
    devices: &[Device],
    links: &[Link],
    iterations: usize,
) -> HashMap<Uuid, (f64, f64)> {
    let n = devices.len();
    if n == 0 {
        return HashMap::new();
    }

    let area = 180.0 * 180.0;
    let k = (area / n as f64).sqrt();

    let mut positions: HashMap<Uuid, (f64, f64)> = HashMap::new();
    for (i, d) in devices.iter().enumerate() {
        let angle = (i as f64 / n as f64) * 2.0 * std::f64::consts::PI;
        let r = 60.0;
        positions.insert(d.id, (r * angle.cos(), r * angle.sin()));
    }

    if n == 1 {
        if let Some(d) = devices.first() {
            positions.insert(d.id, (0.0, 0.0));
        }
        return positions;
    }

    let mut t = 90.0_f64;

    for _ in 0..iterations {
        let mut disps: HashMap<Uuid, (f64, f64)> = HashMap::new();
        for d in devices {
            disps.insert(d.id, (0.0, 0.0));
        }

        for i in 0..n {
            for j in 0..n {
                if i == j {
                    continue;
                }
                let p1 = positions[&devices[i].id];
                let p2 = positions[&devices[j].id];
                let dx = p1.0 - p2.0;
                let dy = p1.1 - p2.1;
                let dist = (dx * dx + dy * dy).sqrt().max(0.5);
                let force = k * k / dist;
                let disp = disps.get_mut(&devices[i].id).unwrap();
                disp.0 += dx / dist * force;
                disp.1 += dy / dist * force;
            }
        }

        for link in links {
            let p1 = positions[&link.source];
            let p2 = positions[&link.target];
            let dx = p1.0 - p2.0;
            let dy = p1.1 - p2.1;
            let dist = (dx * dx + dy * dy).sqrt().max(0.5);
            let force = dist * dist / k;

            if let Some(d) = disps.get_mut(&link.source) {
                d.0 -= dx / dist * force;
                d.1 -= dy / dist * force;
            }
            if let Some(d) = disps.get_mut(&link.target) {
                d.0 += dx / dist * force;
                d.1 += dy / dist * force;
            }
        }

        for d in devices {
            let pos = positions.get_mut(&d.id).unwrap();
            let disp = &disps[&d.id];
            let mag = (disp.0 * disp.0 + disp.1 * disp.1).sqrt().max(0.01);
            let limit = mag.min(t);
            pos.0 += disp.0 / mag * limit;
            pos.1 += disp.1 / mag * limit;
            pos.0 = pos.0.clamp(-95.0, 95.0);
            pos.1 = pos.1.clamp(-95.0, 95.0);
        }

        t *= 0.96;
    }

    positions
}
