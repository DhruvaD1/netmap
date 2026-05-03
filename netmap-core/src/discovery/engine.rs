//! discovery engine - orchestrates scanners and merges results

use crate::discovery::{arp, gateway, icmp, traceroute};
use crate::error::Result;
use crate::fingerprint::mac_vendor::OuiDatabase;
use crate::fingerprint::os_detect;
use crate::fingerprint::pipeline::{self, PipelineConfig};
use crate::model::device::Device;
use crate::model::topology::Topology;
use pnet::datalink::NetworkInterface;
use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::time::{Duration, Instant};

pub struct ScanConfig {
    pub arp_timeout: Duration,
    pub icmp_timeout: Duration,
    pub fingerprint: bool,
    pub pipeline: PipelineConfig,
    pub traceroute_target: Option<Ipv4Addr>,
    pub traceroute_max_hops: u8,
    pub traceroute_timeout: Duration,
}

impl Default for ScanConfig {
    fn default() -> Self {
        Self {
            arp_timeout: Duration::from_secs(3),
            icmp_timeout: Duration::from_secs(3),
            fingerprint: true,
            pipeline: PipelineConfig::default(),
            traceroute_target: Some(Ipv4Addr::new(1, 1, 1, 1)),
            traceroute_max_hops: 12,
            traceroute_timeout: Duration::from_millis(800),
        }
    }
}

pub struct ScanResult {
    pub topology: Topology,
    pub duration: Duration,
    pub arp_found: usize,
    pub icmp_found: usize,
    pub trace_hops: usize,
}

pub fn full_scan(
    interface: &NetworkInterface,
    targets: &[Ipv4Addr],
    oui_db: Option<&OuiDatabase>,
    config: &ScanConfig,
) -> Result<ScanResult> {
    let start = Instant::now();
    let mut device_map: HashMap<Ipv4Addr, Device> = HashMap::new();

    let arp_results = arp::scan(interface, targets, config.arp_timeout)?;
    let arp_found = arp_results.len();

    for r in &arp_results {
        let mut dev = Device::new(r.ip, r.mac);
        if let Some(db) = oui_db {
            dev.vendor = db.lookup(&r.mac).map(String::from);
        }
        device_map.insert(r.ip, dev);
    }

    let icmp_results = icmp::sweep(targets, config.icmp_timeout).unwrap_or_default();
    let icmp_found = icmp_results.len();

    for r in &icmp_results {
        let os = os_detect::from_ttl(r.ttl);
        device_map
            .entry(r.ip)
            .and_modify(|dev| {
                dev.rtt = Some(r.rtt);
                dev.ttl = Some(r.ttl);
                dev.os = Some(os.clone());
            })
            .or_insert_with(|| {
                let mut dev = Device::from_ip(r.ip);
                dev.rtt = Some(r.rtt);
                dev.ttl = Some(r.ttl);
                dev.os = Some(os);
                dev
            });
    }

    let mut devices: Vec<Device> = device_map.into_values().collect();
    devices.sort_by_key(|d| u32::from(d.ip));

    if config.fingerprint {
        pipeline::fingerprint_all(&mut devices, oui_db, &config.pipeline);
    }

    let gw = gateway::default_gateway();

    let upstream_hops: Vec<Ipv4Addr> = match config.traceroute_target {
        Some(target) => traceroute::trace(target, config.traceroute_max_hops, config.traceroute_timeout)
            .unwrap_or_default()
            .into_iter()
            .filter_map(|h| h.ip)
            .collect(),
        None => Vec::new(),
    };
    let trace_hops = upstream_hops.len();

    let topology = Topology::build(devices, gw, upstream_hops);

    Ok(ScanResult {
        topology,
        duration: start.elapsed(),
        arp_found,
        icmp_found,
        trace_hops,
    })
}
