//! arp scanning over raw ethernet sockets

use crate::error::{NetmapError, Result};
use pnet::datalink::{self, Channel, Config, NetworkInterface};
use pnet::packet::arp::{ArpHardwareTypes, ArpOperations, ArpPacket, MutableArpPacket};
use pnet::packet::ethernet::{EtherTypes, EthernetPacket, MutableEthernetPacket};
use pnet::packet::Packet;
use pnet::util::MacAddr;
use std::collections::HashSet;
use std::net::Ipv4Addr;
use std::time::{Duration, Instant};

pub struct ArpResult {
    pub ip: Ipv4Addr,
    pub mac: MacAddr,
}

pub fn get_interface(name: &str) -> Result<NetworkInterface> {
    datalink::interfaces()
        .into_iter()
        .find(|iface| iface.name == name)
        .ok_or_else(|| NetmapError::InterfaceNotFound(name.to_string()))
}

pub fn get_default_interface() -> Result<NetworkInterface> {
    datalink::interfaces()
        .into_iter()
        .find(|iface| {
            iface.is_up()
                && !iface.is_loopback()
                && iface.mac.is_some()
                && iface.ips.iter().any(|ip| ip.is_ipv4())
        })
        .ok_or_else(|| NetmapError::InterfaceNotFound("no suitable interface".to_string()))
}

pub fn scan(
    interface: &NetworkInterface,
    targets: &[Ipv4Addr],
    timeout: Duration,
) -> Result<Vec<ArpResult>> {
    let config = Config {
        read_timeout: Some(Duration::from_millis(100)),
        ..Default::default()
    };

    let (mut tx, mut rx) = match datalink::channel(interface, config) {
        Ok(Channel::Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => return Err(NetmapError::ArpScan("unsupported channel type".into())),
        Err(e) if e.to_string().contains("Operation not permitted") => {
            return Err(NetmapError::PermissionDenied);
        }
        Err(e) => return Err(NetmapError::ArpScan(e.to_string())),
    };

    let src_mac = interface
        .mac
        .ok_or_else(|| NetmapError::ArpScan("interface has no mac".into()))?;

    let src_ip = interface
        .ips
        .iter()
        .find_map(|net| match net.ip() {
            std::net::IpAddr::V4(v4) => Some(v4),
            _ => None,
        })
        .ok_or_else(|| NetmapError::NoIpv4(interface.name.clone()))?;

    for &target in targets {
        let mut buf = [0u8; 42];
        build_arp_request(&mut buf, src_mac, src_ip, target);
        tx.send_to(&buf, None);
    }

    let mut results = Vec::new();
    let mut seen = HashSet::new();
    let deadline = Instant::now() + timeout;

    while Instant::now() < deadline {
        match rx.next() {
            Ok(data) => {
                if let Some(eth) = EthernetPacket::new(data) {
                    if eth.get_ethertype() != EtherTypes::Arp {
                        continue;
                    }
                    if let Some(arp) = ArpPacket::new(eth.payload()) {
                        if arp.get_operation() == ArpOperations::Reply {
                            let ip = arp.get_sender_proto_addr();
                            let mac = arp.get_sender_hw_addr();
                            if mac != src_mac && seen.insert(ip) {
                                results.push(ArpResult { ip, mac });
                            }
                        }
                    }
                }
            }
            Err(_) => continue,
        }
    }

    results.sort_by_key(|r| u32::from(r.ip));
    Ok(results)
}

fn build_arp_request(buf: &mut [u8; 42], src_mac: MacAddr, src_ip: Ipv4Addr, target: Ipv4Addr) {
    let broadcast = MacAddr::new(0xff, 0xff, 0xff, 0xff, 0xff, 0xff);
    let zero = MacAddr::new(0, 0, 0, 0, 0, 0);

    {
        let mut eth = MutableEthernetPacket::new(&mut buf[..]).unwrap();
        eth.set_destination(broadcast);
        eth.set_source(src_mac);
        eth.set_ethertype(EtherTypes::Arp);
    }
    {
        let mut arp = MutableArpPacket::new(&mut buf[14..]).unwrap();
        arp.set_hardware_type(ArpHardwareTypes::Ethernet);
        arp.set_protocol_type(EtherTypes::Ipv4);
        arp.set_hw_addr_len(6);
        arp.set_proto_addr_len(4);
        arp.set_operation(ArpOperations::Request);
        arp.set_sender_hw_addr(src_mac);
        arp.set_sender_proto_addr(src_ip);
        arp.set_target_hw_addr(zero);
        arp.set_target_proto_addr(target);
    }
}
