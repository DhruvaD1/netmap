//! parallel tcp connect port scanning

use crate::model::port::{PortInfo, PortState};
use rayon::prelude::*;
use std::net::{Ipv4Addr, SocketAddr, TcpStream};
use std::time::Duration;

pub const COMMON_PORTS: &[u16] = &[
    22, 53, 80, 443, 445, 631, 3389, 5353, 8080, 8443,
];

pub fn scan(host: Ipv4Addr, ports: &[u16], timeout: Duration) -> Vec<PortInfo> {
    let mut results: Vec<PortInfo> = ports
        .par_iter()
        .filter_map(|&port| {
            let addr = SocketAddr::new(host.into(), port);
            TcpStream::connect_timeout(&addr, timeout).ok().map(|_| PortInfo {
                port,
                state: PortState::Open,
                service: None,
            })
        })
        .collect();

    results.sort_by_key(|p| p.port);
    results
}
