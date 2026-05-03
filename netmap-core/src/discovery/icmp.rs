//! icmp echo sweep for host discovery

use crate::error::{NetmapError, Result};
use std::collections::HashSet;
use std::mem::MaybeUninit;
use std::net::{Ipv4Addr, SocketAddrV4};
use std::time::{Duration, Instant};

pub struct IcmpResult {
    pub ip: Ipv4Addr,
    pub rtt: Duration,
    pub ttl: u8,
}

pub fn sweep(targets: &[Ipv4Addr], timeout: Duration) -> Result<Vec<IcmpResult>> {
    let sock = socket2::Socket::new(
        socket2::Domain::IPV4,
        socket2::Type::RAW,
        Some(socket2::Protocol::ICMPV4),
    )
    .map_err(|e| {
        if e.raw_os_error() == Some(libc::EPERM) || e.raw_os_error() == Some(libc::EACCES) {
            NetmapError::PermissionDenied
        } else {
            NetmapError::Io(e)
        }
    })?;

    sock.set_read_timeout(Some(Duration::from_millis(100)))?;

    let id = std::process::id() as u16;
    let start = Instant::now();

    for (seq, &target) in targets.iter().enumerate() {
        let pkt = build_echo_request(id, seq as u16);
        let dest: socket2::SockAddr = SocketAddrV4::new(target, 0).into();
        let _ = sock.send_to(&pkt, &dest);
    }

    let mut results = Vec::new();
    let mut seen = HashSet::new();
    let deadline = start + timeout;

    loop {
        if Instant::now() >= deadline {
            break;
        }

        let mut buf = [MaybeUninit::<u8>::uninit(); 1024];
        match sock.recv_from(&mut buf) {
            Ok((len, addr)) => {
                let data: Vec<u8> =
                    buf[..len].iter().map(|b| unsafe { b.assume_init() }).collect();

                if let Some((ip, ttl)) = parse_echo_reply(&data, id) {
                    if let Some(src) = addr.as_socket_ipv4() {
                        let reply_ip = *src.ip();
                        if reply_ip == ip && seen.insert(ip) {
                            results.push(IcmpResult {
                                ip,
                                rtt: start.elapsed(),
                                ttl,
                            });
                        }
                    }
                }
            }
            Err(ref e)
                if e.kind() == std::io::ErrorKind::WouldBlock
                    || e.kind() == std::io::ErrorKind::TimedOut =>
            {
                continue
            }
            Err(_) => continue,
        }
    }

    results.sort_by_key(|r| u32::from(r.ip));
    Ok(results)
}

fn parse_echo_reply(data: &[u8], expected_id: u16) -> Option<(Ipv4Addr, u8)> {
    if data.len() < 28 {
        return None;
    }

    let ihl = (data[0] & 0x0f) as usize * 4;
    let ttl = data[8];

    if data.len() < ihl + 8 {
        return None;
    }

    let icmp_type = data[ihl];
    if icmp_type != 0 {
        return None;
    }

    let recv_id = u16::from_be_bytes([data[ihl + 4], data[ihl + 5]]);
    if recv_id != expected_id {
        return None;
    }

    let ip = Ipv4Addr::new(data[12], data[13], data[14], data[15]);
    Some((ip, ttl))
}

fn build_echo_request(id: u16, seq: u16) -> [u8; 64] {
    let mut pkt = [0u8; 64];
    pkt[0] = 8;
    pkt[4] = (id >> 8) as u8;
    pkt[5] = (id & 0xff) as u8;
    pkt[6] = (seq >> 8) as u8;
    pkt[7] = (seq & 0xff) as u8;

    for i in 8..64 {
        pkt[i] = i as u8;
    }

    let cksum = checksum(&pkt);
    pkt[2] = (cksum >> 8) as u8;
    pkt[3] = (cksum & 0xff) as u8;
    pkt
}

fn checksum(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut i = 0;
    while i + 1 < data.len() {
        sum += u16::from_be_bytes([data[i], data[i + 1]]) as u32;
        i += 2;
    }
    if data.len() % 2 == 1 {
        sum += (data[data.len() - 1] as u32) << 8;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !sum as u16
}
