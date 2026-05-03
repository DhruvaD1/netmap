//! icmp traceroute - discover intermediate routers via ttl-limited probes

use crate::error::{NetmapError, Result};
use std::mem::MaybeUninit;
use std::net::{Ipv4Addr, SocketAddrV4};
use std::time::{Duration, Instant};

#[derive(Debug, Clone)]
pub struct Hop {
    pub ttl: u8,
    pub ip: Option<Ipv4Addr>,
    pub rtt: Option<Duration>,
}

pub fn trace(target: Ipv4Addr, max_hops: u8, timeout: Duration) -> Result<Vec<Hop>> {
    let mut hops = Vec::new();

    for ttl in 1..=max_hops {
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

        sock.set_ttl(ttl as u32)?;
        sock.set_read_timeout(Some(timeout))?;

        let id = std::process::id() as u16;
        let pkt = build_echo(id, ttl as u16);
        let dest: socket2::SockAddr = SocketAddrV4::new(target, 0).into();

        let start = Instant::now();
        if sock.send_to(&pkt, &dest).is_err() {
            hops.push(Hop {
                ttl,
                ip: None,
                rtt: None,
            });
            continue;
        }

        let mut buf = [MaybeUninit::<u8>::uninit(); 1024];
        let mut got_reply = false;
        let mut reached_target = false;

        let probe_deadline = Instant::now() + timeout;
        while Instant::now() < probe_deadline {
            match sock.recv_from(&mut buf) {
                Ok((len, addr)) => {
                    let data: Vec<u8> = buf[..len]
                        .iter()
                        .map(|b| unsafe { b.assume_init() })
                        .collect();

                    if data.len() < 28 {
                        continue;
                    }
                    let ihl = (data[0] & 0x0f) as usize * 4;
                    if data.len() < ihl + 8 {
                        continue;
                    }

                    let icmp_type = data[ihl];
                    let hop_ip = addr.as_socket_ipv4().map(|a| *a.ip());

                    if icmp_type == 11 {
                        hops.push(Hop {
                            ttl,
                            ip: hop_ip,
                            rtt: Some(start.elapsed()),
                        });
                        got_reply = true;
                        break;
                    }
                    if icmp_type == 0 {
                        hops.push(Hop {
                            ttl,
                            ip: hop_ip,
                            rtt: Some(start.elapsed()),
                        });
                        got_reply = true;
                        reached_target = true;
                        break;
                    }
                }
                Err(ref e)
                    if e.kind() == std::io::ErrorKind::WouldBlock
                        || e.kind() == std::io::ErrorKind::TimedOut =>
                {
                    break
                }
                Err(_) => break,
            }
        }

        if !got_reply {
            hops.push(Hop {
                ttl,
                ip: None,
                rtt: None,
            });
        }

        if reached_target {
            break;
        }
    }

    Ok(hops)
}

fn build_echo(id: u16, seq: u16) -> [u8; 64] {
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
