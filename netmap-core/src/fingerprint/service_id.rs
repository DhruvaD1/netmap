//! banner grabbing for common services

use crate::model::port::ServiceInfo;
use std::io::{Read, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpStream};
use std::time::Duration;

pub fn identify(host: Ipv4Addr, port: u16, timeout: Duration) -> Option<ServiceInfo> {
    match port {
        22 => grab_ssh(host, timeout),
        80 | 8080 => grab_http(host, port, timeout),
        21 => grab_simple(host, port, "ftp", timeout),
        25 | 587 => grab_simple(host, port, "smtp", timeout),
        110 => grab_simple(host, port, "pop3", timeout),
        143 => grab_simple(host, port, "imap", timeout),
        443 | 8443 => Some(ServiceInfo {
            name: "https".into(),
            version: None,
            banner: None,
        }),
        53 => Some(ServiceInfo {
            name: "dns".into(),
            version: None,
            banner: None,
        }),
        445 => Some(ServiceInfo {
            name: "smb".into(),
            version: None,
            banner: None,
        }),
        631 => Some(ServiceInfo {
            name: "ipp".into(),
            version: None,
            banner: None,
        }),
        3389 => Some(ServiceInfo {
            name: "rdp".into(),
            version: None,
            banner: None,
        }),
        5353 => Some(ServiceInfo {
            name: "mdns".into(),
            version: None,
            banner: None,
        }),
        _ => None,
    }
}

fn open_stream(host: Ipv4Addr, port: u16, timeout: Duration) -> Option<TcpStream> {
    let addr = SocketAddr::new(host.into(), port);
    let stream = TcpStream::connect_timeout(&addr, timeout).ok()?;
    stream.set_read_timeout(Some(timeout)).ok()?;
    stream.set_write_timeout(Some(timeout)).ok()?;
    Some(stream)
}

fn grab_ssh(host: Ipv4Addr, timeout: Duration) -> Option<ServiceInfo> {
    let mut stream = open_stream(host, 22, timeout)?;
    let mut buf = [0u8; 256];
    let n = stream.read(&mut buf).ok()?;
    let banner = std::str::from_utf8(&buf[..n]).ok()?.trim();

    let version = banner
        .strip_prefix("SSH-2.0-")
        .or_else(|| banner.strip_prefix("SSH-1.99-"))
        .map(|s| s.split_whitespace().next().unwrap_or(s).to_string());

    Some(ServiceInfo {
        name: "ssh".into(),
        version,
        banner: Some(banner.to_string()),
    })
}

fn grab_http(host: Ipv4Addr, port: u16, timeout: Duration) -> Option<ServiceInfo> {
    let mut stream = open_stream(host, port, timeout)?;
    let req = format!(
        "GET / HTTP/1.0\r\nHost: {}\r\nUser-Agent: netmap\r\n\r\n",
        host
    );
    stream.write_all(req.as_bytes()).ok()?;

    let mut buf = vec![0u8; 2048];
    let n = stream.read(&mut buf).ok()?;
    let response = std::str::from_utf8(&buf[..n]).ok()?;

    let server = response
        .lines()
        .find(|l| l.to_lowercase().starts_with("server:"))
        .and_then(|l| l.splitn(2, ':').nth(1))
        .map(|s| s.trim().to_string());

    Some(ServiceInfo {
        name: "http".into(),
        version: server.clone(),
        banner: server,
    })
}

fn grab_simple(host: Ipv4Addr, port: u16, name: &str, timeout: Duration) -> Option<ServiceInfo> {
    let mut stream = open_stream(host, port, timeout)?;
    let mut buf = [0u8; 256];
    let n = stream.read(&mut buf).ok()?;
    let banner = std::str::from_utf8(&buf[..n]).ok()?.trim().to_string();

    Some(ServiceInfo {
        name: name.into(),
        version: None,
        banner: if banner.is_empty() { None } else { Some(banner) },
    })
}
