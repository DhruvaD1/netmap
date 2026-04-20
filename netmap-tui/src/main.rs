//! netmap - network topology mapper

use anyhow::{Context, Result};
use clap::Parser;
use ipnetwork::Ipv4Network;
use netmap_core::discovery::arp;
use std::time::Duration;

#[derive(Parser)]
#[command(name = "netmap", about = "network topology mapper")]
struct Args {
    #[arg(short, long, help = "network interface to scan on")]
    interface: Option<String>,

    #[arg(short, long, help = "target subnet, e.g. 192.168.1.0/24")]
    cidr: Option<Ipv4Network>,

    #[arg(short, long, default_value = "3", help = "arp timeout in seconds")]
    timeout: u64,
}

fn main() -> Result<()> {
    let args = Args::parse();

    let iface = match &args.interface {
        Some(name) => arp::get_interface(name)?,
        None => arp::get_default_interface()?,
    };

    let cidr = match args.cidr {
        Some(c) => c,
        None => iface
            .ips
            .iter()
            .find_map(|net| match net {
                ipnetwork::IpNetwork::V4(v4) => Some(*v4),
                _ => None,
            })
            .context("no ipv4 network on interface")?,
    };

    let mac_str = iface
        .mac
        .map(|m| m.to_string())
        .unwrap_or_else(|| "??".into());

    println!("scanning {} on {} [{}]", cidr, iface.name, mac_str);

    let targets: Vec<_> = cidr
        .iter()
        .filter(|ip| *ip != cidr.network() && *ip != cidr.broadcast())
        .collect();

    println!("sending {} arp requests...\n", targets.len());

    let results = arp::scan(&iface, &targets, Duration::from_secs(args.timeout))?;

    if results.is_empty() {
        println!("no devices found");
        return Ok(());
    }

    println!("{} devices found:\n", results.len());
    println!("  {:<18} {}", "IP", "MAC");
    println!("  {:<18} {}", "──────────────────", "─────────────────");
    for r in &results {
        println!("  {:<18} {}", r.ip, r.mac);
    }

    Ok(())
}
