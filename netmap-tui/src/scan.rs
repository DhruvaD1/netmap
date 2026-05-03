//! background scan worker

use netmap_core::discovery::engine::{self, ScanConfig, ScanResult};
use netmap_core::fingerprint::mac_vendor::OuiDatabase;
use pnet::datalink::NetworkInterface;
use std::net::Ipv4Addr;
use std::sync::mpsc::Sender;
use std::sync::Arc;
use std::thread;

pub struct ScanContext {
    pub interface: NetworkInterface,
    pub targets: Vec<Ipv4Addr>,
    pub oui_db: Option<Arc<OuiDatabase>>,
    pub config: ScanConfig,
}

pub enum ScanEvent {
    Started,
    Completed(ScanResult),
    Failed(String),
}

pub fn trigger(ctx: Arc<ScanContext>, tx: Sender<ScanEvent>) {
    thread::spawn(move || {
        let _ = tx.send(ScanEvent::Started);
        let oui_ref = ctx.oui_db.as_deref();
        let result = engine::full_scan(&ctx.interface, &ctx.targets, oui_ref, &ctx.config);
        let _ = match result {
            Ok(r) => tx.send(ScanEvent::Completed(r)),
            Err(e) => tx.send(ScanEvent::Failed(e.to_string())),
        };
    });
}
