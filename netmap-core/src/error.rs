//! netmap error types

use thiserror::Error;

#[derive(Debug, Error)]
pub enum NetmapError {
    #[error("interface '{0}' not found")]
    InterfaceNotFound(String),

    #[error("need root: run with sudo or setcap cap_net_raw+ep on the binary")]
    PermissionDenied,

    #[error("arp scan failed: {0}")]
    ArpScan(String),

    #[error("no ipv4 address on interface '{0}'")]
    NoIpv4(String),

    #[error(transparent)]
    Io(#[from] std::io::Error),
}

pub type Result<T> = std::result::Result<T, NetmapError>;
