//! topology change events

use chrono::{DateTime, Utc};
use std::net::Ipv4Addr;

#[derive(Debug, Clone)]
pub struct EventLogEntry {
    pub timestamp: DateTime<Utc>,
    pub kind: EventKind,
}

impl EventLogEntry {
    pub fn now(kind: EventKind) -> Self {
        Self {
            timestamp: Utc::now(),
            kind,
        }
    }
}

#[derive(Debug, Clone)]
pub enum EventKind {
    DeviceAdded {
        ip: Ipv4Addr,
        vendor: Option<String>,
    },
    DeviceRemoved {
        ip: Ipv4Addr,
    },
    PortOpened {
        ip: Ipv4Addr,
        port: u16,
    },
    PortClosed {
        ip: Ipv4Addr,
        port: u16,
    },
    ScanCompleted {
        device_count: usize,
        duration_ms: u64,
    },
    Error {
        message: String,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Severity {
    Info,
    Notice,
    Warn,
    Error,
}

impl EventKind {
    pub fn severity(&self) -> Severity {
        match self {
            Self::DeviceAdded { .. } => Severity::Notice,
            Self::DeviceRemoved { .. } => Severity::Warn,
            Self::PortOpened { .. } => Severity::Notice,
            Self::PortClosed { .. } => Severity::Info,
            Self::ScanCompleted { .. } => Severity::Info,
            Self::Error { .. } => Severity::Error,
        }
    }

    pub fn tag(&self) -> &'static str {
        match self {
            Self::DeviceAdded { .. } => "+ new",
            Self::DeviceRemoved { .. } => "- gone",
            Self::PortOpened { .. } => "▲ port",
            Self::PortClosed { .. } => "▼ port",
            Self::ScanCompleted { .. } => "✓ scan",
            Self::Error { .. } => "× error",
        }
    }

    pub fn message(&self) -> String {
        match self {
            Self::DeviceAdded { ip, vendor } => match vendor {
                Some(v) => format!("{}  ({})", ip, v),
                None => format!("{}  (unknown)", ip),
            },
            Self::DeviceRemoved { ip } => ip.to_string(),
            Self::PortOpened { ip, port } => format!("{}  opened {}/tcp", ip, port),
            Self::PortClosed { ip, port } => format!("{}  closed {}/tcp", ip, port),
            Self::ScanCompleted {
                device_count,
                duration_ms,
            } => format!("{} devices in {}ms", device_count, duration_ms),
            Self::Error { message } => message.clone(),
        }
    }
}
