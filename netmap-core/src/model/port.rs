//! port and service representation

#[derive(Debug, Clone)]
pub struct PortInfo {
    pub port: u16,
    pub state: PortState,
    pub service: Option<ServiceInfo>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PortState {
    Open,
    Closed,
    Filtered,
}

#[derive(Debug, Clone)]
pub struct ServiceInfo {
    pub name: String,
    pub version: Option<String>,
    pub banner: Option<String>,
}
