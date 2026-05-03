//! network link representation

use uuid::Uuid;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinkType {
    Direct,
    Routed,
    Wireless,
}

#[derive(Debug, Clone)]
pub struct Link {
    pub source: Uuid,
    pub target: Uuid,
    pub link_type: LinkType,
}
