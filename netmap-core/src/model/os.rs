//! os fingerprint representation

#[derive(Debug, Clone)]
pub struct OsFingerprint {
    pub family: String,
    pub confidence: f32,
    pub ttl: u8,
}
