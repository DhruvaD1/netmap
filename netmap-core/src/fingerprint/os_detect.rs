//! os family inference from icmp ttl

use crate::model::os::OsFingerprint;

pub fn from_ttl(ttl: u8) -> OsFingerprint {
    let (family, confidence) = match ttl {
        60..=64 => ("Linux / macOS / BSD", 0.75),
        120..=128 => ("Windows", 0.80),
        240..=255 => ("Cisco / Solaris / IoT", 0.65),
        30..=32 => ("Legacy Windows", 0.50),
        _ => ("Unknown", 0.10),
    };

    OsFingerprint {
        family: family.into(),
        confidence,
        ttl,
    }
}
