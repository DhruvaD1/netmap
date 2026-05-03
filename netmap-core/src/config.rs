//! optional toml config file

use serde::Deserialize;
use std::path::{Path, PathBuf};

#[derive(Debug, Deserialize, Default)]
pub struct Config {
    pub interface: Option<String>,
    pub cidr: Option<String>,
    pub timeout_secs: Option<u64>,
    pub daemon_interval_secs: Option<u64>,
    pub oui_path: Option<String>,
    pub log_path: Option<String>,
    pub traceroute_target: Option<String>,
    pub fingerprint: Option<bool>,
}

impl Config {
    pub fn load(path: &Path) -> std::io::Result<Self> {
        let s = std::fs::read_to_string(path)?;
        toml::from_str(&s)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()))
    }

    pub fn default_path() -> Option<PathBuf> {
        let home = std::env::var_os("HOME")?;
        let mut p = PathBuf::from(home);
        p.push(".config/netmap/config.toml");
        Some(p)
    }
}
