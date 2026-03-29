use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Local CLI configuration.
///
/// Stored at `~/.config/kitepass/config.toml`.
#[derive(Debug, Serialize, Deserialize, Default)]
pub struct CliConfig {
    pub api_url: Option<String>,
    pub default_chain: Option<String>,
}

/// Returns the default config directory path.
pub fn config_dir() -> PathBuf {
    dirs::config_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("kitepass")
}

/// Returns the default config file path.
pub fn config_path() -> PathBuf {
    config_dir().join("config.toml")
}
