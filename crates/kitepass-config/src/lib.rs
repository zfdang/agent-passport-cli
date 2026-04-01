pub mod agents;

use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};
use thiserror::Error;

pub use agents::{
    AGENT_ACCESS_KEY_ID_ENV, AGENT_KEY_PATH_ENV, AGENT_PROFILE_ENV, AgentEnvironmentOverride,
    AgentIdentity, AgentRegistry, DEFAULT_AGENT_PROFILE, env_agent_override,
    load_agent_registry_default, validate_profile_name,
};

pub const DEFAULT_API_URL: &str = "https://api.kitepass.xyz";

#[derive(Error, Debug)]
pub enum ConfigError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("TOML format error: {0}")]
    Toml(#[from] toml::de::Error),
    #[error("TOML serialization error: {0}")]
    TomlSer(#[from] toml::ser::Error),
    #[error("profile not found: {0}")]
    ProfileNotFound(String),
    #[error("invalid profile name: {0}")]
    InvalidProfileName(String),
    #[error(
        "{AGENT_ACCESS_KEY_ID_ENV} and {AGENT_KEY_PATH_ENV} must either both be set or both be unset"
    )]
    IncompleteAgentEnvironmentOverride,
}

/// Local CLI configuration.
///
/// Stored at `~/.config/kitepass/config.toml`.
#[derive(Debug, Serialize, Deserialize, Default, Clone)]
pub struct CliConfig {
    pub api_url: Option<String>,
    pub default_chain: Option<String>,
    pub access_token: Option<String>,
}

impl CliConfig {
    /// Loads the configuration from the specified path, or defaults if it doesn't exist.
    pub fn load(path: &Path) -> Result<Self, ConfigError> {
        if !path.exists() {
            return Ok(CliConfig::default());
        }
        let content = fs::read_to_string(path)?;
        let config: CliConfig = toml::from_str(&content)?;
        Ok(config)
    }

    /// Loads the configuration from the default path.
    pub fn load_default() -> Result<Self, ConfigError> {
        Self::load(&config_path())
    }

    /// Saves the configuration to the specified path safely.
    pub fn save(&self, path: &Path) -> Result<(), ConfigError> {
        save_toml_secure(self, path)
    }

    /// Saves the configuration to the default path.
    pub fn save_default(&self) -> Result<(), ConfigError> {
        self.save(&config_path())
    }

    /// Resolves the configured API URL or falls back to the default public endpoint.
    pub fn resolved_api_url(&self) -> &str {
        self.api_url.as_deref().unwrap_or(DEFAULT_API_URL)
    }
}

pub(crate) fn save_toml_secure<T: Serialize>(value: &T, path: &Path) -> Result<(), ConfigError> {
    if let Some(parent) = path.parent()
        && !parent.exists()
    {
        fs::create_dir_all(parent)?;
    }

    let content = toml::to_string(value)?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        let mut options = fs::OpenOptions::new();
        options.write(true).create(true).truncate(true).mode(0o600);
        let mut file = options.open(path)?;
        use std::io::Write;
        file.write_all(content.as_bytes())?;
    }

    #[cfg(not(unix))]
    {
        fs::write(path, content)?;
    }

    Ok(())
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

/// Returns the default agent registry path.
pub fn agents_path() -> PathBuf {
    config_dir().join("agents.toml")
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_load_save() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("config.toml");

        let conf = CliConfig {
            access_token: Some("test_token_123".to_string()),
            api_url: Some("https://api.example.test".to_string()),
            default_chain: Some("eip155:8453".to_string()),
        };

        conf.save(&path).unwrap();

        let loaded = CliConfig::load(&path).unwrap();
        assert_eq!(loaded.access_token.as_deref(), Some("test_token_123"));
        assert_eq!(loaded.api_url.as_deref(), Some("https://api.example.test"));
        assert_eq!(loaded.default_chain.as_deref(), Some("eip155:8453"));
    }
}
