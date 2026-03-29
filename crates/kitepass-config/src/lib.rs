use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum ConfigError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("TOML format error: {0}")]
    Toml(#[from] toml::de::Error),
    #[error("TOML serialization error: {0}")]
    TomlSer(#[from] toml::ser::Error),
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
    /// Creates directories if they don't exist and sets 0600 permissions on unix systems.
    pub fn save(&self, path: &Path) -> Result<(), ConfigError> {
        if let Some(parent) = path.parent()
            && !parent.exists()
        {
            fs::create_dir_all(parent)?;
        }

        let content = toml::to_string(self)?;

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

    /// Saves the configuration to the default path.
    pub fn save_default(&self) -> Result<(), ConfigError> {
        self.save(&config_path())
    }
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
            ..Default::default()
        };

        conf.save(&path).unwrap();

        let loaded = CliConfig::load(&path).unwrap();
        assert_eq!(loaded.access_token.as_deref(), Some("test_token_123"));
    }
}
