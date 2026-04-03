pub mod agents;

use kitepass_crypto::encryption::{generate_secret_key, CryptoEnvelope, EncryptionError};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};
use thiserror::Error;

pub use agents::{
    env_agent_token, load_agent_registry_default, validate_profile_name, AgentIdentity,
    AgentRegistry, AGENT_PROFILE_ENV, AGENT_TOKEN_ENV, DEFAULT_AGENT_PROFILE,
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
    #[error("missing home/config directory for {0}")]
    MissingHomeDirectory(&'static str),
    #[error("invalid Combined Token format: expected kite_tk_<access_key_id>__<secret_key>")]
    InvalidToken,
    #[error("token encryption error: {0}")]
    Encryption(#[from] EncryptionError),
    #[error("invalid UTF-8 while decoding access token: {0}")]
    Utf8(#[from] std::string::FromUtf8Error),
}

/// Local CLI configuration.
///
/// Stored at `~/.config/kitepass/config.toml`.
#[derive(Debug, Serialize, Deserialize, Default, Clone)]
pub struct CliConfig {
    pub api_url: Option<String>,
    pub default_chain: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub access_token: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub encrypted_access_token: Option<CryptoEnvelope>,
}

impl CliConfig {
    /// Loads the configuration from the specified path, or defaults if it doesn't exist.
    pub fn load(path: &Path) -> Result<Self, ConfigError> {
        if !path.exists() {
            return Ok(CliConfig::default());
        }
        let content = fs::read_to_string(path)?;
        let mut config: CliConfig = toml::from_str(&content)?;
        if config.access_token.is_none() {
            if let Some(envelope) = &config.encrypted_access_token {
                let secret = load_access_token_secret(path)?;
                let token_bytes = envelope.decrypt(secret.trim())?;
                config.access_token = Some(String::from_utf8(token_bytes.to_vec())?);
            }
        }
        Ok(config)
    }

    /// Loads the configuration from the default path.
    pub fn load_default() -> Result<Self, ConfigError> {
        Self::load(&config_path()?)
    }

    /// Saves the configuration to the specified path safely.
    pub fn save(&self, path: &Path) -> Result<(), ConfigError> {
        let mut persisted = self.clone();
        if let Some(access_token) = &self.access_token {
            let secret = load_or_create_access_token_secret(path)?;
            persisted.encrypted_access_token = Some(CryptoEnvelope::encrypt(
                access_token.as_bytes(),
                secret.trim(),
            )?);
            persisted.access_token = None;
        }
        save_toml_secure(&persisted, path)
    }

    /// Saves the configuration to the default path.
    pub fn save_default(&self) -> Result<(), ConfigError> {
        self.save(&config_path()?)
    }

    /// Resolves the configured API URL or falls back to the default public endpoint.
    pub fn resolved_api_url(&self) -> &str {
        self.api_url.as_deref().unwrap_or(DEFAULT_API_URL)
    }
}

pub(crate) fn save_toml_secure<T: Serialize>(value: &T, path: &Path) -> Result<(), ConfigError> {
    if let Some(parent) = path.parent() {
        if !parent.exists() {
            fs::create_dir_all(parent)?;
        }
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

fn access_token_secret_path(config_path: &Path) -> PathBuf {
    config_path.with_file_name("access-token.secret")
}

fn load_access_token_secret(config_path: &Path) -> Result<String, ConfigError> {
    Ok(fs::read_to_string(access_token_secret_path(config_path))?)
}

fn load_or_create_access_token_secret(config_path: &Path) -> Result<String, ConfigError> {
    let secret_path = access_token_secret_path(config_path);
    if secret_path.exists() {
        return Ok(fs::read_to_string(secret_path)?);
    }

    let secret = generate_secret_key();
    save_bytes_secure(secret.as_bytes(), &secret_path)?;
    Ok(secret.to_string())
}

fn save_bytes_secure(contents: &[u8], path: &Path) -> Result<(), ConfigError> {
    if let Some(parent) = path.parent() {
        if !parent.exists() {
            fs::create_dir_all(parent)?;
        }
    }

    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;

        let mut options = fs::OpenOptions::new();
        options.write(true).create(true).truncate(true).mode(0o600);
        let mut file = options.open(path)?;
        file.write_all(contents)?;
    }

    #[cfg(not(unix))]
    {
        fs::write(path, contents)?;
    }

    Ok(())
}

/// Returns the default config directory path.
pub fn config_dir() -> Result<PathBuf, ConfigError> {
    dirs::config_dir()
        .map(|path| path.join("kitepass"))
        .ok_or(ConfigError::MissingHomeDirectory("CLI config"))
}

/// Returns the local agent profile directory path.
pub fn agents_dir() -> Result<PathBuf, ConfigError> {
    dirs::home_dir()
        .map(|path| path.join(".kitepass"))
        .ok_or(ConfigError::MissingHomeDirectory("agent registry"))
}

/// Returns the default config file path.
pub fn config_path() -> Result<PathBuf, ConfigError> {
    Ok(config_dir()?.join("config.toml"))
}

/// Returns the default agent registry path.
pub fn agents_path() -> Result<PathBuf, ConfigError> {
    Ok(agents_dir()?.join("agents.toml"))
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
            encrypted_access_token: None,
        };

        conf.save(&path).unwrap();

        let raw = fs::read_to_string(&path).unwrap();
        assert!(!raw.contains("test_token_123"));
        assert!(raw.contains("encrypted_access_token"));
        assert!(dir.path().join("access-token.secret").exists());

        let loaded = CliConfig::load(&path).unwrap();
        assert_eq!(loaded.access_token.as_deref(), Some("test_token_123"));
        assert_eq!(loaded.api_url.as_deref(), Some("https://api.example.test"));
        assert_eq!(loaded.default_chain.as_deref(), Some("eip155:8453"));
        assert!(loaded.encrypted_access_token.is_some());
    }

    #[test]
    fn test_load_legacy_plaintext_access_token() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("config.toml");
        fs::write(
            &path,
            r#"
api_url = "https://api.example.test"
default_chain = "eip155:8453"
access_token = "legacy_token_123"
"#,
        )
        .unwrap();

        let loaded = CliConfig::load(&path).unwrap();
        assert_eq!(loaded.access_token.as_deref(), Some("legacy_token_123"));
        assert!(loaded.encrypted_access_token.is_none());
    }
}
