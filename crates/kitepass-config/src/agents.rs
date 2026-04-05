use kitepass_crypto::encryption::CryptoEnvelope;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

use crate::{agents_path, save_toml_secure, ConfigError};

pub const DEFAULT_AGENT_PROFILE: &str = "default";
pub const AGENT_PROFILE_ENV: &str = "KITE_PROFILE";
pub const PASSPORT_TOKEN_ENV: &str = "KITE_PASSPORT_TOKEN";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AgentIdentity {
    pub name: String,
    pub passport_id: String,
    pub public_key_hex: String,
    pub encrypted_key: CryptoEnvelope,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct AgentRegistry {
    pub active_profile: Option<String>,
    #[serde(default)]
    pub agents: Vec<AgentIdentity>,
}

/// Returns the Passport Token from `KITE_PASSPORT_TOKEN`, if set.
pub fn env_passport_token() -> Option<String> {
    std::env::var(PASSPORT_TOKEN_ENV)
        .ok()
        .filter(|value| !value.is_empty())
}

impl AgentRegistry {
    pub fn load(path: &Path) -> Result<Self, ConfigError> {
        if !path.exists() {
            return Ok(Self::default());
        }
        let content = fs::read_to_string(path)?;
        Ok(toml::from_str(&content)?)
    }

    pub fn load_default() -> Result<Self, ConfigError> {
        Self::load(&agents_path()?)
    }

    pub fn save(&self, path: &Path) -> Result<(), ConfigError> {
        save_toml_secure(self, path)
    }

    pub fn save_default(&self) -> Result<(), ConfigError> {
        self.save(&agents_path()?)
    }

    pub fn selected_profile_name(&self) -> String {
        std::env::var(AGENT_PROFILE_ENV)
            .ok()
            .filter(|value| !value.is_empty())
            .or_else(|| self.active_profile.clone())
            .unwrap_or_else(|| DEFAULT_AGENT_PROFILE.to_string())
    }

    pub fn get(&self, name: &str) -> Option<&AgentIdentity> {
        self.agents.iter().find(|agent| agent.name == name)
    }

    pub fn get_by_passport_id(&self, passport_id: &str) -> Option<&AgentIdentity> {
        self.agents
            .iter()
            .find(|agent| agent.passport_id == passport_id)
    }

    pub fn upsert(&mut self, agent: AgentIdentity) -> Result<(), ConfigError> {
        validate_profile_name(&agent.name)?;
        if let Some(existing) = self
            .agents
            .iter_mut()
            .find(|existing| existing.name == agent.name)
        {
            *existing = agent;
        } else {
            self.agents.push(agent);
        }
        self.agents
            .sort_by(|left, right| left.name.cmp(&right.name));
        Ok(())
    }

    pub fn set_active_profile(&mut self, name: &str) -> Result<(), ConfigError> {
        validate_profile_name(name)?;
        if self.get(name).is_none() {
            return Err(ConfigError::ProfileNotFound(name.to_string()));
        }
        self.active_profile = Some(name.to_string());
        Ok(())
    }

    pub fn remove_profile(&mut self, name: &str) -> Result<AgentIdentity, ConfigError> {
        let Some(index) = self.agents.iter().position(|agent| agent.name == name) else {
            return Err(ConfigError::ProfileNotFound(name.to_string()));
        };
        let removed = self.agents.remove(index);
        if self.active_profile.as_deref() == Some(name) {
            self.active_profile = self
                .get(DEFAULT_AGENT_PROFILE)
                .map(|agent| agent.name.clone())
                .or_else(|| self.agents.first().map(|agent| agent.name.clone()));
        }
        Ok(removed)
    }

    pub fn resolve_active_agent(&self) -> Result<AgentIdentity, ConfigError> {
        let profile_name = self.selected_profile_name();
        self.get(&profile_name)
            .cloned()
            .ok_or(ConfigError::ProfileNotFound(profile_name))
    }
}

pub fn load_agent_registry_default() -> Result<AgentRegistry, ConfigError> {
    AgentRegistry::load_default()
}

pub fn validate_profile_name(name: &str) -> Result<(), ConfigError> {
    if name.trim().is_empty() {
        return Err(ConfigError::InvalidProfileName(
            "profile name must not be empty".to_string(),
        ));
    }
    if name.chars().any(char::is_whitespace) {
        return Err(ConfigError::InvalidProfileName(
            "profile name must not contain whitespace".to_string(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use kitepass_crypto::encryption::CryptoEnvelope;
    use tempfile::tempdir;

    fn test_envelope() -> CryptoEnvelope {
        CryptoEnvelope::encrypt(b"test-key-data", "test_secret").unwrap()
    }

    #[test]
    fn registry_round_trip_persists_agents_and_active_profile() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("agents.toml");
        let mut registry = AgentRegistry::default();
        registry
            .upsert(AgentIdentity {
                name: "default".to_string(),
                passport_id: "agp_123".to_string(),
                public_key_hex: "abc".to_string(),
                encrypted_key: test_envelope(),
            })
            .unwrap();
        registry.active_profile = Some("default".to_string());

        registry.save(&path).unwrap();
        let loaded = AgentRegistry::load(&path).unwrap();
        assert_eq!(loaded.active_profile.as_deref(), Some("default"));
        assert_eq!(loaded.agents.len(), 1);
        assert_eq!(loaded.agents[0].passport_id, "agp_123");
    }

    #[test]
    fn remove_profile_moves_active_profile_to_default_or_first_remaining() {
        let mut registry = AgentRegistry {
            active_profile: Some("bot".to_string()),
            agents: vec![
                AgentIdentity {
                    name: "default".to_string(),
                    passport_id: "agp_default".to_string(),
                    public_key_hex: "abc".to_string(),
                    encrypted_key: test_envelope(),
                },
                AgentIdentity {
                    name: "bot".to_string(),
                    passport_id: "agp_bot".to_string(),
                    public_key_hex: "def".to_string(),
                    encrypted_key: test_envelope(),
                },
            ],
        };

        registry.remove_profile("bot").unwrap();
        assert_eq!(registry.active_profile.as_deref(), Some("default"));
    }

    #[test]
    fn env_agent_token_returns_none_when_unset() {
        unsafe {
            std::env::remove_var(PASSPORT_TOKEN_ENV);
        }
        assert!(env_passport_token().is_none());
    }

    #[test]
    fn selected_profile_prefers_environment() {
        let registry = AgentRegistry {
            active_profile: Some("default".to_string()),
            agents: Vec::new(),
        };
        unsafe {
            std::env::set_var(AGENT_PROFILE_ENV, "trading_bot");
        }
        assert_eq!(registry.selected_profile_name(), "trading_bot");
        unsafe {
            std::env::remove_var(AGENT_PROFILE_ENV);
        }
    }
}
