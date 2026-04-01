use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

use crate::{ConfigError, agents_path, save_toml_secure};

pub const DEFAULT_AGENT_PROFILE: &str = "default";
pub const AGENT_PROFILE_ENV: &str = "KITE_PROFILE";
pub const AGENT_ACCESS_KEY_ID_ENV: &str = "KITE_AGENT_ACCESS_KEY_ID";
pub const AGENT_KEY_PATH_ENV: &str = "KITE_AGENT_KEY_PATH";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AgentIdentity {
    pub name: String,
    pub access_key_id: String,
    pub private_key_path: String,
    pub public_key_hex: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct AgentRegistry {
    pub active_profile: Option<String>,
    #[serde(default)]
    pub agents: Vec<AgentIdentity>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentEnvironmentOverride {
    pub access_key_id: String,
    pub private_key_path: String,
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
        Self::load(&agents_path())
    }

    pub fn save(&self, path: &Path) -> Result<(), ConfigError> {
        save_toml_secure(self, path)
    }

    pub fn save_default(&self) -> Result<(), ConfigError> {
        self.save(&agents_path())
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

pub fn env_agent_override() -> Result<Option<AgentEnvironmentOverride>, ConfigError> {
    let access_key_id = std::env::var(AGENT_ACCESS_KEY_ID_ENV)
        .ok()
        .filter(|value| !value.is_empty());
    let private_key_path = std::env::var(AGENT_KEY_PATH_ENV)
        .ok()
        .filter(|value| !value.is_empty());
    match (access_key_id, private_key_path) {
        (Some(access_key_id), Some(private_key_path)) => Ok(Some(AgentEnvironmentOverride {
            access_key_id,
            private_key_path,
        })),
        (None, None) => Ok(None),
        _ => Err(ConfigError::IncompleteAgentEnvironmentOverride),
    }
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
    use tempfile::tempdir;

    #[test]
    fn registry_round_trip_persists_agents_and_active_profile() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("agents.toml");
        let mut registry = AgentRegistry::default();
        registry
            .upsert(AgentIdentity {
                name: "default".to_string(),
                access_key_id: "aak_123".to_string(),
                private_key_path: "/tmp/default.pem".to_string(),
                public_key_hex: "abc".to_string(),
            })
            .unwrap();
        registry.active_profile = Some("default".to_string());

        registry.save(&path).unwrap();
        let loaded = AgentRegistry::load(&path).unwrap();
        assert_eq!(loaded.active_profile.as_deref(), Some("default"));
        assert_eq!(loaded.agents.len(), 1);
        assert_eq!(loaded.agents[0].access_key_id, "aak_123");
    }

    #[test]
    fn remove_profile_moves_active_profile_to_default_or_first_remaining() {
        let mut registry = AgentRegistry {
            active_profile: Some("bot".to_string()),
            agents: vec![
                AgentIdentity {
                    name: "default".to_string(),
                    access_key_id: "aak_default".to_string(),
                    private_key_path: "/tmp/default.pem".to_string(),
                    public_key_hex: "abc".to_string(),
                },
                AgentIdentity {
                    name: "bot".to_string(),
                    access_key_id: "aak_bot".to_string(),
                    private_key_path: "/tmp/bot.pem".to_string(),
                    public_key_hex: "def".to_string(),
                },
            ],
        };

        registry.remove_profile("bot").unwrap();
        assert_eq!(registry.active_profile.as_deref(), Some("default"));
    }

    #[test]
    fn env_override_requires_both_fields() {
        unsafe {
            std::env::set_var(AGENT_ACCESS_KEY_ID_ENV, "aak_env");
            std::env::remove_var(AGENT_KEY_PATH_ENV);
        }
        let err = env_agent_override().unwrap_err();
        assert!(matches!(
            err,
            ConfigError::IncompleteAgentEnvironmentOverride
        ));
        unsafe {
            std::env::remove_var(AGENT_ACCESS_KEY_ID_ENV);
        }
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
