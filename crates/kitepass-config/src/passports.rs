use kitepass_crypto::encryption::CryptoEnvelope;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

use crate::{passports_path, save_toml_secure, ConfigError};

pub const PASSPORT_TOKEN_ENV: &str = "KITE_PASSPORT_TOKEN";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LocalPassportRecord {
    pub passport_id: String,
    pub public_key_hex: String,
    pub encrypted_key: CryptoEnvelope,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct LocalPassportRegistry {
    #[serde(default)]
    pub passports: Vec<LocalPassportRecord>,
}

/// Returns the Passport Token from `KITE_PASSPORT_TOKEN`, if set.
pub fn env_passport_token() -> Option<String> {
    std::env::var(PASSPORT_TOKEN_ENV)
        .ok()
        .filter(|value| !value.is_empty())
}

impl LocalPassportRegistry {
    pub fn load(path: &Path) -> Result<Self, ConfigError> {
        if !path.exists() {
            return Ok(Self::default());
        }
        let content = fs::read_to_string(path)?;
        Ok(toml::from_str(&content)?)
    }

    pub fn load_default() -> Result<Self, ConfigError> {
        Self::load(&passports_path()?)
    }

    pub fn save(&self, path: &Path) -> Result<(), ConfigError> {
        save_toml_secure(self, path)
    }

    pub fn save_default(&self) -> Result<(), ConfigError> {
        self.save(&passports_path()?)
    }

    pub fn get_by_passport_id(&self, passport_id: &str) -> Option<&LocalPassportRecord> {
        self.passports
            .iter()
            .find(|passport| passport.passport_id == passport_id)
    }

    pub fn upsert(&mut self, passport: LocalPassportRecord) -> Result<(), ConfigError> {
        validate_passport_id(&passport.passport_id)?;
        if let Some(existing) = self
            .passports
            .iter_mut()
            .find(|existing| existing.passport_id == passport.passport_id)
        {
            *existing = passport;
        } else {
            self.passports.push(passport);
        }
        self.passports
            .sort_by(|left, right| left.passport_id.cmp(&right.passport_id));
        Ok(())
    }

    pub fn remove_passport(
        &mut self,
        passport_id: &str,
    ) -> Result<LocalPassportRecord, ConfigError> {
        validate_passport_id(passport_id)?;
        let Some(index) = self
            .passports
            .iter()
            .position(|passport| passport.passport_id == passport_id)
        else {
            return Err(ConfigError::PassportNotFound(passport_id.to_string()));
        };
        Ok(self.passports.remove(index))
    }
}

pub fn load_local_passport_registry_default() -> Result<LocalPassportRegistry, ConfigError> {
    LocalPassportRegistry::load_default()
}

pub fn validate_passport_id(passport_id: &str) -> Result<(), ConfigError> {
    if passport_id.trim().is_empty() {
        return Err(ConfigError::InvalidPassportId(
            "passport_id must not be empty".to_string(),
        ));
    }
    if passport_id.chars().any(char::is_whitespace) {
        return Err(ConfigError::InvalidPassportId(
            "passport_id must not contain whitespace".to_string(),
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
    fn registry_round_trip_persists_passports() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("passports.toml");
        let mut registry = LocalPassportRegistry::default();
        registry
            .upsert(LocalPassportRecord {
                passport_id: "agp_123".to_string(),
                public_key_hex: "abc".to_string(),
                encrypted_key: test_envelope(),
            })
            .unwrap();

        registry.save(&path).unwrap();
        let loaded = LocalPassportRegistry::load(&path).unwrap();
        assert_eq!(loaded.passports.len(), 1);
        assert_eq!(loaded.passports[0].passport_id, "agp_123");
    }

    #[test]
    fn remove_passport_removes_matching_record() {
        let mut registry = LocalPassportRegistry {
            passports: vec![
                LocalPassportRecord {
                    passport_id: "agp_default".to_string(),
                    public_key_hex: "abc".to_string(),
                    encrypted_key: test_envelope(),
                },
                LocalPassportRecord {
                    passport_id: "agp_bot".to_string(),
                    public_key_hex: "def".to_string(),
                    encrypted_key: test_envelope(),
                },
            ],
        };

        let removed = registry.remove_passport("agp_bot").unwrap();
        assert_eq!(removed.passport_id, "agp_bot");
        assert_eq!(registry.passports.len(), 1);
        assert_eq!(registry.passports[0].passport_id, "agp_default");
    }

    #[test]
    fn env_passport_token_returns_none_when_unset() {
        unsafe {
            std::env::remove_var(PASSPORT_TOKEN_ENV);
        }
        assert!(env_passport_token().is_none());
    }

    #[test]
    fn upsert_replaces_existing_passport() {
        let mut registry = LocalPassportRegistry::default();
        registry
            .upsert(LocalPassportRecord {
                passport_id: "agp_x".to_string(),
                public_key_hex: "old_key".to_string(),
                encrypted_key: test_envelope(),
            })
            .unwrap();

        registry
            .upsert(LocalPassportRecord {
                passport_id: "agp_x".to_string(),
                public_key_hex: "new_key".to_string(),
                encrypted_key: test_envelope(),
            })
            .unwrap();

        assert_eq!(registry.passports.len(), 1);
        assert_eq!(registry.passports[0].public_key_hex, "new_key");
    }

    #[test]
    fn upsert_sorts_alphabetically() {
        let mut registry = LocalPassportRegistry::default();
        registry
            .upsert(LocalPassportRecord {
                passport_id: "agp_z".to_string(),
                public_key_hex: "z".to_string(),
                encrypted_key: test_envelope(),
            })
            .unwrap();
        registry
            .upsert(LocalPassportRecord {
                passport_id: "agp_a".to_string(),
                public_key_hex: "a".to_string(),
                encrypted_key: test_envelope(),
            })
            .unwrap();

        assert_eq!(registry.passports[0].passport_id, "agp_a");
        assert_eq!(registry.passports[1].passport_id, "agp_z");
    }

    #[test]
    fn remove_nonexistent_passport_returns_error() {
        let mut registry = LocalPassportRegistry::default();
        let result = registry.remove_passport("agp_missing");
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("passport not found"));
    }

    #[test]
    fn validate_passport_id_rejects_empty() {
        assert!(validate_passport_id("").is_err());
        assert!(validate_passport_id("   ").is_err());
    }

    #[test]
    fn validate_passport_id_rejects_whitespace() {
        assert!(validate_passport_id("agp 123").is_err());
        assert!(validate_passport_id("agp\t123").is_err());
    }

    #[test]
    fn validate_passport_id_accepts_valid() {
        assert!(validate_passport_id("agp_123").is_ok());
        assert!(validate_passport_id("agp_bot_v2").is_ok());
    }

    #[test]
    fn get_by_passport_id_returns_none_when_not_found() {
        let registry = LocalPassportRegistry::default();
        assert!(registry.get_by_passport_id("agp_missing").is_none());
    }

    #[test]
    fn load_empty_file_returns_default() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("passports.toml");
        std::fs::write(&path, "").unwrap();
        let registry = LocalPassportRegistry::load(&path).unwrap();
        assert!(registry.passports.is_empty());
    }
}
