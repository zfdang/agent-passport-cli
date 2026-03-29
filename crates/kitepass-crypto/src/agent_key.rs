use ed25519_dalek::{SigningKey, VerifyingKey, pkcs8::EncodePrivateKey};
use rand::rngs::OsRng;

#[derive(Debug, thiserror::Error)]
pub enum AgentKeyError {
    #[error("Key serialization error: {0}")]
    SerializationError(String),
}

/// Represents an Ed25519 Agent Access Key.
pub struct AgentKey {
    signing_key: SigningKey,
}

impl AgentKey {
    /// Generates a new random Ed25519 keypair.
    pub fn generate() -> Self {
        let mut csprng = OsRng;
        let signing_key = SigningKey::generate(&mut csprng);
        Self { signing_key }
    }

    /// Returns the public VerifyingKey associated with this agent key.
    pub fn public_key(&self) -> VerifyingKey {
        self.signing_key.verifying_key()
    }

    /// Returns the public key as a hex string for API registration.
    pub fn public_key_hex(&self) -> String {
        hex::encode(self.public_key().as_bytes())
    }

    /// Exports the private key in PKCS#8 PEM format.
    /// The private key should be zeroized after use.
    pub fn export_pem(&self) -> Result<String, AgentKeyError> {
        let doc = self.signing_key.to_pkcs8_pem(Default::default())
            .map_err(|e| AgentKeyError::SerializationError(e.to_string()))?;
        Ok(doc.to_string())
    }
}

impl Drop for AgentKey {
    fn drop(&mut self) {
        // ed25519_dalek::SigningKey implements Zeroize internally.
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_and_export() {
        let key = AgentKey::generate();
        let pub_hex = key.public_key_hex();
        assert_eq!(pub_hex.len(), 64);

        let pem = key.export_pem().unwrap();
        assert!(pem.contains("BEGIN PRIVATE KEY"));
    }
}
