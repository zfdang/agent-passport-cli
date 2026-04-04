use ed25519_dalek::{
    pkcs8::{DecodePrivateKey, EncodePrivateKey},
    Signature, Signer, SigningKey, VerifyingKey,
};
use rand::rngs::OsRng;
use zeroize::Zeroizing;

#[derive(Debug, thiserror::Error)]
pub enum AgentKeyError {
    #[error("Key serialization error: {0}")]
    SerializationError(String),
    #[error("Key parse error: {0}")]
    ParseError(String),
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

    /// Loads an agent key from PKCS#8 PEM.
    pub fn from_pem(pem: &str) -> Result<Self, AgentKeyError> {
        let signing_key = SigningKey::from_pkcs8_pem(pem)
            .map_err(|e| AgentKeyError::ParseError(e.to_string()))?;
        Ok(Self { signing_key })
    }

    /// Exports the private key in PKCS#8 PEM format.
    /// The returned string is wrapped in Zeroizing to ensure memory cleanup.
    pub fn export_pem(&self) -> Result<Zeroizing<String>, AgentKeyError> {
        let doc = self
            .signing_key
            .to_pkcs8_pem(Default::default())
            .map_err(|e| AgentKeyError::SerializationError(e.to_string()))?;
        Ok(Zeroizing::new(doc.to_string()))
    }

    /// Signs the provided message bytes and returns the raw signature bytes.
    pub fn sign_bytes(&self, message: &[u8]) -> Signature {
        self.signing_key.sign(message)
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

    #[test]
    fn test_roundtrip_from_pem_and_sign() {
        let key = AgentKey::generate();
        let pem = key.export_pem().unwrap();
        let loaded = AgentKey::from_pem(&pem).unwrap();
        let sig = loaded.sign_bytes(b"hello");
        assert_eq!(sig.to_bytes().len(), 64);
    }
}
