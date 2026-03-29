use rand::rngs::OsRng;
use x25519_dalek::{PublicKey, StaticSecret};

#[derive(Debug, thiserror::Error)]
pub enum EcdhError {
    #[error("Invalid public key format")]
    InvalidPublicKey,
}

/// Represents an X25519 ephemeral keypair for wallet import.
pub struct EphemeralKey {
    secret: StaticSecret,
}

impl EphemeralKey {
    /// Generates a new ephemeral X25519 static secret.
    pub fn generate() -> Self {
        let csprng = OsRng;
        let secret = StaticSecret::random_from_rng(csprng);
        Self { secret }
    }

    /// Returns the public key associated with this ephemeral secret.
    pub fn public_key(&self) -> PublicKey {
        (&self.secret).into()
    }

    /// Performs ECDH key exchange with the given Vault Signer public key bytes,
    /// returning the computed shared secret bytes.
    pub fn diffie_hellman(&self, vault_signer_pubkey: &[u8; 32]) -> [u8; 32] {
        let vault_pk = PublicKey::from(*vault_signer_pubkey);
        let shared_secret = self.secret.diffie_hellman(&vault_pk);
        *shared_secret.as_bytes()
    }
}

impl Drop for EphemeralKey {
    fn drop(&mut self) {
        // x25519_dalek::StaticSecret implements Zeroize internally.
    }
}

pub fn parse_public_key(hex_str: &str) -> Result<[u8; 32], EcdhError> {
    let bytes = hex::decode(hex_str).map_err(|_| EcdhError::InvalidPublicKey)?;
    if bytes.len() != 32 {
        return Err(EcdhError::InvalidPublicKey);
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    Ok(arr)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ecdh_exchange() {
        let client_key = EphemeralKey::generate();
        let server_key = EphemeralKey::generate();

        let client_shared = client_key.diffie_hellman(server_key.public_key().as_bytes());
        let server_shared = server_key.diffie_hellman(client_key.public_key().as_bytes());

        assert_eq!(client_shared, server_shared);
    }
}
