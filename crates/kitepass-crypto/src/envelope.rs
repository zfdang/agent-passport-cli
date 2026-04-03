use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce as GcmNonce}; // 12-byte nonce
use hkdf::Hkdf;
use rand::rngs::OsRng;
use rand::RngCore;
use sha2::Sha256;
use zeroize::Zeroizing;

const GCM_NONCE_LEN: usize = 12;
const GCM_TAG_LEN: usize = 16;

#[derive(Debug, thiserror::Error)]
pub enum EnvelopeError {
    #[error("Encryption failed")]
    EncryptionFailed,
    #[error("Decryption failed")]
    DecryptionFailed,
}

/// AES-256-GCM Envelope Encryption/Decryption.
pub struct Envelope;

impl Envelope {
    /// Encrypts `plaintext` using a 32-byte secret input expanded with HKDF-SHA256.
    /// The `vault_signer_pubkey` binds the resulting ciphertext to the intended recipient context.
    /// Returns the concatenated `nonce` (12 bytes) and ciphertext (including 16-byte auth tag).
    pub fn encrypt(
        shared_secret: &[u8; 32],
        vault_signer_pubkey: &[u8; 32],
        vault_nonce: &[u8; 32],
        plaintext: &[u8],
    ) -> Result<Vec<u8>, EnvelopeError> {
        // Derive key using HKDF-SHA256
        let hk = Hkdf::<Sha256>::new(Some(vault_nonce.as_ref()), shared_secret.as_ref());
        let mut okm = Zeroizing::new([0u8; 32]);
        hk.expand(vault_signer_pubkey.as_ref(), &mut okm)
            .map_err(|_| EnvelopeError::EncryptionFailed)?;

        let cipher = Aes256Gcm::new(okm.as_ref().into());

        // Generate a random 12-byte nonce
        let mut nonce_bytes = [0u8; GCM_NONCE_LEN];
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = GcmNonce::from_slice(&nonce_bytes);

        // Encrypt with associated data (the public key of vault signer)
        let payload = Payload {
            msg: plaintext,
            aad: vault_signer_pubkey.as_ref(),
        };

        let ciphertext = cipher
            .encrypt(nonce, payload)
            .map_err(|_| EnvelopeError::EncryptionFailed)?;

        // Output format: concat(nonce 12 bytes, ciphertext)
        let mut output = Vec::with_capacity(nonce_bytes.len() + ciphertext.len());
        output.extend_from_slice(&nonce_bytes);
        output.extend_from_slice(&ciphertext);

        Ok(output)
    }

    /// Decrypts a payload encrypted by the above method.
    pub fn decrypt(
        shared_secret: &[u8; 32],
        vault_signer_pubkey: &[u8; 32],
        vault_nonce: &[u8; 32],
        encrypted_payload: &[u8],
    ) -> Result<Vec<u8>, EnvelopeError> {
        if encrypted_payload.len() < GCM_NONCE_LEN + GCM_TAG_LEN {
            return Err(EnvelopeError::DecryptionFailed);
        }

        // Derive key
        let hk = Hkdf::<Sha256>::new(Some(vault_nonce.as_ref()), shared_secret.as_ref());
        let mut okm = Zeroizing::new([0u8; 32]);
        hk.expand(vault_signer_pubkey.as_ref(), &mut okm)
            .map_err(|_| EnvelopeError::DecryptionFailed)?;

        let cipher = Aes256Gcm::new(okm.as_ref().into());

        // The length guard above guarantees this split is safe and that
        // ciphertext still includes the required 16-byte GCM authentication tag.
        let (nonce_bytes, ciphertext) = encrypted_payload.split_at(GCM_NONCE_LEN);

        let nonce = GcmNonce::from_slice(nonce_bytes);
        let payload = Payload {
            msg: ciphertext,
            aad: vault_signer_pubkey.as_ref(),
        };

        cipher
            .decrypt(nonce, payload)
            .map_err(|_| EnvelopeError::DecryptionFailed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt() {
        let shared_secret = [1u8; 32];
        let pubkey = [2u8; 32];
        let vault_nonce = [3u8; 32];
        let plaintext = b"wallet-secret-data-12345";

        let encrypted =
            Envelope::encrypt(&shared_secret, &pubkey, &vault_nonce, plaintext).unwrap();
        assert_ne!(encrypted, plaintext);

        let decrypted =
            Envelope::decrypt(&shared_secret, &pubkey, &vault_nonce, &encrypted).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn decrypt_rejects_payload_shorter_than_nonce_and_tag() {
        let shared_secret = [1u8; 32];
        let pubkey = [2u8; 32];
        let vault_nonce = [3u8; 32];
        let encrypted = vec![0u8; GCM_NONCE_LEN + GCM_TAG_LEN - 1];

        let result = Envelope::decrypt(&shared_secret, &pubkey, &vault_nonce, &encrypted);
        assert!(matches!(result, Err(EnvelopeError::DecryptionFailed)));
    }
}
