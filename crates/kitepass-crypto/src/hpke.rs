use hpke::{
    aead::AesGcm256, kdf::HkdfSha256, kem::X25519HkdfSha256, setup_receiver, setup_sender,
    Deserializable, Kem as KemTrait, OpModeR, OpModeS, Serializable,
};
use rand09::{rngs::StdRng, SeedableRng};
use zeroize::Zeroizing;

type ImportKem = X25519HkdfSha256;
type ImportKdf = HkdfSha256;
type ImportAead = AesGcm256;

pub const IMPORT_ENCRYPTION_SCHEME: &str = "hpke_base_x25519_hkdf_sha256_aes_256_gcm_v1";

#[derive(Debug, thiserror::Error)]
pub enum HpkeError {
    #[error("invalid HPKE key material")]
    InvalidKeyMaterial,
    #[error("HPKE setup failed")]
    SetupFailed,
    #[error("HPKE encryption failed")]
    EncryptionFailed,
    #[error("HPKE decryption failed")]
    DecryptionFailed,
}

#[derive(Debug, Clone)]
pub struct RecipientKeyPair {
    pub private_key_hex: Zeroizing<String>,
    pub public_key_hex: String,
}

#[derive(Debug, Clone)]
pub struct SealedMessage {
    pub encapsulated_key_hex: String,
    pub ciphertext_hex: String,
}

pub fn generate_recipient_keypair() -> RecipientKeyPair {
    let mut csprng = StdRng::from_os_rng();
    let (private_key, public_key) = ImportKem::gen_keypair(&mut csprng);
    RecipientKeyPair {
        private_key_hex: Zeroizing::new(hex::encode(private_key.to_bytes())),
        public_key_hex: hex::encode(public_key.to_bytes()),
    }
}

pub fn seal_to_hex(
    recipient_public_key_hex: &str,
    info: &[u8],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<SealedMessage, HpkeError> {
    let public_key_bytes =
        hex::decode(recipient_public_key_hex).map_err(|_| HpkeError::InvalidKeyMaterial)?;
    let public_key = <ImportKem as KemTrait>::PublicKey::from_bytes(&public_key_bytes)
        .map_err(|_| HpkeError::InvalidKeyMaterial)?;
    let mut csprng = StdRng::from_os_rng();

    let (encapsulated_key, mut encryption_context) =
        setup_sender::<ImportAead, ImportKdf, ImportKem, _>(
            &OpModeS::Base,
            &public_key,
            info,
            &mut csprng,
        )
        .map_err(|_| HpkeError::SetupFailed)?;

    let ciphertext = encryption_context
        .seal(plaintext, aad)
        .map_err(|_| HpkeError::EncryptionFailed)?;

    Ok(SealedMessage {
        encapsulated_key_hex: hex::encode(encapsulated_key.to_bytes()),
        ciphertext_hex: hex::encode(ciphertext),
    })
}

pub fn open_from_hex(
    recipient_private_key_hex: &str,
    encapsulated_key_hex: &str,
    ciphertext_hex: &str,
    info: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, HpkeError> {
    let private_key_bytes =
        hex::decode(recipient_private_key_hex).map_err(|_| HpkeError::InvalidKeyMaterial)?;
    let private_key = <ImportKem as KemTrait>::PrivateKey::from_bytes(&private_key_bytes)
        .map_err(|_| HpkeError::InvalidKeyMaterial)?;

    let encapsulated_key_bytes =
        hex::decode(encapsulated_key_hex).map_err(|_| HpkeError::InvalidKeyMaterial)?;
    let encapsulated_key =
        <ImportKem as KemTrait>::EncappedKey::from_bytes(&encapsulated_key_bytes)
            .map_err(|_| HpkeError::InvalidKeyMaterial)?;

    let ciphertext = hex::decode(ciphertext_hex).map_err(|_| HpkeError::InvalidKeyMaterial)?;
    let mut decryption_context = setup_receiver::<ImportAead, ImportKdf, ImportKem>(
        &OpModeR::Base,
        &private_key,
        &encapsulated_key,
        info,
    )
    .map_err(|_| HpkeError::SetupFailed)?;

    decryption_context
        .open(&ciphertext, aad)
        .map_err(|_| HpkeError::DecryptionFailed)
}

#[cfg(test)]
mod tests {
    use super::{generate_recipient_keypair, open_from_hex, seal_to_hex, IMPORT_ENCRYPTION_SCHEME};

    #[test]
    fn hpke_round_trip_succeeds() {
        let keypair = generate_recipient_keypair();
        let info = format!(
            r#"{{"scheme":"{}","session":"wis_123"}}"#,
            IMPORT_ENCRYPTION_SCHEME
        );
        let aad = br#"{"owner_id":"own_123","request_id":"req_123"}"#;
        let sealed = seal_to_hex(
            &keypair.public_key_hex,
            info.as_bytes(),
            aad,
            b"wallet-secret",
        )
        .expect("seal should succeed");

        let plaintext = open_from_hex(
            keypair.private_key_hex.as_str(),
            &sealed.encapsulated_key_hex,
            &sealed.ciphertext_hex,
            info.as_bytes(),
            aad,
        )
        .expect("open should succeed");

        assert_eq!(plaintext, b"wallet-secret");
    }
}
