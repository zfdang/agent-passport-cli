/// Client-side cryptographic operations for the Kitepass CLI.
///
/// - Ed25519 Agent Access Key generation and signing (agent proof)
/// - X25519 ECDH for wallet import envelope encryption
/// - AES-256-GCM envelope encryption/decryption
pub mod agent_key;
pub mod ecdh;
pub mod envelope;
