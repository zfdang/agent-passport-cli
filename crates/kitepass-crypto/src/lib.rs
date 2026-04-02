/// Client-side cryptographic operations for the Kitepass CLI.
///
/// - Ed25519 Agent Access Key generation and signing (agent proof)
/// - HPKE for wallet import envelope encryption
/// - AES-256-GCM encryption for agent private keys (CryptoEnvelope)
pub mod agent_key;
pub mod encryption;
pub mod hpke;
