/// Client-side cryptographic operations for the Kitepass CLI.
///
/// - Ed25519 Agent Access Key generation and signing (agent proof)
/// - HPKE for wallet import envelope encryption
pub mod agent_key;
pub mod envelope;

pub use kap_hpke_shared as hpke;
