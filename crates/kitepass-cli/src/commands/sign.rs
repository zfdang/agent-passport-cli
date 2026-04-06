use crate::commands::{load_cli_config, load_local_passport_registry};
use crate::runtime::Runtime;
use anyhow::{bail, Context, Result};
use kitepass_api_client::{
    AgentProof, CreateSessionChallengeRequest, CreateSessionRequest, PassportClient, SignRequest,
    SigningMode, ValidateAgentProof, ValidateSignIntentRequest,
};
use kitepass_config::{env_passport_token, LocalPassportRegistry, PASSPORT_TOKEN_ENV};
use kitepass_crypto::agent_key::AgentKey;
use kitepass_crypto::encryption::PassportToken;
use serde::Serialize;
use serde_json::json;
use sha2::{Digest, Sha256};
use uuid::Uuid;

pub struct SignArgs {
    pub validate: bool,
    pub broadcast: bool,
    pub passport_id: Option<String>,
    pub wallet_id: Option<String>,
    pub chain_id: String,
    pub signing_type: String,
    pub payload: String,
    pub destination: String,
    pub value: String,
}

struct CanonicalSignIntent<'a> {
    request_id: &'a str,
    resolved_wallet_id: &'a str,
    passport_id: &'a str,
    chain_id: &'a str,
    signing_type: &'a str,
    payload: &'a str,
    destination: &'a str,
    value: &'a str,
    session_nonce: &'a str,
    mode: &'a str,
}

struct CanonicalValidateIntent<'a> {
    request_id: &'a str,
    passport_id: &'a str,
    wallet_id: Option<&'a str>,
    wallet_selector: Option<&'a str>,
    chain_id: &'a str,
    signing_type: &'a str,
    payload: &'a str,
    destination: &'a str,
    value: &'a str,
}

struct CanonicalSessionCreate<'a> {
    request_id: &'a str,
    passport_id: &'a str,
    challenge_id: &'a str,
    challenge_nonce: &'a str,
}

#[derive(Serialize)]
struct CanonicalAgentIntent<'a> {
    #[serde(rename = "type")]
    intent_type: &'a str,
    #[serde(rename = "version")]
    intent_version: u32,
    request_id: &'a str,
    wallet_id: &'a str,
    passport_id: &'a str,
    chain_id: &'a str,
    signing_type: &'a str,
    payload_hash: &'a str,
    destination: &'a str,
    value: &'a str,
    session_nonce: &'a str,
    mode: &'a str,
}

#[derive(Serialize)]
struct CanonicalValidateProof<'a> {
    #[serde(rename = "type")]
    intent_type: &'a str,
    #[serde(rename = "version")]
    intent_version: u32,
    request_id: &'a str,
    passport_id: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    wallet_id: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    wallet_selector: Option<&'a str>,
    chain_id: &'a str,
    signing_type: &'a str,
    payload_hash: &'a str,
    destination: &'a str,
    value: &'a str,
}

#[derive(Serialize)]
struct CanonicalSessionCreateProof<'a> {
    #[serde(rename = "type")]
    intent_type: &'a str,
    #[serde(rename = "version")]
    intent_version: u32,
    request_id: &'a str,
    passport_id: &'a str,
    challenge_id: &'a str,
    challenge_nonce: &'a str,
}

fn canonical_agent_message(intent: &CanonicalSignIntent<'_>) -> Result<Vec<u8>> {
    let payload_hash = format!(
        "0x{}",
        hex::encode(Sha256::digest(intent.payload.as_bytes()))
    );
    let intent = CanonicalAgentIntent {
        intent_type: "sign_intent",
        intent_version: 1,
        request_id: intent.request_id,
        wallet_id: intent.resolved_wallet_id,
        passport_id: intent.passport_id,
        chain_id: intent.chain_id,
        signing_type: intent.signing_type,
        payload_hash: &payload_hash,
        destination: intent.destination,
        value: intent.value,
        session_nonce: intent.session_nonce,
        mode: intent.mode,
    };
    serde_json_canonicalizer::to_vec(&intent).context("Failed to canonicalize sign intent")
}

fn payload_hash(payload: &str) -> String {
    format!("0x{}", hex::encode(Sha256::digest(payload.as_bytes())))
}

fn canonical_validate_message(intent: &CanonicalValidateIntent<'_>) -> Result<Vec<u8>> {
    let payload_hash = payload_hash(intent.payload);
    let intent = CanonicalValidateProof {
        intent_type: "validate_sign_intent",
        intent_version: 1,
        request_id: intent.request_id,
        passport_id: intent.passport_id,
        wallet_id: intent.wallet_id,
        wallet_selector: intent.wallet_selector,
        chain_id: intent.chain_id,
        signing_type: intent.signing_type,
        payload_hash: &payload_hash,
        destination: intent.destination,
        value: intent.value,
    };
    serde_json_canonicalizer::to_vec(&intent)
        .context("Failed to canonicalize validate-sign-intent proof")
}

fn canonical_session_create_message(intent: &CanonicalSessionCreate<'_>) -> Result<Vec<u8>> {
    let intent = CanonicalSessionCreateProof {
        intent_type: "create_session",
        intent_version: 1,
        request_id: intent.request_id,
        passport_id: intent.passport_id,
        challenge_id: intent.challenge_id,
        challenge_nonce: intent.challenge_nonce,
    };
    serde_json_canonicalizer::to_vec(&intent).context("Failed to canonicalize create-session proof")
}

fn sign_hex(agent_key: &AgentKey, message: &[u8]) -> String {
    format!(
        "0x{}",
        hex::encode(agent_key.sign_bytes(message).to_bytes())
    )
}

struct ResolvedSigner {
    passport_id: String,
    agent_key: AgentKey,
}

fn resolve_validate_passport_id(cli_passport_id: Option<String>) -> Result<String> {
    if let Some(passport_id) = cli_passport_id {
        return Ok(passport_id);
    }

    if let Some(token_str) = env_passport_token() {
        let token = PassportToken::parse(&token_str)
            .with_context(|| format!("Failed to parse {PASSPORT_TOKEN_ENV}"))?;
        return Ok(token.passport_id);
    }

    bail!(
        "`kitepass sign --validate` requires `--passport-id` when KITE_PASSPORT_TOKEN is not set."
    )
}

fn resolve_signer(
    cli_passport_id: Option<String>,
    registry: &LocalPassportRegistry,
) -> Result<ResolvedSigner> {
    let token_str = env_passport_token().with_context(|| {
        format!(
            "`kitepass sign` requires {PASSPORT_TOKEN_ENV} because local agent keys are stored as encrypted envelopes in `~/.kitepass/passports.toml`."
        )
    })?;
    let token = PassportToken::parse(&token_str)
        .with_context(|| format!("Failed to parse {PASSPORT_TOKEN_ENV}"))?;

    if let Some(passport_id) = cli_passport_id {
        if passport_id != token.passport_id {
            bail!(
                "`--passport-id` ({passport_id}) does not match the passport embedded in {PASSPORT_TOKEN_ENV} ({})",
                token.passport_id
            );
        }
    }

    let identity = registry
        .get_by_passport_id(&token.passport_id)
        .cloned()
        .with_context(|| {
            format!(
                "No local encrypted passport key found for passport_id `{}`. Recreate it on this machine with `kitepass passport create` or sync `~/.kitepass/passports.toml`.",
                token.passport_id
            )
        })?;

    let decrypted_pem = identity
        .encrypted_key
        .decrypt(token.secret_key.as_str())
        .with_context(|| {
            format!(
                "Failed to decrypt the local passport key for passport_id `{}`. Check that {PASSPORT_TOKEN_ENV} matches the passport created on this machine.",
                token.passport_id
            )
        })?;
    let pem = std::str::from_utf8(decrypted_pem.as_slice())
        .context("Decrypted local key is not valid UTF-8 PEM data")?;
    let agent_key = AgentKey::from_pem(pem).context("Failed to parse decrypted private key PEM")?;

    Ok(ResolvedSigner {
        passport_id: token.passport_id,
        agent_key,
    })
}

fn wallet_selector_for(wallet_id: &Option<String>) -> Option<String> {
    if wallet_id.is_some() {
        None
    } else {
        Some("auto".to_string())
    }
}

fn signing_mode(broadcast: bool) -> (SigningMode, &'static str) {
    if broadcast {
        (SigningMode::SignAndSubmit, "sign_and_submit")
    } else {
        (SigningMode::SignatureOnly, "signature_only")
    }
}

pub async fn run(args: SignArgs, runtime: &Runtime) -> Result<()> {
    let config = load_cli_config().context("Failed to load CLI config")?;
    let api_url = config.resolved_api_url();
    let client =
        PassportClient::new(api_url).context("Failed to initialize Passport API client")?;
    let registry =
        load_local_passport_registry().context("Failed to load local passport registry")?;

    if args.validate {
        // Validate mode: check routing and policy without returning a final signature.
        let request_id = format!("req_{}", Uuid::new_v4().simple());
        let wallet_selector = wallet_selector_for(&args.wallet_id);
        let result = if env_passport_token().is_some() {
            let signer = resolve_signer(args.passport_id, &registry)?;
            let proof_signature = sign_hex(
                &signer.agent_key,
                &canonical_validate_message(&CanonicalValidateIntent {
                    request_id: &request_id,
                    passport_id: &signer.passport_id,
                    wallet_id: args.wallet_id.as_deref(),
                    wallet_selector: wallet_selector.as_deref(),
                    chain_id: &args.chain_id,
                    signing_type: &args.signing_type,
                    payload: &args.payload,
                    destination: &args.destination,
                    value: &args.value,
                })?,
            );
            client
                .validate_sign_intent(&ValidateSignIntentRequest {
                    request_id,
                    wallet_id: args.wallet_id,
                    wallet_selector,
                    passport_id: signer.passport_id,
                    chain_id: args.chain_id,
                    signing_type: args.signing_type,
                    payload: args.payload,
                    destination: args.destination,
                    value: args.value,
                    agent_proof: Some(ValidateAgentProof {
                        signature: proof_signature,
                    }),
                })
                .await
                .context("Failed to validate sign intent")?
        } else if let Some(token) = config.access_token.clone() {
            let owner_client = PassportClient::new(api_url)
                .context("Failed to initialize Passport API client")?
                .with_token(token);
            let passport_id = resolve_validate_passport_id(args.passport_id)?;
            owner_client
                .validate_sign_intent(&ValidateSignIntentRequest {
                    request_id,
                    wallet_id: args.wallet_id,
                    wallet_selector,
                    passport_id,
                    chain_id: args.chain_id,
                    signing_type: args.signing_type,
                    payload: args.payload,
                    destination: args.destination,
                    value: args.value,
                    agent_proof: None,
                })
                .await
                .context("Failed to validate sign intent")?
        } else {
            bail!(
                "`kitepass sign --validate` requires either KITE_PASSPORT_TOKEN or a logged-in principal session in ~/.kitepass/config.toml."
            );
        };
        runtime.print_data(&result)?;
    } else {
        // Signing modes: default is signature only; --broadcast forwards after signing.
        let resolved_signer = resolve_signer(args.passport_id, &registry)?;
        let wallet_selector = wallet_selector_for(&args.wallet_id);
        let (mode, mode_name) = signing_mode(args.broadcast);

        if runtime.dry_run_enabled() {
            runtime.print_data(&json!({
                "dry_run": true,
                "action": "sign",
                "passport_id": resolved_signer.passport_id,
                "wallet_id": args.wallet_id,
                "chain_id": args.chain_id,
                "signing_type": args.signing_type,
                "destination": args.destination,
                "value": args.value,
                "mode": mode_name,
                "private_key_storage": "encrypted_inline",
                "passport_token_env": PASSPORT_TOKEN_ENV,
            }))?;
            return Ok(());
        }

        let request_id = format!("req_{}", Uuid::new_v4().simple());
        let idempotency_key = format!("idem_{}", Uuid::new_v4().simple());
        let validate_proof_signature = sign_hex(
            &resolved_signer.agent_key,
            &canonical_validate_message(&CanonicalValidateIntent {
                request_id: &request_id,
                passport_id: &resolved_signer.passport_id,
                wallet_id: args.wallet_id.as_deref(),
                wallet_selector: wallet_selector.as_deref(),
                chain_id: &args.chain_id,
                signing_type: &args.signing_type,
                payload: &args.payload,
                destination: &args.destination,
                value: &args.value,
            })?,
        );
        let validate = client
            .validate_sign_intent(&ValidateSignIntentRequest {
                request_id: request_id.clone(),
                wallet_id: args.wallet_id,
                wallet_selector,
                passport_id: resolved_signer.passport_id.clone(),
                chain_id: args.chain_id.clone(),
                signing_type: args.signing_type.clone(),
                payload: args.payload.clone(),
                destination: args.destination.clone(),
                value: args.value.clone(),
                agent_proof: Some(ValidateAgentProof {
                    signature: validate_proof_signature,
                }),
            })
            .await
            .context("Failed to validate sign intent")?;
        if !validate.valid {
            bail!("Sign intent validation succeeded but returned valid=false");
        }
        let session_request_id = format!("req_{}", Uuid::new_v4().simple());
        let challenge = client
            .create_session_challenge(&CreateSessionChallengeRequest {
                passport_id: resolved_signer.passport_id.clone(),
            })
            .await
            .context("Failed to create agent session challenge")?;
        let session = client
            .create_session(&CreateSessionRequest {
                passport_id: resolved_signer.passport_id.clone(),
                request_id: Some(session_request_id.clone()),
                challenge_id: Some(challenge.challenge_id.clone()),
                proof_signature: Some(sign_hex(
                    &resolved_signer.agent_key,
                    &canonical_session_create_message(&CanonicalSessionCreate {
                        request_id: &session_request_id,
                        passport_id: &resolved_signer.passport_id,
                        challenge_id: &challenge.challenge_id,
                        challenge_nonce: &challenge.challenge_nonce,
                    })?,
                )),
            })
            .await
            .context("Failed to create agent session")?;

        let signature = sign_hex(
            &resolved_signer.agent_key,
            &canonical_agent_message(&CanonicalSignIntent {
                request_id: &request_id,
                resolved_wallet_id: &validate.resolved_wallet_id,
                passport_id: &resolved_signer.passport_id,
                chain_id: &args.chain_id,
                signing_type: &args.signing_type,
                payload: &args.payload,
                destination: &args.destination,
                value: &args.value,
                session_nonce: &session.session_nonce,
                mode: mode_name,
            })?,
        );

        let response = client
            .submit_signature(&SignRequest {
                request_id,
                idempotency_key,
                wallet_id: validate.resolved_wallet_id,
                passport_id: resolved_signer.passport_id.clone(),
                chain_id: args.chain_id,
                signing_type: args.signing_type,
                mode,
                payload: args.payload,
                destination: args.destination,
                value: args.value,
                agent_proof: AgentProof {
                    passport_id: resolved_signer.passport_id,
                    session_nonce: session.session_nonce,
                    signature,
                },
            })
            .await
            .context("Failed to submit sign request")?;
        runtime.print_data(&response)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn payload_hash_is_sha256_hex() {
        let hash = payload_hash("0xdeadbeef");
        assert!(hash.starts_with("0x"));
        assert_eq!(hash.len(), 2 + 64); // 0x + 32 bytes hex
    }

    #[test]
    fn payload_hash_is_deterministic() {
        assert_eq!(payload_hash("test"), payload_hash("test"));
        assert_ne!(payload_hash("a"), payload_hash("b"));
    }

    #[test]
    fn wallet_selector_for_none_returns_auto() {
        assert_eq!(wallet_selector_for(&None), Some("auto".to_string()));
    }

    #[test]
    fn wallet_selector_for_some_returns_none() {
        assert_eq!(wallet_selector_for(&Some("wal_123".to_string())), None);
    }

    #[test]
    fn signing_mode_default_is_signature_only() {
        let (mode, name) = signing_mode(false);
        assert!(matches!(mode, SigningMode::SignatureOnly));
        assert_eq!(name, "signature_only");
    }

    #[test]
    fn signing_mode_broadcast_is_sign_and_submit() {
        let (mode, name) = signing_mode(true);
        assert!(matches!(mode, SigningMode::SignAndSubmit));
        assert_eq!(name, "sign_and_submit");
    }

    #[test]
    fn canonical_validate_message_includes_type_and_version() {
        let message = canonical_validate_message(&CanonicalValidateIntent {
            request_id: "req_123",
            passport_id: "agp_123",
            wallet_id: Some("wal_123"),
            wallet_selector: None,
            chain_id: "eip155:8453",
            signing_type: "transaction",
            payload: "0xdeadbeef",
            destination: "0xabc",
            value: "10",
        })
        .expect("should canonicalize");

        let canonical = String::from_utf8(message).expect("should be utf-8");
        assert!(canonical.contains("\"type\":\"validate_sign_intent\""));
        assert!(canonical.contains("\"version\":1"));
        assert!(canonical.contains("\"passport_id\":\"agp_123\""));
    }

    #[test]
    fn canonical_validate_message_omits_null_wallet_id() {
        let message = canonical_validate_message(&CanonicalValidateIntent {
            request_id: "req_123",
            passport_id: "agp_123",
            wallet_id: None,
            wallet_selector: Some("auto"),
            chain_id: "eip155:8453",
            signing_type: "transaction",
            payload: "0xdeadbeef",
            destination: "0xabc",
            value: "10",
        })
        .expect("should canonicalize");

        let canonical = String::from_utf8(message).expect("should be utf-8");
        assert!(!canonical.contains("wallet_id"));
        assert!(canonical.contains("\"wallet_selector\":\"auto\""));
    }

    #[test]
    fn canonical_session_create_message_includes_challenge() {
        let message = canonical_session_create_message(&CanonicalSessionCreate {
            request_id: "req_sess",
            passport_id: "agp_123",
            challenge_id: "sch_456",
            challenge_nonce: "nonce_789",
        })
        .expect("should canonicalize");

        let canonical = String::from_utf8(message).expect("should be utf-8");
        assert!(canonical.contains("\"type\":\"create_session\""));
        assert!(canonical.contains("\"challenge_id\":\"sch_456\""));
        assert!(canonical.contains("\"challenge_nonce\":\"nonce_789\""));
    }

    #[test]
    fn canonical_agent_message_uses_requested_mode() {
        let message = canonical_agent_message(&CanonicalSignIntent {
            request_id: "req_123",
            resolved_wallet_id: "wal_123",
            passport_id: "agp_123",
            chain_id: "eip155:8453",
            signing_type: "transaction",
            payload: "0xdeadbeef",
            destination: "0xabc",
            value: "10",
            session_nonce: "nonce_123",
            mode: "sign_and_submit",
        })
        .expect("canonical sign intent should canonicalize");

        let canonical = String::from_utf8(message).expect("canonical message should be utf-8");
        assert!(canonical.contains("\"mode\":\"sign_and_submit\""));
    }
}
