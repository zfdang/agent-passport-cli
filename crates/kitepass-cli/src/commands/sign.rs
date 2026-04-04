use crate::commands::{load_agent_registry, load_cli_config};
use crate::runtime::Runtime;
use anyhow::{bail, Context, Result};
use kitepass_api_client::{
    AgentProof, CreateSessionChallengeRequest, CreateSessionRequest, PassportClient, SignRequest,
    SigningMode, ValidateAgentProof, ValidateSignIntentRequest,
};
use kitepass_config::{env_agent_token, AgentRegistry};
use kitepass_crypto::agent_key::AgentKey;
use kitepass_crypto::encryption::AgentPassportToken;
use serde::Serialize;
use serde_json::json;
use sha2::{Digest, Sha256};
use uuid::Uuid;

pub struct SignArgs {
    pub validate: bool,
    pub broadcast: bool,
    pub agent_passport_id: Option<String>,
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
    agent_passport_id: &'a str,
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
    agent_passport_id: &'a str,
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
    agent_passport_id: &'a str,
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
    agent_passport_id: &'a str,
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
    agent_passport_id: &'a str,
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
    agent_passport_id: &'a str,
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
        agent_passport_id: intent.agent_passport_id,
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
        agent_passport_id: intent.agent_passport_id,
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
        agent_passport_id: intent.agent_passport_id,
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
    agent_passport_id: String,
    profile_name: String,
    agent_key: AgentKey,
}

fn resolve_validate_agent_passport_id(
    cli_agent_passport_id: Option<String>,
    registry: &AgentRegistry,
) -> Result<String> {
    if let Some(agent_passport_id) = cli_agent_passport_id {
        return Ok(agent_passport_id);
    }

    if let Some(token_str) = env_agent_token() {
        let token = AgentPassportToken::parse(&token_str)
            .context("Failed to parse KITE_AGENT_PASSPORT_TOKEN")?;
        return Ok(token.agent_passport_id);
    }

    Ok(registry.resolve_active_agent()?.agent_passport_id)
}

fn resolve_signer(
    cli_agent_passport_id: Option<String>,
    registry: &AgentRegistry,
) -> Result<ResolvedSigner> {
    let token_str = env_agent_token().context(
        "`kitepass sign` requires KITE_AGENT_PASSPORT_TOKEN because local agent keys are stored as encrypted envelopes in `~/.kitepass/agents.toml`.",
    )?;
    let token = AgentPassportToken::parse(&token_str)
        .context("Failed to parse KITE_AGENT_PASSPORT_TOKEN")?;

    if let Some(agent_passport_id) = cli_agent_passport_id {
        if agent_passport_id != token.agent_passport_id {
            bail!(
                "`--agent-passport-id` ({agent_passport_id}) does not match the agent passport embedded in KITE_AGENT_PASSPORT_TOKEN ({})",
                token.agent_passport_id
            );
        }
    }

    let identity = registry
        .get_by_agent_passport_id(&token.agent_passport_id)
        .cloned()
        .with_context(|| {
            format!(
                "No local encrypted agent profile found for agent_passport_id `{}`. Recreate it on this machine with `kitepass agent-passport create --name <profile>` or sync `~/.kitepass/agents.toml`.",
                token.agent_passport_id
            )
        })?;

    let decrypted_pem = identity
        .encrypted_key
        .decrypt(token.secret_key.as_str())
        .with_context(|| {
            format!(
                "Failed to decrypt the local agent key for agent_passport_id `{}`. Check that KITE_AGENT_PASSPORT_TOKEN matches the profile created on this machine.",
                token.agent_passport_id
            )
        })?;
    let pem = std::str::from_utf8(decrypted_pem.as_slice())
        .context("Decrypted local key is not valid UTF-8 PEM data")?;
    let agent_key = AgentKey::from_pem(pem).context("Failed to parse decrypted private key PEM")?;

    Ok(ResolvedSigner {
        agent_passport_id: token.agent_passport_id,
        profile_name: identity.name,
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
    let registry = load_agent_registry().context("Failed to load local agent registry")?;

    if args.validate {
        // Validate mode: check routing and policy without returning a final signature.
        let request_id = format!("req_{}", Uuid::new_v4().simple());
        let wallet_selector = wallet_selector_for(&args.wallet_id);
        let result = if env_agent_token().is_some() {
            let signer = resolve_signer(args.agent_passport_id, &registry)?;
            let proof_signature = sign_hex(
                &signer.agent_key,
                &canonical_validate_message(&CanonicalValidateIntent {
                    request_id: &request_id,
                    agent_passport_id: &signer.agent_passport_id,
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
                    agent_passport_id: signer.agent_passport_id,
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
            let agent_passport_id =
                resolve_validate_agent_passport_id(args.agent_passport_id, &registry)?;
            owner_client
                .validate_sign_intent(&ValidateSignIntentRequest {
                    request_id,
                    wallet_id: args.wallet_id,
                    wallet_selector,
                    agent_passport_id,
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
                "`kitepass sign --validate` requires either KITE_AGENT_PASSPORT_TOKEN or a logged-in principal session in ~/.kitepass/config.toml."
            );
        };
        runtime.print_data(&result)?;
    } else {
        // Signing modes: default is signature only; --broadcast forwards after signing.
        let resolved_signer = resolve_signer(args.agent_passport_id, &registry)?;
        let wallet_selector = wallet_selector_for(&args.wallet_id);
        let (mode, mode_name) = signing_mode(args.broadcast);

        if runtime.dry_run_enabled() {
            runtime.print_data(&json!({
                "dry_run": true,
                "action": "sign",
                "agent_passport_id": resolved_signer.agent_passport_id,
                "wallet_id": args.wallet_id,
                "chain_id": args.chain_id,
                "signing_type": args.signing_type,
                "destination": args.destination,
                "value": args.value,
                "mode": mode_name,
                "profile_name": resolved_signer.profile_name,
                "private_key_storage": "encrypted_inline",
                "agent_token_env": "KITE_AGENT_PASSPORT_TOKEN",
            }))?;
            return Ok(());
        }

        let request_id = format!("req_{}", Uuid::new_v4().simple());
        let idempotency_key = format!("idem_{}", Uuid::new_v4().simple());
        let validate_proof_signature = sign_hex(
            &resolved_signer.agent_key,
            &canonical_validate_message(&CanonicalValidateIntent {
                request_id: &request_id,
                agent_passport_id: &resolved_signer.agent_passport_id,
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
                agent_passport_id: resolved_signer.agent_passport_id.clone(),
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
                agent_passport_id: resolved_signer.agent_passport_id.clone(),
            })
            .await
            .context("Failed to create agent session challenge")?;
        let session = client
            .create_session(&CreateSessionRequest {
                agent_passport_id: resolved_signer.agent_passport_id.clone(),
                request_id: Some(session_request_id.clone()),
                challenge_id: Some(challenge.challenge_id.clone()),
                proof_signature: Some(sign_hex(
                    &resolved_signer.agent_key,
                    &canonical_session_create_message(&CanonicalSessionCreate {
                        request_id: &session_request_id,
                        agent_passport_id: &resolved_signer.agent_passport_id,
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
                agent_passport_id: &resolved_signer.agent_passport_id,
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
                agent_passport_id: resolved_signer.agent_passport_id.clone(),
                chain_id: args.chain_id,
                signing_type: args.signing_type,
                mode,
                payload: args.payload,
                destination: args.destination,
                value: args.value,
                agent_proof: AgentProof {
                    agent_passport_id: resolved_signer.agent_passport_id,
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
    fn canonical_agent_message_uses_requested_mode() {
        let message = canonical_agent_message(&CanonicalSignIntent {
            request_id: "req_123",
            resolved_wallet_id: "wal_123",
            agent_passport_id: "agp_123",
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
