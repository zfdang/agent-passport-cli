use crate::cli::SignAction;
use crate::commands::{load_agent_registry, load_cli_config};
use crate::runtime::Runtime;
use anyhow::{bail, Context, Result};
use kitepass_api_client::{
    AgentProof, PassportClient, SignRequest, SigningMode, ValidateSignIntentRequest,
};
use kitepass_config::{env_agent_token, AgentRegistry};
use kitepass_crypto::agent_key::AgentKey;
use kitepass_crypto::encryption::CombinedToken;
use serde::Serialize;
use serde_json::json;
use sha2::{Digest, Sha256};
use uuid::Uuid;

struct CanonicalSignIntent<'a> {
    request_id: &'a str,
    resolved_wallet_id: &'a str,
    access_key_id: &'a str,
    chain_id: &'a str,
    signing_type: &'a str,
    payload: &'a str,
    destination: &'a str,
    value: &'a str,
    session_nonce: &'a str,
    mode: &'a str,
}

#[derive(Serialize)]
struct CanonicalAgentIntent<'a> {
    #[serde(rename = "type")]
    intent_type: &'a str,
    #[serde(rename = "version")]
    intent_version: u32,
    request_id: &'a str,
    wallet_id: &'a str,
    access_key_id: &'a str,
    chain_id: &'a str,
    signing_type: &'a str,
    payload_hash: &'a str,
    destination: &'a str,
    value: &'a str,
    session_nonce: &'a str,
    mode: &'a str,
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
        access_key_id: intent.access_key_id,
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

struct ResolvedSigner {
    access_key_id: String,
    profile_name: String,
    agent_key: AgentKey,
}

fn resolve_validate_access_key_id(
    cli_access_key_id: Option<String>,
    registry: &AgentRegistry,
) -> Result<String> {
    if let Some(access_key_id) = cli_access_key_id {
        return Ok(access_key_id);
    }

    if let Some(token_str) = env_agent_token() {
        let token = CombinedToken::parse(&token_str).context("Failed to parse KITE_AGENT_TOKEN")?;
        return Ok(token.access_key_id);
    }

    Ok(registry.resolve_active_agent()?.access_key_id)
}

fn resolve_submit_signer(
    cli_access_key_id: Option<String>,
    registry: &AgentRegistry,
) -> Result<ResolvedSigner> {
    let token_str = env_agent_token().context(
        "`kitepass sign submit` requires KITE_AGENT_TOKEN because local agent keys are stored as encrypted envelopes in `~/.kitepass/agents.toml`.",
    )?;
    let token = CombinedToken::parse(&token_str).context("Failed to parse KITE_AGENT_TOKEN")?;

    if let Some(access_key_id) = cli_access_key_id {
        if access_key_id != token.access_key_id {
            bail!(
                "`--access-key-id` ({access_key_id}) does not match the access key embedded in KITE_AGENT_TOKEN ({})",
                token.access_key_id
            );
        }
    }

    let identity = registry
        .get_by_access_key_id(&token.access_key_id)
        .cloned()
        .with_context(|| {
            format!(
                "No local encrypted agent profile found for access_key_id `{}`. Recreate it on this machine with `kitepass access-key create --name <profile>` or sync `~/.kitepass/agents.toml`.",
                token.access_key_id
            )
        })?;

    let decrypted_pem = identity
        .encrypted_key
        .decrypt(token.secret_key.as_str())
        .with_context(|| {
            format!(
                "Failed to decrypt the local agent key for access_key_id `{}`. Check that KITE_AGENT_TOKEN matches the profile created on this machine.",
                token.access_key_id
            )
        })?;
    let pem = std::str::from_utf8(decrypted_pem.as_slice())
        .context("Decrypted local key is not valid UTF-8 PEM data")?;
    let agent_key = AgentKey::from_pem(pem).context("Failed to parse decrypted private key PEM")?;

    Ok(ResolvedSigner {
        access_key_id: token.access_key_id,
        profile_name: identity.name,
        agent_key,
    })
}

fn resolve_wallet_selector(wallet_id: &Option<String>, wallet_selector: String) -> Option<String> {
    if wallet_id.is_some() {
        None
    } else {
        Some(wallet_selector)
    }
}

fn signing_mode_strings(sign_and_submit: bool) -> (SigningMode, &'static str) {
    if sign_and_submit {
        (SigningMode::SignAndSubmit, "sign_and_submit")
    } else {
        (SigningMode::SignatureOnly, "signature_only")
    }
}

pub async fn run(action: SignAction, runtime: &Runtime) -> Result<()> {
    let config = load_cli_config().context("Failed to load CLI config")?;
    let api_url = config.resolved_api_url();
    let client =
        PassportClient::new(api_url).context("Failed to initialize Passport API client")?;
    let registry = load_agent_registry().context("Failed to load local agent registry")?;

    match action {
        SignAction::Validate {
            access_key_id,
            wallet_id,
            wallet_selector,
            chain_id,
            signing_type,
            payload,
            destination,
            value,
        } => {
            let access_key_id = resolve_validate_access_key_id(access_key_id, &registry)?;

            let request_id = format!("req_{}", Uuid::new_v4().simple());
            let wallet_selector = resolve_wallet_selector(&wallet_id, wallet_selector);
            let result = client
                .validate_sign_intent(&ValidateSignIntentRequest {
                    request_id,
                    wallet_id,
                    wallet_selector,
                    access_key_id,
                    chain_id,
                    signing_type,
                    payload,
                    destination,
                    value,
                })
                .await
                .context("Failed to validate sign intent")?;
            runtime.print_data(&result)?;
        }
        SignAction::Submit {
            access_key_id,
            wallet_id,
            wallet_selector,
            chain_id,
            signing_type,
            payload,
            destination,
            value,
            sign_and_submit,
        } => {
            let resolved_signer = resolve_submit_signer(access_key_id, &registry)?;
            let wallet_selector = resolve_wallet_selector(&wallet_id, wallet_selector);
            let (signing_mode, signing_mode_name) = signing_mode_strings(sign_and_submit);

            if runtime.dry_run_enabled() {
                runtime.print_data(&json!({
                    "dry_run": true,
                    "action": "sign.submit",
                    "access_key_id": resolved_signer.access_key_id,
                    "wallet_id": wallet_id,
                    "wallet_selector": wallet_selector,
                    "chain_id": chain_id,
                    "signing_type": signing_type,
                    "destination": destination,
                    "value": value,
                    "mode": signing_mode_name,
                    "profile_name": resolved_signer.profile_name,
                    "private_key_storage": "encrypted_inline",
                    "agent_token_env": "KITE_AGENT_TOKEN",
                }))?;
                return Ok(());
            }

            let request_id = format!("req_{}", Uuid::new_v4().simple());
            let idempotency_key = format!("idem_{}", Uuid::new_v4().simple());
            let validate = client
                .validate_sign_intent(&ValidateSignIntentRequest {
                    request_id: request_id.clone(),
                    wallet_id,
                    wallet_selector,
                    access_key_id: resolved_signer.access_key_id.clone(),
                    chain_id: chain_id.clone(),
                    signing_type: signing_type.clone(),
                    payload: payload.clone(),
                    destination: destination.clone(),
                    value: value.clone(),
                })
                .await
                .context("Failed to validate sign intent before submit")?;
            if !validate.valid {
                bail!("Sign intent validation succeeded but returned valid=false");
            }
            let session = client
                .create_session(&resolved_signer.access_key_id)
                .await
                .context("Failed to create agent session")?;

            let signature = resolved_signer
                .agent_key
                .sign_bytes(&canonical_agent_message(&CanonicalSignIntent {
                    request_id: &request_id,
                    resolved_wallet_id: &validate.resolved_wallet_id,
                    access_key_id: &resolved_signer.access_key_id,
                    chain_id: &chain_id,
                    signing_type: &signing_type,
                    payload: &payload,
                    destination: &destination,
                    value: &value,
                    session_nonce: &session.session_nonce,
                    mode: signing_mode_name,
                })?);

            let response = client
                .submit_signature(&SignRequest {
                    request_id,
                    idempotency_key,
                    wallet_id: validate.resolved_wallet_id,
                    access_key_id: resolved_signer.access_key_id.clone(),
                    chain_id,
                    signing_type,
                    mode: signing_mode,
                    payload,
                    destination,
                    value,
                    agent_proof: AgentProof {
                        access_key_id: resolved_signer.access_key_id,
                        session_nonce: session.session_nonce,
                        signature: format!("0x{}", hex::encode(signature.to_bytes())),
                    },
                })
                .await
                .context("Failed to submit sign request")?;
            runtime.print_data(&response)?;
        }
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
            access_key_id: "aak_123",
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
