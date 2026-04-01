use crate::cli::SignAction;
use crate::runtime::Runtime;
use anyhow::{Context, Result};
use kitepass_api_client::{
    AgentProof, PassportClient, SignRequest, SigningMode, ValidateSignIntentRequest,
};
use kitepass_config::{AgentRegistry, CliConfig, env_agent_override};
use kitepass_crypto::agent_key::AgentKey;
use secrecy::{ExposeSecret, SecretString};
use serde::Serialize;
use serde_json::json;
use sha2::{Digest, Sha256};
use std::fs;
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

fn canonical_agent_message(intent: &CanonicalSignIntent<'_>) -> Vec<u8> {
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
        mode: "signature_only",
    };
    serde_json_canonicalizer::to_vec(&intent)
        .expect("canonical sign intent should canonicalize")
}

pub async fn run(action: SignAction, runtime: &Runtime) -> Result<()> {
    let config = CliConfig::load_default().unwrap_or_default();
    let api_url = config.resolved_api_url();
    let client = PassportClient::new(api_url);

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
            let request_id = format!("req_{}", Uuid::new_v4().simple());
            let wallet_selector = wallet_id
                .as_ref()
                .map(|_| None)
                .unwrap_or(Some(wallet_selector));
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
            key_path,
            sign_and_submit,
        } => {
            let registry = AgentRegistry::load_default().unwrap_or_default();
            let env_override = env_agent_override()?;
            let needs_registry_profile = env_override.is_none()
                && (access_key_id.is_none() || key_path.is_none());
            let resolved_profile = if needs_registry_profile {
                Some(registry.resolve_active_agent()?)
            } else {
                None
            };
            let access_key_id = access_key_id
                .or_else(|| env_override.as_ref().map(|override_| override_.access_key_id.clone()))
                .or_else(|| {
                    resolved_profile
                        .as_ref()
                        .map(|identity| identity.access_key_id.clone())
                })
                .context("Missing agent access key ID. Provide via `--access-key-id`, `KITE_AGENT_ACCESS_KEY_ID` env var, or create one with `access-key create`.")?;
            let key_path = key_path
                .or_else(|| env_override.as_ref().map(|override_| override_.private_key_path.clone()))
                .or_else(|| {
                    resolved_profile
                        .as_ref()
                        .map(|identity| identity.private_key_path.clone())
                })
                .context("Missing agent private key path. Provide via `--key-path`, `KITE_AGENT_KEY_PATH` env var, or create one with `access-key create`.")?;

            if runtime.dry_run_enabled() {
                runtime.print_data(&json!({
                    "dry_run": true,
                    "action": "sign.submit",
                    "access_key_id": access_key_id,
                    "wallet_id": wallet_id,
                    "wallet_selector": wallet_selector,
                    "chain_id": chain_id,
                    "signing_type": signing_type,
                    "destination": destination,
                    "value": value,
                    "mode": if sign_and_submit { "sign_and_submit" } else { "signature_only" },
                    "key_path": key_path,
                    "profile_name": resolved_profile.as_ref().map(|identity| identity.name.clone()),
                }))?;
                return Ok(());
            }

            let request_id = format!("req_{}", Uuid::new_v4().simple());
            let idempotency_key = format!("idem_{}", Uuid::new_v4().simple());
            let wallet_selector = wallet_id
                .as_ref()
                .map(|_| None)
                .unwrap_or(Some(wallet_selector));
            let validate = client
                .validate_sign_intent(&ValidateSignIntentRequest {
                    request_id: request_id.clone(),
                    wallet_id,
                    wallet_selector,
                    access_key_id: access_key_id.clone(),
                    chain_id: chain_id.clone(),
                    signing_type: signing_type.clone(),
                    payload: payload.clone(),
                    destination: destination.clone(),
                    value: value.clone(),
                })
                .await
                .context("Failed to validate sign intent before submit")?;
            let session = client
                .create_session(&access_key_id)
                .await
                .context("Failed to create agent session")?;

            let pem = SecretString::from(
                fs::read_to_string(&key_path)
                    .with_context(|| format!("Failed to read private key from {key_path}"))?,
            );
            let agent_key =
                AgentKey::from_pem(pem.expose_secret()).context("Failed to parse private key PEM")?;
            let signature = agent_key.sign_bytes(&canonical_agent_message(&CanonicalSignIntent {
                request_id: &request_id,
                resolved_wallet_id: &validate.resolved_wallet_id,
                access_key_id: &access_key_id,
                chain_id: &chain_id,
                signing_type: &signing_type,
                payload: &payload,
                destination: &destination,
                value: &value,
                session_nonce: &session.session_nonce,
            }));

            let response = client
                .submit_signature(&SignRequest {
                    request_id,
                    idempotency_key,
                    wallet_id: validate.resolved_wallet_id,
                    access_key_id: access_key_id.clone(),
                    chain_id,
                    signing_type,
                    mode: if sign_and_submit {
                        SigningMode::SignAndSubmit
                    } else {
                        SigningMode::SignatureOnly
                    },
                    payload,
                    destination,
                    value,
                    agent_proof: AgentProof {
                        access_key_id,
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
