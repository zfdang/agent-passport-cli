use crate::{
    cli::AccessKeyAction,
    commands::{load_agent_registry, load_cli_config},
    error::CliError,
    runtime::Runtime,
};
use anyhow::{Context, Result};
use chrono::{Duration, Utc};
use kitepass_api_client::{
    BindingInput, BindingResult, FinalizeAccessKeyRequest, PassportClient, RegisterAccessKeyRequest,
};
use kitepass_config::{AgentIdentity, DEFAULT_AGENT_PROFILE};
use kitepass_crypto::agent_key::AgentKey;
use kitepass_crypto::encryption::{generate_secret_key, CombinedToken, CryptoEnvelope};
use serde::Serialize;
use serde_json::json;
use uuid::Uuid;
use zeroize::Zeroizing;

#[derive(Serialize)]
struct AccessKeyCreateOutput<'a> {
    profile_name: &'a str,
    access_key_id: &'a str,
    status: &'a str,
    public_key: &'a str,
    combined_token: &'a str,
    bindings: &'a [BindingResult],
    activated: bool,
}

pub async fn run(action: AccessKeyAction, runtime: &Runtime) -> Result<()> {
    let config = load_cli_config().context("Failed to load CLI config")?;
    let api_url = config.resolved_api_url();
    let token = config
        .access_token
        .clone()
        .ok_or(CliError::AuthenticationRequired)?;

    let client = PassportClient::new(api_url)
        .context("Failed to initialize Passport API client")?
        .with_token(token);

    match action {
        AccessKeyAction::List => {
            let access_keys = client
                .list_access_keys()
                .await
                .context("Failed to list access keys")?;
            runtime.print_data(&access_keys)?;
        }
        AccessKeyAction::Create {
            name,
            wallet_id,
            policy_id,
            no_activate,
        } => {
            let mut registry =
                load_agent_registry().context("Failed to load local agent registry")?;
            let profile_name = name.unwrap_or_else(|| registry.selected_profile_name());

            if runtime.dry_run_enabled() {
                runtime.print_data(&json!({
                    "dry_run": true,
                    "action": "access_key.create",
                    "profile_name": profile_name,
                    "wallet_id": wallet_id,
                    "policy_id": policy_id,
                }))?;
                return Ok(());
            }

            if profile_name.trim().is_empty() {
                anyhow::bail!("Profile name must not be empty");
            }

            if profile_name == DEFAULT_AGENT_PROFILE {
                runtime.progress("Generating new Ed25519 Agent Access Key for default profile...");
            } else {
                runtime.progress(format!(
                    "Generating new Ed25519 Agent Access Key for profile `{profile_name}`..."
                ));
            }

            // 1. Generate local keypair
            let key = AgentKey::generate();
            let pubkey_hex = key.public_key_hex();

            // 2. Generate a secret key for the Combined Token and encrypt the private key
            let secret_key = generate_secret_key();
            let pem = key
                .export_pem()
                .context("Failed to serialize private key")?;
            let encrypted_key = CryptoEnvelope::encrypt(pem.as_bytes(), &secret_key)
                .context("Failed to encrypt private key")?;

            // 3. Register public key on Passport Gateway
            runtime.progress(format!("Registering public key with Gateway: {pubkey_hex}"));
            let bindings = match (wallet_id.clone(), policy_id.clone()) {
                (Some(wallet_id), Some(policy_id)) => {
                    let policy = client
                        .get_policy(&policy_id)
                        .await
                        .with_context(|| format!("Failed to get policy {policy_id}"))?;
                    vec![BindingInput {
                        wallet_id,
                        policy_id,
                        policy_version: policy.version,
                        is_default: true,
                        selection_priority: 0,
                    }]
                }
                (None, None) => Vec::new(),
                _ => {
                    anyhow::bail!(
                        "`--wallet-id` and `--policy-id` must be provided together when provisioning an active delegated authority"
                    );
                }
            };
            let request = RegisterAccessKeyRequest {
                public_key: pubkey_hex.clone(),
                key_address: format!("ed25519:{}", &pubkey_hex[..16]),
                expires_at: (Utc::now() + Duration::days(365)).to_rfc3339(),
                bindings,
                idempotency_key: format!("idem_{}", Uuid::new_v4().simple()),
            };
            let prepared = client
                .register_access_key(&request)
                .await
                .context("Failed to prepare access key provisioning")?;
            runtime.progress(format!(
                "Prepared provisioning intent: {}",
                prepared.intent_id
            ));
            let approval = client
                .approve_provisioning_intent(&prepared.intent_id)
                .await
                .context("Failed to approve provisioning intent")?;
            let res = client
                .finalize_access_key(&FinalizeAccessKeyRequest {
                    intent_id: prepared.intent_id.clone(),
                    owner_approval_id: approval.owner_approval_id.clone(),
                    idempotency_key: format!("idem_{}", Uuid::new_v4().simple()),
                })
                .await
                .context("Failed to finalize access key provisioning")?;

            // 4. Persist agent profile with encrypted key inline
            registry.upsert(AgentIdentity {
                name: profile_name.clone(),
                access_key_id: res.access_key_id.clone(),
                public_key_hex: pubkey_hex.clone(),
                encrypted_key,
            })?;

            if !no_activate {
                registry.active_profile = Some(profile_name.clone());
            }

            let mut persistence_errors = Vec::new();
            if let Err(error) = registry.save_default() {
                persistence_errors.push(format!(
                    "failed to persist encrypted local agent profile: {error}"
                ));
            } else if !no_activate {
                runtime.progress(format!(
                    "Updated local agent registry and activated profile `{profile_name}`."
                ));
            } else {
                runtime.progress(format!(
                    "Updated local agent registry for profile `{profile_name}`."
                ));
            }

            // 5. Build and display the Combined Token
            let combined_token =
                Zeroizing::new(CombinedToken::format(&res.access_key_id, &secret_key));

            // Keep the owner config on disk for API/base settings only.
            if let Err(error) = config.save_default() {
                persistence_errors.push(format!("failed to persist CLI config: {error}"));
            }

            runtime.important("╔══════════════════════════════════════════════════════════╗");
            runtime.important("║  IMPORTANT: Save the Combined Token below immediately!   ║");
            runtime.important("║  It will NOT be displayed again.                         ║");
            runtime.important("║  If lost, revoke this key and create a new one.          ║");
            runtime.important("╚══════════════════════════════════════════════════════════╝");

            runtime.print_data(&AccessKeyCreateOutput {
                profile_name: &profile_name,
                access_key_id: &res.access_key_id,
                status: &res.status,
                public_key: &pubkey_hex,
                combined_token: combined_token.as_str(),
                bindings: &res.bindings,
                activated: !no_activate,
            })?;

            if !persistence_errors.is_empty() {
                anyhow::bail!(
                    "Access key was created, but local persistence is incomplete: {}. Save the Combined Token above, then fix the local config/registry or revoke and recreate the access key if needed.",
                    persistence_errors.join("; ")
                );
            }
        }
        AccessKeyAction::Get { access_key_id } => {
            let access_key = client
                .get_access_key(&access_key_id)
                .await
                .with_context(|| format!("Failed to get access key {access_key_id}"))?;
            let bindings = client
                .list_bindings(&access_key_id)
                .await
                .with_context(|| format!("Failed to list bindings for access key {access_key_id}"))?;
            let usage = client
                .get_access_key_usage(&access_key_id)
                .await
                .with_context(|| format!("Failed to get usage for access key {access_key_id}"))?;
            runtime.print_data(&serde_json::json!({
                "access_key": access_key,
                "bindings": bindings,
                "usage": usage,
            }))?;
        }
        AccessKeyAction::Freeze { access_key_id } => {
            let key_id = access_key_id;
            if runtime.dry_run_enabled() {
                runtime.print_data(&json!({
                    "dry_run": true,
                    "action": "access_key.freeze",
                    "access_key_id": key_id,
                }))?;
                return Ok(());
            }
            let access_key = client
                .freeze_access_key(&key_id)
                .await
                .with_context(|| format!("Failed to freeze access key {key_id}"))?;
            runtime.print_data(&access_key)?;
        }
        AccessKeyAction::Revoke { access_key_id } => {
            let key_id = access_key_id;
            if runtime.dry_run_enabled() {
                runtime.print_data(&json!({
                    "dry_run": true,
                    "action": "access_key.revoke",
                    "access_key_id": key_id,
                }))?;
                return Ok(());
            }
            let access_key = client
                .revoke_access_key(&key_id)
                .await
                .with_context(|| format!("Failed to revoke access key {key_id}"))?;
            runtime.print_data(&access_key)?;
        }
    }
    Ok(())
}
