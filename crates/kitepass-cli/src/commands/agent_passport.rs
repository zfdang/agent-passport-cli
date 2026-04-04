use crate::{
    cli::AgentPassportAction,
    commands::{load_agent_registry, load_cli_config},
    error::CliError,
    runtime::Runtime,
};
use anyhow::{Context, Result};
use chrono::{Duration, Utc};
use kitepass_api_client::{
    BindingInput, BindingResult, FinalizeAgentPassportRequest, PassportClient,
    RegisterAgentPassportRequest,
};
use kitepass_config::{AgentIdentity, DEFAULT_AGENT_PROFILE};
use kitepass_crypto::agent_key::AgentKey;
use kitepass_crypto::encryption::{generate_secret_key, AgentPassportToken, CryptoEnvelope};
use serde::Serialize;
use serde_json::json;
use uuid::Uuid;
use zeroize::Zeroizing;

#[derive(Serialize)]
struct AgentPassportCreateOutput<'a> {
    profile_name: &'a str,
    agent_passport_id: &'a str,
    status: &'a str,
    public_key: &'a str,
    agent_passport_token: &'a str,
    bindings: &'a [BindingResult],
    activated: bool,
}

pub async fn run(action: AgentPassportAction, runtime: &Runtime) -> Result<()> {
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
        AgentPassportAction::List => {
            let agent_passports = client
                .list_agent_passports()
                .await
                .context("Failed to list agent passports")?;
            runtime.print_data(&agent_passports)?;
        }
        AgentPassportAction::Create {
            name,
            wallet_id,
            passport_policy_id,
            no_activate,
        } => {
            let mut registry =
                load_agent_registry().context("Failed to load local agent registry")?;
            let profile_name = name.unwrap_or_else(|| registry.selected_profile_name());

            if runtime.dry_run_enabled() {
                runtime.print_data(&json!({
                    "dry_run": true,
                    "action": "agent_passport.create",
                    "profile_name": profile_name,
                    "wallet_id": wallet_id,
                    "passport_policy_id": passport_policy_id,
                }))?;
                return Ok(());
            }

            if profile_name.trim().is_empty() {
                anyhow::bail!("Profile name must not be empty");
            }

            if profile_name == DEFAULT_AGENT_PROFILE {
                runtime.progress("Generating new Ed25519 Agent Passport for default profile...");
            } else {
                runtime.progress(format!(
                    "Generating new Ed25519 Agent Passport for profile `{profile_name}`..."
                ));
            }

            // 1. Generate local keypair
            let key = AgentKey::generate();
            let pubkey_hex = key.public_key_hex();

            // 2. Generate a secret key for the Agent Passport Token and encrypt the private key
            let secret_key = generate_secret_key();
            let pem = key
                .export_pem()
                .context("Failed to serialize private key")?;
            let encrypted_key = CryptoEnvelope::encrypt(pem.as_bytes(), &secret_key)
                .context("Failed to encrypt private key")?;

            // 3. Register public key on Passport Gateway
            runtime.progress(format!("Registering public key with Gateway: {pubkey_hex}"));
            let bindings = match (wallet_id.clone(), passport_policy_id.clone()) {
                (Some(wallet_id), Some(passport_policy_id)) => {
                    let policy = client
                        .get_policy(&passport_policy_id)
                        .await
                        .with_context(|| format!("Failed to get policy {passport_policy_id}"))?;
                    vec![BindingInput {
                        wallet_id,
                        passport_policy_id,
                        passport_policy_version: policy.version,
                        is_default: true,
                        selection_priority: 0,
                    }]
                }
                (None, None) => Vec::new(),
                _ => {
                    anyhow::bail!(
                        "`--wallet-id` and `--passport-policy-id` must be provided together when provisioning an active delegated authority"
                    );
                }
            };
            let request = RegisterAgentPassportRequest {
                public_key: pubkey_hex.clone(),
                key_address: format!("ed25519:{}", &pubkey_hex[..16]),
                expires_at: (Utc::now() + Duration::days(365)).to_rfc3339(),
                bindings,
                idempotency_key: format!("idem_{}", Uuid::new_v4().simple()),
            };
            let prepared = client
                .register_agent_passport(&request)
                .await
                .context("Failed to prepare agent passport provisioning")?;
            runtime.progress(format!(
                "Prepared provisioning intent: {}",
                prepared.intent_id
            ));
            let approval = client
                .approve_provisioning_intent(&prepared.intent_id)
                .await
                .context("Failed to approve provisioning intent")?;
            let res = client
                .finalize_agent_passport(&FinalizeAgentPassportRequest {
                    intent_id: prepared.intent_id.clone(),
                    principal_approval_id: approval.principal_approval_id.clone(),
                    idempotency_key: format!("idem_{}", Uuid::new_v4().simple()),
                })
                .await
                .context("Failed to finalize agent passport provisioning")?;

            // 4. Persist agent profile with encrypted key inline
            registry.upsert(AgentIdentity {
                name: profile_name.clone(),
                agent_passport_id: res.agent_passport_id.clone(),
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

            // 5. Build and display the Agent Passport Token
            let agent_passport_token = Zeroizing::new(AgentPassportToken::format(
                &res.agent_passport_id,
                &secret_key,
            ));

            // Keep the owner config on disk for API/base settings only.
            if let Err(error) = config.save_default() {
                persistence_errors.push(format!("failed to persist CLI config: {error}"));
            }

            runtime.important("╔══════════════════════════════════════════════════════════╗");
            runtime.important("║  IMPORTANT: Save the Agent Passport Token below immediately!   ║");
            runtime.important("║  It will NOT be displayed again.                         ║");
            runtime.important("║  If lost, revoke this key and create a new one.          ║");
            runtime.important("╚══════════════════════════════════════════════════════════╝");

            runtime.print_data(&AgentPassportCreateOutput {
                profile_name: &profile_name,
                agent_passport_id: &res.agent_passport_id,
                status: &res.status,
                public_key: &pubkey_hex,
                agent_passport_token: agent_passport_token.as_str(),
                bindings: &res.bindings,
                activated: !no_activate,
            })?;

            if !persistence_errors.is_empty() {
                anyhow::bail!(
                    "Agent Passport was created, but local persistence is incomplete: {}. Save the Agent Passport Token above, then fix the local config/registry or revoke and recreate the agent passport if needed.",
                    persistence_errors.join("; ")
                );
            }
        }
        AgentPassportAction::Get { agent_passport_id } => {
            let agent_passport = client
                .get_agent_passport(&agent_passport_id)
                .await
                .with_context(|| format!("Failed to get agent passport {agent_passport_id}"))?;
            let bindings = client
                .list_bindings(&agent_passport_id)
                .await
                .with_context(|| {
                    format!("Failed to list bindings for agent passport {agent_passport_id}")
                })?;
            let usage = client
                .get_agent_passport_usage(&agent_passport_id)
                .await
                .with_context(|| {
                    format!("Failed to get usage for agent passport {agent_passport_id}")
                })?;
            runtime.print_data(&serde_json::json!({
                "agent_passport": agent_passport,
                "bindings": bindings,
                "usage": usage,
            }))?;
        }
        AgentPassportAction::Freeze { agent_passport_id } => {
            let key_id = agent_passport_id;
            if runtime.dry_run_enabled() {
                runtime.print_data(&json!({
                    "dry_run": true,
                    "action": "agent_passport.freeze",
                    "agent_passport_id": key_id,
                }))?;
                return Ok(());
            }
            let agent_passport = client
                .freeze_agent_passport(&key_id)
                .await
                .with_context(|| format!("Failed to freeze agent passport {key_id}"))?;
            runtime.print_data(&agent_passport)?;
        }
        AgentPassportAction::Revoke { agent_passport_id } => {
            let key_id = agent_passport_id;
            if runtime.dry_run_enabled() {
                runtime.print_data(&json!({
                    "dry_run": true,
                    "action": "agent_passport.revoke",
                    "agent_passport_id": key_id,
                }))?;
                return Ok(());
            }
            let agent_passport = client
                .revoke_agent_passport(&key_id)
                .await
                .with_context(|| format!("Failed to revoke agent passport {key_id}"))?;
            runtime.print_data(&agent_passport)?;
        }
    }
    Ok(())
}
