use crate::{cli::AccessKeyAction, error::CliError, runtime::Runtime};
use anyhow::{Context, Result};
use chrono::{Duration, Utc};
use kitepass_api_client::{
    BindingInput, FinalizeAccessKeyRequest, PassportClient, RegisterAccessKeyRequest,
};
use kitepass_config::{AgentIdentity, AgentRegistry, CliConfig, DEFAULT_AGENT_PROFILE, config_dir};
use kitepass_crypto::agent_key::AgentKey;
use serde_json::json;
use std::fs;
use uuid::Uuid;
use zeroize::Zeroizing;

pub async fn run(action: AccessKeyAction, runtime: &Runtime) -> Result<()> {
    let config = CliConfig::load_default().unwrap_or_default();
    let api_url = config.resolved_api_url();
    let token = config
        .access_token
        .clone()
        .ok_or(CliError::AuthenticationRequired)?;

    let client = PassportClient::new(api_url).with_token(token);

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
            let mut registry = AgentRegistry::load_default().unwrap_or_default();
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

            // 2. Prepare the private key for later writing (after successful provisioning)
            let keys_dir = config_dir().join("keys");
            let pem = Zeroizing::new(
                key.export_pem()
                    .context("Failed to serialize private key")?,
            );
            let key_filename = format!("{}.pem", &pubkey_hex[..8]);
            let key_path = keys_dir.join(&key_filename);

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

            // 4. Write private key to disk only after successful provisioning
            fs::create_dir_all(&keys_dir).context("Failed to create keys directory")?;

            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                let mut options = fs::OpenOptions::new();
                options.write(true).create(true).truncate(true).mode(0o600);
                let mut file = options
                    .open(&key_path)
                    .context("Failed to securely open key file")?;
                use std::io::Write;
                file.write_all(pem.as_bytes())
                    .context("Failed to write key to disk")?;
            }

            #[cfg(not(unix))]
            {
                fs::write(&key_path, pem.as_bytes()).context("Failed to write key to disk")?;
            }

            // 4. Persist local agent profile
            registry.upsert(AgentIdentity {
                name: profile_name.clone(),
                access_key_id: res.access_key_id.clone(),
                private_key_path: key_path.to_string_lossy().to_string(),
                public_key_hex: pubkey_hex.clone(),
            })?;

            if !no_activate {
                registry.active_profile = Some(profile_name.clone());
            }

            if let Err(e) = registry.save_default() {
                runtime.progress(format!(
                    "Warning: Failed to update local agent registry: {e}"
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

            // 5. Keep the owner config on disk for API/base settings only.
            if let Err(e) = config.save_default() {
                runtime.progress(format!("Warning: Failed to save CLI config: {e}"));
            }

            runtime.print_data(&json!({
                "profile_name": profile_name,
                "access_key_id": res.access_key_id,
                "status": res.status,
                "public_key": pubkey_hex,
                "private_key_path": key_path,
                "bindings": res.bindings,
                "activated": !no_activate,
            }))?;
        }
        AccessKeyAction::Get { key_id } => {
            let access_key = client
                .get_access_key(&key_id)
                .await
                .with_context(|| format!("Failed to get access key {key_id}"))?;
            let bindings = client
                .list_bindings(&key_id)
                .await
                .with_context(|| format!("Failed to list bindings for access key {key_id}"))?;
            let usage = client
                .get_access_key_usage(&key_id)
                .await
                .with_context(|| format!("Failed to get usage for access key {key_id}"))?;
            runtime.print_data(&serde_json::json!({
                "access_key": access_key,
                "bindings": bindings,
                "usage": usage,
            }))?;
        }
        AccessKeyAction::Bind {
            key_id,
            wallet_id,
            policy_id,
        } => {
            let _ = (key_id, wallet_id, policy_id);
            anyhow::bail!(
                "Direct binding expansion is disabled. Create a new access key with `--wallet-id` and `--policy-id` so the delegated authority can go through owner-approved provisioning."
            );
        }
        AccessKeyAction::Freeze { key_id } => {
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
        AccessKeyAction::Revoke { key_id } => {
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
