use crate::{cli::AccessKeyAction, error::CliError, runtime::Runtime};
use anyhow::{Context, Result};
use chrono::{Duration, Utc};
use kitepass_api_client::{
    BindingInput, FinalizeAccessKeyRequest, PassportClient, RegisterAccessKeyRequest,
};
use kitepass_config::{CliConfig, config_dir};
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
        } => {
            if runtime.dry_run_enabled() {
                runtime.print_data(&json!({
                    "dry_run": true,
                    "action": "access_key.create",
                    "name": name,
                    "wallet_id": wallet_id,
                    "policy_id": policy_id,
                }))?;
                return Ok(());
            }

            if let Some(name) = name.as_deref() {
                runtime.progress(format!(
                    "Generating new Ed25519 Agent Access Key for {name}..."
                ));
            } else {
                runtime.progress("Generating new Ed25519 Agent Access Key...");
            }

            // 1. Generate local keypair
            let key = AgentKey::generate();
            let pubkey_hex = key.public_key_hex();

            // 2. Export and save the private key locally
            let keys_dir = config_dir().join("keys");
            fs::create_dir_all(&keys_dir).context("Failed to create keys directory")?;

            let pem = Zeroizing::new(
                key.export_pem()
                    .context("Failed to serialize private key")?,
            );
            let key_filename = format!("{}.pem", &pubkey_hex[..8]);
            let key_path = keys_dir.join(&key_filename);

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

            runtime.print_data(&json!({
                "access_key_id": res.access_key_id,
                "status": res.status,
                "public_key": pubkey_hex,
                "private_key_path": key_path,
                "bindings": res.bindings,
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
