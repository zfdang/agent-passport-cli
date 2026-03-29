use crate::cli::AccessKeyAction;
use anyhow::{Context, Result};
use chrono::{Duration, Utc};
use kitepass_api_client::{CreateBindingRequest, PassportClient, RegisterAccessKeyRequest};
use kitepass_config::{CliConfig, config_dir};
use kitepass_crypto::agent_key::AgentKey;
use kitepass_output::print_json;
use std::fs;
use uuid::Uuid;

pub async fn run(action: AccessKeyAction) -> Result<()> {
    let config = CliConfig::load_default().unwrap_or_default();
    let api_url = config.resolved_api_url();
    let token = config
        .access_token
        .clone()
        .context("Please run `kitepass login` first")?;

    let client = PassportClient::new(api_url).with_token(token);

    match action {
        AccessKeyAction::List => {
            let access_keys = client
                .list_access_keys()
                .await
                .context("Failed to list access keys")?;
            print_json(&access_keys).context("Failed to render access keys")?;
        }
        AccessKeyAction::Create { name } => {
            if let Some(name) = name.as_deref() {
                println!("Generating new Ed25519 Agent Access Key for {name}...");
            } else {
                println!("Generating new Ed25519 Agent Access Key...");
            }

            // 1. Generate local keypair
            let key = AgentKey::generate();
            let pubkey_hex = key.public_key_hex();

            // 2. Export and save the private key locally
            let keys_dir = config_dir().join("keys");
            fs::create_dir_all(&keys_dir).context("Failed to create keys directory")?;

            let pem = key
                .export_pem()
                .context("Failed to serialize private key")?;
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
                fs::write(&key_path, &pem).context("Failed to write key to disk")?;
            }

            println!("\n=========== AGENT PRIVATE KEY ===========");
            println!("{}", pem);
            println!("=========================================\n");

            println!("⚠️ IMPORTANT: The private key string above has been securely saved to:");
            println!("   {:?}", key_path);
            println!(
                "   Please back it up and do not share it with anyone. It will not be shown again.\n"
            );

            // 3. Register public key on Passport Gateway
            println!("Registering public key with Gateway: {}", pubkey_hex);
            let request = RegisterAccessKeyRequest {
                public_key: pubkey_hex.clone(),
                key_address: format!("ed25519:{}", &pubkey_hex[..16]),
                expires_at: (Utc::now() + Duration::days(365)).to_rfc3339(),
                bindings: Vec::new(),
                idempotency_key: format!("idem_{}", Uuid::new_v4().simple()),
            };
            let res = client
                .register_access_key(&request)
                .await
                .context("Failed to register access key")?;

            println!(
                "Agent Access Key registered successfully. Key ID: {}",
                res.access_key_id
            );
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
            print_json(&serde_json::json!({
                "access_key": access_key,
                "bindings": bindings,
                "usage": usage,
            }))
            .context("Failed to render access key details")?;
        }
        AccessKeyAction::Bind {
            key_id,
            wallet_id,
            policy_id,
        } => {
            let policy_id = policy_id.context("`--policy-id` is required for bind")?;
            let policy = client
                .get_policy(&policy_id)
                .await
                .with_context(|| format!("Failed to get policy {policy_id}"))?;
            let binding = client
                .create_binding(
                    &key_id,
                    &CreateBindingRequest {
                        wallet_id,
                        policy_id,
                        policy_version: policy.version,
                        is_default: true,
                        selection_priority: 0,
                    },
                )
                .await
                .with_context(|| format!("Failed to bind access key {key_id}"))?;
            print_json(&binding).context("Failed to render binding result")?;
        }
        AccessKeyAction::Freeze { key_id } => {
            let access_key = client
                .freeze_access_key(&key_id)
                .await
                .with_context(|| format!("Failed to freeze access key {key_id}"))?;
            print_json(&access_key).context("Failed to render access key")?;
        }
        AccessKeyAction::Revoke { key_id } => {
            let access_key = client
                .revoke_access_key(&key_id)
                .await
                .with_context(|| format!("Failed to revoke access key {key_id}"))?;
            print_json(&access_key).context("Failed to render access key")?;
        }
    }
    Ok(())
}
