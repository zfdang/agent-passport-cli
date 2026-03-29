use crate::cli::AccessKeyAction;
use anyhow::{Context, Result};
use kitepass_api_client::PassportClient;
use kitepass_config::{CliConfig, config_dir};
use kitepass_crypto::agent_key::AgentKey;
use std::fs;

pub async fn run(action: AccessKeyAction) -> Result<()> {
    let config = CliConfig::load_default().unwrap_or_default();
    let api_url = config.api_url.as_deref().unwrap_or("https://api.kitepass.ai");
    let token = config.access_token.clone().context("Please run `kitepass login` first")?;

    let client = PassportClient::new(api_url).with_token(token);

    match action {
        AccessKeyAction::List => {
            println!("kitepass access-key list (not implemented)");
        }
        AccessKeyAction::Create { name } => {
            println!("Generating new Ed25519 Agent Access Key...");

            // 1. Generate local keypair
            let key = AgentKey::generate();
            let pubkey_hex = key.public_key_hex();

            // 2. Export and save the private key locally
            let keys_dir = config_dir().join("keys");
            fs::create_dir_all(&keys_dir).context("Failed to create keys directory")?;

            let pem = key.export_pem().context("Failed to serialize private key")?;
            let key_filename = format!("{}.pem", pubkey_hex[..8].to_string());
            let key_path = keys_dir.join(&key_filename);

            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                let mut options = fs::OpenOptions::new();
                options.write(true).create(true).truncate(true).mode(0o600);
                let mut file = options.open(&key_path).context("Failed to securely open key file")?;
                use std::io::Write;
                file.write_all(pem.as_bytes()).context("Failed to write key to disk")?;
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
            println!("   Please back it up and do not share it with anyone. It will not be shown again.\n");

            // 3. Register public key on Passport Gateway
            println!("Registering public key with Gateway: {}", pubkey_hex);
            let res = client
                .register_access_key(&pubkey_hex, name)
                .await
                .context("Failed to register access key")?;

            println!("Agent Access Key registered successfully. Key ID: {}", res.key_id);
        }
        AccessKeyAction::Get { key_id } => {
            println!("kitepass access-key get: {key_id}");
        }
        AccessKeyAction::Bind {
            key_id,
            wallet_id,
            policy_id,
        } => {
            println!(
                "kitepass access-key bind: key={key_id}, wallet={wallet_id}, policy={}",
                policy_id.as_deref().unwrap_or("(none)")
            );
        }
        AccessKeyAction::Freeze { key_id } => {
            println!("kitepass access-key freeze: {key_id}");
        }
        AccessKeyAction::Revoke { key_id } => {
            println!("kitepass access-key revoke: {key_id}");
        }
    }
    Ok(())
}
