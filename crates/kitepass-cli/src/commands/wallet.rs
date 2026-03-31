use crate::cli::WalletAction;
use anyhow::{Context, Result};
use dialoguer::Password;
use kitepass_api_client::{ImportAad, PassportClient, UploadWalletCiphertextRequest};
use kitepass_config::CliConfig;
use kitepass_crypto::ecdh::{EphemeralKey, parse_public_key};
use kitepass_crypto::envelope::Envelope;
use kitepass_output::print_json;
use uuid::Uuid;

pub async fn run(action: WalletAction) -> Result<()> {
    let config = CliConfig::load_default().unwrap_or_default();
    let api_url = config.resolved_api_url();
    let token = config
        .access_token
        .clone()
        .context("Please run `kitepass login` first")?;

    let client = PassportClient::new(api_url).with_token(token);

    match action {
        WalletAction::List => {
            let wallets = client
                .list_wallets()
                .await
                .context("Failed to list wallets")?;
            print_json(&wallets).context("Failed to render wallets")?;
        }
        WalletAction::Import { chain, name } => {
            println!("Starting hybrid wallet import for chain: {}", chain);

            // 1. Fetch import session
            let session_res = client
                .create_import_session(&chain, name, format!("idem_{}", Uuid::new_v4().simple()))
                .await
                .context("Failed to create import session")?;

            println!("Session created: {}", session_res.session_id);
            println!(
                "Target Vault Signer: {}",
                session_res.vault_signer_attestation_endpoint
            );

            let attestation = client
                .fetch_import_attestation(&session_res.vault_signer_attestation_endpoint)
                .await
                .context("Failed to fetch Vault Signer attestation")?;
            println!(
                "Fetched attestation bundle for session {}",
                attestation.session_id
            );

            // 2. Prompt for wallet secret
            let wallet_secret = if std::io::IsTerminal::is_terminal(&std::io::stdin()) {
                dialoguer::Password::new()
                    .with_prompt("Enter Wallet Mnemonic or Hex Private Key")
                    .interact()
                    .context("Failed to read wallet secret")?
            } else {
                let mut input = String::new();
                std::io::stdin()
                    .read_line(&mut input)
                    .context("Failed to read wallet secret from stdin")?;
                input.trim().to_string()
            };

            // 3. Setup Ephemeral Keypair
            let vault_pk = parse_public_key(&attestation.import_public_key)
                .context("Invalid Vault Public Key from API")?;
            let vault_nonce = parse_public_key(&attestation.import_nonce)
                .context("Invalid Vault Nonce from API")?;

            let ephemeral_key = EphemeralKey::generate();
            let shared_secret = ephemeral_key.diffie_hellman(&vault_pk);

            // 4. Encrypt Envelope
            let ciphertext = Envelope::encrypt(
                &shared_secret,
                &vault_pk,
                &vault_nonce,
                wallet_secret.as_bytes(),
            )
            .context("Failed to encrypt wallet secret")?;

            // Clear the password string
            let mut wallet_secret = wallet_secret;
            wallet_secret.clear();

            let my_pubkey = ephemeral_key.public_key();
            let envelope_nonce = &ciphertext[..12];
            let cipher_and_tag = &ciphertext[12..];
            let split_at = cipher_and_tag
                .len()
                .checked_sub(16)
                .context("encrypted envelope shorter than expected")?;
            let cipher_bytes = &cipher_and_tag[..split_at];
            let tag_bytes = &cipher_and_tag[split_at..];

            // 5. Upload Ciphertext
            println!("Uploading encrypted envelope to Passport Gateway...");
            let upload_res = client
                .upload_wallet_ciphertext(
                    &session_res.session_id,
                    &UploadWalletCiphertextRequest {
                        vault_signer_instance_id: session_res.vault_signer_instance_id.clone(),
                        owner_ephemeral_pubkey: hex::encode(my_pubkey.as_bytes()),
                        ciphertext: hex::encode(cipher_bytes),
                        nonce: hex::encode(envelope_nonce),
                        tag: hex::encode(tag_bytes),
                        aad: ImportAad {
                            owner_id: session_res.channel_binding.owner_id.clone(),
                            owner_session_id: session_res.channel_binding.owner_session_id.clone(),
                            request_id: session_res.channel_binding.request_id.clone(),
                            vault_signer_instance_id: session_res.vault_signer_instance_id.clone(),
                        },
                    },
                )
                .await
                .context("Failed to upload wallet ciphertext")?;

            if let Some(wallet_id) = upload_res.wallet_id {
                println!("Wallet imported successfully! Wallet ID: {}", wallet_id);
            } else {
                println!(
                    "Wallet import submitted successfully. Operation ID: {}",
                    upload_res.operation_id
                );
            }
        }
        WalletAction::Get { wallet_id } => {
            let wallet = client
                .get_wallet(&wallet_id)
                .await
                .with_context(|| format!("Failed to get wallet {wallet_id}"))?;
            print_json(&wallet).context("Failed to render wallet")?;
        }
        WalletAction::Freeze { wallet_id } => {
            let wallet = client
                .freeze_wallet(&wallet_id)
                .await
                .with_context(|| format!("Failed to freeze wallet {wallet_id}"))?;
            print_json(&wallet).context("Failed to render wallet")?;
        }
        WalletAction::Revoke { wallet_id } => {
            let wallet = client
                .revoke_wallet(&wallet_id)
                .await
                .with_context(|| format!("Failed to revoke wallet {wallet_id}"))?;
            print_json(&wallet).context("Failed to render wallet")?;
        }
    }
    Ok(())
}
