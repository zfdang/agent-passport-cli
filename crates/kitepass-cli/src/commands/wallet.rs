use crate::commands::load_cli_config;
use crate::commands::wallet_import::{build_import_hpke_info, verify_import_attestation};
use crate::{cli::WalletAction, error::CliError, runtime::Runtime};
use anyhow::{bail, Context, Result};
use kitepass_api_client::{ImportAad, PassportClient, UploadWalletCiphertextRequest};
use kitepass_crypto::hpke::seal_to_hex;
use serde_json::json;
use tokio::task::spawn_blocking;
use uuid::Uuid;
use zeroize::Zeroizing;

pub async fn run(action: WalletAction, runtime: &Runtime) -> Result<()> {
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
        WalletAction::List => {
            let wallets = client
                .list_wallets()
                .await
                .context("Failed to list wallets")?;
            runtime.print_data(&wallets)?;
        }
        WalletAction::Import { chain_family, name } => {
            if runtime.dry_run_enabled() {
                let chain_family = normalize_wallet_chain_family(&chain_family)?;
                runtime.print_data(&json!({
                    "dry_run": true,
                    "action": "wallet.import",
                    "chain_family": chain_family,
                    "label": name,
                }))?;
                return Ok(());
            }

            let chain_family = normalize_wallet_chain_family(&chain_family)?;
            runtime.progress(format!(
                "Starting hybrid wallet import for chain family: {chain_family}"
            ));

            // 1. Fetch import session
            let session_res = client
                .create_import_session(
                    chain_family,
                    name,
                    format!("idem_{}", Uuid::new_v4().simple()),
                )
                .await
                .context("Failed to create import session")?;

            runtime.progress(format!("Session created: {}", session_res.session_id));
            runtime.progress(format!(
                "Target Vault Signer: {}",
                session_res.vault_signer_attestation_endpoint
            ));

            let attestation = client
                .fetch_import_attestation(&session_res.vault_signer_attestation_endpoint)
                .await
                .context("Failed to fetch Vault Signer attestation")?;
            verify_import_attestation(&session_res, &attestation)
                .context("Failed to verify Vault Signer attestation")?;
            runtime.progress(format!(
                "Fetched attestation bundle for session {}",
                attestation.session_id
            ));

            // 2. Prompt for wallet secret
            let wallet_secret = if std::io::IsTerminal::is_terminal(&std::io::stdin()) {
                runtime.require_secret_from_stdin("wallet import")?;
                spawn_blocking(|| -> Result<Zeroizing<String>> {
                    Ok(Zeroizing::new(
                        dialoguer::Password::new()
                            .with_prompt("Enter EVM Hex Private Key")
                            .interact()
                            .context("Failed to read wallet secret")?,
                    ))
                })
                .await
                .context("wallet prompt task failed")??
            } else {
                spawn_blocking(|| -> Result<Zeroizing<String>> {
                    let mut input = Zeroizing::new(String::new());
                    std::io::stdin()
                        .read_line(&mut input)
                        .context("Failed to read wallet secret from stdin")?;
                    while matches!(input.chars().last(), Some('\n' | '\r')) {
                        input.pop();
                    }
                    Ok(input)
                })
                .await
                .context("stdin wallet read task failed")??
            };

            let aad = ImportAad {
                owner_id: session_res.channel_binding.owner_id.clone(),
                owner_session_id: session_res.channel_binding.owner_session_id.clone(),
                request_id: session_res.channel_binding.request_id.clone(),
                vault_signer_instance_id: session_res.vault_signer_instance_id.clone(),
            };
            let hpke_info = build_import_hpke_info(&session_res, &attestation)?;
            let aad_bytes =
                serde_json::to_vec(&aad).context("Failed to serialize import channel binding")?;

            // 3. Encrypt Envelope
            let sealed = seal_to_hex(
                &attestation.import_public_key,
                &hpke_info,
                &aad_bytes,
                wallet_secret.as_bytes(),
            )
            .context("Failed to HPKE-encrypt wallet secret")?;

            // 4. Upload Ciphertext
            runtime.progress("Uploading encrypted envelope to Passport Gateway...");
            let upload_res = client
                .upload_wallet_ciphertext(
                    &session_res.session_id,
                    &UploadWalletCiphertextRequest {
                        vault_signer_instance_id: session_res.vault_signer_instance_id.clone(),
                        encapsulated_key: sealed.encapsulated_key_hex,
                        ciphertext: sealed.ciphertext_hex,
                        aad,
                    },
                )
                .await
                .context("Failed to upload wallet ciphertext")?;

            runtime.print_data(&upload_res)?;
        }
        WalletAction::Get { wallet_id } => {
            let wallet = client
                .get_wallet(&wallet_id)
                .await
                .with_context(|| format!("Failed to get wallet {wallet_id}"))?;
            runtime.print_data(&wallet)?;
        }
        WalletAction::Freeze { wallet_id } => {
            if runtime.dry_run_enabled() {
                runtime.print_data(&json!({
                    "dry_run": true,
                    "action": "wallet.freeze",
                    "wallet_id": wallet_id,
                }))?;
                return Ok(());
            }
            let wallet = client
                .freeze_wallet(&wallet_id)
                .await
                .with_context(|| format!("Failed to freeze wallet {wallet_id}"))?;
            runtime.print_data(&wallet)?;
        }
        WalletAction::Revoke { wallet_id } => {
            if runtime.dry_run_enabled() {
                runtime.print_data(&json!({
                    "dry_run": true,
                    "action": "wallet.revoke",
                    "wallet_id": wallet_id,
                }))?;
                return Ok(());
            }
            let wallet = client
                .revoke_wallet(&wallet_id)
                .await
                .with_context(|| format!("Failed to revoke wallet {wallet_id}"))?;
            runtime.print_data(&wallet)?;
        }
    }
    Ok(())
}

fn normalize_wallet_chain_family(value: &str) -> Result<&'static str> {
    match value.trim().to_ascii_lowercase().as_str() {
        "evm" | "eip155" | "base" => Ok("evm"),
        other => bail!("wallet import currently supports the evm chain family only, got `{other}`"),
    }
}
