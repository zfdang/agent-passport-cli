use crate::cli::WalletAction;
use anyhow::{Context, Result};
use dialoguer::Password;
use kitepass_api_client::PassportClient;
use kitepass_config::CliConfig;
use kitepass_crypto::ecdh::{EphemeralKey, parse_public_key};
use kitepass_crypto::envelope::Envelope;

pub async fn run(action: WalletAction) -> Result<()> {
    let config = CliConfig::load_default().unwrap_or_default();
    let api_url = config.api_url.as_deref().unwrap_or("https://api.kitepass.ai");
    let token = config.access_token.clone().context("Please run `kitepass login` first")?;

    let client = PassportClient::new(api_url).with_token(token);

    match action {
        WalletAction::List => {
            println!("kitepass wallet list (not yet implemented)");
        }
        WalletAction::Import { chain, name } => {
            println!("Starting hybrid wallet import for chain: {}", chain);

            // 1. Fetch import session
            let session_res = client
                .create_import_session(&chain, name)
                .await
                .context("Failed to create import session")?;

            println!("Session created: {}", session_res.session_id);
            println!("Target Vault Signer: {}", session_res.vault_signer_url);
            // TODO: verify attestation document returned in session_res.attestation_doc

            // 2. Prompt for wallet secret
            let wallet_secret = Password::new()
                .with_prompt("Enter Wallet Mnemonic or Hex Private Key")
                .interact()
                .context("Failed to read wallet secret")?;

            // 3. Setup Ephemeral Keypair
            let vault_pk = parse_public_key(&session_res.vault_signer_pubkey)
                .context("Invalid Vault Public Key from API")?;
            let vault_nonce = parse_public_key(&session_res.vault_nonce)
                .context("Invalid Vault Nonce from API")?;

            let ephemeral_key = EphemeralKey::generate();
            let shared_secret = ephemeral_key.diffie_hellman(&vault_pk);

            // 4. Encrypt Envelope
            let mut ciphertext = Envelope::encrypt(
                &shared_secret,
                &vault_pk,
                &vault_nonce,
                wallet_secret.as_bytes(),
            )
            .context("Failed to encrypt wallet secret")?;

            // Clear the password string
            let mut wallet_secret = wallet_secret;
            wallet_secret.clear();

            // The ciphertext payload expects my ephemeral pubkey appended or prefix?
            // Actually the design depends on Vault Signer knowing our ephemeral Key.
            // Let's prepend the ephemeral public key (32 bytes) to the payload so it can decrypt it.
            let my_pubkey = ephemeral_key.public_key();
            let mut final_payload = Vec::with_capacity(32 + ciphertext.len());
            final_payload.extend_from_slice(my_pubkey.as_bytes());
            final_payload.append(&mut ciphertext);

            let payload_hex = hex::encode(&final_payload);

            // 5. Upload Ciphertext
            println!("Uploading encrypted envelope to Passport Gateway...");
            let upload_res = client
                .upload_wallet_ciphertext(&session_res.session_id, &payload_hex)
                .await
                .context("Failed to upload wallet ciphertext")?;

            println!("Wallet imported successfully! Wallet ID: {}", upload_res.wallet_id);
        }
        WalletAction::Get { wallet_id } => {
            println!("kitepass wallet get: {wallet_id} (not implemented)");
        }
        WalletAction::Freeze { wallet_id } => {
            println!("kitepass wallet freeze: {wallet_id} (not implemented)");
        }
        WalletAction::Revoke { wallet_id } => {
            println!("kitepass wallet revoke: {wallet_id} (not implemented)");
        }
    }
    Ok(())
}
