use crate::cli::WalletAction;
use anyhow::Result;

pub async fn run(action: WalletAction) -> Result<()> {
    match action {
        WalletAction::List => {
            println!("kitepass wallet list (not yet implemented)");
        }
        WalletAction::Import { chain, name } => {
            println!(
                "kitepass wallet import: chain={chain}, name={}",
                name.as_deref().unwrap_or("(none)")
            );
            // TODO:
            // 1. POST /v1/wallets/import-sessions → get session_id + attestation info
            // 2. Verify attestation document
            // 3. Prompt for private key or keystore
            // 4. ECDH encrypt → upload envelope
        }
        WalletAction::Get { wallet_id } => {
            println!("kitepass wallet get: {wallet_id}");
        }
        WalletAction::Freeze { wallet_id } => {
            println!("kitepass wallet freeze: {wallet_id}");
        }
        WalletAction::Revoke { wallet_id } => {
            println!("kitepass wallet revoke: {wallet_id}");
        }
    }
    Ok(())
}
