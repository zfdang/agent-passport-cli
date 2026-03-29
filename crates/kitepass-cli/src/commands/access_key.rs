use anyhow::Result;
use crate::cli::AccessKeyAction;

pub async fn run(action: AccessKeyAction) -> Result<()> {
    match action {
        AccessKeyAction::List => {
            println!("kitepass access-key list (not yet implemented)");
        }
        AccessKeyAction::Create { name } => {
            println!(
                "kitepass access-key create: name={}",
                name.as_deref().unwrap_or("(none)")
            );
            // TODO:
            // 1. Generate Ed25519 keypair locally
            // 2. POST /v1/access-keys with public key
            // 3. Store keypair in local secure config
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
