use crate::cli::AuditAction;
use anyhow::Result;

pub async fn run(action: AuditAction) -> Result<()> {
    match action {
        AuditAction::List { wallet_id } => {
            println!(
                "kitepass audit list: wallet={}",
                wallet_id.as_deref().unwrap_or("(all)")
            );
        }
        AuditAction::Get { event_id } => {
            println!("kitepass audit get: {event_id}");
        }
        AuditAction::Verify => {
            println!("kitepass audit verify (not yet implemented)");
        }
    }
    Ok(())
}
