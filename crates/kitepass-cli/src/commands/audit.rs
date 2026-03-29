use crate::cli::AuditAction;
use anyhow::{Context, Result};
use kitepass_api_client::PassportClient;
use kitepass_config::CliConfig;
use kitepass_output::print_json;

pub async fn run(action: AuditAction) -> Result<()> {
    let config = CliConfig::load_default().unwrap_or_default();
    let api_url = config.resolved_api_url();
    let token = config
        .access_token
        .clone()
        .context("Please run `kitepass login` first")?;

    let client = PassportClient::new(api_url).with_token(token);

    match action {
        AuditAction::List { wallet_id } => {
            let events = client
                .list_audit_events(wallet_id.as_deref())
                .await
                .context("Failed to list audit events")?;
            print_json(&events).context("Failed to render audit events")?;
        }
        AuditAction::Get { event_id } => {
            let event = client
                .get_audit_event(&event_id)
                .await
                .with_context(|| format!("Failed to get audit event {event_id}"))?;
            print_json(&event).context("Failed to render audit event")?;
        }
        AuditAction::Verify => {
            let verification = client
                .verify_audit_chain()
                .await
                .context("Failed to verify audit chain")?;
            print_json(&verification).context("Failed to render audit verification")?;
        }
    }
    Ok(())
}
