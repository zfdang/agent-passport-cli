use crate::{cli::AuditAction, error::CliError, runtime::Runtime};
use anyhow::{Context, Result};
use kitepass_api_client::PassportClient;
use kitepass_config::CliConfig;

pub async fn run(action: AuditAction, runtime: &Runtime) -> Result<()> {
    let config = CliConfig::load_default().unwrap_or_default();
    let api_url = config.resolved_api_url();
    let token = config
        .access_token
        .clone()
        .ok_or(CliError::AuthenticationRequired)?;

    let client = PassportClient::new(api_url).with_token(token);

    match action {
        AuditAction::List { wallet_id } => {
            let events = client
                .list_audit_events(wallet_id.as_deref())
                .await
                .context("Failed to list audit events")?;
            runtime.print_data(&events)?;
        }
        AuditAction::Get { event_id } => {
            let event = client
                .get_audit_event(&event_id)
                .await
                .with_context(|| format!("Failed to get audit event {event_id}"))?;
            runtime.print_data(&event)?;
        }
        AuditAction::Verify => {
            let verification = client
                .verify_audit_chain()
                .await
                .context("Failed to verify audit chain")?;
            runtime.print_data(&verification)?;
        }
    }
    Ok(())
}
