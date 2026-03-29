use crate::cli::OperationsAction;
use anyhow::{Context, Result};
use kitepass_api_client::PassportClient;
use kitepass_config::CliConfig;
use kitepass_output::print_json;

pub async fn run(action: OperationsAction) -> Result<()> {
    let config = CliConfig::load_default().unwrap_or_default();
    let api_url = config.resolved_api_url();

    let client = if let Some(token) = config.access_token.clone() {
        PassportClient::new(api_url).with_token(token)
    } else {
        PassportClient::new(api_url)
    };

    match action {
        OperationsAction::Get { operation_id } => {
            let operation = client
                .get_operation(&operation_id)
                .await
                .with_context(|| format!("Failed to get operation {operation_id}"))?;
            print_json(&operation).context("Failed to render operation")?;
        }
    }
    Ok(())
}
