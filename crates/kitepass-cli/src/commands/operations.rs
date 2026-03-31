use crate::{cli::OperationsAction, runtime::Runtime};
use anyhow::{Context, Result};
use kitepass_api_client::PassportClient;
use kitepass_config::CliConfig;

pub async fn run(action: OperationsAction, runtime: &Runtime) -> Result<()> {
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
            runtime.print_data(&operation)?;
        }
    }
    Ok(())
}
