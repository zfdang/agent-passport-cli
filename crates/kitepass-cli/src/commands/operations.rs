use crate::{cli::OperationsAction, commands::load_cli_config, runtime::Runtime};
use anyhow::{Context, Result};
use kitepass_api_client::PassportClient;

pub async fn run(action: OperationsAction, runtime: &Runtime) -> Result<()> {
    let config = load_cli_config().context("Failed to load CLI config")?;
    let api_url = config.resolved_api_url();

    let client = if let Some(token) = config.access_token.clone() {
        PassportClient::new(api_url)
            .context("Failed to initialize Passport API client")?
            .with_token(token)
    } else {
        PassportClient::new(api_url).context("Failed to initialize Passport API client")?
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
