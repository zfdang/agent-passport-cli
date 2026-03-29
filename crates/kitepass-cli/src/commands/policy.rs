use crate::cli::PolicyAction;
use anyhow::{Context, Result};
use chrono::{Duration, Utc};
use kitepass_api_client::{CreatePolicyRequest, PassportClient};
use kitepass_config::CliConfig;
use kitepass_output::print_json;

pub async fn run(action: PolicyAction) -> Result<()> {
    let config = CliConfig::load_default().unwrap_or_default();
    let api_url = config.resolved_api_url();
    let token = config
        .access_token
        .clone()
        .context("Please run `kitepass login` first")?;

    let client = PassportClient::new(api_url).with_token(token);

    match action {
        PolicyAction::List => {
            let policies = client
                .list_policies()
                .await
                .context("Failed to list policies")?;
            print_json(&policies).context("Failed to render policies")?;
        }
        PolicyAction::Create {
            name,
            wallet_id,
            access_key_id,
            allowed_chains,
            allowed_actions,
            max_single_amount,
            max_daily_amount,
            allowed_destinations,
            valid_for_hours,
        } => {
            let _ = name;
            let now = Utc::now();
            let policy = client
                .create_policy(&CreatePolicyRequest {
                    binding_id: None,
                    wallet_id,
                    access_key_id,
                    allowed_chains,
                    allowed_actions,
                    max_single_amount,
                    max_daily_amount,
                    allowed_destinations,
                    valid_from: now,
                    valid_until: now + Duration::hours(valid_for_hours),
                })
                .await
                .context("Failed to create policy")?;
            print_json(&policy).context("Failed to render policy")?;
        }
        PolicyAction::Get { policy_id } => {
            let policy = client
                .get_policy(&policy_id)
                .await
                .with_context(|| format!("Failed to get policy {policy_id}"))?;
            print_json(&policy).context("Failed to render policy")?;
        }
        PolicyAction::Activate { policy_id } => {
            let policy = client
                .activate_policy(&policy_id)
                .await
                .with_context(|| format!("Failed to activate policy {policy_id}"))?;
            print_json(&policy).context("Failed to render policy")?;
        }
        PolicyAction::Deactivate { policy_id } => {
            let policy = client
                .deactivate_policy(&policy_id)
                .await
                .with_context(|| format!("Failed to deactivate policy {policy_id}"))?;
            print_json(&policy).context("Failed to render policy")?;
        }
    }
    Ok(())
}
