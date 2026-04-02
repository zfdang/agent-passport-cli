use crate::{cli::PolicyAction, commands::load_cli_config, error::CliError, runtime::Runtime};
use anyhow::{Context, Result};
use chrono::{Duration, Utc};
use kitepass_api_client::{CreatePolicyRequest, PassportClient};
use serde_json::json;

pub async fn run(action: PolicyAction, runtime: &Runtime) -> Result<()> {
    let config = load_cli_config().context("Failed to load CLI config")?;
    let api_url = config.resolved_api_url();
    let token = config
        .access_token
        .clone()
        .ok_or(CliError::AuthenticationRequired)?;

    let client = PassportClient::new(api_url)
        .context("Failed to initialize Passport API client")?
        .with_token(token);

    match action {
        PolicyAction::List => {
            let policies = client
                .list_policies()
                .await
                .context("Failed to list policies")?;
            runtime.print_data(&policies)?;
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
            if runtime.dry_run_enabled() {
                runtime.print_data(&json!({
                    "dry_run": true,
                    "action": "policy.create",
                    "name": name,
                    "wallet_id": wallet_id,
                    "access_key_id": access_key_id,
                    "allowed_chains": allowed_chains,
                    "allowed_actions": allowed_actions,
                    "max_single_amount": max_single_amount,
                    "max_daily_amount": max_daily_amount,
                    "allowed_destinations": allowed_destinations,
                    "valid_for_hours": valid_for_hours,
                }))?;
                return Ok(());
            }

            let _ = name;
            if valid_for_hours <= 0 {
                anyhow::bail!("--valid-for-hours must be a positive integer");
            }
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
            runtime.print_data(&policy)?;
        }
        PolicyAction::Get { policy_id } => {
            let policy = client
                .get_policy(&policy_id)
                .await
                .with_context(|| format!("Failed to get policy {policy_id}"))?;
            runtime.print_data(&policy)?;
        }
        PolicyAction::Activate { policy_id } => {
            if runtime.dry_run_enabled() {
                runtime.print_data(&json!({
                    "dry_run": true,
                    "action": "policy.activate",
                    "policy_id": policy_id,
                }))?;
                return Ok(());
            }
            let policy = client
                .activate_policy(&policy_id)
                .await
                .with_context(|| format!("Failed to activate policy {policy_id}"))?;
            runtime.print_data(&policy)?;
        }
        PolicyAction::Deactivate { policy_id } => {
            if runtime.dry_run_enabled() {
                runtime.print_data(&json!({
                    "dry_run": true,
                    "action": "policy.deactivate",
                    "policy_id": policy_id,
                }))?;
                return Ok(());
            }
            let policy = client
                .deactivate_policy(&policy_id)
                .await
                .with_context(|| format!("Failed to deactivate policy {policy_id}"))?;
            runtime.print_data(&policy)?;
        }
    }
    Ok(())
}
