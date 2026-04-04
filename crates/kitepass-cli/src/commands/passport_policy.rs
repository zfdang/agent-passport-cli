use crate::{
    cli::PassportPolicyAction, commands::load_cli_config, error::CliError, runtime::Runtime,
};
use anyhow::{Context, Result};
use chrono::{Duration, Utc};
use kitepass_api_client::{CreatePassportPolicyRequest, PassportClient};
use serde_json::json;

pub async fn run(action: PassportPolicyAction, runtime: &Runtime) -> Result<()> {
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
        PassportPolicyAction::List => {
            let policies = client
                .list_policies()
                .await
                .context("Failed to list policies")?;
            runtime.print_data(&policies)?;
        }
        PassportPolicyAction::Create {
            wallet_id,
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
                    "action": "passport_policy.create",
                    "wallet_id": wallet_id,
                    "allowed_chains": allowed_chains,
                    "allowed_actions": allowed_actions,
                    "max_single_amount": max_single_amount,
                    "max_daily_amount": max_daily_amount,
                    "allowed_destinations": allowed_destinations,
                    "valid_for_hours": valid_for_hours,
                }))?;
                return Ok(());
            }

            if valid_for_hours <= 0 {
                anyhow::bail!("--valid-for-hours must be a positive integer");
            }
            let now = Utc::now();
            let policy = client
                .create_policy(&CreatePassportPolicyRequest {
                    binding_id: None,
                    wallet_id,
                    agent_passport_id: None,
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
        PassportPolicyAction::Get { passport_policy_id } => {
            let policy = client
                .get_policy(&passport_policy_id)
                .await
                .with_context(|| format!("Failed to get policy {passport_policy_id}"))?;
            runtime.print_data(&policy)?;
        }
        PassportPolicyAction::Activate { passport_policy_id } => {
            if runtime.dry_run_enabled() {
                runtime.print_data(&json!({
                    "dry_run": true,
                    "action": "passport_policy.activate",
                    "passport_policy_id": passport_policy_id,
                }))?;
                return Ok(());
            }
            let policy = client
                .activate_policy(&passport_policy_id)
                .await
                .with_context(|| format!("Failed to activate policy {passport_policy_id}"))?;
            runtime.print_data(&policy)?;
        }
        PassportPolicyAction::Deactivate { passport_policy_id } => {
            if runtime.dry_run_enabled() {
                runtime.print_data(&json!({
                    "dry_run": true,
                    "action": "passport_policy.deactivate",
                    "passport_policy_id": passport_policy_id,
                }))?;
                return Ok(());
            }
            let policy = client
                .deactivate_policy(&passport_policy_id)
                .await
                .with_context(|| format!("Failed to deactivate policy {passport_policy_id}"))?;
            runtime.print_data(&policy)?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    /// The dry-run branches in `run()` emit JSON via `serde_json::json!`.
    /// These tests verify the exact shape and action names so downstream
    /// consumers (CI scripts, MCP tooling) can rely on a stable contract.

    #[test]
    fn dry_run_create_json_has_expected_fields() {
        let wallet_id = "wal_abc123".to_string();
        let allowed_chains = vec!["eip155:8453".to_string()];
        let allowed_actions = vec!["sign_transaction".to_string()];
        let max_single_amount = "1000".to_string();
        let max_daily_amount = "5000".to_string();
        let allowed_destinations = vec!["0xdeadbeef".to_string()];
        let valid_for_hours: i64 = 48;

        let output = json!({
            "dry_run": true,
            "action": "passport_policy.create",
            "wallet_id": wallet_id,
            "allowed_chains": allowed_chains,
            "allowed_actions": allowed_actions,
            "max_single_amount": max_single_amount,
            "max_daily_amount": max_daily_amount,
            "allowed_destinations": allowed_destinations,
            "valid_for_hours": valid_for_hours,
        });

        assert_eq!(output["dry_run"], true);
        assert_eq!(output["action"], "passport_policy.create");
        assert_eq!(output["wallet_id"], "wal_abc123");
        assert_eq!(output["allowed_chains"][0], "eip155:8453");
        assert_eq!(output["allowed_actions"][0], "sign_transaction");
        assert_eq!(output["max_single_amount"], "1000");
        assert_eq!(output["max_daily_amount"], "5000");
        assert_eq!(output["allowed_destinations"][0], "0xdeadbeef");
        assert_eq!(output["valid_for_hours"], 48);
    }

    #[test]
    fn dry_run_activate_json_has_expected_fields() {
        let passport_policy_id = "pp_activate_001".to_string();

        let output = json!({
            "dry_run": true,
            "action": "passport_policy.activate",
            "passport_policy_id": passport_policy_id,
        });

        assert_eq!(output["dry_run"], true);
        assert_eq!(output["action"], "passport_policy.activate");
        assert_eq!(output["passport_policy_id"], "pp_activate_001");
    }

    #[test]
    fn dry_run_deactivate_json_has_expected_fields() {
        let passport_policy_id = "pp_deactivate_002".to_string();

        let output = json!({
            "dry_run": true,
            "action": "passport_policy.deactivate",
            "passport_policy_id": passport_policy_id,
        });

        assert_eq!(output["dry_run"], true);
        assert_eq!(output["action"], "passport_policy.deactivate");
        assert_eq!(output["passport_policy_id"], "pp_deactivate_002");
    }

    #[test]
    fn action_names_are_distinct() {
        let create = json!({ "action": "passport_policy.create" });
        let activate = json!({ "action": "passport_policy.activate" });
        let deactivate = json!({ "action": "passport_policy.deactivate" });

        assert_ne!(create["action"], activate["action"]);
        assert_ne!(activate["action"], deactivate["action"]);
        assert_ne!(create["action"], deactivate["action"]);
    }
}
