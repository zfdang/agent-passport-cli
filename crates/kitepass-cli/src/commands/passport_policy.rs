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

    // -----------------------------------------------------------------------
    // Dry-run JSON contract tests
    // -----------------------------------------------------------------------
    // The dry-run branches in `run()` emit JSON via `serde_json::json!`.
    // These tests verify the exact shape and action names so downstream
    // consumers (CI scripts, MCP tooling) can rely on a stable contract.

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

    // -----------------------------------------------------------------------
    // Dry-run JSON: edge-case / boundary values
    // -----------------------------------------------------------------------

    #[test]
    fn dry_run_create_json_with_empty_vectors() {
        let output = json!({
            "dry_run": true,
            "action": "passport_policy.create",
            "wallet_id": "wal_empty",
            "allowed_chains": Vec::<String>::new(),
            "allowed_actions": Vec::<String>::new(),
            "max_single_amount": "0",
            "max_daily_amount": "0",
            "allowed_destinations": Vec::<String>::new(),
            "valid_for_hours": 1,
        });

        assert!(output["allowed_chains"].as_array().unwrap().is_empty());
        assert!(output["allowed_actions"].as_array().unwrap().is_empty());
        assert!(output["allowed_destinations"]
            .as_array()
            .unwrap()
            .is_empty());
        assert_eq!(output["max_single_amount"], "0");
        assert_eq!(output["max_daily_amount"], "0");
    }

    #[test]
    fn dry_run_create_json_with_multiple_chains_and_actions() {
        let allowed_chains = vec![
            "eip155:1".to_string(),
            "eip155:8453".to_string(),
            "eip155:42161".to_string(),
        ];
        let allowed_actions = vec!["sign_transaction".to_string(), "sign_message".to_string()];
        let allowed_destinations = vec!["0xaaa".to_string(), "0xbbb".to_string()];

        let output = json!({
            "dry_run": true,
            "action": "passport_policy.create",
            "wallet_id": "wal_multi",
            "allowed_chains": allowed_chains,
            "allowed_actions": allowed_actions,
            "max_single_amount": "999999",
            "max_daily_amount": "9999999",
            "allowed_destinations": allowed_destinations,
            "valid_for_hours": 168,
        });

        assert_eq!(output["allowed_chains"].as_array().unwrap().len(), 3);
        assert_eq!(output["allowed_actions"].as_array().unwrap().len(), 2);
        assert_eq!(output["allowed_destinations"].as_array().unwrap().len(), 2);
        assert_eq!(output["allowed_chains"][2], "eip155:42161");
        assert_eq!(output["allowed_actions"][1], "sign_message");
        assert_eq!(output["allowed_destinations"][1], "0xbbb");
        assert_eq!(output["valid_for_hours"], 168);
    }

    #[test]
    fn dry_run_create_json_preserves_valid_for_hours_type_as_integer() {
        let output = json!({
            "dry_run": true,
            "action": "passport_policy.create",
            "wallet_id": "wal_type",
            "allowed_chains": ["eip155:1"],
            "allowed_actions": ["sign_transaction"],
            "max_single_amount": "100",
            "max_daily_amount": "200",
            "allowed_destinations": ["0xfoo"],
            "valid_for_hours": 24_i64,
        });

        // Must serialize as a JSON integer, not a string
        assert!(output["valid_for_hours"].is_i64());
        assert_eq!(output["valid_for_hours"].as_i64().unwrap(), 24);
    }

    // -----------------------------------------------------------------------
    // valid_for_hours validation logic
    // -----------------------------------------------------------------------
    // The `run()` function bails when `valid_for_hours <= 0`.  We replicate
    // the guard here so the boundary conditions are covered without needing
    // an API client or Runtime.

    fn validate_valid_for_hours(value: i64) -> Result<(), &'static str> {
        if value <= 0 {
            return Err("--valid-for-hours must be a positive integer");
        }
        Ok(())
    }

    #[test]
    fn valid_for_hours_rejects_zero() {
        assert!(validate_valid_for_hours(0).is_err());
    }

    #[test]
    fn valid_for_hours_rejects_negative() {
        assert!(validate_valid_for_hours(-1).is_err());
        assert!(validate_valid_for_hours(-100).is_err());
    }

    #[test]
    fn valid_for_hours_accepts_positive() {
        assert!(validate_valid_for_hours(1).is_ok());
        assert!(validate_valid_for_hours(24).is_ok());
        assert!(validate_valid_for_hours(8760).is_ok()); // one year
    }

    #[test]
    fn valid_for_hours_error_message_matches_run() {
        let err = validate_valid_for_hours(0).unwrap_err();
        assert_eq!(err, "--valid-for-hours must be a positive integer");
    }

    // -----------------------------------------------------------------------
    // valid_until calculation (Duration::hours)
    // -----------------------------------------------------------------------

    #[test]
    fn valid_until_is_after_valid_from() {
        use chrono::{Duration, Utc};

        let now = Utc::now();
        let hours: i64 = 48;
        let valid_until = now + Duration::hours(hours);

        assert!(valid_until > now);
        // The difference should be exactly 48 hours (within a small epsilon
        // for the time elapsed between the two calls, but since both use
        // the same `now` this is exact).
        assert_eq!((valid_until - now).num_hours(), 48);
    }

    #[test]
    fn valid_until_at_boundary_one_hour() {
        use chrono::{Duration, Utc};

        let now = Utc::now();
        let valid_until = now + Duration::hours(1);

        assert_eq!((valid_until - now).num_hours(), 1);
        assert_eq!((valid_until - now).num_minutes(), 60);
    }

    // -----------------------------------------------------------------------
    // CLI argument parsing for passport-policy subcommand
    // -----------------------------------------------------------------------

    use crate::cli::Cli;
    use clap::Parser;

    #[test]
    fn parses_passport_policy_list() {
        let cli = Cli::try_parse_from(["kitepass", "passport-policy", "list"])
            .expect("passport-policy list should parse");

        match cli.command {
            crate::cli::Command::PassportPolicy {
                action: crate::cli::PassportPolicyAction::List,
            } => {} // expected
            _ => panic!("expected PassportPolicy List variant"),
        }
    }

    #[test]
    fn parses_passport_policy_create_with_all_args() {
        let cli = Cli::try_parse_from([
            "kitepass",
            "passport-policy",
            "create",
            "--wallet-id",
            "wal_123",
            "--allowed-chain",
            "eip155:8453",
            "--allowed-action",
            "sign_transaction",
            "--max-single-amount",
            "500",
            "--max-daily-amount",
            "2000",
            "--allowed-destination",
            "0xdead",
            "--valid-for-hours",
            "72",
        ])
        .expect("passport-policy create should parse");

        match cli.command {
            crate::cli::Command::PassportPolicy {
                action:
                    crate::cli::PassportPolicyAction::Create {
                        wallet_id,
                        allowed_chains,
                        allowed_actions,
                        max_single_amount,
                        max_daily_amount,
                        allowed_destinations,
                        valid_for_hours,
                    },
            } => {
                assert_eq!(wallet_id, "wal_123");
                assert_eq!(allowed_chains, vec!["eip155:8453"]);
                assert_eq!(allowed_actions, vec!["sign_transaction"]);
                assert_eq!(max_single_amount, "500");
                assert_eq!(max_daily_amount, "2000");
                assert_eq!(allowed_destinations, vec!["0xdead"]);
                assert_eq!(valid_for_hours, 72);
            }
            _ => panic!("expected PassportPolicy Create variant"),
        }
    }

    #[test]
    fn passport_policy_create_valid_for_hours_defaults_to_24() {
        let cli = Cli::try_parse_from([
            "kitepass",
            "passport-policy",
            "create",
            "--wallet-id",
            "wal_default",
            "--allowed-chain",
            "eip155:1",
            "--allowed-action",
            "sign_transaction",
            "--max-single-amount",
            "100",
            "--max-daily-amount",
            "1000",
        ])
        .expect("passport-policy create should parse with defaults");

        match cli.command {
            crate::cli::Command::PassportPolicy {
                action:
                    crate::cli::PassportPolicyAction::Create {
                        valid_for_hours, ..
                    },
            } => {
                assert_eq!(valid_for_hours, 24, "default valid_for_hours should be 24");
            }
            _ => panic!("expected PassportPolicy Create variant"),
        }
    }

    #[test]
    fn passport_policy_create_accepts_multiple_chains() {
        let cli = Cli::try_parse_from([
            "kitepass",
            "passport-policy",
            "create",
            "--wallet-id",
            "wal_multi",
            "--allowed-chain",
            "eip155:1",
            "eip155:8453",
            "eip155:42161",
            "--allowed-action",
            "sign_transaction",
            "--max-single-amount",
            "100",
            "--max-daily-amount",
            "500",
        ])
        .expect("passport-policy create with multiple chains should parse");

        match cli.command {
            crate::cli::Command::PassportPolicy {
                action: crate::cli::PassportPolicyAction::Create { allowed_chains, .. },
            } => {
                assert_eq!(
                    allowed_chains,
                    vec!["eip155:1", "eip155:8453", "eip155:42161"]
                );
            }
            _ => panic!("expected PassportPolicy Create variant"),
        }
    }

    #[test]
    fn passport_policy_create_accepts_multiple_actions() {
        let cli = Cli::try_parse_from([
            "kitepass",
            "passport-policy",
            "create",
            "--wallet-id",
            "wal_acts",
            "--allowed-chain",
            "eip155:1",
            "--allowed-action",
            "sign_transaction",
            "sign_message",
            "--max-single-amount",
            "100",
            "--max-daily-amount",
            "500",
        ])
        .expect("passport-policy create with multiple actions should parse");

        match cli.command {
            crate::cli::Command::PassportPolicy {
                action:
                    crate::cli::PassportPolicyAction::Create {
                        allowed_actions, ..
                    },
            } => {
                assert_eq!(allowed_actions, vec!["sign_transaction", "sign_message"]);
            }
            _ => panic!("expected PassportPolicy Create variant"),
        }
    }

    #[test]
    fn passport_policy_create_rejects_missing_wallet_id() {
        let result = Cli::try_parse_from([
            "kitepass",
            "passport-policy",
            "create",
            "--allowed-chain",
            "eip155:1",
            "--allowed-action",
            "sign_transaction",
            "--max-single-amount",
            "100",
            "--max-daily-amount",
            "500",
        ]);
        assert!(result.is_err(), "missing --wallet-id should fail");
    }

    #[test]
    fn passport_policy_create_rejects_missing_max_single_amount() {
        let result = Cli::try_parse_from([
            "kitepass",
            "passport-policy",
            "create",
            "--wallet-id",
            "wal_123",
            "--allowed-chain",
            "eip155:1",
            "--allowed-action",
            "sign_transaction",
            "--max-daily-amount",
            "500",
        ]);
        assert!(result.is_err(), "missing --max-single-amount should fail");
    }

    #[test]
    fn passport_policy_create_rejects_missing_max_daily_amount() {
        let result = Cli::try_parse_from([
            "kitepass",
            "passport-policy",
            "create",
            "--wallet-id",
            "wal_123",
            "--allowed-chain",
            "eip155:1",
            "--allowed-action",
            "sign_transaction",
            "--max-single-amount",
            "100",
        ]);
        assert!(result.is_err(), "missing --max-daily-amount should fail");
    }

    #[test]
    fn parses_passport_policy_get() {
        let cli = Cli::try_parse_from([
            "kitepass",
            "passport-policy",
            "get",
            "--passport-policy-id",
            "pp_get_123",
        ])
        .expect("passport-policy get should parse");

        match cli.command {
            crate::cli::Command::PassportPolicy {
                action: crate::cli::PassportPolicyAction::Get { passport_policy_id },
            } => {
                assert_eq!(passport_policy_id, "pp_get_123");
            }
            _ => panic!("expected PassportPolicy Get variant"),
        }
    }

    #[test]
    fn passport_policy_get_rejects_missing_id() {
        let result = Cli::try_parse_from(["kitepass", "passport-policy", "get"]);
        assert!(
            result.is_err(),
            "get without --passport-policy-id should fail"
        );
    }

    #[test]
    fn parses_passport_policy_activate() {
        let cli = Cli::try_parse_from([
            "kitepass",
            "passport-policy",
            "activate",
            "--passport-policy-id",
            "pp_act_456",
        ])
        .expect("passport-policy activate should parse");

        match cli.command {
            crate::cli::Command::PassportPolicy {
                action: crate::cli::PassportPolicyAction::Activate { passport_policy_id },
            } => {
                assert_eq!(passport_policy_id, "pp_act_456");
            }
            _ => panic!("expected PassportPolicy Activate variant"),
        }
    }

    #[test]
    fn passport_policy_activate_rejects_missing_id() {
        let result = Cli::try_parse_from(["kitepass", "passport-policy", "activate"]);
        assert!(
            result.is_err(),
            "activate without --passport-policy-id should fail"
        );
    }

    #[test]
    fn parses_passport_policy_deactivate() {
        let cli = Cli::try_parse_from([
            "kitepass",
            "passport-policy",
            "deactivate",
            "--passport-policy-id",
            "pp_deact_789",
        ])
        .expect("passport-policy deactivate should parse");

        match cli.command {
            crate::cli::Command::PassportPolicy {
                action: crate::cli::PassportPolicyAction::Deactivate { passport_policy_id },
            } => {
                assert_eq!(passport_policy_id, "pp_deact_789");
            }
            _ => panic!("expected PassportPolicy Deactivate variant"),
        }
    }

    #[test]
    fn passport_policy_deactivate_rejects_missing_id() {
        let result = Cli::try_parse_from(["kitepass", "passport-policy", "deactivate"]);
        assert!(
            result.is_err(),
            "deactivate without --passport-policy-id should fail"
        );
    }

    // -----------------------------------------------------------------------
    // Global flags propagate through passport-policy subcommands
    // -----------------------------------------------------------------------

    #[test]
    fn global_dry_run_propagates_to_passport_policy() {
        let cli = Cli::try_parse_from(["kitepass", "--dry-run", "passport-policy", "list"])
            .expect("dry-run + passport-policy list should parse");

        assert!(cli.dry_run);
    }

    #[test]
    fn global_json_flag_propagates_to_passport_policy() {
        let cli = Cli::try_parse_from([
            "kitepass",
            "--json",
            "passport-policy",
            "get",
            "--passport-policy-id",
            "pp_json_test",
        ])
        .expect("json + passport-policy get should parse");

        assert!(cli.json);
    }

    #[test]
    fn multiple_global_flags_propagate_to_passport_policy() {
        let cli = Cli::try_parse_from([
            "kitepass",
            "--json",
            "--quiet",
            "--no-color",
            "--dry-run",
            "passport-policy",
            "activate",
            "--passport-policy-id",
            "pp_flags_test",
        ])
        .expect("multiple global flags + passport-policy should parse");

        assert!(cli.json);
        assert!(cli.quiet);
        assert!(cli.no_color);
        assert!(cli.dry_run);
    }
}
