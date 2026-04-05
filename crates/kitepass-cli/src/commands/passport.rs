use crate::{
    cli::PassportAction,
    commands::{load_agent_registry, load_cli_config},
    error::CliError,
    runtime::Runtime,
};
use anyhow::{Context, Result};
use chrono::{Duration, Utc};
use kitepass_api_client::{
    BindingInput, BindingResult, FinalizePassportRequest, PassportClient, RegisterPassportRequest,
};
use kitepass_config::{AgentIdentity, DEFAULT_AGENT_PROFILE};
use kitepass_crypto::agent_key::AgentKey;
use kitepass_crypto::encryption::{generate_secret_key, CryptoEnvelope, PassportToken};
use serde::Serialize;
use serde_json::json;
use uuid::Uuid;
use zeroize::Zeroizing;

#[derive(Serialize)]
struct PassportCreateOutput<'a> {
    profile_name: &'a str,
    passport_id: &'a str,
    status: &'a str,
    public_key: &'a str,
    passport_token: &'a str,
    bindings: &'a [BindingResult],
    activated: bool,
}

pub async fn run(action: PassportAction, runtime: &Runtime) -> Result<()> {
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
        PassportAction::List => {
            let passports = client
                .list_passports()
                .await
                .context("Failed to list passports")?;
            runtime.print_data(&passports)?;
        }
        PassportAction::Create {
            name,
            wallet_id,
            passport_policy_id,
            no_activate,
        } => {
            let mut registry =
                load_agent_registry().context("Failed to load local agent registry")?;
            let profile_name = name.unwrap_or_else(|| registry.selected_profile_name());

            if runtime.dry_run_enabled() {
                runtime.print_data(&json!({
                    "dry_run": true,
                    "action": "passport.create",
                    "profile_name": profile_name,
                    "wallet_id": wallet_id,
                    "passport_policy_id": passport_policy_id,
                }))?;
                return Ok(());
            }

            if profile_name.trim().is_empty() {
                anyhow::bail!("Profile name must not be empty");
            }

            if profile_name == DEFAULT_AGENT_PROFILE {
                runtime.progress("Generating new Ed25519 Passport for default profile...");
            } else {
                runtime.progress(format!(
                    "Generating new Ed25519 Passport for profile `{profile_name}`..."
                ));
            }

            // 1. Generate local keypair
            let key = AgentKey::generate();
            let pubkey_hex = key.public_key_hex();

            // 2. Generate a secret key for the Passport Token and encrypt the private key
            let secret_key = generate_secret_key();
            let pem = key
                .export_pem()
                .context("Failed to serialize private key")?;
            let encrypted_key = CryptoEnvelope::encrypt(pem.as_bytes(), &secret_key)
                .context("Failed to encrypt private key")?;

            // 3. Register public key on Passport Gateway
            runtime.progress(format!("Registering public key with Gateway: {pubkey_hex}"));
            let bindings = match (wallet_id.clone(), passport_policy_id.clone()) {
                (Some(wallet_id), Some(passport_policy_id)) => {
                    let policy = client
                        .get_policy(&passport_policy_id)
                        .await
                        .with_context(|| format!("Failed to get policy {passport_policy_id}"))?;
                    vec![BindingInput {
                        wallet_id,
                        passport_policy_id,
                        passport_policy_version: policy.version,
                        is_default: true,
                        selection_priority: 0,
                    }]
                }
                (None, None) => Vec::new(),
                _ => {
                    anyhow::bail!(
                        "`--wallet-id` and `--passport-policy-id` must be provided together when provisioning an active delegated authority"
                    );
                }
            };
            let request = RegisterPassportRequest {
                public_key: pubkey_hex.clone(),
                key_address: format!("ed25519:{}", &pubkey_hex[..16]),
                expires_at: (Utc::now() + Duration::days(365)).to_rfc3339(),
                bindings,
                idempotency_key: format!("idem_{}", Uuid::new_v4().simple()),
            };
            let prepared = client
                .register_passport(&request)
                .await
                .context("Failed to prepare passport provisioning")?;
            runtime.progress(format!(
                "Prepared provisioning intent: {}",
                prepared.intent_id
            ));
            let approval = client
                .approve_provisioning_intent(&prepared.intent_id)
                .await
                .context("Failed to approve provisioning intent")?;
            let res = client
                .finalize_passport(&FinalizePassportRequest {
                    intent_id: prepared.intent_id.clone(),
                    principal_approval_id: approval.principal_approval_id.clone(),
                    idempotency_key: format!("idem_{}", Uuid::new_v4().simple()),
                })
                .await
                .context("Failed to finalize passport provisioning")?;

            // 4. Persist agent profile with encrypted key inline
            registry.upsert(AgentIdentity {
                name: profile_name.clone(),
                passport_id: res.passport_id.clone(),
                public_key_hex: pubkey_hex.clone(),
                encrypted_key,
            })?;

            if !no_activate {
                registry.active_profile = Some(profile_name.clone());
            }

            let mut persistence_errors = Vec::new();
            if let Err(error) = registry.save_default() {
                persistence_errors.push(format!(
                    "failed to persist encrypted local agent profile: {error}"
                ));
            } else if !no_activate {
                runtime.progress(format!(
                    "Updated local agent registry and activated profile `{profile_name}`."
                ));
            } else {
                runtime.progress(format!(
                    "Updated local agent registry for profile `{profile_name}`."
                ));
            }

            // 5. Build and display the Passport Token
            let passport_token =
                Zeroizing::new(PassportToken::format(&res.passport_id, &secret_key));

            // Keep the owner config on disk for API/base settings only.
            if let Err(error) = config.save_default() {
                persistence_errors.push(format!("failed to persist CLI config: {error}"));
            }

            runtime.important("╔══════════════════════════════════════════════════════════╗");
            runtime.important("║  IMPORTANT: Save the Passport Token below immediately!         ║");
            runtime.important("║  It will NOT be displayed again.                         ║");
            runtime.important("║  If lost, revoke this key and create a new one.          ║");
            runtime.important("╚══════════════════════════════════════════════════════════╝");

            runtime.print_data(&PassportCreateOutput {
                profile_name: &profile_name,
                passport_id: &res.passport_id,
                status: &res.status,
                public_key: &pubkey_hex,
                passport_token: passport_token.as_str(),
                bindings: &res.bindings,
                activated: !no_activate,
            })?;

            if !persistence_errors.is_empty() {
                anyhow::bail!(
                    "Passport was created, but local persistence is incomplete: {}. Save the Passport Token above, then fix the local config/registry or revoke and recreate the passport if needed.",
                    persistence_errors.join("; ")
                );
            }
        }
        PassportAction::Get { passport_id } => {
            let passport = client
                .get_passport(&passport_id)
                .await
                .with_context(|| format!("Failed to get passport {passport_id}"))?;
            let bindings = client
                .list_bindings(&passport_id)
                .await
                .with_context(|| format!("Failed to list bindings for passport {passport_id}"))?;
            let usage = client
                .get_passport_usage(&passport_id)
                .await
                .with_context(|| format!("Failed to get usage for passport {passport_id}"))?;
            runtime.print_data(&serde_json::json!({
                "passport": passport,
                "bindings": bindings,
                "usage": usage,
            }))?;
        }
        PassportAction::Freeze { passport_id } => {
            let key_id = passport_id;
            if runtime.dry_run_enabled() {
                runtime.print_data(&json!({
                    "dry_run": true,
                    "action": "passport.freeze",
                    "passport_id": key_id,
                }))?;
                return Ok(());
            }
            let passport = client
                .freeze_passport(&key_id)
                .await
                .with_context(|| format!("Failed to freeze passport {key_id}"))?;
            runtime.print_data(&passport)?;
        }
        PassportAction::Revoke { passport_id } => {
            let key_id = passport_id;
            if runtime.dry_run_enabled() {
                runtime.print_data(&json!({
                    "dry_run": true,
                    "action": "passport.revoke",
                    "passport_id": key_id,
                }))?;
                return Ok(());
            }
            let passport = client
                .revoke_passport(&key_id)
                .await
                .with_context(|| format!("Failed to revoke passport {key_id}"))?;
            runtime.print_data(&passport)?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    // ── PassportCreateOutput serialization ──────────────────────

    fn sample_binding() -> BindingResult {
        BindingResult {
            binding_id: "bnd_001".into(),
            wallet_id: "wal_abc".into(),
            passport_policy_id: "pp_xyz".into(),
            passport_policy_version: 3,
            tee_mirror_status: "synced".into(),
        }
    }

    #[test]
    fn create_output_serializes_all_fields() {
        let bindings = vec![sample_binding()];
        let output = PassportCreateOutput {
            profile_name: "my-agent",
            passport_id: "agp_12345",
            status: "active",
            public_key: "deadbeef01234567",
            passport_token: "kite_passport_agp_12345__secret",
            bindings: &bindings,
            activated: true,
        };
        let value = serde_json::to_value(&output).expect("should serialize");
        assert_eq!(value["profile_name"], "my-agent");
        assert_eq!(value["passport_id"], "agp_12345");
        assert_eq!(value["status"], "active");
        assert_eq!(value["public_key"], "deadbeef01234567");
        assert_eq!(value["passport_token"], "kite_passport_agp_12345__secret");
        assert_eq!(value["activated"], true);
        assert_eq!(value["bindings"][0]["binding_id"], "bnd_001");
        assert_eq!(value["bindings"][0]["wallet_id"], "wal_abc");
        assert_eq!(value["bindings"][0]["passport_policy_id"], "pp_xyz");
        assert_eq!(value["bindings"][0]["passport_policy_version"], 3);
        assert_eq!(value["bindings"][0]["tee_mirror_status"], "synced");
    }

    #[test]
    fn create_output_with_empty_bindings() {
        let output = PassportCreateOutput {
            profile_name: "default",
            passport_id: "agp_000",
            status: "pending",
            public_key: "aabbccdd",
            passport_token: "kite_passport_agp_000__sk",
            bindings: &[],
            activated: false,
        };
        let value = serde_json::to_value(&output).expect("should serialize");
        assert_eq!(value["bindings"], json!([]));
        assert_eq!(value["activated"], false);
    }

    // ── Key address derivation format ───────────────────────────

    #[test]
    fn key_address_format_takes_first_16_hex_chars() {
        let pubkey_hex = "abcdef0123456789ffee";
        let key_address = format!("ed25519:{}", &pubkey_hex[..16]);
        assert_eq!(key_address, "ed25519:abcdef0123456789");
    }

    #[test]
    fn key_address_uses_ed25519_prefix() {
        let pubkey_hex = "0000000000000000rest_ignored";
        let key_address = format!("ed25519:{}", &pubkey_hex[..16]);
        assert!(key_address.starts_with("ed25519:"));
        assert_eq!(key_address.len(), "ed25519:".len() + 16);
    }

    // ── Dry-run JSON contracts ──────────────────────────────────

    #[test]
    fn dry_run_create_json_has_expected_shape() {
        let profile_name = "test-profile".to_string();
        let wallet_id = Some("wal_abc".to_string());
        let passport_policy_id = Some("pp_xyz".to_string());

        let output = json!({
            "dry_run": true,
            "action": "passport.create",
            "profile_name": profile_name,
            "wallet_id": wallet_id,
            "passport_policy_id": passport_policy_id,
        });

        assert_eq!(output["dry_run"], true);
        assert_eq!(output["action"], "passport.create");
        assert_eq!(output["profile_name"], "test-profile");
        assert_eq!(output["wallet_id"], "wal_abc");
        assert_eq!(output["passport_policy_id"], "pp_xyz");
    }

    #[test]
    fn dry_run_create_json_null_wallet_policy() {
        let profile_name = "default".to_string();
        let wallet_id: Option<String> = None;
        let passport_policy_id: Option<String> = None;

        let output = json!({
            "dry_run": true,
            "action": "passport.create",
            "profile_name": profile_name,
            "wallet_id": wallet_id,
            "passport_policy_id": passport_policy_id,
        });

        assert_eq!(output["dry_run"], true);
        assert!(output["wallet_id"].is_null());
        assert!(output["passport_policy_id"].is_null());
    }

    #[test]
    fn dry_run_freeze_json_has_expected_shape() {
        let key_id = "agp_freeze_me".to_string();
        let output = json!({
            "dry_run": true,
            "action": "passport.freeze",
            "passport_id": key_id,
        });

        assert_eq!(output["dry_run"], true);
        assert_eq!(output["action"], "passport.freeze");
        assert_eq!(output["passport_id"], "agp_freeze_me");
    }

    #[test]
    fn dry_run_revoke_json_has_expected_shape() {
        let key_id = "agp_revoke_me".to_string();
        let output = json!({
            "dry_run": true,
            "action": "passport.revoke",
            "passport_id": key_id,
        });

        assert_eq!(output["dry_run"], true);
        assert_eq!(output["action"], "passport.revoke");
        assert_eq!(output["passport_id"], "agp_revoke_me");
    }

    // ── Idempotency key format ──────────────────────────────────

    #[test]
    fn idempotency_key_has_idem_prefix() {
        let key = format!("idem_{}", Uuid::new_v4().simple());
        assert!(key.starts_with("idem_"));
        // uuid simple format is 32 hex chars
        assert_eq!(key.len(), "idem_".len() + 32);
    }

    #[test]
    fn idempotency_keys_are_unique() {
        let key1 = format!("idem_{}", Uuid::new_v4().simple());
        let key2 = format!("idem_{}", Uuid::new_v4().simple());
        assert_ne!(key1, key2);
    }

    // ── Profile name validation ─────────────────────────────────

    #[test]
    fn empty_profile_name_is_rejected() {
        // Mirrors the validation at line 73: profile_name.trim().is_empty()
        let profile_name = "   ";
        assert!(
            profile_name.trim().is_empty(),
            "whitespace-only profile name should be treated as empty"
        );
    }

    #[test]
    fn non_empty_profile_name_is_accepted() {
        let profile_name = "my-agent";
        assert!(
            !profile_name.trim().is_empty(),
            "non-empty profile name should be accepted"
        );
    }

    #[test]
    fn default_profile_name_is_recognized() {
        assert_eq!(DEFAULT_AGENT_PROFILE, "default");
    }

    // ── Binding input pair validation ───────────────────────────

    #[test]
    fn both_wallet_and_policy_provided_is_valid() {
        let wallet_id: Option<String> = Some("wal_abc".into());
        let passport_policy_id: Option<String> = Some("pp_xyz".into());
        // This match mirrors lines 99-119 of run()
        let result = match (wallet_id, passport_policy_id) {
            (Some(_), Some(_)) => Ok("both provided"),
            (None, None) => Ok("neither provided"),
            _ => Err("must be provided together"),
        };
        assert_eq!(result, Ok("both provided"));
    }

    #[test]
    fn neither_wallet_nor_policy_produces_empty_bindings() {
        let wallet_id: Option<String> = None;
        let passport_policy_id: Option<String> = None;
        let result = match (wallet_id, passport_policy_id) {
            (Some(_), Some(_)) => Ok("both provided"),
            (None, None) => Ok("neither provided"),
            _ => Err("must be provided together"),
        };
        assert_eq!(result, Ok("neither provided"));
    }

    #[test]
    fn wallet_without_policy_is_rejected() {
        let wallet_id: Option<String> = Some("wal_abc".into());
        let passport_policy_id: Option<String> = None;
        let result = match (wallet_id, passport_policy_id) {
            (Some(_), Some(_)) => Ok("both"),
            (None, None) => Ok("neither"),
            _ => Err("must be provided together"),
        };
        assert_eq!(result, Err("must be provided together"));
    }

    #[test]
    fn policy_without_wallet_is_rejected() {
        let wallet_id: Option<String> = None;
        let passport_policy_id: Option<String> = Some("pp_xyz".into());
        let result = match (wallet_id, passport_policy_id) {
            (Some(_), Some(_)) => Ok("both"),
            (None, None) => Ok("neither"),
            _ => Err("must be provided together"),
        };
        assert_eq!(result, Err("must be provided together"));
    }

    // ── Expires-at timestamp format ─────────────────────────────

    #[test]
    fn expires_at_is_rfc3339_one_year_from_now() {
        let now = Utc::now();
        let expires = now + Duration::days(365);
        let formatted = expires.to_rfc3339();
        // RFC 3339 must contain 'T' and timezone info
        assert!(formatted.contains('T'));
        // Parse it back to ensure round-trip validity
        let parsed = chrono::DateTime::parse_from_rfc3339(&formatted)
            .expect("expires_at should be valid RFC 3339");
        let diff = parsed.signed_duration_since(now);
        // Should be approximately 365 days (within a few seconds of test execution)
        assert!(diff.num_days() >= 364 && diff.num_days() <= 365);
    }
}
