use crate::commands::load_cli_config;
use crate::runtime::Runtime;
use anyhow::{Context, Result};
use kitepass_api_client::PassportClient;
use serde::Serialize;

#[derive(Serialize)]
struct LogoutOutput<'a> {
    status: &'a str,
    had_local_owner_session: bool,
    local_credentials_cleared: bool,
    remote_logout: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    remote_error: Option<String>,
    passport_keys_preserved: bool,
}

pub async fn run(runtime: &Runtime) -> Result<()> {
    let mut config = load_cli_config().context("Failed to load CLI config")?;
    let had_local_owner_session =
        config.access_token.is_some() || config.encrypted_access_token.is_some();

    if runtime.dry_run_enabled() {
        runtime.print_data(&LogoutOutput {
            status: "dry_run",
            had_local_owner_session,
            local_credentials_cleared: false,
            remote_logout: if had_local_owner_session {
                "would_attempt"
            } else {
                "skipped"
            },
            remote_error: None,
            passport_keys_preserved: true,
        })?;
        return Ok(());
    }

    let remote = if let Some(token) = config.access_token.clone() {
        let client = PassportClient::new(config.resolved_api_url().to_string())
            .context("Failed to initialize Passport API client")?
            .with_token(token);
        match client.logout().await {
            Ok(_) => ("completed", None),
            Err(error) => ("failed", Some(error.to_string())),
        }
    } else {
        ("skipped", None)
    };

    config
        .clear_owner_session_default()
        .context("Failed to clear local owner session")?;

    runtime.print_data(&LogoutOutput {
        status: "logged_out",
        had_local_owner_session,
        local_credentials_cleared: true,
        remote_logout: remote.0,
        remote_error: remote.1,
        passport_keys_preserved: true,
    })?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn logout_output_serializes_all_fields() {
        let output = LogoutOutput {
            status: "logged_out",
            had_local_owner_session: true,
            local_credentials_cleared: true,
            remote_logout: "completed",
            remote_error: None,
            passport_keys_preserved: true,
        };
        let value = serde_json::to_value(&output).expect("should serialize");
        assert_eq!(value["status"], "logged_out");
        assert_eq!(value["had_local_owner_session"], true);
        assert_eq!(value["local_credentials_cleared"], true);
        assert_eq!(value["remote_logout"], "completed");
        assert!(value.get("remote_error").is_none());
        assert_eq!(value["passport_keys_preserved"], true);
    }

    #[test]
    fn logout_output_includes_remote_error_when_present() {
        let output = LogoutOutput {
            status: "logged_out",
            had_local_owner_session: true,
            local_credentials_cleared: true,
            remote_logout: "failed",
            remote_error: Some("connection refused".to_string()),
            passport_keys_preserved: true,
        };
        let value = serde_json::to_value(&output).expect("should serialize");
        assert_eq!(value["remote_logout"], "failed");
        assert_eq!(value["remote_error"], "connection refused");
    }

    #[test]
    fn dry_run_output_shows_would_attempt_when_session_exists() {
        let output = LogoutOutput {
            status: "dry_run",
            had_local_owner_session: true,
            local_credentials_cleared: false,
            remote_logout: "would_attempt",
            remote_error: None,
            passport_keys_preserved: true,
        };
        let value = serde_json::to_value(&output).expect("should serialize");
        assert_eq!(value["status"], "dry_run");
        assert_eq!(value["local_credentials_cleared"], false);
        assert_eq!(value["remote_logout"], "would_attempt");
    }

    #[test]
    fn dry_run_output_shows_skipped_when_no_session() {
        let output = LogoutOutput {
            status: "dry_run",
            had_local_owner_session: false,
            local_credentials_cleared: false,
            remote_logout: "skipped",
            remote_error: None,
            passport_keys_preserved: true,
        };
        let value = serde_json::to_value(&output).expect("should serialize");
        assert_eq!(value["had_local_owner_session"], false);
        assert_eq!(value["remote_logout"], "skipped");
    }
}
