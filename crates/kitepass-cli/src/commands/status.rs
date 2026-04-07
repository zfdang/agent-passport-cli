use crate::commands::{load_cli_config, load_local_passport_registry};
use crate::runtime::Runtime;
use anyhow::{Context, Result};
use kitepass_config::{config_dir, env_passport_token, PASSPORT_TOKEN_ENV};
use serde::Serialize;

#[derive(Serialize)]
struct StatusOutput {
    logged_in: bool,
    api_url: String,
    local_passport_keys: usize,
    passport_token_env_set: bool,
    config_dir: String,
}

pub fn run(runtime: &Runtime) -> Result<()> {
    let config = load_cli_config().context("Failed to load CLI config")?;
    let registry =
        load_local_passport_registry().context("Failed to load local passport registry")?;

    let config_dir_path = config_dir()
        .map(|p| p.display().to_string())
        .unwrap_or_else(|_| "(unknown)".to_string());

    let output = StatusOutput {
        logged_in: config.access_token.is_some(),
        api_url: config.resolved_api_url().to_string(),
        local_passport_keys: registry.passports.len(),
        passport_token_env_set: env_passport_token().is_some(),
        config_dir: config_dir_path,
    };

    if !matches!(runtime.output_format(), crate::cli::OutputFormat::Json) {
        if output.logged_in {
            runtime.important("Logged in");
        } else {
            runtime.important("Not logged in (run `kitepass login`)");
        }
        runtime.progress(format!("API endpoint:         {}", output.api_url));
        runtime.progress(format!(
            "Local passport keys:  {}",
            output.local_passport_keys
        ));
        runtime.progress(format!(
            "{} set:  {}",
            PASSPORT_TOKEN_ENV,
            if output.passport_token_env_set {
                "yes"
            } else {
                "no"
            }
        ));
        runtime.progress(format!("Config directory:     {}", output.config_dir));
    }

    runtime.print_data(&output)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn status_output_serializes_all_fields() {
        let output = StatusOutput {
            logged_in: true,
            api_url: "https://api.kitepass.xyz".to_string(),
            local_passport_keys: 3,
            passport_token_env_set: false,
            config_dir: "~/.kitepass".to_string(),
        };
        let value = serde_json::to_value(&output).expect("should serialize");
        assert_eq!(value["logged_in"], true);
        assert_eq!(value["api_url"], "https://api.kitepass.xyz");
        assert_eq!(value["local_passport_keys"], 3);
        assert_eq!(value["passport_token_env_set"], false);
        assert_eq!(value["config_dir"], "~/.kitepass");
    }

    #[test]
    fn status_output_not_logged_in() {
        let output = StatusOutput {
            logged_in: false,
            api_url: "https://api.kitepass.xyz".to_string(),
            local_passport_keys: 0,
            passport_token_env_set: true,
            config_dir: "/home/agent/.kitepass".to_string(),
        };
        let value = serde_json::to_value(&output).expect("should serialize");
        assert_eq!(value["logged_in"], false);
        assert_eq!(value["local_passport_keys"], 0);
        assert_eq!(value["passport_token_env_set"], true);
    }
}
