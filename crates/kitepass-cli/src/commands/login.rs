use crate::{commands::load_cli_config, runtime::Runtime};
use anyhow::{Context, Result};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use kitepass_api_client::{AuthPollRequest, DeviceCodeRequest, PassportClient};
use rand_core::{OsRng, TryRngCore};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::cmp;
use std::time::Duration;
use tokio::time::{sleep, timeout};
use zeroize::Zeroizing;

const MAX_DEVICE_CODE_TIMEOUT_SECS: u64 = 600;
const MAX_DEVICE_CODE_ERROR_BACKOFF_SECS: u64 = 30;

fn generate_pkce_verifier() -> Result<String> {
    let mut bytes = Zeroizing::new([0u8; 32]);
    OsRng
        .try_fill_bytes(bytes.as_mut())
        .context("failed to read secure randomness for PKCE verifier")?;
    Ok(URL_SAFE_NO_PAD.encode(&*bytes))
}

fn pkce_s256_challenge(code_verifier: &str) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(code_verifier.as_bytes()))
}

/// Owner login via device-code flow.
pub async fn run(runtime: &Runtime) -> Result<()> {
    if runtime.dry_run_enabled() {
        runtime.print_data(&json!({
            "dry_run": true,
            "action": "login",
        }))?;
        return Ok(());
    }

    let mut config = load_cli_config().context("Failed to load CLI config")?;
    let api_url = config.resolved_api_url();

    let client =
        PassportClient::new(api_url).context("Failed to initialize Passport API client")?;
    let code_verifier = Zeroizing::new(generate_pkce_verifier()?);
    let code_challenge = pkce_s256_challenge(code_verifier.as_str());

    runtime.progress("Starting CLI device login...");
    let device_res = client
        .request_device_code(&DeviceCodeRequest {
            code_challenge: Some(code_challenge),
            code_challenge_method: Some("S256".to_string()),
        })
        .await
        .context("Failed to request device code")?;

    if !runtime.non_interactive() {
        if let Err(err) = webbrowser::open(&device_res.verification_uri) {
            runtime.progress(format!(
                "Unable to open browser automatically: {err}. Continue in your browser manually."
            ));
        }
    }

    runtime.important("\n=============================================");
    runtime.important(format!("Please go to: {}", device_res.verification_uri));
    runtime.important(format!("And enter the code: {}", device_res.user_code));
    runtime.important("Sign in on the website first with passkey, then approve this CLI device.");
    runtime.important("=============================================\n");
    runtime.progress("Waiting for authorization...");

    let interval = Duration::from_secs(device_res.interval.max(2) as u64);
    let expires_in = match u64::try_from(device_res.expires_in) {
        Ok(0) | Err(_) => anyhow::bail!("Login timed out."),
        Ok(seconds) => seconds.min(MAX_DEVICE_CODE_TIMEOUT_SECS),
    };
    let max_error_backoff = Duration::from_secs(MAX_DEVICE_CODE_ERROR_BACKOFF_SECS);
    let mut error_streak = 0u32;

    match timeout(Duration::from_secs(expires_in), async {
        loop {
            match client
                .poll_device_code(
                    &device_res.device_code,
                    &AuthPollRequest {
                        code_verifier: Some(code_verifier.to_string()),
                    },
                )
                .await
            {
                Ok(poll_res) => {
                    error_streak = 0;
                    if let Some(token) = poll_res.access_token {
                        config.access_token = Some(token);
                        config
                            .save_default()
                            .context("Failed to save credentials locally")?;
                        runtime.print_data(&json!({
                            "status": "authenticated",
                            "token_saved": true,
                        }))?;
                        return Ok(());
                    }

                    if let Some(error) = poll_res.error {
                        if error != "authorization_pending" {
                            anyhow::bail!("Authorization failed: {}", error);
                        }
                    }
                }
                Err(e) => {
                    error_streak = error_streak.saturating_add(1);
                    let _ = e;
                    runtime.progress("Polling error... retrying.");
                }
            }

            let backoff_factor = 1u32 << error_streak.min(3);
            let delay = cmp::min(
                interval
                    .checked_mul(backoff_factor)
                    .unwrap_or(max_error_backoff),
                max_error_backoff,
            );
            sleep(delay).await;
        }
    })
    .await
    {
        Ok(result) => result,
        Err(_) => anyhow::bail!("Login timed out."),
    }
}
