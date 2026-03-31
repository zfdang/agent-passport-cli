use crate::runtime::Runtime;
use anyhow::{Context, Result};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use kitepass_api_client::{AuthPollRequest, DeviceCodeRequest, PassportClient};
use kitepass_config::CliConfig;
use serde_json::json;
use sha2::{Digest, Sha256};
use std::time::Duration;
use tokio::time::sleep;
use uuid::Uuid;

fn generate_pkce_verifier() -> String {
    format!("kp{}{}", Uuid::new_v4().simple(), Uuid::new_v4().simple())
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

    let mut config = CliConfig::load_default().unwrap_or_default();
    let api_url = config.resolved_api_url();

    let client = PassportClient::new(api_url);
    let code_verifier = generate_pkce_verifier();
    let code_challenge = pkce_s256_challenge(&code_verifier);

    runtime.progress("Starting CLI device login...");
    let device_res = client
        .request_device_code(&DeviceCodeRequest {
            code_challenge: Some(code_challenge),
            code_challenge_method: Some("S256".to_string()),
        })
        .await
        .context("Failed to request device code")?;

    if !runtime.non_interactive()
        && let Err(err) = webbrowser::open(&device_res.verification_uri)
    {
        runtime.progress(format!(
            "Unable to open browser automatically: {err}. Continue in your browser manually."
        ));
    }

    runtime.important("\n=============================================");
    runtime.important(format!("Please go to: {}", device_res.verification_uri));
    runtime.important(format!("And enter the code: {}", device_res.user_code));
    runtime.important("Sign in on the website first with passkey, then approve this CLI device.");
    runtime.important("=============================================\n");
    runtime.progress("Waiting for authorization...");

    let interval = Duration::from_secs(device_res.interval.max(2) as u64);
    let mut elapsed = 0;
    let expires_in = device_res.expires_in;

    loop {
        if elapsed >= expires_in {
            anyhow::bail!("Login timed out.");
        }

        match client
            .poll_device_code(
                &device_res.device_code,
                &AuthPollRequest {
                    code_verifier: Some(code_verifier.clone()),
                },
            )
            .await
        {
            Ok(poll_res) => {
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

                if let Some(error) = poll_res.error
                    && error != "authorization_pending"
                {
                    anyhow::bail!("Authorization failed: {}", error);
                }
            }
            Err(e) => {
                runtime.progress(format!("Polling error... retrying. ({e})"));
            }
        }

        sleep(interval).await;
        elapsed += interval.as_secs() as i32;
    }
}
