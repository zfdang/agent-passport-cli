use anyhow::{Context, Result};
use kitepass_api_client::PassportClient;
use kitepass_config::CliConfig;
use std::time::Duration;
use tokio::time::sleep;

/// Owner login via device-code flow.
pub async fn run() -> Result<()> {
    let mut config = CliConfig::load_default().unwrap_or_default();
    let api_url = config.resolved_api_url();

    let client = PassportClient::new(api_url);

    println!("Starting CLI device login...");
    let device_res = client
        .request_device_code()
        .await
        .context("Failed to request device code")?;

    println!("\n=============================================");
    println!("Please go to: {}", device_res.verification_uri);
    println!("And enter the code: {}", device_res.user_code);
    println!("Sign in on the website first with passkey, then approve this CLI device.");
    println!("=============================================\n");
    println!("Waiting for authorization...");

    let interval = Duration::from_secs(device_res.interval.max(2) as u64);
    let mut elapsed = 0;
    let expires_in = device_res.expires_in;

    loop {
        if elapsed >= expires_in {
            anyhow::bail!("Login timed out.");
        }

        match client.poll_device_code(&device_res.device_code).await {
            Ok(poll_res) => {
                if let Some(token) = poll_res.access_token {
                    println!("Successfully authenticated!");
                    config.access_token = Some(token);
                    config
                        .save_default()
                        .context("Failed to save credentials locally")?;
                    println!("Token saved to config file.");
                    return Ok(());
                }

                if let Some(error) = poll_res.error
                    && error != "authorization_pending"
                {
                    anyhow::bail!("Authorization failed: {}", error);
                }
            }
            Err(e) => {
                eprintln!("Polling error... retrying. ({})", e);
            }
        }

        sleep(interval).await;
        elapsed += interval.as_secs() as i32;
    }
}
