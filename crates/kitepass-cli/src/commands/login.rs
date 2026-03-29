use anyhow::Result;

/// Owner login via device-code flow.
///
/// 1. POST /v1/owner/auth/device-code → get device_code + user_code + verification_uri
/// 2. Display user_code and verification_uri to the owner
/// 3. Poll POST /v1/owner/auth/poll until token is returned
/// 4. Store token in local config
pub async fn run() -> Result<()> {
    println!("kitepass login: device-code flow (not yet implemented)");
    Ok(())
}
