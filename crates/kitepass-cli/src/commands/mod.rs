pub mod audit;
pub mod login;
pub mod logout;
pub mod operations;
pub mod passport;
pub mod passport_policy;
pub mod sign;
pub mod status;
pub mod wallet;
pub mod wallet_import;

use crate::cli::{Cli, Command};
use crate::runtime::Runtime;
use anyhow::Result;
use kitepass_config::{CliConfig, LocalPassportRegistry};

pub(crate) fn load_cli_config() -> Result<CliConfig> {
    Ok(CliConfig::load_default()?)
}

pub(crate) fn load_local_passport_registry() -> Result<LocalPassportRegistry> {
    Ok(LocalPassportRegistry::load_default()?)
}

pub async fn dispatch(cli: Cli) -> Result<()> {
    let runtime = Runtime::from_cli(&cli);

    match cli.command {
        Command::Status => status::run(&runtime),
        Command::Login => login::run(&runtime).await,
        Command::Logout => logout::run(&runtime).await,
        Command::Wallet { action } => wallet::run(action, &runtime).await,
        Command::Passport { action } => passport::run(action, &runtime).await,
        Command::PassportPolicy { action } => passport_policy::run(action, &runtime).await,
        Command::Sign {
            validate,
            broadcast,
            passport_id,
            wallet_id,
            chain_id,
            signing_type,
            payload,
            destination,
            value,
        } => {
            sign::run(
                sign::SignArgs {
                    validate,
                    broadcast,
                    passport_id,
                    wallet_id,
                    chain_id,
                    signing_type,
                    payload,
                    destination,
                    value,
                },
                &runtime,
            )
            .await
        }
        Command::Audit { action } => audit::run(action, &runtime).await,
        Command::Operations { action } => operations::run(action, &runtime).await,
    }
}
