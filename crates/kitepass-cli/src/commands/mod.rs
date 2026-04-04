pub mod agent_passport;
pub mod audit;
pub mod login;
pub mod operations;
pub mod passport_policy;
pub mod profile;
pub mod sign;
pub mod wallet;
pub mod wallet_import;

use crate::cli::{Cli, Command};
use crate::runtime::Runtime;
use anyhow::Result;
use kitepass_config::{AgentRegistry, CliConfig};

pub(crate) fn load_cli_config() -> Result<CliConfig> {
    Ok(CliConfig::load_default()?)
}

pub(crate) fn load_agent_registry() -> Result<AgentRegistry> {
    Ok(AgentRegistry::load_default()?)
}

pub async fn dispatch(cli: Cli) -> Result<()> {
    let runtime = Runtime::from_cli(&cli);

    match cli.command {
        Command::Login => login::run(&runtime).await,
        Command::Wallet { action } => wallet::run(action, &runtime).await,
        Command::AgentPassport { action } => agent_passport::run(action, &runtime).await,
        Command::PassportPolicy { action } => passport_policy::run(action, &runtime).await,
        Command::Profile { action } => profile::run(action, &runtime).await,
        Command::Sign {
            validate,
            broadcast,
            agent_passport_id,
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
                    agent_passport_id,
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
