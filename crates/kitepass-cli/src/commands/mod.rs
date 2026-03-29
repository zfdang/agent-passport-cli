pub mod access_key;
pub mod audit;
pub mod login;
pub mod operations;
pub mod policy;
pub mod sign;
pub mod wallet;

use crate::cli::{Cli, Command};
use anyhow::Result;

pub async fn dispatch(cli: Cli) -> Result<()> {
    match cli.command {
        Command::Login => login::run().await,
        Command::Wallet { action } => wallet::run(action).await,
        Command::AccessKey { action } => access_key::run(action).await,
        Command::Policy { action } => policy::run(action).await,
        Command::Sign { action } => sign::run(action).await,
        Command::Audit { action } => audit::run(action).await,
        Command::Operations { action } => operations::run(action).await,
    }
}
