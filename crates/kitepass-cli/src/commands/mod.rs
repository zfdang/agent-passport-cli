pub mod access_key;
pub mod audit;
pub mod login;
pub mod operations;
pub mod policy;
pub mod sign;
pub mod wallet;

use crate::cli::{Cli, Command};
use crate::runtime::Runtime;
use anyhow::Result;

pub async fn dispatch(cli: Cli) -> Result<()> {
    let runtime = Runtime::from_cli(&cli);

    match cli.command {
        Command::Login => login::run(&runtime).await,
        Command::Wallet { action } => wallet::run(action, &runtime).await,
        Command::AccessKey { action } => access_key::run(action, &runtime).await,
        Command::Policy { action } => policy::run(action, &runtime).await,
        Command::Sign { action } => sign::run(action, &runtime).await,
        Command::Audit { action } => audit::run(action, &runtime).await,
        Command::Operations { action } => operations::run(action, &runtime).await,
    }
}
