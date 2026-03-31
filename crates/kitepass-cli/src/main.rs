mod auth;
mod cli;
mod commands;
mod config;
mod error;
mod output;
mod runtime;

use clap::Parser;
use std::process::ExitCode;

#[tokio::main]
async fn main() -> ExitCode {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "warn".into()),
        )
        .init();

    let args = match cli::Cli::try_parse() {
        Ok(args) => args,
        Err(err) => {
            eprint!("{err}");
            return ExitCode::from(err.exit_code() as u8);
        }
    };

    match commands::dispatch(args).await {
        Ok(()) => ExitCode::from(error::ExitCode::Success.as_u8()),
        Err(err) => {
            eprintln!("{err:#}");
            ExitCode::from(error::classify_error(&err).as_u8())
        }
    }
}
