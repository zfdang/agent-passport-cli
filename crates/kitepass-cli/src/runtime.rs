use anyhow::Result;
use serde::Serialize;

use crate::{
    cli::{Cli, OutputFormat},
    error::CliError,
    output,
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RuntimeOptions {
    pub output_format: OutputFormat,
    pub quiet: bool,
    pub no_color: bool,
    pub non_interactive: bool,
    pub dry_run: bool,
}

impl RuntimeOptions {
    pub fn from_cli(cli: &Cli) -> Self {
        Self {
            output_format: if cli.json {
                OutputFormat::Json
            } else {
                cli.format.clone()
            },
            quiet: cli.quiet,
            no_color: cli.no_color,
            non_interactive: cli.non_interactive,
            dry_run: cli.dry_run,
        }
    }
}

#[derive(Clone, Debug)]
pub struct Runtime {
    options: RuntimeOptions,
}

impl Runtime {
    pub fn from_cli(cli: &Cli) -> Self {
        Self {
            options: RuntimeOptions::from_cli(cli),
        }
    }

    pub fn dry_run_enabled(&self) -> bool {
        self.options.dry_run
    }

    pub fn non_interactive(&self) -> bool {
        self.options.non_interactive
    }

    pub fn progress(&self, message: impl AsRef<str>) {
        if self.options.quiet {
            return;
        }

        if matches!(self.options.output_format, OutputFormat::Json) {
            eprintln!("{}", message.as_ref());
        } else {
            println!("{}", message.as_ref());
        }
    }

    /// Like `progress()` but never suppressed by `--quiet`.
    pub fn important(&self, message: impl AsRef<str>) {
        if matches!(self.options.output_format, OutputFormat::Json) {
            eprintln!("{}", message.as_ref());
        } else {
            println!("{}", message.as_ref());
        }
    }

    pub fn print_data<T: Serialize>(&self, value: &T) -> Result<()> {
        output::print_data(&self.options.output_format, value)
    }

    pub fn require_secret_from_stdin(&self, operation: &str) -> Result<()> {
        if self.options.non_interactive && std::io::IsTerminal::is_terminal(&std::io::stdin()) {
            return Err(CliError::InteractiveRequired(format!(
                "{operation} requires the secret on stdin when `--non-interactive` is set"
            ))
            .into());
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::{Cli, Command, WalletAction};

    #[test]
    fn json_flag_overrides_text_default() {
        let cli = Cli {
            format: OutputFormat::Text,
            json: true,
            quiet: false,
            no_color: true,
            non_interactive: true,
            dry_run: true,
            command: Command::Wallet {
                action: WalletAction::List,
            },
        };

        let options = RuntimeOptions::from_cli(&cli);
        assert_eq!(options.output_format, OutputFormat::Json);
        assert!(options.no_color);
        assert!(options.non_interactive);
        assert!(options.dry_run);
    }
}
