use clap::{Parser, Subcommand, ValueEnum};

#[derive(Parser)]
#[command(
    name = "kitepass",
    about = "Kite Agent Passport CLI",
    version = crate::version::DISPLAY_VERSION,
    propagate_version = true
)]
pub struct Cli {
    /// Output format
    #[arg(long, global = true, value_enum, default_value_t = OutputFormat::Text)]
    pub format: OutputFormat,

    /// Emit structured JSON output
    #[arg(long, global = true, default_value_t = false)]
    pub json: bool,

    /// Suppress progress logs
    #[arg(long, global = true, default_value_t = false)]
    pub quiet: bool,

    /// Disable ANSI color output
    #[arg(long, global = true, default_value_t = false)]
    pub no_color: bool,

    /// Disable browser launches and interactive prompts
    #[arg(long, global = true, default_value_t = false)]
    pub non_interactive: bool,

    /// Preview mutating actions without applying them
    #[arg(long, global = true, default_value_t = false)]
    pub dry_run: bool,

    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand)]
pub enum Command {
    /// Authenticate as wallet owner via device-code flow
    Login,

    /// Wallet management
    Wallet {
        #[command(subcommand)]
        action: WalletAction,
    },

    /// Agent Access Key management
    AccessKey {
        #[command(subcommand)]
        action: AccessKeyAction,
    },

    /// Policy management
    Policy {
        #[command(subcommand)]
        action: PolicyAction,
    },

    /// Local agent profile management
    Profile {
        #[command(subcommand)]
        action: ProfileAction,
    },

    /// Transaction signing
    Sign {
        #[command(subcommand)]
        action: SignAction,
    },

    /// Audit log
    Audit {
        #[command(subcommand)]
        action: AuditAction,
    },

    /// Operation tracking
    Operations {
        #[command(subcommand)]
        action: OperationsAction,
    },
}

#[derive(Subcommand)]
pub enum WalletAction {
    /// List wallets
    List,
    /// Import a new wallet
    Import {
        #[arg(long)]
        chain: String,
        #[arg(long)]
        name: Option<String>,
    },
    /// Get wallet details
    Get {
        #[arg(long)]
        wallet_id: String,
    },
    /// Freeze a wallet
    Freeze {
        #[arg(long)]
        wallet_id: String,
    },
    /// Revoke a wallet
    Revoke {
        #[arg(long)]
        wallet_id: String,
    },
}

#[derive(Subcommand)]
pub enum AccessKeyAction {
    /// List access keys
    List,
    /// Create or replace a local agent profile backed by a new access key
    Create {
        /// Local profile name. Defaults to the selected profile or `default`.
        #[arg(long)]
        name: Option<String>,
        #[arg(long)]
        wallet_id: Option<String>,
        #[arg(long)]
        policy_id: Option<String>,
        #[arg(long, default_value_t = false)]
        no_activate: bool,
    },
    /// Get access key details
    Get {
        #[arg(long)]
        key_id: String,
    },
    /// Bind access key to wallet with policy
    Bind {
        #[arg(long)]
        key_id: String,
        #[arg(long)]
        wallet_id: String,
        #[arg(long)]
        policy_id: Option<String>,
    },
    /// Freeze an access key
    Freeze {
        #[arg(long)]
        key_id: String,
    },
    /// Revoke an access key
    Revoke {
        #[arg(long)]
        key_id: String,
    },
}

#[derive(Subcommand)]
pub enum ProfileAction {
    /// List local agent profiles
    List,
    /// Set the active local agent profile
    Use {
        #[arg(long)]
        name: String,
    },
    /// Delete a local agent profile record
    Delete {
        #[arg(long)]
        name: String,
    },
}

#[derive(Subcommand)]
pub enum PolicyAction {
    /// List policies
    List,
    /// Create a new policy
    Create {
        #[arg(long)]
        name: String,
        #[arg(long)]
        wallet_id: String,
        #[arg(long)]
        access_key_id: String,
        #[arg(long = "allowed-chain", num_args = 1..)]
        allowed_chains: Vec<String>,
        #[arg(long = "allowed-action", num_args = 1..)]
        allowed_actions: Vec<String>,
        #[arg(long)]
        max_single_amount: String,
        #[arg(long)]
        max_daily_amount: String,
        #[arg(long = "allowed-destination")]
        allowed_destinations: Vec<String>,
        #[arg(long, default_value_t = 24)]
        valid_for_hours: i64,
    },
    /// Get policy details
    Get {
        #[arg(long)]
        policy_id: String,
    },
    /// Activate a policy
    Activate {
        #[arg(long)]
        policy_id: String,
    },
    /// Deactivate a policy
    Deactivate {
        #[arg(long)]
        policy_id: String,
    },
}

#[derive(Subcommand)]
pub enum SignAction {
    /// Validate a sign intent (dry run)
    Validate {
        #[arg(long)]
        access_key_id: Option<String>,
        #[arg(long)]
        wallet_id: Option<String>,
        #[arg(long, default_value = "auto")]
        wallet_selector: String,
        #[arg(long)]
        chain_id: String,
        #[arg(long, default_value = "transaction")]
        signing_type: String,
        #[arg(long)]
        payload: String,
        #[arg(long, default_value = "")]
        destination: String,
        #[arg(long, default_value = "0")]
        value: String,
    },
    /// Submit a signing request
    Submit {
        #[arg(long)]
        access_key_id: Option<String>,
        #[arg(long)]
        wallet_id: Option<String>,
        #[arg(long, default_value = "auto")]
        wallet_selector: String,
        #[arg(long)]
        chain_id: String,
        #[arg(long, default_value = "transaction")]
        signing_type: String,
        #[arg(long)]
        payload: String,
        #[arg(long, default_value = "")]
        destination: String,
        #[arg(long, default_value = "0")]
        value: String,
        #[arg(long, default_value_t = false)]
        sign_and_submit: bool,
    },
}

#[derive(Subcommand)]
pub enum AuditAction {
    /// List audit events
    List {
        #[arg(long)]
        wallet_id: Option<String>,
    },
    /// Get audit event details
    Get {
        #[arg(long)]
        event_id: String,
    },
    /// Verify audit chain integrity
    Verify,
}

#[derive(Subcommand)]
pub enum OperationsAction {
    /// Get operation status
    Get {
        #[arg(long)]
        operation_id: String,
    },
}

#[derive(Clone, Debug, Default, Eq, PartialEq, ValueEnum)]
pub enum OutputFormat {
    #[default]
    Text,
    Json,
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::{error::ErrorKind, CommandFactory, Parser};

    #[test]
    fn parses_required_global_flags() {
        let cli = Cli::try_parse_from([
            "kitepass",
            "--json",
            "--quiet",
            "--no-color",
            "--non-interactive",
            "--dry-run",
            "wallet",
            "list",
        ])
        .expect("cli should parse");

        assert!(cli.json);
        assert!(cli.quiet);
        assert!(cli.no_color);
        assert!(cli.non_interactive);
        assert!(cli.dry_run);
        assert_eq!(cli.format, OutputFormat::Text);
    }

    #[test]
    fn parses_format_value_enum() {
        let cli = Cli::try_parse_from(["kitepass", "--format", "json", "audit", "verify"])
            .expect("cli should parse");

        assert_eq!(cli.format, OutputFormat::Json);
    }

    #[test]
    fn reports_build_version() {
        let err = match Cli::try_parse_from(["kitepass", "--version"]) {
            Ok(_) => panic!("version flag should short-circuit parsing"),
            Err(err) => err,
        };

        assert_eq!(err.kind(), ErrorKind::DisplayVersion);
        assert!(err.to_string().contains(crate::version::DISPLAY_VERSION));
    }

    #[test]
    fn clap_command_uses_build_version() {
        let command = Cli::command();
        let version = command.get_version().expect("version should be configured");
        assert_eq!(version.to_string(), crate::version::DISPLAY_VERSION);
    }
}
