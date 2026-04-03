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

    /// Validate, sign, or broadcast a transaction
    Sign {
        /// Validate routing and policy only; do not produce a final signature
        #[arg(long, default_value_t = false, conflicts_with = "broadcast")]
        validate: bool,

        /// Broadcast after signing; default behavior is signature only
        #[arg(long, default_value_t = false, conflicts_with = "validate")]
        broadcast: bool,

        /// Explicit Passport access key id; must match KITE_AGENT_TOKEN when provided
        #[arg(long)]
        access_key_id: Option<String>,
        /// Explicit wallet id; omit to allow auto routing by chain
        #[arg(long)]
        wallet_id: Option<String>,
        /// CAIP-2 chain id, for example eip155:8453
        #[arg(long)]
        chain_id: String,
        /// Signing surface, such as transaction
        #[arg(long, default_value = "transaction")]
        signing_type: String,
        /// Hex-encoded payload to be signed
        #[arg(long)]
        payload: String,
        /// Destination address when relevant to the signing type
        #[arg(long, default_value = "")]
        destination: String,
        /// Value field when relevant to the signing type
        #[arg(long, default_value = "0")]
        value: String,
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
        /// Wallet chain family, for example evm, eip155, or base
        #[arg(long)]
        chain_family: String,
        /// Optional local wallet label
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
        /// Bind the new runtime key to this wallet; requires --policy-id
        #[arg(long, requires = "policy_id")]
        wallet_id: Option<String>,
        /// Bind the new runtime key to this policy; requires --wallet-id
        #[arg(long, requires = "wallet_id")]
        policy_id: Option<String>,
        /// Keep the current active profile unchanged after creation
        #[arg(long, default_value_t = false)]
        no_activate: bool,
    },
    /// Get access key details
    Get {
        /// Passport access key id, for example aak_...
        #[arg(long)]
        access_key_id: String,
    },
    /// Freeze an access key
    Freeze {
        /// Passport access key id, for example aak_...
        #[arg(long)]
        access_key_id: String,
    },
    /// Revoke an access key
    Revoke {
        /// Passport access key id, for example aak_...
        #[arg(long)]
        access_key_id: String,
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
        /// Wallet id the policy applies to
        #[arg(long)]
        wallet_id: String,
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

    #[test]
    fn parses_sign_default_mode() {
        let cli = Cli::try_parse_from([
            "kitepass",
            "sign",
            "--chain-id",
            "eip155:8453",
            "--payload",
            "0xdeadbeef",
        ])
        .expect("sign command should parse");

        match cli.command {
            Command::Sign {
                validate,
                broadcast,
                chain_id,
                payload,
                ..
            } => {
                assert!(!validate);
                assert!(!broadcast);
                assert_eq!(chain_id, "eip155:8453");
                assert_eq!(payload, "0xdeadbeef");
            }
            _ => panic!("expected sign command"),
        }
    }

    #[test]
    fn rejects_conflicting_sign_mode_flags() {
        let err = match Cli::try_parse_from([
            "kitepass",
            "sign",
            "--validate",
            "--broadcast",
            "--chain-id",
            "eip155:8453",
            "--payload",
            "0xdeadbeef",
        ]) {
            Ok(_) => panic!("conflicting sign mode flags should fail"),
            Err(err) => err,
        };

        assert_eq!(err.kind(), ErrorKind::ArgumentConflict);
    }

    #[test]
    fn rejects_access_key_create_with_wallet_without_policy() {
        let err = match Cli::try_parse_from([
            "kitepass",
            "access-key",
            "create",
            "--wallet-id",
            "wal_123",
        ]) {
            Ok(_) => panic!("wallet-only access-key create should fail"),
            Err(err) => err,
        };

        assert_eq!(err.kind(), ErrorKind::MissingRequiredArgument);
        assert!(err.to_string().contains("--policy-id"));
    }

    #[test]
    fn rejects_access_key_create_with_policy_without_wallet() {
        let err = match Cli::try_parse_from([
            "kitepass",
            "access-key",
            "create",
            "--policy-id",
            "pol_123",
        ]) {
            Ok(_) => panic!("policy-only access-key create should fail"),
            Err(err) => err,
        };

        assert_eq!(err.kind(), ErrorKind::MissingRequiredArgument);
        assert!(err.to_string().contains("--wallet-id"));
    }

    #[test]
    fn rejects_policy_create_direct_binding_flag() {
        let err = match Cli::try_parse_from([
            "kitepass",
            "policy",
            "create",
            "--wallet-id",
            "wal_123",
            "--access-key-id",
            "aak_123",
            "--allowed-chain",
            "eip155:8453",
            "--allowed-action",
            "transaction",
            "--max-single-amount",
            "100",
            "--max-daily-amount",
            "1000",
        ]) {
            Ok(_) => panic!("policy create should reject direct binding flags"),
            Err(err) => err,
        };

        assert_eq!(err.kind(), ErrorKind::UnknownArgument);
        assert!(err.to_string().contains("--access-key-id"));
    }
}
