use clap::{Parser, Subcommand, ValueEnum};

#[derive(Parser)]
#[command(
    name = "kitepass",
    about = "Kitepass CLI",
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
    /// Show current session status, API endpoint, and local key inventory
    Status,

    /// Authenticate as wallet owner via device-code flow
    Login,

    /// Clear the locally stored owner session and log out from Passport Gateway
    Logout,

    /// Wallet management
    Wallet {
        #[command(subcommand)]
        action: WalletAction,
    },

    /// Passport management
    Passport {
        #[command(subcommand)]
        action: PassportAction,
    },

    /// Passport Policy management
    PassportPolicy {
        #[command(subcommand)]
        action: PassportPolicyAction,
    },

    /// Validate, sign, or broadcast a transaction
    Sign {
        /// Validate routing and policy only; do not produce a final signature
        #[arg(long, default_value_t = false, conflicts_with = "broadcast")]
        validate: bool,

        /// Broadcast after signing; default behavior is signature only
        #[arg(long, default_value_t = false, conflicts_with = "validate")]
        broadcast: bool,

        /// Explicit Passport id; must match `KITE_PASSPORT_TOKEN` when provided
        #[arg(long)]
        passport_id: Option<String>,
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
pub enum PassportAction {
    /// List passports
    List,
    /// Create a new passport and save its encrypted local signing key
    Create {
        /// Bind the new runtime key to this wallet; requires --passport-policy-id
        #[arg(long, requires = "passport_policy_id")]
        wallet_id: Option<String>,
        /// Bind the new runtime key to this policy; requires --wallet-id
        #[arg(long, requires = "wallet_id")]
        passport_policy_id: Option<String>,
    },
    /// Local encrypted passport-key storage management
    Local {
        #[command(subcommand)]
        action: LocalPassportAction,
    },
    /// Get passport details
    Get {
        /// Passport id, for example `agp_...`
        #[arg(long)]
        passport_id: String,
    },
    /// Freeze a passport
    Freeze {
        /// Passport id, for example `agp_...`
        #[arg(long)]
        passport_id: String,
    },
    /// Revoke a passport
    Revoke {
        /// Passport id, for example `agp_...`
        #[arg(long)]
        passport_id: String,
    },
}

#[derive(Subcommand)]
pub enum LocalPassportAction {
    /// List locally stored encrypted passport keys
    List,
    /// Delete a local encrypted passport-key record
    Delete {
        #[arg(long)]
        passport_id: String,
    },
}

#[derive(Subcommand)]
pub enum PassportPolicyAction {
    /// List passport_policies
    List,
    /// Create a new passport policy
    Create {
        /// Wallet id the passport policy applies to
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
    /// Get passport policy details
    Get {
        #[arg(long)]
        passport_policy_id: String,
    },
    /// Activate a passport policy
    Activate {
        #[arg(long)]
        passport_policy_id: String,
    },
    /// Deactivate a passport policy
    Deactivate {
        #[arg(long)]
        passport_policy_id: String,
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

#[derive(ValueEnum, Clone, Copy, Debug, PartialEq, Eq)]
pub enum OutputFormat {
    Text,
    Json,
}
