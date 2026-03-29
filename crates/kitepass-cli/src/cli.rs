use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "kitepass", about = "Kite Agent Passport CLI")]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,

    /// Output format
    #[arg(long, global = true, default_value = "text")]
    pub format: OutputFormat,
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
    /// Create a new access key
    Create {
        #[arg(long)]
        name: Option<String>,
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
        access_key_id: String,
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
        access_key_id: String,
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
        #[arg(long)]
        key_path: String,
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

#[derive(Clone, Debug)]
pub enum OutputFormat {
    Text,
    Json,
}

impl std::str::FromStr for OutputFormat {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "text" => Ok(Self::Text),
            "json" => Ok(Self::Json),
            _ => Err(format!("unknown format: {s}")),
        }
    }
}
