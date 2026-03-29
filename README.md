# Kitepass CLI

Command-line interface for **Kite Agent Passport**.

## Installation

```bash
curl -fsSL https://releases.kitepass.ai/install.sh | sh
```

## Usage

```bash
# Login as wallet owner
kitepass login

# Import a wallet
kitepass wallet import --chain base --name "my-agent-wallet"

# Create an agent access key
kitepass access-key create --name "trading-agent"

# List policies
kitepass policy list

# Check audit log
kitepass audit list --wallet <wallet-id>
```

## Development

```bash
cargo build
cargo test
cargo run -- --help
```
