# Kitepass CLI

Command-line interface for **Kite Agent Passport**.

Default API endpoint: `https://api.kitepass.xyz`

## Installation

```bash
curl -fsSL https://raw.githubusercontent.com/zfdang/kite-agent-passport-cli/main/scripts/install.sh | sh
```

Install a specific release:

```bash
curl -fsSL https://raw.githubusercontent.com/zfdang/kite-agent-passport-cli/main/scripts/install.sh | \
  KITEPASS_VERSION=v0.1.0 sh
```

## Usage

```bash
# Uses https://api.kitepass.xyz by default

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

Override the endpoint for local or staging environments:

```bash
kitepass --api-url http://127.0.0.1:8080 login
```

## Development

```bash
cargo build
cargo test
cargo run -- --help
```

## Related Repositories

- [`kite-agent-passport`](https://github.com/zfdang/kite-agent-passport) — main platform repository
