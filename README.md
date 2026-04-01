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

# Create or replace a local agent profile backed by a new access key
kitepass access-key create --name trading-agent

# List policies
kitepass policy list

# Switch the active local agent profile
kitepass profile use --name trading-agent

# List local agent profiles
kitepass profile list

# Check audit log
kitepass audit list --wallet-id <wallet-id>
```

## Local Agent Profiles

Kitepass CLI stores:

- owner/session settings in `~/.config/kitepass/config.toml`
- local agent profiles in `~/.config/kitepass/agents.toml`
- agent private keys as PEM files under `~/.config/kitepass/keys/`

`agents.toml` supports multiple named profiles. The CLI resolves agent credentials in this order:

1. `KITE_AGENT_ACCESS_KEY_ID` + `KITE_AGENT_KEY_PATH`
2. the profile named by `KITE_PROFILE`
3. the active profile from `agents.toml`
4. the `default` profile

Example:

```bash
KITE_PROFILE=trading-agent kitepass sign submit \
  --wallet-id wal_123 \
  --chain-id eip155:8453 \
  --payload 0xdeadbeef \
  --destination 0xabc \
  --value 10 \
  --sign-and-submit
```

## Development

```bash
cargo build
cargo test
cargo run -- --help
```

## Related Repositories

- [`kite-agent-passport`](https://github.com/zfdang/kite-agent-passport) — main platform repository
