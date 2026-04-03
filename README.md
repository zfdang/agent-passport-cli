# Kitepass CLI

Command-line interface for **Kite Agent Passport**.

Default API endpoint: `https://api.kitepass.xyz`

## Installation

```bash
curl -fsSL https://raw.githubusercontent.com/zfdang/agent-passport-cli/main/scripts/install.sh | sh
```

Install a specific release:

```bash
curl -fsSL https://raw.githubusercontent.com/zfdang/agent-passport-cli/main/scripts/install.sh | \
  KITEPASS_VERSION=v0.1.0 sh
```

## Usage

```bash
# Uses https://api.kitepass.xyz by default

# Login as wallet owner
kitepass login

# Import an EVM wallet from a hex private key
printf '4f3edf983ac636a65a842ce7c78d9aa706d3b113bce036f9b0b7fcb7e7f6b4c7\n' | \
  kitepass wallet import --chain evm --name "my-agent-wallet"

# Create or replace a local agent profile backed by a new access key
kitepass access-key create --name trading-agent

# Export the one-time Combined Token returned by the create command
export KITE_AGENT_TOKEN="kite_tk_<access_key_id>__<secret_key>"

# Submit a transaction using CAIP-2 chain IDs and automatic wallet discovery
kitepass sign submit \
  --chain-id eip155:8453 \
  --payload 0xdeadbeef \
  --destination 0xabc \
  --value 10 \
  --sign-and-submit

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
- local agent profiles in `~/.kitepass/agents.toml`
- agent private keys as encrypted inline `CryptoEnvelope` records inside `agents.toml`

`access-key create` prints a one-time Combined Token:

```text
kite_tk_<access_key_id>__<secret_key>
```

At runtime, `kitepass sign submit` requires `KITE_AGENT_TOKEN`. The CLI parses the embedded `access_key_id`, finds the matching encrypted profile in `agents.toml`, decrypts the private key locally, and signs the request without depending on any PEM file.

For validation-only requests, the access key resolves in this order:

1. `--access-key-id`
2. `KITE_AGENT_TOKEN`
3. the profile named by `KITE_PROFILE`
4. the active profile from `agents.toml`
5. the `default` profile

Example:

```bash
export KITE_AGENT_TOKEN="kite_tk_aak_123__<secret>"

kitepass sign submit \
  --chain-id eip155:8453 \
  --payload 0xdeadbeef \
  --destination 0xabc \
  --value 10 \
  --sign-and-submit
```

`chain_id` uses CAIP-2 notation. When `--wallet-id` is omitted, the Gateway auto-selects the correct wallet binding for that chain.

`wallet import` currently accepts EVM private keys in hex form. The Gateway/Vault Signer path canonicalizes `base`, `eip155`, and `evm` to the same EVM chain family before sealing the normalized 32-byte key inside the TEE.

## Development

```bash
cargo build
cargo test
cargo run -- --help
```

## Related Repositories

- [`agent-passport`](https://github.com/zfdang/agent-passport) — main platform repository
