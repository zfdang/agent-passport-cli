# Kitepass CLI

Command-line interface for **Kite Agent Passport**.

Default API endpoint: `https://api.kitepass.xyz`

## Install

```bash
curl -fsSL https://raw.githubusercontent.com/zfdang/agent-passport-cli/main/scripts/install.sh | sh
```

Install a specific release:

```bash
curl -fsSL https://raw.githubusercontent.com/zfdang/agent-passport-cli/main/scripts/install.sh | \
  KITEPASS_VERSION=v0.1.0 sh
```

Verify the installed build:

```bash
kitepass --version
```

The version string is emitted in the form:

```text
kitepass 0.1.0 (1a2b3c4d)
```

## What You Need Before Signing

- a reachable Kitepass deployment
  - the CLI uses `https://api.kitepass.xyz` by default
- access to a browser that can reach the Kitepass Console for owner passkey approval
- an EVM private key in hex form for wallet import
- `jq` if you want to copy-paste the shell examples below exactly

## End-to-End Signing Guide

The current delegated-signing flow is:

1. log in as the owner
2. import a wallet
3. create and activate a policy for that wallet
4. create a bound runtime access key attached to the wallet and policy
5. export the one-time Combined Token for that bound key
6. validate and submit a sign request

### 1. Log In As The Owner

```bash
kitepass login
```

This opens the browser-based device flow. On success, the CLI stores the owner session locally.

In the current implementation, the CLI stores:

- an encrypted owner access-token envelope in `~/.kitepass/config.toml`
- the local decryption secret in `~/.kitepass/access-token.secret`

### 2. Import A Wallet

```bash
WALLET_JSON="$(
  printf '%s\n' '4f3edf983ac636a65a842ce7c78d9aa706d3b113bce036f9b0b7fcb7e7f6b4c7' | \
    kitepass --json wallet import --chain evm --name "Demo Wallet"
)"

WALLET_ID="$(printf '%s' "$WALLET_JSON" | jq -r '.wallet_id')"
echo "wallet_id=${WALLET_ID}"
```

`wallet import` encrypts the private key locally, fetches the Vault Signer attestation, verifies it, and uploads only attestation-bound ciphertext.

### 3. Create And Activate A Policy

```bash
POLICY_JSON="$(
  kitepass --json policy create \
    --name demo-policy \
    --wallet-id "$WALLET_ID" \
    --allowed-chain eip155:8453 \
    --allowed-action transaction \
    --max-single-amount 100 \
    --max-daily-amount 1000 \
    --allowed-destination 0xabc \
    --valid-for-hours 24
)"

POLICY_ID="$(printf '%s' "$POLICY_JSON" | jq -r '.policy_id')"
echo "policy_id=${POLICY_ID}"

kitepass --json policy activate --policy-id "$POLICY_ID"
```

### 4. Create The Bound Runtime Access Key

```bash
BOUND_KEY_JSON="$(
  kitepass --json access-key create \
    --name demo-agent \
    --wallet-id "$WALLET_ID" \
    --policy-id "$POLICY_ID"
)"

ACCESS_KEY_ID="$(printf '%s' "$BOUND_KEY_JSON" | jq -r '.access_key_id')"
export KITE_AGENT_TOKEN="$(printf '%s' "$BOUND_KEY_JSON" | jq -r '.combined_token')"

echo "access_key_id=${ACCESS_KEY_ID}"
echo "combined_token_prefix=${KITE_AGENT_TOKEN:0:24}..."
```

This command:

- generates a new Ed25519 agent key locally
- encrypts the private key into an inline `CryptoEnvelope`
- stores that encrypted profile in `~/.kitepass/agents.toml`
- prints a one-time Combined Token

The Combined Token format is:

```text
kite_tk_<access_key_id>__<secret_key>
```

Save it immediately. The CLI does not print it again.

### 5. Select The Active Local Profile

```bash
kitepass --json profile use --name demo-agent
```

### 6. Validate The Signing Route

```bash
kitepass --json sign validate \
  --access-key-id "$ACCESS_KEY_ID" \
  --wallet-id "$WALLET_ID" \
  --chain-id eip155:8453 \
  --signing-type transaction \
  --payload 0xdeadbeef \
  --destination 0xabc \
  --value 10
```

For a first successful run, prefer passing both `--access-key-id` and `--wallet-id` explicitly. Auto wallet selection is supported, but explicit routing is easier to debug when you are bootstrapping a new environment.

`sign validate` can run in two modes:

- with `KITE_AGENT_TOKEN`, the CLI signs a validate proof locally with the decrypted agent key
- with only a logged-in owner session, the CLI can still ask Gateway to validate the route as an owner-facing diagnostic step

### 7. Submit The Signing Request

```bash
SIGN_JSON="$(
  KITE_AGENT_TOKEN="$KITE_AGENT_TOKEN" \
    kitepass --json sign submit \
      --access-key-id "$ACCESS_KEY_ID" \
      --wallet-id "$WALLET_ID" \
      --chain-id eip155:8453 \
      --signing-type transaction \
      --payload 0xdeadbeef \
      --destination 0xabc \
      --value 10 \
      --sign-and-submit
)"

OPERATION_ID="$(printf '%s' "$SIGN_JSON" | jq -r '.operation_id')"
echo "operation_id=${OPERATION_ID}"
```

`sign submit` always requires `KITE_AGENT_TOKEN`. Internally, the CLI performs:

1. `validate_sign_intent`
2. `create_session_challenge`
3. `create_session`
4. final sign submission with the agent proof

### 9. Check Operation And Audit State

```bash
kitepass --json operations get --operation-id "$OPERATION_ID"
kitepass --json audit list --wallet-id "$WALLET_ID"
```

## Local Files

Kitepass CLI stores owner and agent state under `~/.kitepass/`:

- `~/.kitepass/config.toml`
  - API settings
  - encrypted owner access token envelope
- `~/.kitepass/access-token.secret`
  - local secret used to decrypt the stored owner token
- `~/.kitepass/agents.toml`
  - local agent profiles
  - encrypted inline `CryptoEnvelope` records for agent private keys

## Troubleshooting

- `sign submit` requires `KITE_AGENT_TOKEN`
  - if the token is lost, revoke that access key and create a new one
- `sign validate` works with either a logged-in owner session or `KITE_AGENT_TOKEN`
  - `sign submit` is stricter and requires `KITE_AGENT_TOKEN`
- `wallet import` currently supports the EVM chain family only
  - accepted aliases are normalized to `evm`
- `policy create` must happen before the bound runtime key is created
  - create the policy first, then mint the bound runtime key with `--wallet-id` and `--policy-id`
- if `sign submit` says no local encrypted profile was found
  - recreate the access key on the same machine, or sync `~/.kitepass/agents.toml`

## Additional Docs

- [CLI manual](./docs/cli-manual.md)
- [Owner token and agent access-key flow](./docs/owner-token-and-agent-access-key-flow.md)
- [Agent security design](./docs/agent-security-design.md)
- [Wallet import security notes](./docs/security-wallet-import.md)
- [Development guide](./docs/development.md)

## Related Repositories

- [`agent-passport`](https://github.com/zfdang/agent-passport) — main platform repository
