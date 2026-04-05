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
4. create a bound runtime passport attached to the wallet and policy
5. export the one-time Passport Token for that bound key
6. validate the signing route
7. request a signature without broadcast
8. optionally sign and submit through the relayer

### 1. Log In As The Owner

```bash
kitepass login
```

This opens the browser-based device flow. On success, the CLI stores the principal session locally.

In the current implementation, the CLI stores:

- an encrypted owner access-token envelope in `~/.kitepass/config.toml`
- the local decryption secret in `~/.kitepass/access-token.secret`

### 2. Import A Wallet

```bash
WALLET_JSON="$(
  printf '%s\n' '4f3edf983ac636a65a842ce7c78d9aa706d3b113bce036f9b0b7fcb7e7f6b4c7' | \
    kitepass --json wallet import --chain-family evm --name "Demo Wallet"
)"

WALLET_ID="$(printf '%s' "$WALLET_JSON" | jq -r '.wallet_id')"
echo "wallet_id=${WALLET_ID}"
```

`wallet import` encrypts the private key locally, fetches the Vault Signer attestation, verifies it, and uploads only attestation-bound ciphertext.

### 3. Create And Activate A Policy

```bash
POLICY_JSON="$(
  kitepass --json passport-policy create \
    --wallet-id "$WALLET_ID" \
    --allowed-chain eip155:8453 \
    --allowed-action transaction \
    --max-single-amount 100 \
    --max-daily-amount 1000 \
    --allowed-destination 0xabc \
    --valid-for-hours 24
)"

POLICY_ID="$(printf '%s' "$POLICY_JSON" | jq -r '.passport_policy_id')"
echo "passport_policy_id=${POLICY_ID}"

kitepass --json passport-policy activate --passport-policy-id "$POLICY_ID"
```

### 4. Create The Bound Runtime Passport

```bash
BOUND_KEY_JSON="$(
  kitepass --json passport create \
    --name demo-agent \
    --wallet-id "$WALLET_ID" \
    --passport-policy-id "$POLICY_ID"
)"

PASSPORT_ID="$(printf '%s' "$BOUND_KEY_JSON" | jq -r '.passport_id')"
export KITE_PASSPORT_TOKEN="$(printf '%s' "$BOUND_KEY_JSON" | jq -r '.passport_token')"

echo "passport_id=${PASSPORT_ID}"
echo "passport_token_prefix=${KITE_PASSPORT_TOKEN:0:24}..."
```

This command:

- generates a new Ed25519 agent key locally
- encrypts the private key into an inline `CryptoEnvelope`
- stores that encrypted profile in `~/.kitepass/agents.toml`
- prints a one-time Passport Token

The Passport Token format is:

```text
kite_passport_<passport_id>__<secret_key>
```

The example intentionally prints only `passport_token_prefix` so the full secret does not get written to your terminal history, shell scrollback, screenshots, or CI logs.

The full Passport Token is already available in the current shell as `KITE_PASSPORT_TOKEN`. That is the value an agent should use.

Typical usage patterns are:

- run the next command in the same shell session:

```bash
KITE_PASSPORT_TOKEN="$KITE_PASSPORT_TOKEN" \
  kitepass --json sign ...
```

- launch an agent/runtime with the token injected as an environment variable:

```bash
KITE_PASSPORT_TOKEN="$KITE_PASSPORT_TOKEN" your-agent-runtime
```

- if the agent runs in another terminal, container, or host, pass the full `KITE_PASSPORT_TOKEN` there through your normal secret-injection path

If you lose the full token value, revoke that passport and create a new one. The CLI does not print the full token again.

### 5. Select The Active Local Profile

```bash
kitepass --json profile use --name demo-agent
```

### 6. Validate The Signing Route

```bash
kitepass --json sign --validate \
  --passport-id "$PASSPORT_ID" \
  --wallet-id "$WALLET_ID" \
  --chain-id eip155:8453 \
  --signing-type transaction \
  --payload 0xdeadbeef \
  --destination 0xabc \
  --value 10
```

For a first successful run, prefer passing both `--passport-id` and `--wallet-id` explicitly. Auto wallet selection is supported, but explicit routing is easier to debug when you are bootstrapping a new environment.

`kitepass sign --validate` can run in two modes:

- with `KITE_PASSPORT_TOKEN`, the CLI signs a validate proof locally with the decrypted agent key
- with only a logged-in principal session, the CLI can still ask Gateway to validate the route as an owner-facing diagnostic step

### 7. Sign Without Submitting

If the agent wants the final wallet signature but will broadcast the transaction itself, call `kitepass sign` without `--broadcast`.

```bash
SIGN_JSON="$(
  KITE_PASSPORT_TOKEN="$KITE_PASSPORT_TOKEN" \
    kitepass --json sign \
      --passport-id "$PASSPORT_ID" \
      --wallet-id "$WALLET_ID" \
      --chain-id eip155:8453 \
      --signing-type transaction \
      --payload 0xdeadbeef \
      --destination 0xabc \
      --value 10
)"

SIGNATURE="$(printf '%s' "$SIGN_JSON" | jq -r '.signature')"
echo "signature=${SIGNATURE}"
```

In this default mode, `kitepass sign` uses `signature_only`. This is the "sign" step: the agent receives the final wallet signature, and no transaction submission `operation_id` is created.

### 8. Sign And Submit The Transaction

```bash
SIGN_JSON="$(
  KITE_PASSPORT_TOKEN="$KITE_PASSPORT_TOKEN" \
    kitepass --json sign \
      --broadcast \
      --passport-id "$PASSPORT_ID" \
      --wallet-id "$WALLET_ID" \
      --chain-id eip155:8453 \
      --signing-type transaction \
      --payload 0xdeadbeef \
      --destination 0xabc \
      --value 10
)"

OPERATION_ID="$(printf '%s' "$SIGN_JSON" | jq -r '.operation_id')"
echo "operation_id=${OPERATION_ID}"
```

`kitepass sign` always requires `KITE_PASSPORT_TOKEN` for signing modes. Internally, the CLI performs:

1. `validate_sign_intent`
2. `create_session_challenge`
3. `create_session`
4. final sign submission with the agent proof

With `--broadcast`, Passport forwards the signed transaction to the relayer and returns an `operation_id` you can poll.

### 9. Check Operation And Audit State

```bash
kitepass --json operations get --operation-id "$OPERATION_ID"
kitepass --json audit list --wallet-id "$WALLET_ID"
```

## Local Files

Kitepass CLI stores owner and agent state under `~/.kitepass/`:

- `~/.kitepass/config.toml`
  - API settings
  - encrypted principal session token envelope
- `~/.kitepass/access-token.secret`
  - local secret used to decrypt the stored principal session token
- `~/.kitepass/agents.toml`
  - local agent profiles
  - encrypted inline `CryptoEnvelope` records for agent private keys

## Troubleshooting

- `kitepass sign` requires `KITE_PASSPORT_TOKEN`
  - if the token is lost, revoke that passport and create a new one
- `kitepass sign --validate` works with either a logged-in principal session or `KITE_PASSPORT_TOKEN`
  - `kitepass sign` and `kitepass sign --broadcast` are stricter and require `KITE_PASSPORT_TOKEN`
- `kitepass sign` without `--broadcast` returns the final signature only
  - add `--broadcast` only when you want Passport to forward the transaction to the relayer
- `wallet import` currently supports the EVM chain family only
  - accepted aliases are normalized to `evm`
- `passport-policy create` must happen before the passport is created
  - create the policy first, then create the passport with `--wallet-id` and `--passport-policy-id`
- if `kitepass sign` says no local encrypted profile was found
  - recreate the passport on the same machine, or sync `~/.kitepass/agents.toml`

## Additional Docs

- [CLI manual](./docs/cli-manual.md)
- [Principal session token and passport flow](./docs/principal-auth-and-agent-passport-flow.md)
- [Agent security design](./docs/agent-security-design.md)
- [Wallet import security notes](./docs/security-wallet-import.md)
- [Development guide](./docs/development.md)

## Related Repositories

- [`agent-passport`](https://github.com/zfdang/agent-passport) — main platform repository
