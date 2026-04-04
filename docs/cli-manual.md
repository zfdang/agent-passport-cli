# Kitepass CLI Manual

This manual explains the current production-facing CLI flow for owner login, wallet import, delegated key provisioning, and agent signing.

## 1. Version And Install Verification

```bash
kitepass --version
```

Expected format:

```text
kitepass 0.1.0 (1a2b3c4d)
```

## 2. Owner Login

Owner actions require an authenticated principal session:

```bash
kitepass login
```

The CLI starts the device-code flow, opens the browser when possible, and stores the principal session under `~/.kitepass/`.

Current local storage behavior:

- `~/.kitepass/config.toml` stores API settings plus an encrypted owner access-token envelope
- `~/.kitepass/access-token.secret` stores the local secret used to decrypt that token

## 3. Wallet Import

Wallet import is an owner action. The CLI verifies the Vault Signer attestation, then HPKE-encrypts the wallet secret before upload.

```bash
printf '4f3edf983ac636a65a842ce7c78d9aa706d3b113bce036f9b0b7fcb7e7f6b4c7\n' | \
  kitepass --json wallet import --chain-family evm --name "MyTradingWallet"
```

Useful follow-up commands:

```bash
kitepass --json wallet list
kitepass --json wallet get --wallet-id <wallet-id>
```

Notes:

- wallet import currently supports the EVM chain family only
- `evm`, `eip155`, and `base` are normalized to the same EVM path

## 4. Agent Passport Provisioning Model

The current provisioning flow is policy-first:

1. create a policy for the wallet
2. activate that policy
3. create a bound runtime agent passport attached to the wallet and policy

This sequence is the most reliable way to reach a successful runtime signing flow today.

### 4.1 Create And Activate A Policy

```bash
kitepass --json policy create \
  --wallet-id <wallet-id> \
  --allowed-chain eip155:8453 \
  --allowed-action transaction \
  --max-single-amount 100 \
  --max-daily-amount 1000 \
  --allowed-destination 0xabc \
  --valid-for-hours 24
```

```bash
kitepass --json policy activate --policy-id <policy-id>
```

### 4.2 Create The Bound Runtime Agent Passport

```bash
kitepass --json agent-passport create \
  --name trading-bot \
  --wallet-id <wallet-id> \
  --policy-id <policy-id>
```

This creates or updates a local agent profile in `~/.kitepass/agents.toml`, encrypts the private key into an inline `CryptoEnvelope`, and prints the one-time Agent Passport Token:

```text
kite_apt_<agent_passport_id>__<secret_key>
```

Important notes:

- the private key is not stored as plaintext PEM
- the Agent Passport Token is shown only once
- if the token is lost, revoke the key and mint a new one
- there is no post-creation bind command; create a new bound key instead

## 5. Local Profiles

List local profiles:

```bash
kitepass --json profile list
```

Select the active profile:

```bash
kitepass --json profile use --name trading-bot
```

Delete a local profile record:

```bash
kitepass --json profile delete --name trading-bot
```

`profile list` shows safe metadata such as `private_key_storage = "encrypted_inline"` and envelope algorithm details without printing the encrypted blob itself.

## 6. Signing

Export the Agent Passport Token from the bound runtime key before signing:

```bash
export KITE_AGENT_PASSPORT_TOKEN="kite_apt_<agent_passport_id>__<secret_key>"
```

### 6.1 Validate Routing And Policy

```bash
kitepass --json sign --validate \
  --passport-id <passport-id> \
  --wallet-id <wallet-id> \
  --chain-id eip155:8453 \
  --signing-type transaction \
  --payload 0xdeadbeef \
  --destination 0xabc \
  --value 10
```

`kitepass sign --validate` can be used either:

- as an owner-facing diagnostic command after `kitepass login`
- or as an agent-facing proof flow when `KITE_AGENT_PASSPORT_TOKEN` is present

### 6.2 Sign Without Broadcasting

```bash
KITE_AGENT_PASSPORT_TOKEN="$KITE_AGENT_PASSPORT_TOKEN" \
  kitepass --json sign \
    --passport-id <passport-id> \
    --wallet-id <wallet-id> \
    --chain-id eip155:8453 \
    --signing-type transaction \
    --payload 0xdeadbeef \
    --destination 0xabc \
    --value 10
```

Key behavior:

- `chain_id` uses CAIP-2 notation, such as `eip155:8453`
- `kitepass sign` requires `KITE_AGENT_PASSPORT_TOKEN`
- `kitepass sign` internally runs validate, requests a session challenge, creates an agent session, and then submits the final sign request
- the CLI parses the embedded `agent_passport_id`, finds the matching encrypted profile in `~/.kitepass/agents.toml`, decrypts the local private key, and signs the canonical agent intent locally
- the Gateway then validates agent proof, policy state, wallet binding, and limits before returning the final signature

### 6.3 Sign And Broadcast

```bash
KITE_AGENT_PASSPORT_TOKEN="$KITE_AGENT_PASSPORT_TOKEN" \
  kitepass --json sign \
    --broadcast \
    --passport-id <passport-id> \
    --wallet-id <wallet-id> \
    --chain-id eip155:8453 \
    --signing-type transaction \
    --payload 0xdeadbeef \
    --destination 0xabc \
    --value 10
```

When `--broadcast` is present, Passport forwards the signed transaction to the relayer and returns an `operation_id`.

## 7. Operation And Audit Checks

```bash
kitepass --json operations get --operation-id <operation-id>
kitepass --json audit list --wallet-id <wallet-id>
kitepass --json audit get --event-id <event-id>
kitepass --json audit verify
```

## 8. Local Storage

Kitepass CLI stores state in `~/.kitepass/`:

- `config.toml`
  - API settings
  - encrypted owner access-token envelope
- `access-token.secret`
  - local secret used to decrypt the stored principal session token
- `agents.toml`
  - encrypted local agent profiles

## 9. Troubleshooting

- **Missing Agent Passport Token**
  - `kitepass sign` and `kitepass sign --broadcast` fail by design without `KITE_AGENT_PASSPORT_TOKEN`
- **No local encrypted profile**
  - the agent passport was created on another machine, or `agents.toml` is missing
- **Policy creation order**
  - create the policy first, then provision the bound runtime key with `--wallet-id` and `--policy-id`
- **Wallet import chain family**
  - use `evm`, `eip155`, or `base`
