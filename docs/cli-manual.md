# Kitepass CLI Manual

This manual explains the current production-facing CLI flow for owner login, wallet import, delegated key provisioning, and agent signing.

## 1. Version And Install Verification

```bash
kitepass --version
```

Expected format:

```text
0.1.0 (1a2b3c4d)
```

## 2. Owner Login

Owner actions require an authenticated owner session:

```bash
kitepass login
```

The CLI starts the device-code flow, opens the browser when possible, and stores the owner session in `~/.kitepass/config.toml`.

## 3. Wallet Import

Wallet import is an owner action. The CLI verifies the Vault Signer attestation, then HPKE-encrypts the wallet secret before upload.

```bash
printf '4f3edf983ac636a65a842ce7c78d9aa706d3b113bce036f9b0b7fcb7e7f6b4c7\n' | \
  kitepass --json wallet import --chain evm --name "MyTradingWallet"
```

Useful follow-up commands:

```bash
kitepass --json wallet list
kitepass --json wallet get --wallet-id <wallet-id>
```

Notes:

- wallet import currently supports the EVM chain family only
- `evm`, `eip155`, and `base` are normalized to the same EVM path

## 4. Access-Key Provisioning Model

The current provisioning flow is intentionally two-stage:

1. create a bootstrap access key
2. create a policy referencing that bootstrap key
3. create a second, bound runtime access key attached to the wallet and policy

This sequence is the most reliable way to reach a successful `sign submit` today.

### 4.1 Create A Bootstrap Access Key

```bash
kitepass --json access-key create --name trading-seed
```

This creates a local encrypted profile and prints a one-time Combined Token, but the bootstrap key is mainly used to seed policy creation.

### 4.2 Create And Activate A Policy

```bash
kitepass --json policy create \
  --name trading-policy \
  --wallet-id <wallet-id> \
  --access-key-id <seed-access-key-id> \
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

### 4.3 Create The Bound Runtime Access Key

```bash
kitepass --json access-key create \
  --name trading-bot \
  --wallet-id <wallet-id> \
  --policy-id <policy-id>
```

This creates or updates a local agent profile in `~/.kitepass/agents.toml`, encrypts the private key into an inline `CryptoEnvelope`, and prints the one-time Combined Token:

```text
kite_tk_<access_key_id>__<secret_key>
```

Important notes:

- the private key is not stored as plaintext PEM
- the Combined Token is shown only once
- if the token is lost, revoke the key and mint a new one
- `access-key bind` is intentionally disabled; create a new bound key instead

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

Export the Combined Token from the bound runtime key before signing:

```bash
export KITE_AGENT_TOKEN="kite_tk_<access_key_id>__<secret_key>"
```

### 6.1 Validate Routing And Policy

```bash
kitepass --json sign validate \
  --access-key-id <access-key-id> \
  --wallet-id <wallet-id> \
  --chain-id eip155:8453 \
  --signing-type transaction \
  --payload 0xdeadbeef \
  --destination 0xabc \
  --value 10
```

### 6.2 Submit The Signing Request

```bash
KITE_AGENT_TOKEN="$KITE_AGENT_TOKEN" \
  kitepass --json sign submit \
    --access-key-id <access-key-id> \
    --wallet-id <wallet-id> \
    --chain-id eip155:8453 \
    --signing-type transaction \
    --payload 0xdeadbeef \
    --destination 0xabc \
    --value 10 \
    --sign-and-submit
```

Key behavior:

- `chain_id` uses CAIP-2 notation, such as `eip155:8453`
- `sign submit` requires `KITE_AGENT_TOKEN`
- the CLI parses the embedded `access_key_id`, finds the matching encrypted profile in `~/.kitepass/agents.toml`, decrypts the local private key, and signs the canonical agent intent locally
- the Gateway then validates agent proof, policy state, wallet binding, and limits before forwarding to the signer path

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
- `access-token.secret`
- `agents.toml`

## 9. Troubleshooting

- **Missing Combined Token**
  - `sign submit` fails by design without `KITE_AGENT_TOKEN`
- **No local encrypted profile**
  - the access key was created on another machine, or `agents.toml` is missing
- **Policy creation order**
  - create the bootstrap access key first, then the policy, then the bound runtime key
- **Wallet import chain family**
  - use `evm`, `eip155`, or `base`
