# Kitepass CLI Manual

This manual provides detailed instructions on how to use the `kitepass-cli` to interact with the Agent Passport system.

## 1. Authentication

Before performing any operations, you must log in as the owner.

### 101: Passkey Login
```bash
kitepass login
```
This will open a browser to perform a passkey-based authentication.

---

## 2. Wallet Management

### 201: Import an Existing Wallet
To import a wallet (e.g., from an EOA private key) into the TEE:
```bash
kitepass wallet import --chain base --name "MyTradingWallet"
```
*Note: The CLI will prompt for the private key securely. The key is encrypted via HPKE before leaving your local machine and can only be decrypted inside the TEE.*

### 202: List Wallets
```bash
kitepass wallet list
```

---

## 3. Policy Management

Policies define the spending limits and allowed destinations for your agents.

### 301: Create a Spending Policy
```bash
kitepass policy create \
  --name trading-policy \
  --wallet-id <WALLET_ID> \
  --access-key-id <ACCESS_KEY_ID> \
  --allowed-chains "eip155:8453" \
  --allowed-action transaction \
  --max-single-amount "100000000000000000" \
  --max-daily-amount "1000000000000000000" \
  --allowed-destinations "0xabc..." \
  --valid-for-hours 24
```

### 302: Activate a Policy
```bash
kitepass policy activate --policy-id <POLICY_ID>
```

---

## 4. Agent Access Keys

Access keys are delegated credentials used by autonomous agents.

### 401: Register an Agent Key
```bash
kitepass access-key create \
  --name trading-bot \
  --wallet-id <WALLET_ID> \
  --policy-id <POLICY_ID>
```

This creates or updates a local agent profile in `~/.config/kitepass/agents.toml`, encrypts the private key into an inline `CryptoEnvelope`, and prints a one-time Combined Token:

```text
KITE_AGENT_TOKEN="kite_tk_<access_key_id>_<secret_key>"
```

Important notes:

- the private key is no longer stored as a plaintext PEM file
- the Combined Token is shown only once, so save it immediately
- if the token is lost, revoke the access key and create a new one

### 402: List Local Agent Profiles
```bash
kitepass profile list
```

`profile list` shows a safe summary of each profile, including storage mode (`encrypted_inline`) and the envelope algorithm metadata, without printing the encrypted blob itself.

### 403: Switch the Active Local Agent Profile
```bash
kitepass profile use --name trading-bot
```

---

## 5. Signing Operations

Agents use their access keys to request signatures via the Passport Gateway.

### 501: Sign a Transaction
First export the Combined Token returned by `access-key create`:

```bash
export KITE_AGENT_TOKEN="kite_tk_<access_key_id>_<secret_key>"
```

```bash
kitepass sign submit \
  --signing-type transaction \
  --chain-id "eip155:8453" \
  --destination "0xabc..." \
  --value "50000000000000000" \
  --payload "0x..." \
  --sign-and-submit
```

Key behavior in the new signing flow:

- `chain_id` must use CAIP-2 notation, such as `eip155:8453` or `eip155:1`
- when `--wallet-id` is omitted, the CLI sends `wallet_selector=auto` and the Gateway resolves the correct wallet and policy binding for that chain
- `kitepass sign submit` requires `KITE_AGENT_TOKEN`; the CLI parses the embedded `access_key_id`, locates the matching encrypted profile in `agents.toml`, decrypts the private key locally, and signs the canonical agent intent

### 502: Validate Routing Without Submitting
```bash
kitepass sign validate \
  --chain-id "eip155:1" \
  --signing-type transaction \
  --destination "0xabc..." \
  --value "1000000000000000" \
  --payload "0x..."
```

For `sign validate`, the access key is resolved in this order:

1. `--access-key-id`
2. `KITE_AGENT_TOKEN`
3. `KITE_PROFILE`
4. `active_profile` in `agents.toml`
5. the `default` profile

---

## Troubleshooting

- **Check Logs**: Run with `RUST_LOG=debug` to see detailed network interactions.
- **Missing Token**: `sign submit` now requires `KITE_AGENT_TOKEN`. If the token is lost, revoke the access key and create a new one.
- **Config Files**:
  - `~/.config/kitepass/config.toml`
  - `~/.config/kitepass/agents.toml`
