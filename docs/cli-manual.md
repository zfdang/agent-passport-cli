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

This creates or updates a local agent profile in `~/.config/kitepass/agents.toml` and stores the private key as a PEM file under `~/.config/kitepass/keys/`.

### 402: List Local Agent Profiles
```bash
kitepass profile list
```

### 403: Switch the Active Local Agent Profile
```bash
kitepass profile use --name trading-bot
```

---

## 5. Signing Operations

Agents use their access keys to request signatures via the Passport Gateway.

### 501: Sign a Transaction
```bash
kitepass sign submit \
  --wallet-id <WALLET_ID> \
  --signing-type transaction \
  --chain-id "eip155:8453" \
  --destination "0xabc..." \
  --value "50000000000000000" \
  --payload "0x..." \
  --sign-and-submit
```

If `--access-key-id` and `--key-path` are omitted, the CLI resolves the agent from:

1. `KITE_AGENT_ACCESS_KEY_ID` + `KITE_AGENT_KEY_PATH`
2. `KITE_PROFILE`
3. `active_profile` in `agents.toml`
4. the `default` profile

---

## Troubleshooting

- **Check Logs**: Run with `RUST_LOG=debug` to see detailed network interactions.
- **Config Files**:
  - `~/.config/kitepass/config.toml`
  - `~/.config/kitepass/agents.toml`
