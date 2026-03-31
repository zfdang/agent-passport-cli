# Kitepass CLI Manual

This manual provides detailed instructions on how to use the `kitepass-cli` to interact with the Agent Passport system.

## 1. Authentication

Before performing any operations, you must log in as the owner.

### 101: Passkey Login
```bash
kitepass login --method passkey
```
This will open a browser to perform a passkey-based authentication.

---

## 2. Wallet Management

### 201: Import an Existing Wallet
To import a wallet (e.g., from an EOA private key) into the TEE:
```bash
kitepass wallets import --label "MyTradingWallet" --chain-family eip155
```
*Note: The CLI will prompt for the private key securely. The key is encrypted via HPKE before leaving your local machine and can only be decrypted inside the TEE.*

### 202: List Wallets
```bash
kitepass wallets list
```

---

## 3. Policy Management

Policies define the spending limits and allowed destinations for your agents.

### 301: Create a Spending Policy
```bash
kitepass policy create \
  --wallet-id <WALLET_ID> \
  --allowed-chains "eip155:8453" \
  --max-single-amount "0.1" \
  --max-daily-amount "1.0" \
  --allowed-destinations "0xabc..." \
  --valid-days 30
```

### 302: Activate a Policy
```bash
kitepass policy activate <POLICY_ID>
```

---

## 4. Agent Access Keys

Access keys are delegated credentials used by autonomous agents.

### 401: Register an Agent Key
```bash
kitepass access-key create \
  --public-key <AGENT_PUBKEY_HEX> \
  --wallet-id <WALLET_ID> \
  --policy-id <POLICY_ID>
```

---

## 5. Signing Operations

Agents use their access keys to request signatures via the Passport Gateway.

### 501: Sign a Transaction
```bash
kitepass sign \
  --access-key-id <ACCESS_KEY_ID> \
  --signing-type transaction \
  --chain-id "eip155:8453" \
  --destination "0xabc..." \
  --value "0.05" \
  --payload "0x..."
```

---

## Troubleshooting

- **Check Logs**: Run with `RUST_LOG=debug` to see detailed network interactions.
- **Config File**: Located at `~/.config/kitepass/config.toml`.
