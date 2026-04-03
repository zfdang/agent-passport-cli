# Agent Security Design

This document explains how `kitepass-cli` protects agent signing credentials after the Combined Token and encrypted-profile migration.

## Security Goals

The runtime model is designed to satisfy four goals:

1. the owner credential and the agent credential stay separate
2. the Passport Gateway never receives the agent private key
3. local agent private keys are not stored as plaintext PEM files
4. a single agent credential can route across multiple chains by using CAIP-2 `chain_id` values

## Credential Model

The system now uses two different credential types:

- **Owner token**: stored in `~/.kitepass/config.toml`; used for login, wallet import, policy management, and access-key provisioning
- **Combined Token**: shown once during `kitepass access-key create`; used by the agent runtime to unlock the encrypted local key

Combined Token format:

```text
kite_tk_<access_key_id>__<secret_key>
```

The token carries:

- the Passport `access_key_id`, which identifies the delegated authority on the Gateway
- a random secret, which is only used locally to decrypt the stored private-key envelope

The CLI does not store the Combined Token on disk.

## Local Storage Format

Local agent profiles are stored in `~/.kitepass/agents.toml`:

```toml
[[agents]]
name = "trading-bot"
access_key_id = "aak_123"
public_key_hex = "..."
encrypted_key = { cipher = "aes-256-gcm", kdf = "hkdf-sha256", salt = "...", nonce = "...", ciphertext = "..." }
```

Each profile contains:

- a human-friendly local profile name
- the remote `access_key_id`
- the Ed25519 public key for diagnostics
- an inline `CryptoEnvelope` for the private key

Plaintext PEM files are no longer part of the runtime design.

## Envelope Encryption

`CryptoEnvelope` uses the following construction:

- **KDF**: HKDF-SHA256
- **Cipher**: AES-256-GCM
- **Salt**: randomly generated per envelope
- **Nonce**: randomly generated per encryption

The Combined Token secret is the input keying material. The CLI derives the AES key locally and decrypts the envelope only in process memory right before signing.

Security properties:

- losing `agents.toml` alone is not enough to recover the private key
- losing the Combined Token alone is not enough to sign without the matching local encrypted profile
- losing both means the delegated authority should be treated as compromised and rotated

## Signing Flow

For `kitepass sign submit`, the runtime flow is:

1. read `KITE_AGENT_TOKEN`
2. parse `access_key_id` and `secret_key`
3. load the matching profile from `agents.toml`
4. decrypt the inline `encrypted_key`
5. sign the canonical agent intent locally
6. call Passport with the resulting `agent_proof`

The Gateway only receives:

- `access_key_id`
- sign intent metadata
- the agent proof signature

It never receives the decrypted private key.

## CAIP-2 and Multi-Chain Routing

The sign APIs use CAIP-2 `chain_id` values, such as:

- `eip155:1`
- `eip155:8453`
- `solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp`

When `wallet_id` is omitted, the CLI sends `wallet_selector=auto` during `ValidateSignIntent`. The Gateway resolves the correct wallet and policy binding for the requested chain, allowing the same access key to operate across multiple chains without hardcoding wallet IDs in the agent runtime.

## Operational Guidance

- Save the Combined Token in a secure secret manager immediately after creation.
- Do not commit `agents.toml` to source control.
- If the Combined Token is lost, revoke the access key and create a new one.
- If `agents.toml` is moved to another machine, the Combined Token still must be supplied separately for signing.
- If the Combined Token and the local encrypted profile are both exposed, rotate the delegated authority.

## Failure Modes

Expected local failure cases include:

- `KITE_AGENT_TOKEN` is missing
- the token format is invalid
- the token `access_key_id` does not match the requested key
- no local encrypted profile exists for the token's `access_key_id`
- the supplied token secret cannot decrypt the stored envelope

These failures are deliberate: they prevent the CLI from silently falling back to weaker plaintext-key behavior.
