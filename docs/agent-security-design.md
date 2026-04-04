# Agent Security Design

This document explains how `kitepass-cli` protects agent signing credentials after the Passport Token and encrypted-profile migration.

## Security Goals

The runtime model is designed to satisfy four goals:

1. the owner credential and the agent credential stay separate
2. the Passport Gateway never receives the agent private key
3. local agent private keys are not stored as plaintext PEM files
4. a single agent credential can route across multiple chains by using CAIP-2 `chain_id` values

## Credential Model

The system now uses two different credential types:

- **Principal session token**: stored as an encrypted envelope in `~/.kitepass/config.toml`, with a local decrypt secret in `~/.kitepass/access-token.secret`; used for login, wallet import, policy management, and passport provisioning
- **Passport Token**: shown once during `kitepass passport create`; used by the agent runtime to unlock the encrypted local key

Passport Token format:

```text
kite_apt_<agent_passport_id>__<secret_key>
```

The token carries:

- the Passport `agent_passport_id`, which identifies the delegated authority on the Gateway
- a random secret, which is only used locally to decrypt the stored private-key envelope

The CLI does not store the Passport Token on disk.

## Local Storage Format

Local agent profiles are stored in `~/.kitepass/agents.toml`:

```toml
[[agents]]
name = "trading-bot"
agent_passport_id = "agp_123"
public_key_hex = "..."
encrypted_key = { cipher = "aes-256-gcm", kdf = "hkdf-sha256", salt = "...", nonce = "...", ciphertext = "..." }
```

Each profile contains:

- a human-friendly local profile name
- the remote `agent_passport_id`
- the Ed25519 public key for diagnostics
- an inline `CryptoEnvelope` for the private key

Plaintext PEM files are no longer part of the runtime design.

## Envelope Encryption

`CryptoEnvelope` uses the following construction:

- **KDF**: HKDF-SHA256
- **Cipher**: AES-256-GCM
- **Salt**: randomly generated per envelope
- **Nonce**: randomly generated per encryption

The Passport Token secret is the input keying material. The CLI derives the AES key locally and decrypts the envelope only in process memory right before signing.

Security properties:

- losing `agents.toml` alone is not enough to recover the private key
- losing the Passport Token alone is not enough to sign without the matching local encrypted profile
- losing both means the delegated authority should be treated as compromised and rotated

## Signing Flow

For `kitepass sign`, the runtime flow is:

1. read `KITE_AGENT_PASSPORT_TOKEN`
2. parse `agent_passport_id` and `secret_key`
3. load the matching profile from `agents.toml`
4. decrypt the inline `encrypted_key`
5. sign the canonical agent intent locally
6. call Passport with the resulting `agent_proof`

The Gateway only receives:

- `agent_passport_id`
- sign intent metadata
- the agent proof signature

It never receives the decrypted private key.

`kitepass sign --validate` is slightly broader: it can run either with `KITE_AGENT_PASSPORT_TOKEN` or with a logged-in principal session. That owner path is intended for debugging and route validation, not as the final runtime signing credential.

## CAIP-2 and Multi-Chain Routing

The sign APIs use CAIP-2 `chain_id` values, such as:

- `eip155:1`
- `eip155:8453`
- `solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp`

When `wallet_id` is omitted, the CLI sends `wallet_selector=auto` during `ValidateSignIntent`. The Gateway resolves the correct wallet and policy binding for the requested chain, allowing the same agent passport to operate across multiple chains without hardcoding wallet IDs in the agent runtime.

## Operational Guidance

- Save the Passport Token in a secure secret manager immediately after creation.
- Do not commit `agents.toml` to source control.
- If the Passport Token is lost, revoke the agent passport and create a new one.
- If `agents.toml` is moved to another machine, the Passport Token still must be supplied separately for signing.
- If the Passport Token and the local encrypted profile are both exposed, rotate the delegated authority.

## Failure Modes

Expected local failure cases include:

- `KITE_AGENT_PASSPORT_TOKEN` is missing
- the token format is invalid
- the token `agent_passport_id` does not match the requested key
- no local encrypted profile exists for the token's `agent_passport_id`
- the supplied token secret cannot decrypt the stored envelope

These failures are deliberate: they prevent the CLI from silently falling back to weaker plaintext-key behavior.
