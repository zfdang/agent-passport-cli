# Agent Security Design

This document explains how `kitepass-cli` protects delegated signing credentials with the Passport Token and encrypted local passport-key model.

## Security Goals

The runtime model is designed to satisfy four goals:

1. the owner credential and the agent credential stay separate
2. Passport Gateway never receives the agent private key
3. local passport keys are not stored as plaintext PEM files
4. a single agent credential can route across multiple chains by using CAIP-2 `chain_id` values

## Credential Model

The system uses two different credential types:

- **Principal session token**
  - stored as an encrypted envelope in `~/.kitepass/config.toml`
  - decrypted locally with `~/.kitepass/access-token.secret`
  - used for login, wallet import, policy management, and passport provisioning
  - can be cleared after provisioning with `kitepass logout`
- **Passport Token**
  - shown once during `kitepass passport create`
  - used by the runtime to unlock the encrypted local passport key
  - not stored by the CLI on disk

Passport Token format:

```text
kite_passport_<passport_id>__<secret_key>
```

The token carries:

- the Passport `passport_id`, which identifies the delegated authority on Gateway
- a random secret, which is used only locally to decrypt the stored private-key envelope

## Local Storage Format

Local passport-key records are stored in `~/.kitepass/passports.toml`:

```toml
[[passports]]
passport_id = "agp_123"
public_key_hex = "..."
encrypted_key = { cipher = "aes-256-gcm", kdf = "hkdf-sha256", salt = "...", nonce = "...", ciphertext = "..." }
```

Each record contains:

- the remote `passport_id`
- the Ed25519 public key for diagnostics
- an inline `CryptoEnvelope` for the private key

Plaintext PEM files are not part of the runtime design.

## Envelope Encryption

`CryptoEnvelope` uses the following construction:

- **KDF**: HKDF-SHA256
- **Cipher**: AES-256-GCM
- **Salt**: randomly generated per envelope
- **Nonce**: randomly generated per encryption
- **HKDF info string**: `kitepass-agent-key-encryption`

The Passport Token secret is the input keying material. The CLI derives the AES key locally and decrypts the envelope only in process memory right before signing.

Security properties:

- losing `passports.toml` alone is not enough to recover the private key
- losing the Passport Token alone is not enough to sign without the matching local encrypted passport record
- losing both means the delegated authority should be treated as compromised and rotated

## Signing Flow

For `kitepass sign`, the runtime flow is:

1. read `KITE_PASSPORT_TOKEN`
2. parse `passport_id` and `secret_key`
3. load the matching passport-key record from `passports.toml`
4. decrypt the inline `encrypted_key`
5. sign the canonical agent intent locally
6. call Passport with the resulting `agent_proof`

Gateway only receives:

- `passport_id`
- sign intent metadata
- the agent proof signature

It never receives the decrypted private key.

`kitepass sign --validate` is slightly broader: it can run either with `KITE_PASSPORT_TOKEN` or with a logged-in principal session. That owner path is intended for debugging and route validation, not as the final runtime signing credential.

## CAIP-2 and Multi-Chain Routing

The sign APIs use CAIP-2 `chain_id` values, such as:

- `eip155:1`
- `eip155:8453`
- `solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp`

When `wallet_id` is omitted, the CLI sends `wallet_selector=auto` during `ValidateSignIntent`. Gateway resolves the correct wallet and policy binding for the requested chain, allowing the same Agent Passport to operate across multiple chains without hardcoding wallet IDs in the agent runtime.

## Operational Guidance

- Save the Passport Token in a secure secret manager immediately after creation.
- Run `kitepass logout` after wallet import, policy creation, and passport creation are complete.
- Do not commit `passports.toml` to source control.
- If the Passport Token is lost, revoke the passport and create a new one.
- If `passports.toml` is moved to another machine, the Passport Token still must be supplied separately for signing.
- If the Passport Token and the local encrypted passport record are both exposed, rotate the delegated authority.

## Failure Modes

Expected local failure cases include:

- `KITE_PASSPORT_TOKEN` is missing
- the token format is invalid
- the token `passport_id` does not match the requested key
- no local encrypted passport-key record exists for the token's `passport_id`
- the supplied token secret cannot decrypt the stored envelope

These failures are deliberate: they prevent the CLI from silently falling back to weaker plaintext-key behavior.
