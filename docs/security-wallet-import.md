# Security: Secure Wallet Import Protocol

One of the core value propositions of Agent Passport is the ability to import existing wallet secrets (currently EVM private keys in hex form) into a **Trusted Execution Environment (TEE)** without exposing them to the Passport Gateway or any intermediate infrastructure.

Implementation note as of 2026-04-03:

- `kitepass wallet import` currently supports the EVM chain family only
- the CLI currently normalizes `evm`, `eip155`, and `base` to the same EVM import path
- the current CLI verifies the attestation discovery payload against Gateway-provided session metadata, expected PCRs, measurement profile data, and reviewed-build metadata before encrypting and uploading the wallet secret

## How it Works

The security of the wallet import flow is based on **P-384 ECDH + AES-256-GCM attestation-bound encryption** and **Remote Attestation**.

### 1. Remote Attestation

Before you input your private key into the `kitepass-cli`, the CLI performs the following:

- Requests an **import session** from Gateway.
- Fetches the Vault Signer **attestation discovery response** from the session-bound attestation endpoint.
- Verifies that the attestation response matches the Gateway bootstrap data:
  - `session_id`
  - `vault_signer_instance_id`
  - `endpoint_binding`
  - `import_encryption_scheme`
  - `authorization_model`
  - measurement profile ID + version
  - reviewed build ID + digest + source + security model reference
  - expected PCR values (`pcr0`, `pcr1`, `pcr2`)

The current CLI does not treat the Gateway as a blind relay here. It checks that the Vault Signer discovery payload and the Gateway bootstrap metadata agree before continuing.

### 2. Attestation-Bound Encryption

The Vault Signer provides its Capsule runtime's attestation-bound P-384 public key for the import session.

- The `kitepass-cli` uses this public key to encrypt your wallet secret using **P-384 ECDH + AES-256-GCM**.
- Encryption occurs **locally** in your terminal's memory.
- The CLI binds the encryption to both:
  - **AAD**, which currently includes `principal_account_id`, `principal_session_id`, `request_id`, and `vault_signer_instance_id`
  - **encryption info**, which currently includes `import_session_id`, `vault_signer_instance_id`, `endpoint_binding`, `authorization_model`, measurement profile data, and reviewed-build metadata

### 3. End-to-End Encryption

The encrypted blob (ciphertext) is sent to the Passport Gateway and then forwarded to the Vault Signer.

- **Gateway as a Relayer**: The Gateway cannot decrypt the secret because it does not possess the TEE's private keys.
- **Decryption in TEE**: The Vault Signer TEE receives the ciphertext, verifies the AAD, validates that the imported secret is a supported EVM private key, normalizes it to raw 32-byte secp256k1 bytes, and then seals it to its own internal storage.

## Why it is Secure

1. **Zero-Knowledge Gateway Path**: Gateway and other control-plane services do not receive plaintext wallet material.
2. **Session And Instance Binding**: The import envelope is bound to the specific import session, principal session, request, and Vault Signer instance.
3. **Reviewed-Build And Measurement Checks**: The CLI rejects discovery payloads whose PCRs, measurement profile, or reviewed-build metadata do not match the Gateway bootstrap expectations.
4. **TEE-Only Plaintext Use**: Plaintext wallet material exists only on the owner-controlled CLI surface before encryption and inside Vault Signer TEE memory after decryption.
