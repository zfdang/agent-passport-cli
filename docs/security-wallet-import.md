# Security: Secure Wallet Import Protocol

One of the core value propositions of Agent Passport is the ability to import existing wallet secrets (currently EVM private keys in hex form) into a **Trusted Execution Environment (TEE)** without exposing them to the Passport Gateway or any intermediate infrastructure.

## How it Works

The security of the wallet import flow is based on the **Hybrid Public Key Encryption (HPKE)** scheme and **Remote Attestation**.

### 1. Remote Attestation
Before you input your private key into the `kitepass-cli`, the CLI performs the following:
- Requests an **Attestation Bundle** from the Vault Signer TEE.
- Verifies the **Hardware Quote** (e.g., AWS Nitro Enclave document).
- Verifies the **Measurement (PCRs)** of the code running inside the TEE to ensure it matches the reviewed, open-source build.

### 2. HPKE-Based Encryption
The TEE generates an ephemeral X25519 public key and includes it in the signed attestation bundle.
- The `kitepass-cli` uses this public key to encrypt your wallet secret using **HPKE (RFC 9180)**.
- Encryption occurs **locally** in your terminal's memory.
- The secret is wrapped with **AAD (Additional Authenticated Data)** that binds the secret to your specific `owner_id` and `import_session_id`.

### 3. End-to-End Encryption
The encrypted blob (ciphertext) is sent to the Passport Gateway and then forwarded to the Vault Signer.
- **Gateway as a Relayer**: The Gateway cannot decrypt the secret because it does not possess the TEE's private keys.
- **Decryption in TEE**: The Vault Signer TEE receives the ciphertext, verifies the AAD, validates that the imported secret is a supported EVM private key, normalizes it to raw 32-byte secp256k1 bytes, and then seals it to its own internal storage.

## Why it is Secure

1.  **Zero-Knowledge Infrastructure**: Neither the system operators nor the Gateway software have access to your raw private keys.
2.  **Man-in-the-Middle Protection**: Even if the network traffic is intercepted, the ciphertext is useless without the TEE's private key.
3.  **Domain Isolation**: Secrets are bound to their session and owner. Replay attacks are prevented by short-lived session nonces and mandatory AAD verification.
4.  **Hardware-Gated Access**: The TEE hardware (Nitro Enclave) ensures that the memory containing the unsealed keys is mathematically isolated from the host OS and peripheral devices.
