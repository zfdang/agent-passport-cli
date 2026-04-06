//! API types for the Kitepass CLI.
//!
//! Canonical types are re-exported from `kitepass-api-types`. CLI-only wrapper
//! types for list responses and type aliases for naming compatibility live here.

use serde::Deserialize;

// ── Re-exports from canonical protocol types ───────────────────────────────

// Chains
pub use kitepass_api_types::chains::ChainFamily;

// Principal auth
pub use kitepass_api_types::principal_auth::{
    AuthPollRequest, AuthPollResponse, DeviceCodeRequest, DeviceCodeResponse,
};

// Wallets
pub use kitepass_api_types::wallets::{
    ChannelBinding, CreateImportSessionRequest, CreateImportSessionResponse, ExpectedMeasurements,
    GetImportAttestationResponse, ImportAad, MeasurementProfile, MutateWalletRequest,
    ReviewedBuild, UploadImportEnvelopeRequest, UploadImportEnvelopeResponse, VaultSignerIdentity,
    Wallet, WalletStatus,
};

// Passports
pub use kitepass_api_types::passports::{
    BindingInput, BindingResult, BindingStatus, CreatePassportRequest, CreatePassportResponse,
    MutatePassportRequest, Passport, PassportStatus, WalletPassportBinding,
};

// Provisioning
pub use kitepass_api_types::provisioning::{
    FinalizePassportRequest, PreparePassportResponse, PrincipalApprovalRecord,
};

// Passport policies
pub use kitepass_api_types::passport_policies::{
    CreatePassportPolicyRequest, PassportPolicy, PassportPolicyState, PassportPolicyUsageState,
};

// Sessions
pub use kitepass_api_types::sessions::{
    AgentSession, CreateSessionChallengeRequest, CreateSessionChallengeResponse,
    CreateSessionRequest,
};

// Signing
pub use kitepass_api_types::signing::{
    AgentProof, NormalizedIntent, SignRequest, SignResponse, SigningMode, ValidateAgentProof,
    ValidateSignIntentRequest, ValidateSignIntentResponse,
};

// Audit
pub use kitepass_api_types::audit::{AuditEvent, VerifyAuditResponse};

// Operations
pub use kitepass_api_types::operations::{Operation, OperationStatus};

// ── Type aliases for CLI naming compatibility ──────────────────────────────

/// CLI alias: the CLI used `RegisterPassportRequest` for the prepare step.
pub type RegisterPassportRequest = CreatePassportRequest;

/// CLI alias: the CLI used `RegisterPassportResponse` for the finalize result.
pub type RegisterPassportResponse = CreatePassportResponse;

/// CLI alias: the CLI used `ImportSessionRequest`.
pub type ImportSessionRequest = CreateImportSessionRequest;

/// CLI alias: the CLI used `ImportSessionResponse`.
pub type ImportSessionResponse = CreateImportSessionResponse;

/// CLI alias: the CLI used `ImportAttestationResponse`.
pub type ImportAttestationResponse = GetImportAttestationResponse;

/// CLI alias: the CLI used `UploadWalletCiphertextRequest`.
pub type UploadWalletCiphertextRequest = UploadImportEnvelopeRequest;

/// CLI alias: the CLI used `UploadWalletCiphertextResponse`.
pub type UploadWalletCiphertextResponse = UploadImportEnvelopeResponse;

/// CLI alias: the CLI used `WalletMutationRequest`.
pub type WalletMutationRequest = MutateWalletRequest;

/// CLI alias: the CLI used `PassportMutationRequest`.
pub type PassportMutationRequest = MutatePassportRequest;

/// CLI alias: the CLI used `ProvisioningIntentStatusResponse`.
pub type ProvisioningIntentStatusResponse =
    kitepass_api_types::provisioning::GetProvisioningIntentResponse;

// ── CLI-only types ─────────────────────────────────────────────────────────

/// Generic status response used by logout and similar endpoints.
#[derive(Deserialize, serde::Serialize, Debug)]
pub struct StatusResponse {
    pub status: String,
}

#[derive(Deserialize)]
pub(crate) struct WalletListResponse {
    pub wallets: Vec<Wallet>,
}

#[derive(Deserialize)]
pub(crate) struct PassportListResponse {
    pub passports: Vec<Passport>,
}

#[derive(Deserialize)]
pub(crate) struct BindingListResponse {
    pub bindings: Vec<WalletPassportBinding>,
}

#[derive(Deserialize)]
pub(crate) struct UsageResponse {
    pub usage: Option<PassportPolicyUsageState>,
}

#[derive(Deserialize)]
pub(crate) struct PolicyListResponse {
    pub passport_policies: Vec<PassportPolicy>,
}

#[derive(Deserialize)]
pub(crate) struct AuditEventListResponse {
    pub events: Vec<AuditEvent>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chain_family_parse_evm_variants() {
        assert_eq!(ChainFamily::parse("evm"), Some(ChainFamily::Evm));
        assert_eq!(ChainFamily::parse("eip155"), Some(ChainFamily::Evm));
        assert_eq!(ChainFamily::parse("base"), Some(ChainFamily::Evm));
    }

    #[test]
    fn chain_family_parse_is_case_insensitive() {
        assert_eq!(ChainFamily::parse("EVM"), Some(ChainFamily::Evm));
        assert_eq!(ChainFamily::parse("Eip155"), Some(ChainFamily::Evm));
        assert_eq!(ChainFamily::parse("BASE"), Some(ChainFamily::Evm));
    }

    #[test]
    fn chain_family_parse_trims_whitespace() {
        assert_eq!(ChainFamily::parse("  evm  "), Some(ChainFamily::Evm));
    }

    #[test]
    fn chain_family_parse_invalid_returns_none() {
        assert_eq!(ChainFamily::parse("solana"), None);
        assert_eq!(ChainFamily::parse("bitcoin"), None);
        assert_eq!(ChainFamily::parse(""), None);
        assert_eq!(ChainFamily::parse("ev"), None);
    }

    #[test]
    fn chain_family_display_evm() {
        assert_eq!(format!("{}", ChainFamily::Evm), "evm");
    }

    #[test]
    fn chain_family_serde_roundtrip() {
        let original = ChainFamily::Evm;
        let json = serde_json::to_string(&original).unwrap();
        assert_eq!(json, "\"evm\"");
        let decoded: ChainFamily = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded, original);
    }

    #[test]
    fn passport_serde_roundtrip() {
        let json_str = r#"{
            "passport_id": "agp_001",
            "principal_account_id": "pa_001",
            "public_key": "0xpubkey",
            "key_alg": "secp256k1",
            "key_address": "0xaddr",
            "status": "active",
            "expires_at": "2026-12-31T23:59:59Z",
            "created_at": "2026-01-01T00:00:00Z",
            "updated_at": "2026-06-15T12:00:00Z"
        }"#;

        let passport: Passport = serde_json::from_str(json_str).unwrap();
        assert_eq!(passport.passport_id, "agp_001");
        assert_eq!(passport.key_alg, "secp256k1");

        let serialized = serde_json::to_string(&passport).unwrap();
        let deserialized: Passport = serde_json::from_str(&serialized).unwrap();
        assert_eq!(deserialized.passport_id, passport.passport_id);
        assert_eq!(deserialized.public_key, passport.public_key);
    }

    #[test]
    fn passport_policy_serde_roundtrip() {
        let json_str = r#"{
            "passport_policy_id": "pp_001",
            "binding_id": "bind_001",
            "wallet_id": "wal_001",
            "passport_id": "agp_001",
            "allowed_chains": ["eip155:8453"],
            "allowed_actions": ["sign_transaction"],
            "max_single_amount": "1000",
            "max_daily_amount": "5000",
            "allowed_destinations": ["0xdead"],
            "valid_from": "2026-01-01T00:00:00Z",
            "valid_until": "2026-12-31T23:59:59Z",
            "state": "active",
            "version": 1
        }"#;

        let policy: PassportPolicy = serde_json::from_str(json_str).unwrap();
        assert_eq!(policy.passport_policy_id, "pp_001");
        assert_eq!(policy.allowed_chains, vec!["eip155:8453"]);
        assert_eq!(policy.version, 1);

        let serialized = serde_json::to_string(&policy).unwrap();
        let deserialized: PassportPolicy = serde_json::from_str(&serialized).unwrap();
        assert_eq!(deserialized.passport_policy_id, policy.passport_policy_id);
        assert_eq!(deserialized.max_single_amount, policy.max_single_amount);
    }

    #[test]
    fn passport_policy_defaults_passport_id() {
        let json_str = r#"{
            "passport_policy_id": "pp_002",
            "binding_id": "bind_002",
            "wallet_id": "wal_002",
            "allowed_chains": [],
            "allowed_actions": [],
            "max_single_amount": "0",
            "max_daily_amount": "0",
            "allowed_destinations": [],
            "valid_from": "2026-01-01T00:00:00Z",
            "valid_until": "2026-12-31T23:59:59Z",
            "state": "draft",
            "version": 0
        }"#;

        let policy: PassportPolicy = serde_json::from_str(json_str).unwrap();
        assert_eq!(policy.passport_id, "");
    }

    #[test]
    fn sign_request_serde_roundtrip() {
        let req = SignRequest {
            request_id: "req_001".into(),
            idempotency_key: "idem_001".into(),
            wallet_id: "wal_001".into(),
            passport_id: "agp_001".into(),
            chain_id: "eip155:8453".into(),
            signing_type: "transaction".into(),
            mode: SigningMode::SignAndSubmit,
            payload: "0xdeadbeef".into(),
            destination: "0xrecipient".into(),
            value: "1000000".into(),
            agent_proof: AgentProof {
                passport_id: "agp_001".into(),
                session_nonce: "nonce_abc".into(),
                signature: "0xsig".into(),
            },
        };

        let json = serde_json::to_string(&req).unwrap();
        let decoded: SignRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.request_id, "req_001");
        assert_eq!(decoded.wallet_id, "wal_001");
        assert_eq!(decoded.agent_proof.session_nonce, "nonce_abc");
        assert!(json.contains("sign_and_submit"));
    }

    #[test]
    fn sign_response_serde_roundtrip() {
        let json_str = r#"{
            "request_id": "req_001",
            "status": "completed",
            "permit_id": "permit_001",
            "signature": "0xsig123",
            "enclave_receipt": null,
            "operation_id": null,
            "poll_after_ms": null,
            "reservation_id": null
        }"#;

        let resp: SignResponse = serde_json::from_str(json_str).unwrap();
        assert_eq!(resp.request_id, "req_001");
        assert_eq!(resp.signature.as_deref(), Some("0xsig123"));
        assert!(resp.enclave_receipt.is_none());

        let serialized = serde_json::to_string(&resp).unwrap();
        let decoded: SignResponse = serde_json::from_str(&serialized).unwrap();
        assert_eq!(decoded.request_id, resp.request_id);
    }

    #[test]
    fn sign_response_all_optional_fields_present() {
        let json_str = r#"{
            "request_id": "req_002",
            "status": "pending",
            "permit_id": "permit_002",
            "signature": "0xsig456",
            "enclave_receipt": "receipt_data",
            "operation_id": "op_001",
            "poll_after_ms": 2000,
            "reservation_id": "res_001"
        }"#;

        let resp: SignResponse = serde_json::from_str(json_str).unwrap();
        assert_eq!(resp.operation_id.as_deref(), Some("op_001"));
        assert_eq!(resp.poll_after_ms, Some(2000));
        assert_eq!(resp.reservation_id.as_deref(), Some("res_001"));
        assert_eq!(resp.enclave_receipt.as_deref(), Some("receipt_data"));
    }
}
