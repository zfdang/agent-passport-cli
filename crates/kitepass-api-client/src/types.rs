use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::fmt;

/// Supported wallet chain families.
///
/// Intentional subset of the protocol crate's `kitepass_api_types::chains::ChainFamily`.
/// Variants and serde representation must stay in sync; helper methods like
/// `namespace()` and `matches_chain_id()` live only in the protocol crate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ChainFamily {
    Evm,
}

impl ChainFamily {
    pub fn parse(value: &str) -> Option<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "evm" | "eip155" | "base" => Some(ChainFamily::Evm),
            _ => None,
        }
    }
}

impl fmt::Display for ChainFamily {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ChainFamily::Evm => write!(f, "evm"),
        }
    }
}

#[derive(Deserialize, Serialize, Debug)]
pub struct DeviceCodeResponse {
    pub device_code: String,
    pub user_code: String,
    pub verification_uri: String,
    pub expires_in: i32,
    pub interval: i32,
}

#[derive(Deserialize, Serialize, Debug, Default)]
pub struct DeviceCodeRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub code_challenge: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub code_challenge_method: Option<String>,
}

#[derive(Deserialize, Serialize, Debug, Default)]
pub struct AuthPollRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub code_verifier: Option<String>,
}

#[derive(Deserialize, Serialize, Debug)]
pub struct AuthPollResponse {
    pub access_token: Option<String>,
    pub error: Option<String>,
}

#[derive(Deserialize, Serialize, Debug)]
pub struct StatusResponse {
    pub status: String,
}

#[derive(Serialize, Debug)]
pub struct ImportSessionRequest {
    pub chain_family: ChainFamily,
    pub label: Option<String>,
    pub idempotency_key: String,
}

#[derive(Deserialize, Serialize, Debug)]
pub struct ImportSessionResponse {
    pub session_id: String,
    pub status: String,
    pub vault_signer_instance_id: String,
    pub vault_signer_attestation_endpoint: String,
    pub import_encryption_scheme: String,
    pub vault_signer_identity: VaultSignerIdentity,
    pub channel_binding: ChannelBinding,
    pub expires_at: DateTime<Utc>,
}

#[derive(Deserialize, Serialize, Debug)]
pub struct ChannelBinding {
    pub principal_account_id: String,
    pub principal_session_id: String,
    pub request_id: String,
}

#[derive(Deserialize, Serialize, Debug)]
pub struct ImportAttestationResponse {
    pub session_id: String,
    pub vault_signer_instance_id: String,
    pub import_encryption_scheme: String,
    pub attestation_bundle: String,
    pub import_public_key: String,
    pub endpoint_binding: String,
}

#[derive(Deserialize, Serialize, Debug)]
pub struct VaultSignerIdentity {
    pub instance_id: String,
    pub tee_type: String,
    pub expected_measurements: ExpectedMeasurements,
    pub measurement_profile: MeasurementProfile,
    pub reviewed_build: ReviewedBuild,
    pub authorization_model: String,
}

#[derive(Deserialize, Serialize, Debug)]
pub struct ExpectedMeasurements {
    pub pcr0: String,
    pub pcr1: String,
    pub pcr2: String,
}

#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct MeasurementProfile {
    pub profile_id: String,
    pub version: u32,
}

#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct ReviewedBuild {
    pub build_id: String,
    pub build_digest: String,
    pub build_source: String,
    pub security_model_ref: String,
}

#[derive(Serialize, Debug)]
pub struct UploadWalletCiphertextRequest {
    pub vault_signer_instance_id: String,
    pub encapsulated_key: String,
    pub ciphertext: String,
    pub aad: ImportAad,
}

#[derive(Serialize, Debug)]
pub struct ImportAad {
    pub principal_account_id: String,
    pub principal_session_id: String,
    pub request_id: String,
    pub vault_signer_instance_id: String,
}

#[derive(Deserialize, Serialize, Debug)]
pub struct UploadWalletCiphertextResponse {
    pub operation_id: String,
    pub session_id: String,
    pub status: String,
    pub wallet_id: Option<String>,
}

#[derive(Serialize, Debug)]
pub struct RegisterPassportRequest {
    pub public_key: String,
    pub key_address: String,
    pub expires_at: String,
    pub bindings: Vec<BindingInput>,
    pub idempotency_key: String,
}

#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct PreparePassportResponse {
    pub intent_id: String,
    pub intent_hash: String,
    pub approval_url: String,
    pub approval_status: String,
    pub approval_expires_at: DateTime<Utc>,
}

#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct ProvisioningIntentStatusResponse {
    pub intent_id: String,
    pub intent_hash: String,
    pub approval_status: String,
    pub principal_approval_id: Option<String>,
    pub principal_approval_expires_at: Option<DateTime<Utc>>,
}

#[derive(Serialize, Debug, Clone)]
pub struct FinalizePassportRequest {
    pub intent_id: String,
    pub principal_approval_id: String,
    pub idempotency_key: String,
}

#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct PrincipalApprovalRecord {
    pub principal_approval_id: String,
    pub record_type: String,
    pub record_version: u32,
    pub principal_account_id: String,
    pub intent_id: String,
    pub intent_hash: String,
    pub operation: String,
    pub approval_method: String,
    pub approved_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub approver_key_ref: String,
    pub principal_approval_signature: String,
}

#[derive(Serialize, Debug)]
pub struct BindingInput {
    pub wallet_id: String,
    pub passport_policy_id: String,
    pub passport_policy_version: u64,
    pub is_default: bool,
    pub selection_priority: u32,
}

#[derive(Serialize, Debug, Clone)]
#[serde(tag = "operation", rename_all = "snake_case")]
pub(crate) enum WalletMutationRequest {
    Freeze,
    Revoke,
}

#[derive(Serialize, Debug, Clone)]
#[serde(tag = "operation", rename_all = "snake_case")]
pub(crate) enum PassportMutationRequest {
    Freeze,
    Revoke,
}

#[derive(Deserialize, Serialize, Debug)]
pub struct RegisterPassportResponse {
    pub passport_id: String,
    pub status: String,
    pub principal_approval_status: Option<String>,
    pub bindings: Vec<BindingResult>,
}

#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct BindingResult {
    pub binding_id: String,
    pub wallet_id: String,
    pub passport_policy_id: String,
    pub passport_policy_version: u64,
    pub tee_mirror_status: String,
}

#[derive(Serialize, Debug, Clone)]
pub struct CreatePassportPolicyRequest {
    pub binding_id: Option<String>,
    pub wallet_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub passport_id: Option<String>,
    pub allowed_chains: Vec<String>,
    pub allowed_actions: Vec<String>,
    pub max_single_amount: String,
    pub max_daily_amount: String,
    pub allowed_destinations: Vec<String>,
    pub valid_from: DateTime<Utc>,
    pub valid_until: DateTime<Utc>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "snake_case")]
pub enum SigningMode {
    SignatureOnly,
    SignAndSubmit,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "snake_case")]
pub struct AgentProof {
    pub passport_id: String,
    pub session_nonce: String,
    pub signature: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "snake_case")]
pub struct SignRequest {
    pub request_id: String,
    pub idempotency_key: String,
    pub wallet_id: String,
    pub passport_id: String,
    pub chain_id: String,
    pub signing_type: String,
    pub mode: SigningMode,
    pub payload: String,
    pub destination: String,
    pub value: String,
    pub agent_proof: AgentProof,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "snake_case")]
pub struct SignResponse {
    pub request_id: String,
    pub status: String,
    pub permit_id: Option<String>,
    pub signature: Option<String>,
    pub enclave_receipt: Option<String>,
    pub operation_id: Option<String>,
    pub poll_after_ms: Option<u64>,
    pub reservation_id: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "snake_case")]
pub struct ValidateSignIntentRequest {
    pub request_id: String,
    pub wallet_id: Option<String>,
    pub wallet_selector: Option<String>,
    pub passport_id: String,
    pub chain_id: String,
    pub signing_type: String,
    pub payload: String,
    pub destination: String,
    pub value: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub agent_proof: Option<ValidateAgentProof>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "snake_case")]
pub struct ValidateAgentProof {
    pub signature: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "snake_case")]
pub struct NormalizedIntent {
    pub wallet_id: String,
    pub chain_id: String,
    pub payload_hash: String,
    pub destination: String,
    pub value: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "snake_case")]
pub struct ValidateSignIntentResponse {
    pub request_id: String,
    pub valid: bool,
    pub resolved_wallet_id: String,
    pub passport_policy_id: String,
    pub passport_policy_version: u64,
    pub normalized: NormalizedIntent,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct CreateSessionRequest {
    pub passport_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub challenge_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proof_signature: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct CreateSessionChallengeRequest {
    pub passport_id: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct CreateSessionChallengeResponse {
    pub challenge_id: String,
    pub passport_id: String,
    pub challenge_nonce: String,
    pub expires_at: DateTime<Utc>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct AgentSession {
    pub session_id: String,
    pub passport_id: String,
    pub session_nonce: String,
    pub status: String,
    pub expires_at: DateTime<Utc>,
}

#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct Wallet {
    pub wallet_id: String,
    pub principal_account_id: String,
    pub chain_family: ChainFamily,
    pub status: String,
    pub key_blob_ref: String,
    pub key_version: u64,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct Passport {
    pub passport_id: String,
    pub principal_account_id: String,
    pub public_key: String,
    pub key_alg: String,
    pub key_address: String,
    pub status: String,
    pub expires_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct WalletPassportBinding {
    pub binding_id: String,
    pub passport_id: String,
    pub wallet_id: String,
    pub passport_policy_id: String,
    pub passport_policy_version: u64,
    pub status: String,
    pub is_default: bool,
    pub selection_priority: u32,
}

#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct PassportPolicyUsageState {
    pub binding_id: String,
    pub passport_policy_id: String,
    pub passport_policy_version: u64,
    pub wallet_id: String,
    pub passport_id: String,
    pub lifetime_spent: String,
    pub daily_window_started_at: DateTime<Utc>,
    pub daily_spent: String,
    pub rolling_window_started_at: DateTime<Utc>,
    pub rolling_spent: String,
    pub last_consumed_request_id: String,
    pub updated_at: DateTime<Utc>,
}

#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct PassportPolicy {
    pub passport_policy_id: String,
    pub binding_id: String,
    pub wallet_id: String,
    #[serde(default)]
    pub passport_id: String,
    pub allowed_chains: Vec<String>,
    pub allowed_actions: Vec<String>,
    pub max_single_amount: String,
    pub max_daily_amount: String,
    pub allowed_destinations: Vec<String>,
    pub valid_from: DateTime<Utc>,
    pub valid_until: DateTime<Utc>,
    pub state: String,
    pub version: u64,
}

#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct AuditEvent {
    pub event_id: String,
    pub action: String,
    pub trace_id: String,
    pub request_id: String,
    pub wallet_id: String,
    pub passport_id: String,
    pub chain_id: String,
    pub payload_hash: String,
    pub outcome: String,
    pub passport_policy_id: String,
    pub passport_policy_version: u64,
    pub permit_id: String,
    pub enclave_receipt: Option<String>,
    pub previous_event_hash: String,
    pub timestamp: DateTime<Utc>,
}

#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct VerifyAuditResponse {
    pub valid: bool,
    pub event_count: usize,
    pub latest_event_id: Option<String>,
}

#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct Operation {
    pub operation_id: String,
    pub operation_type: String,
    pub request_id: String,
    pub status: String,
    pub resource_type: String,
    pub resource_id: String,
    pub error_code: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub poll_after_ms: Option<u64>,
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
    // ── ChainFamily::parse ──────────────────────────────────────────

    #[test]
    fn parse_evm_variants() {
        assert_eq!(ChainFamily::parse("evm"), Some(ChainFamily::Evm));
        assert_eq!(ChainFamily::parse("eip155"), Some(ChainFamily::Evm));
        assert_eq!(ChainFamily::parse("base"), Some(ChainFamily::Evm));
    }

    #[test]
    fn parse_is_case_insensitive() {
        assert_eq!(ChainFamily::parse("EVM"), Some(ChainFamily::Evm));
        assert_eq!(ChainFamily::parse("Eip155"), Some(ChainFamily::Evm));
        assert_eq!(ChainFamily::parse("BASE"), Some(ChainFamily::Evm));
    }

    #[test]
    fn parse_trims_whitespace() {
        assert_eq!(ChainFamily::parse("  evm  "), Some(ChainFamily::Evm));
    }

    #[test]
    fn parse_invalid_returns_none() {
        assert_eq!(ChainFamily::parse("solana"), None);
        assert_eq!(ChainFamily::parse("bitcoin"), None);
        assert_eq!(ChainFamily::parse(""), None);
        assert_eq!(ChainFamily::parse("ev"), None);
    }

    // ── ChainFamily::Display ────────────────────────────────────────

    #[test]
    fn display_evm() {
        assert_eq!(format!("{}", ChainFamily::Evm), "evm");
    }

    // ── ChainFamily serde round-trip ────────────────────────────────

    #[test]
    fn chain_family_serde_roundtrip() {
        let original = ChainFamily::Evm;
        let json = serde_json::to_string(&original).unwrap();
        assert_eq!(json, "\"evm\"");
        let decoded: ChainFamily = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded, original);
    }

    // ── Passport serde round-trip ────────────────────────────────────

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
        assert_eq!(passport.status, "active");

        // round-trip
        let serialized = serde_json::to_string(&passport).unwrap();
        let deserialized: Passport = serde_json::from_str(&serialized).unwrap();
        assert_eq!(deserialized.passport_id, passport.passport_id);
        assert_eq!(deserialized.public_key, passport.public_key);
    }

    // ── PassportPolicy serde round-trip ─────────────────────────────

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
        // passport_id has #[serde(default)], so omitting it should work
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

    // ── SignRequest serde round-trip ────────────────────────────────

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

        // Verify SigningMode serializes as snake_case
        assert!(json.contains("sign_and_submit"));
    }

    // ── SignResponse serde round-trip ───────────────────────────────

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
        assert_eq!(resp.status, "completed");
        assert_eq!(resp.permit_id.as_deref(), Some("permit_001"));
        assert_eq!(resp.signature.as_deref(), Some("0xsig123"));
        assert!(resp.enclave_receipt.is_none());

        let serialized = serde_json::to_string(&resp).unwrap();
        let decoded: SignResponse = serde_json::from_str(&serialized).unwrap();
        assert_eq!(decoded.request_id, resp.request_id);
        assert_eq!(decoded.permit_id, resp.permit_id);
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
