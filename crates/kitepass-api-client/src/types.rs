use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

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

#[derive(Serialize, Debug)]
pub struct ImportSessionRequest {
    pub chain_family: String,
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
    pub owner_id: String,
    pub owner_session_id: String,
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
    pub owner_id: String,
    pub owner_session_id: String,
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
pub struct RegisterAccessKeyRequest {
    pub public_key: String,
    pub key_address: String,
    pub expires_at: String,
    pub bindings: Vec<BindingInput>,
    pub idempotency_key: String,
}

#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct PrepareAccessKeyResponse {
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
    pub owner_approval_id: Option<String>,
    pub owner_approval_expires_at: Option<DateTime<Utc>>,
}

#[derive(Serialize, Debug, Clone)]
pub struct FinalizeAccessKeyRequest {
    pub intent_id: String,
    pub owner_approval_id: String,
    pub idempotency_key: String,
}

#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct OwnerApprovalRecord {
    pub owner_approval_id: String,
    pub record_type: String,
    pub record_version: u32,
    pub owner_id: String,
    pub intent_id: String,
    pub intent_hash: String,
    pub operation: String,
    pub approval_method: String,
    pub approved_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub approver_key_ref: String,
    pub owner_approval_signature: String,
}

#[derive(Serialize, Debug)]
pub struct BindingInput {
    pub wallet_id: String,
    pub policy_id: String,
    pub policy_version: u64,
    pub is_default: bool,
    pub selection_priority: u32,
}

#[derive(Serialize, Debug, Clone)]
pub struct CreateBindingRequest {
    pub wallet_id: String,
    pub policy_id: String,
    pub policy_version: u64,
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
pub(crate) enum AccessKeyMutationRequest {
    Freeze,
    Revoke,
}

#[derive(Deserialize, Serialize, Debug)]
pub struct RegisterAccessKeyResponse {
    pub access_key_id: String,
    pub status: String,
    pub owner_approval_status: Option<String>,
    pub bindings: Vec<BindingResult>,
}

#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct BindingResult {
    pub binding_id: String,
    pub wallet_id: String,
    pub policy_id: String,
    pub policy_version: u64,
    pub tee_mirror_status: String,
}

#[derive(Serialize, Debug, Clone)]
pub struct CreatePolicyRequest {
    pub binding_id: Option<String>,
    pub wallet_id: String,
    pub access_key_id: String,
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
    pub access_key_id: String,
    pub session_nonce: String,
    pub signature: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "snake_case")]
pub struct SignRequest {
    pub request_id: String,
    pub idempotency_key: String,
    pub wallet_id: String,
    pub access_key_id: String,
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
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "snake_case")]
pub struct ValidateSignIntentRequest {
    pub request_id: String,
    pub wallet_id: Option<String>,
    pub wallet_selector: Option<String>,
    pub access_key_id: String,
    pub chain_id: String,
    pub signing_type: String,
    pub payload: String,
    pub destination: String,
    pub value: String,
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
    pub policy_id: String,
    pub policy_version: u64,
    pub normalized: NormalizedIntent,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct CreateSessionRequest {
    pub access_key_id: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct AgentSession {
    pub session_id: String,
    pub access_key_id: String,
    pub session_nonce: String,
    pub status: String,
    pub expires_at: DateTime<Utc>,
}

#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct Wallet {
    pub wallet_id: String,
    pub owner_id: String,
    pub chain_family: String,
    pub status: String,
    pub key_blob_ref: String,
    pub key_version: u64,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct AgentAccessKey {
    pub access_key_id: String,
    pub owner_id: String,
    pub public_key: String,
    pub key_alg: String,
    pub key_address: String,
    pub status: String,
    pub expires_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct WalletAccessBinding {
    pub binding_id: String,
    pub access_key_id: String,
    pub wallet_id: String,
    pub policy_id: String,
    pub policy_version: u64,
    pub status: String,
    pub is_default: bool,
    pub selection_priority: u32,
}

#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct PolicyUsageState {
    pub binding_id: String,
    pub policy_id: String,
    pub policy_version: u64,
    pub wallet_id: String,
    pub access_key_id: String,
    pub lifetime_spent: String,
    pub daily_window_started_at: DateTime<Utc>,
    pub daily_spent: String,
    pub rolling_window_started_at: DateTime<Utc>,
    pub rolling_spent: String,
    pub last_consumed_request_id: String,
    pub updated_at: DateTime<Utc>,
}

#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct Policy {
    pub policy_id: String,
    pub binding_id: String,
    pub wallet_id: String,
    pub access_key_id: String,
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
    pub access_key_id: String,
    pub chain_id: String,
    pub payload_hash: String,
    pub outcome: String,
    pub policy_id: String,
    pub policy_version: u64,
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
pub(crate) struct AccessKeyListResponse {
    pub access_keys: Vec<AgentAccessKey>,
}

#[derive(Deserialize)]
pub(crate) struct BindingListResponse {
    pub bindings: Vec<WalletAccessBinding>,
}

#[derive(Deserialize)]
pub(crate) struct UsageResponse {
    pub usage: Option<PolicyUsageState>,
}

#[derive(Deserialize)]
pub(crate) struct PolicyListResponse {
    pub policies: Vec<Policy>,
}

#[derive(Deserialize)]
pub(crate) struct AuditEventListResponse {
    pub events: Vec<AuditEvent>,
}
