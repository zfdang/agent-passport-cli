use chrono::{DateTime, Utc};
use reqwest::StatusCode;
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum ApiError {
    #[error("HTTP Request Error: {0}")]
    Reqwest(#[from] reqwest::Error),
    #[error("API Data Parsing Error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("API Status Error: {status} - {message}")]
    HttpStatus { status: StatusCode, message: String },
}

/// HTTP client for the Passport API.
pub struct PassportClient {
    base_url: String,
    http: reqwest::Client,
    token: Option<String>,
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
enum WalletMutationRequest {
    Freeze,
    Revoke,
}

#[derive(Serialize, Debug, Clone)]
#[serde(tag = "operation", rename_all = "snake_case")]
enum AccessKeyMutationRequest {
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
struct WalletListResponse {
    wallets: Vec<Wallet>,
}

#[derive(Deserialize)]
struct AccessKeyListResponse {
    access_keys: Vec<AgentAccessKey>,
}

#[derive(Deserialize)]
struct BindingListResponse {
    bindings: Vec<WalletAccessBinding>,
}

#[derive(Deserialize)]
struct UsageResponse {
    usage: Option<PolicyUsageState>,
}

#[derive(Deserialize)]
struct PolicyListResponse {
    policies: Vec<Policy>,
}

#[derive(Deserialize)]
struct AuditEventListResponse {
    events: Vec<AuditEvent>,
}

impl PassportClient {
    pub fn new(base_url: impl Into<String>) -> Self {
        let base_url = base_url.into().trim_end_matches('/').to_string();
        Self {
            base_url,
            http: reqwest::Client::builder()
                .user_agent("kitepass-cli/0.1")
                .build()
                .unwrap(),
            token: None,
        }
    }

    pub fn with_token(mut self, token: String) -> Self {
        self.token = Some(token);
        self
    }

    fn maybe_auth(&self, req: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
        if let Some(t) = &self.token {
            req.bearer_auth(t)
        } else {
            req
        }
    }

    async fn handle_res<T: serde::de::DeserializeOwned>(
        res: reqwest::Response,
    ) -> Result<T, ApiError> {
        let status = res.status();
        if status.is_success() {
            Ok(res.json::<T>().await?)
        } else {
            let msg = res.text().await.unwrap_or_default();
            Err(ApiError::HttpStatus {
                status,
                message: msg,
            })
        }
    }

    pub async fn request_device_code(
        &self,
        req_body: &DeviceCodeRequest,
    ) -> Result<DeviceCodeResponse, ApiError> {
        let url = format!("{}/v1/owner-auth/device-code", self.base_url);
        let res = self.http.post(&url).json(req_body).send().await?;
        Self::handle_res(res).await
    }

    pub async fn poll_device_code(
        &self,
        device_code: &str,
        req_body: &AuthPollRequest,
    ) -> Result<AuthPollResponse, ApiError> {
        let url = format!("{}/v1/owner-auth/poll/{}", self.base_url, device_code);
        let res = self.http.post(&url).json(req_body).send().await?;
        Self::handle_res(res).await
    }

    pub async fn create_import_session(
        &self,
        chain_family: &str,
        label: Option<String>,
        idempotency_key: String,
    ) -> Result<ImportSessionResponse, ApiError> {
        let url = format!("{}/v1/wallets/import-sessions", self.base_url);
        let req = self.maybe_auth(self.http.post(&url));
        let res = req
            .json(&ImportSessionRequest {
                chain_family: chain_family.to_string(),
                label,
                idempotency_key,
            })
            .send()
            .await?;
        Self::handle_res(res).await
    }

    pub async fn fetch_import_attestation(
        &self,
        attestation_url: &str,
    ) -> Result<ImportAttestationResponse, ApiError> {
        let res = self.http.get(attestation_url).send().await?;
        Self::handle_res(res).await
    }

    pub async fn upload_wallet_ciphertext(
        &self,
        session_id: &str,
        req_body: &UploadWalletCiphertextRequest,
    ) -> Result<UploadWalletCiphertextResponse, ApiError> {
        let url = format!(
            "{}/v1/wallets/import-sessions/{}/upload",
            self.base_url, session_id
        );
        let req = self.maybe_auth(self.http.post(&url));
        let res = req.json(req_body).send().await?;
        Self::handle_res(res).await
    }

    pub async fn register_access_key(
        &self,
        req_body: &RegisterAccessKeyRequest,
    ) -> Result<PrepareAccessKeyResponse, ApiError> {
        let url = format!("{}/v1/agent-access-keys:prepare", self.base_url);
        let req = self.maybe_auth(self.http.post(&url));
        let res = req.json(req_body).send().await?;
        Self::handle_res(res).await
    }

    pub async fn get_provisioning_intent(
        &self,
        intent_id: &str,
    ) -> Result<ProvisioningIntentStatusResponse, ApiError> {
        let url = format!("{}/v1/provisioning-intents/{}", self.base_url, intent_id);
        let req = self.maybe_auth(self.http.get(&url));
        let res = req.send().await?;
        Self::handle_res(res).await
    }

    pub async fn approve_provisioning_intent(
        &self,
        intent_id: &str,
    ) -> Result<OwnerApprovalRecord, ApiError> {
        let url = format!(
            "{}/v1/provisioning-intents/{}/approve",
            self.base_url, intent_id
        );
        let req = self.maybe_auth(self.http.post(&url));
        let res = req.send().await?;
        Self::handle_res(res).await
    }

    pub async fn finalize_access_key(
        &self,
        req_body: &FinalizeAccessKeyRequest,
    ) -> Result<RegisterAccessKeyResponse, ApiError> {
        let url = format!("{}/v1/agent-access-keys", self.base_url);
        let req = self.maybe_auth(self.http.post(&url));
        let res = req.json(req_body).send().await?;
        Self::handle_res(res).await
    }

    pub async fn create_binding(
        &self,
        access_key_id: &str,
        req_body: &CreateBindingRequest,
    ) -> Result<BindingResult, ApiError> {
        let url = format!(
            "{}/v1/agent-access-keys/{}/bindings",
            self.base_url, access_key_id
        );
        let req = self.maybe_auth(self.http.post(&url));
        let res = req.json(req_body).send().await?;
        Self::handle_res(res).await
    }

    pub async fn list_wallets(&self) -> Result<Vec<Wallet>, ApiError> {
        let url = format!("{}/v1/wallets", self.base_url);
        let req = self.maybe_auth(self.http.get(&url));
        let res = req.send().await?;
        Ok(Self::handle_res::<WalletListResponse>(res).await?.wallets)
    }

    pub async fn get_wallet(&self, wallet_id: &str) -> Result<Wallet, ApiError> {
        let url = format!("{}/v1/wallets/{}", self.base_url, wallet_id);
        let req = self.maybe_auth(self.http.get(&url));
        let res = req.send().await?;
        Self::handle_res(res).await
    }

    pub async fn freeze_wallet(&self, wallet_id: &str) -> Result<Wallet, ApiError> {
        let url = format!("{}/v1/wallets/{}", self.base_url, wallet_id);
        let req = self.maybe_auth(self.http.post(&url));
        let res = req.json(&WalletMutationRequest::Freeze).send().await?;
        Self::handle_res(res).await
    }

    pub async fn revoke_wallet(&self, wallet_id: &str) -> Result<Wallet, ApiError> {
        let url = format!("{}/v1/wallets/{}", self.base_url, wallet_id);
        let req = self.maybe_auth(self.http.post(&url));
        let res = req.json(&WalletMutationRequest::Revoke).send().await?;
        Self::handle_res(res).await
    }

    pub async fn list_access_keys(&self) -> Result<Vec<AgentAccessKey>, ApiError> {
        let url = format!("{}/v1/agent-access-keys", self.base_url);
        let req = self.maybe_auth(self.http.get(&url));
        let res = req.send().await?;
        Ok(Self::handle_res::<AccessKeyListResponse>(res)
            .await?
            .access_keys)
    }

    pub async fn get_access_key(&self, access_key_id: &str) -> Result<AgentAccessKey, ApiError> {
        let url = format!("{}/v1/agent-access-keys/{}", self.base_url, access_key_id);
        let req = self.maybe_auth(self.http.get(&url));
        let res = req.send().await?;
        Self::handle_res(res).await
    }

    pub async fn freeze_access_key(&self, access_key_id: &str) -> Result<AgentAccessKey, ApiError> {
        let url = format!("{}/v1/agent-access-keys/{}", self.base_url, access_key_id);
        let req = self.maybe_auth(self.http.post(&url));
        let res = req.json(&AccessKeyMutationRequest::Freeze).send().await?;
        Self::handle_res(res).await
    }

    pub async fn revoke_access_key(&self, access_key_id: &str) -> Result<AgentAccessKey, ApiError> {
        let url = format!("{}/v1/agent-access-keys/{}", self.base_url, access_key_id);
        let req = self.maybe_auth(self.http.post(&url));
        let res = req.json(&AccessKeyMutationRequest::Revoke).send().await?;
        Self::handle_res(res).await
    }

    pub async fn list_bindings(
        &self,
        access_key_id: &str,
    ) -> Result<Vec<WalletAccessBinding>, ApiError> {
        let url = format!(
            "{}/v1/agent-access-keys/{}/bindings",
            self.base_url, access_key_id
        );
        let req = self.maybe_auth(self.http.get(&url));
        let res = req.send().await?;
        Ok(Self::handle_res::<BindingListResponse>(res).await?.bindings)
    }

    pub async fn get_access_key_usage(
        &self,
        access_key_id: &str,
    ) -> Result<Option<PolicyUsageState>, ApiError> {
        let url = format!(
            "{}/v1/agent-access-keys/{}/usage",
            self.base_url, access_key_id
        );
        let req = self.maybe_auth(self.http.get(&url));
        let res = req.send().await?;
        Ok(Self::handle_res::<UsageResponse>(res).await?.usage)
    }

    pub async fn list_policies(&self) -> Result<Vec<Policy>, ApiError> {
        let url = format!("{}/v1/policies", self.base_url);
        let req = self.maybe_auth(self.http.get(&url));
        let res = req.send().await?;
        Ok(Self::handle_res::<PolicyListResponse>(res).await?.policies)
    }

    pub async fn get_policy(&self, policy_id: &str) -> Result<Policy, ApiError> {
        let url = format!("{}/v1/policies/{}", self.base_url, policy_id);
        let req = self.maybe_auth(self.http.get(&url));
        let res = req.send().await?;
        Self::handle_res(res).await
    }

    pub async fn create_policy(&self, req_body: &CreatePolicyRequest) -> Result<Policy, ApiError> {
        let url = format!("{}/v1/policies", self.base_url);
        let req = self.maybe_auth(self.http.post(&url));
        let res = req.json(req_body).send().await?;
        Self::handle_res(res).await
    }

    pub async fn update_policy(
        &self,
        policy_id: &str,
        req_body: &CreatePolicyRequest,
    ) -> Result<Policy, ApiError> {
        let url = format!("{}/v1/policies/{}", self.base_url, policy_id);
        let req = self.maybe_auth(self.http.post(&url));
        let res = req
            .json(&serde_json::json!({
                "operation": "update",
                "binding_id": req_body.binding_id,
                "wallet_id": req_body.wallet_id,
                "access_key_id": req_body.access_key_id,
                "allowed_chains": req_body.allowed_chains,
                "allowed_actions": req_body.allowed_actions,
                "max_single_amount": req_body.max_single_amount,
                "max_daily_amount": req_body.max_daily_amount,
                "allowed_destinations": req_body.allowed_destinations,
                "valid_from": req_body.valid_from,
                "valid_until": req_body.valid_until,
            }))
            .send()
            .await?;
        Self::handle_res(res).await
    }

    pub async fn activate_policy(&self, policy_id: &str) -> Result<Policy, ApiError> {
        let url = format!("{}/v1/policies/{}", self.base_url, policy_id);
        let req = self.maybe_auth(self.http.post(&url));
        let res = req
            .json(&serde_json::json!({ "operation": "activate" }))
            .send()
            .await?;
        Self::handle_res(res).await
    }

    pub async fn deactivate_policy(&self, policy_id: &str) -> Result<Policy, ApiError> {
        let url = format!("{}/v1/policies/{}", self.base_url, policy_id);
        let req = self.maybe_auth(self.http.post(&url));
        let res = req
            .json(&serde_json::json!({ "operation": "deactivate" }))
            .send()
            .await?;
        Self::handle_res(res).await
    }

    pub async fn list_audit_events(
        &self,
        wallet_id: Option<&str>,
    ) -> Result<Vec<AuditEvent>, ApiError> {
        let url = format!("{}/v1/audit-events", self.base_url);
        let mut req = self.maybe_auth(self.http.get(&url));
        if let Some(wallet_id) = wallet_id {
            req = req.query(&[("wallet_id", wallet_id)]);
        }
        let res = req.send().await?;
        Ok(Self::handle_res::<AuditEventListResponse>(res)
            .await?
            .events)
    }

    pub async fn get_audit_event(&self, event_id: &str) -> Result<AuditEvent, ApiError> {
        let url = format!("{}/v1/audit-events/{}", self.base_url, event_id);
        let req = self.maybe_auth(self.http.get(&url));
        let res = req.send().await?;
        Self::handle_res(res).await
    }

    pub async fn verify_audit_chain(&self) -> Result<VerifyAuditResponse, ApiError> {
        let url = format!("{}/v1/audit-events/verify", self.base_url);
        let req = self.maybe_auth(self.http.post(&url));
        let res = req.send().await?;
        Self::handle_res(res).await
    }

    pub async fn get_operation(&self, operation_id: &str) -> Result<Operation, ApiError> {
        let url = format!("{}/v1/operations/{}", self.base_url, operation_id);
        let req = self.maybe_auth(self.http.get(&url));
        let res = req.send().await?;
        Self::handle_res(res).await
    }

    pub async fn create_session(&self, access_key_id: &str) -> Result<AgentSession, ApiError> {
        let url = format!("{}/v1/sessions", self.base_url);
        let res = self
            .http
            .post(&url)
            .json(&CreateSessionRequest {
                access_key_id: access_key_id.to_string(),
            })
            .send()
            .await?;
        Self::handle_res(res).await
    }

    pub async fn validate_sign_intent(
        &self,
        req_body: &ValidateSignIntentRequest,
    ) -> Result<ValidateSignIntentResponse, ApiError> {
        let url = format!("{}/v1/sign-intents/validate", self.base_url);
        let res = self.http.post(&url).json(req_body).send().await?;
        Self::handle_res(res).await
    }

    pub async fn submit_signature(&self, req_body: &SignRequest) -> Result<SignResponse, ApiError> {
        let url = format!("{}/v1/signatures", self.base_url);
        let res = self.http.post(&url).json(req_body).send().await?;
        Self::handle_res(res).await
    }
}
