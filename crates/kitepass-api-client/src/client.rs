use crate::error::ApiError;
use crate::types::{
    AccessKeyListResponse, AccessKeyMutationRequest, AgentAccessKey, AgentSession, AuditEvent,
    AuditEventListResponse, AuthPollRequest, AuthPollResponse, BindingListResponse, BindingResult,
    CreateBindingRequest, CreatePolicyRequest, CreateSessionRequest, DeviceCodeRequest,
    DeviceCodeResponse, FinalizeAccessKeyRequest, ImportAttestationResponse,
    ImportSessionRequest, ImportSessionResponse, Operation, OwnerApprovalRecord, Policy,
    PolicyListResponse, PolicyUsageState, PrepareAccessKeyResponse, ProvisioningIntentStatusResponse,
    RegisterAccessKeyRequest, RegisterAccessKeyResponse, SignRequest, SignResponse,
    UploadWalletCiphertextRequest, UploadWalletCiphertextResponse, UsageResponse,
    ValidateSignIntentRequest, ValidateSignIntentResponse, VerifyAuditResponse, Wallet,
    WalletAccessBinding, WalletListResponse, WalletMutationRequest,
};

/// HTTP client for the Passport API.
pub struct PassportClient {
    base_url: String,
    http: reqwest::Client,
    token: Option<String>,
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

    pub async fn freeze_access_key(
        &self,
        access_key_id: &str,
    ) -> Result<AgentAccessKey, ApiError> {
        let url = format!("{}/v1/agent-access-keys/{}", self.base_url, access_key_id);
        let req = self.maybe_auth(self.http.post(&url));
        let res = req.json(&AccessKeyMutationRequest::Freeze).send().await?;
        Self::handle_res(res).await
    }

    pub async fn revoke_access_key(
        &self,
        access_key_id: &str,
    ) -> Result<AgentAccessKey, ApiError> {
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
