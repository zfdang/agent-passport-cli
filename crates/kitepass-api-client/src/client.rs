use crate::error::ApiError;
use crate::types::{
    AgentPassport, AgentPassportListResponse, AgentPassportMutationRequest, AgentSession,
    AuditEvent, AuditEventListResponse, AuthPollRequest, AuthPollResponse, BindingListResponse,
    ChainFamily, CreatePassportPolicyRequest, CreateSessionChallengeRequest,
    CreateSessionChallengeResponse, CreateSessionRequest, DeviceCodeRequest, DeviceCodeResponse,
    FinalizeAgentPassportRequest, ImportAttestationResponse, ImportSessionRequest,
    ImportSessionResponse, Operation, PassportPolicy, PassportPolicyUsageState, PolicyListResponse,
    PrepareAgentPassportResponse, PrincipalApprovalRecord, ProvisioningIntentStatusResponse,
    RegisterAgentPassportRequest, RegisterAgentPassportResponse, SignRequest, SignResponse,
    UploadWalletCiphertextRequest, UploadWalletCiphertextResponse, UsageResponse,
    ValidateSignIntentRequest, ValidateSignIntentResponse, VerifyAuditResponse, Wallet,
    WalletAgentPassportBinding, WalletListResponse, WalletMutationRequest,
};

/// HTTP client for the Passport API.
pub struct PassportClient {
    base_url: String,
    http: reqwest::Client,
    token: Option<String>,
}

impl PassportClient {
    pub fn new(base_url: impl Into<String>) -> Result<Self, ApiError> {
        let base_url = base_url.into().trim_end_matches('/').to_string();
        Ok(Self {
            base_url,
            http: reqwest::Client::builder()
                .user_agent("kitepass-cli/0.1")
                .connect_timeout(std::time::Duration::from_secs(5))
                .timeout(std::time::Duration::from_secs(30))
                .build()?,
            token: None,
        })
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
            let msg = match res.text().await {
                Ok(body) => body,
                Err(error) => format!("failed to read error response body: {error}"),
            };
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
        let url = format!("{}/v1/principal-auth/device-code", self.base_url);
        let res = self.http.post(&url).json(req_body).send().await?;
        Self::handle_res(res).await
    }

    pub async fn poll_device_code(
        &self,
        device_code: &str,
        req_body: &AuthPollRequest,
    ) -> Result<AuthPollResponse, ApiError> {
        let url = format!("{}/v1/principal-auth/poll/{}", self.base_url, device_code);
        let res = self.http.post(&url).json(req_body).send().await?;
        Self::handle_res(res).await
    }

    pub async fn create_import_session(
        &self,
        chain_family: ChainFamily,
        label: Option<String>,
        idempotency_key: String,
    ) -> Result<ImportSessionResponse, ApiError> {
        let url = format!("{}/v1/wallets/import-sessions", self.base_url);
        let req = self.maybe_auth(self.http.post(&url));
        let res = req
            .json(&ImportSessionRequest {
                chain_family,
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

    pub async fn register_agent_passport(
        &self,
        req_body: &RegisterAgentPassportRequest,
    ) -> Result<PrepareAgentPassportResponse, ApiError> {
        let url = format!("{}/v1/agent-passports:prepare", self.base_url);
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
    ) -> Result<PrincipalApprovalRecord, ApiError> {
        let url = format!(
            "{}/v1/provisioning-intents/{}/approve",
            self.base_url, intent_id
        );
        let req = self.maybe_auth(self.http.post(&url));
        let res = req.send().await?;
        Self::handle_res(res).await
    }

    pub async fn finalize_agent_passport(
        &self,
        req_body: &FinalizeAgentPassportRequest,
    ) -> Result<RegisterAgentPassportResponse, ApiError> {
        let url = format!("{}/v1/agent-passports", self.base_url);
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

    pub async fn list_agent_passports(&self) -> Result<Vec<AgentPassport>, ApiError> {
        let url = format!("{}/v1/agent-passports", self.base_url);
        let req = self.maybe_auth(self.http.get(&url));
        let res = req.send().await?;
        Ok(Self::handle_res::<AgentPassportListResponse>(res)
            .await?
            .agent_passports)
    }

    pub async fn get_agent_passport(
        &self,
        agent_passport_id: &str,
    ) -> Result<AgentPassport, ApiError> {
        let url = format!("{}/v1/agent-passports/{}", self.base_url, agent_passport_id);
        let req = self.maybe_auth(self.http.get(&url));
        let res = req.send().await?;
        Self::handle_res(res).await
    }

    pub async fn freeze_agent_passport(
        &self,
        agent_passport_id: &str,
    ) -> Result<AgentPassport, ApiError> {
        let url = format!("{}/v1/agent-passports/{}", self.base_url, agent_passport_id);
        let req = self.maybe_auth(self.http.post(&url));
        let res = req
            .json(&AgentPassportMutationRequest::Freeze)
            .send()
            .await?;
        Self::handle_res(res).await
    }

    pub async fn revoke_agent_passport(
        &self,
        agent_passport_id: &str,
    ) -> Result<AgentPassport, ApiError> {
        let url = format!("{}/v1/agent-passports/{}", self.base_url, agent_passport_id);
        let req = self.maybe_auth(self.http.post(&url));
        let res = req
            .json(&AgentPassportMutationRequest::Revoke)
            .send()
            .await?;
        Self::handle_res(res).await
    }

    pub async fn list_bindings(
        &self,
        agent_passport_id: &str,
    ) -> Result<Vec<WalletAgentPassportBinding>, ApiError> {
        let url = format!(
            "{}/v1/agent-passports/{}/bindings",
            self.base_url, agent_passport_id
        );
        let req = self.maybe_auth(self.http.get(&url));
        let res = req.send().await?;
        Ok(Self::handle_res::<BindingListResponse>(res).await?.bindings)
    }

    pub async fn get_agent_passport_usage(
        &self,
        agent_passport_id: &str,
    ) -> Result<Option<PassportPolicyUsageState>, ApiError> {
        let url = format!(
            "{}/v1/agent-passports/{}/usage",
            self.base_url, agent_passport_id
        );
        let req = self.maybe_auth(self.http.get(&url));
        let res = req.send().await?;
        Ok(Self::handle_res::<UsageResponse>(res).await?.usage)
    }

    pub async fn list_policies(&self) -> Result<Vec<PassportPolicy>, ApiError> {
        let url = format!("{}/v1/passport-policies", self.base_url);
        let req = self.maybe_auth(self.http.get(&url));
        let res = req.send().await?;
        Ok(Self::handle_res::<PolicyListResponse>(res)
            .await?
            .passport_policies)
    }

    pub async fn get_policy(&self, passport_policy_id: &str) -> Result<PassportPolicy, ApiError> {
        let url = format!(
            "{}/v1/passport-policies/{}",
            self.base_url, passport_policy_id
        );
        let req = self.maybe_auth(self.http.get(&url));
        let res = req.send().await?;
        Self::handle_res(res).await
    }

    pub async fn create_policy(
        &self,
        req_body: &CreatePassportPolicyRequest,
    ) -> Result<PassportPolicy, ApiError> {
        let url = format!("{}/v1/passport-policies", self.base_url);
        let req = self.maybe_auth(self.http.post(&url));
        let res = req.json(req_body).send().await?;
        Self::handle_res(res).await
    }

    pub async fn activate_policy(
        &self,
        passport_policy_id: &str,
    ) -> Result<PassportPolicy, ApiError> {
        let url = format!(
            "{}/v1/passport-policies/{}",
            self.base_url, passport_policy_id
        );
        let req = self.maybe_auth(self.http.post(&url));
        let res = req
            .json(&serde_json::json!({ "operation": "activate" }))
            .send()
            .await?;
        Self::handle_res(res).await
    }

    pub async fn deactivate_policy(
        &self,
        passport_policy_id: &str,
    ) -> Result<PassportPolicy, ApiError> {
        let url = format!(
            "{}/v1/passport-policies/{}",
            self.base_url, passport_policy_id
        );
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

    pub async fn create_session_challenge(
        &self,
        req_body: &CreateSessionChallengeRequest,
    ) -> Result<CreateSessionChallengeResponse, ApiError> {
        let url = format!("{}/v1/sessions/challenge", self.base_url);
        let req = self.maybe_auth(self.http.post(&url));
        let res = req.json(req_body).send().await?;
        Self::handle_res(res).await
    }

    pub async fn create_session(
        &self,
        req_body: &CreateSessionRequest,
    ) -> Result<AgentSession, ApiError> {
        let url = format!("{}/v1/sessions", self.base_url);
        let req = self.maybe_auth(self.http.post(&url));
        let res = req.json(req_body).send().await?;
        Self::handle_res(res).await
    }

    pub async fn validate_sign_intent(
        &self,
        req_body: &ValidateSignIntentRequest,
    ) -> Result<ValidateSignIntentResponse, ApiError> {
        let url = format!("{}/v1/sign-intents/validate", self.base_url);
        let req = self.maybe_auth(self.http.post(&url));
        let res = req.json(req_body).send().await?;
        Self::handle_res(res).await
    }

    pub async fn submit_signature(&self, req_body: &SignRequest) -> Result<SignResponse, ApiError> {
        let url = format!("{}/v1/signatures", self.base_url);
        let res = self.http.post(&url).json(req_body).send().await?;
        Self::handle_res(res).await
    }
}
