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
    #[error("Auth Error (Polling): {0}")]
    AuthPolling(String),
}

/// HTTP client for the Passport API.
pub struct PassportClient {
    base_url: String,
    http: reqwest::Client,
    token: Option<String>,
}

// ---- Data Structures ----

#[derive(Deserialize, Debug)]
pub struct DeviceCodeResponse {
    pub device_code: String,
    pub user_code: String,
    pub verification_uri: String,
    pub expires_in: i32,
    pub interval: i32,
}

#[derive(Deserialize, Debug)]
pub struct AuthPollResponse {
    pub access_token: Option<String>,
    pub error: Option<String>,
}

#[derive(Serialize, Debug)]
pub struct ImportSessionRequest {
    pub chain: String,
    pub name: Option<String>,
}

#[derive(Deserialize, Debug)]
pub struct ImportSessionResponse {
    pub session_id: String,
    pub vault_signer_url: String,    // Public read-only endpoint
    pub vault_signer_pubkey: String, // hex encoded
    pub vault_nonce: String,         // hex encoded
    pub attestation_doc: String,
}

#[derive(Serialize, Debug)]
pub struct UploadWalletCiphertextRequest {
    pub session_id: String,
    pub ciphertext_hex: String, // Encrypted envelope format: nonce + ciphertext
}

#[derive(Deserialize, Debug)]
pub struct UploadWalletCiphertextResponse {
    pub wallet_id: String,
    pub status: String,
}

#[derive(Serialize, Debug)]
pub struct RegisterAccessKeyRequest {
    pub name: Option<String>,
    pub public_key_hex: String,
}

#[derive(Deserialize, Debug)]
pub struct RegisterAccessKeyResponse {
    pub key_id: String,
    pub status: String,
}

// -------------------------

impl PassportClient {
    pub fn new(base_url: impl Into<String>) -> Self {
        Self {
            base_url: base_url.into(),
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

    // --- Auth Endpoints ---

    pub async fn request_device_code(&self) -> Result<DeviceCodeResponse, ApiError> {
        let url = format!("{}/v1/owner/auth/device-code", self.base_url);
        let res = self.http.post(&url).send().await?;
        Self::handle_res(res).await
    }

    pub async fn poll_device_code(&self, device_code: &str) -> Result<AuthPollResponse, ApiError> {
        let url = format!("{}/v1/owner/auth/poll", self.base_url);
        let payload = serde_json::json!({ "device_code": device_code });
        let res = self.http.post(&url).json(&payload).send().await?;
        Self::handle_res(res).await
    }

    // --- Wallet Endpoints ---

    pub async fn create_import_session(
        &self,
        chain: &str,
        name: Option<String>,
    ) -> Result<ImportSessionResponse, ApiError> {
        let url = format!("{}/v1/wallets/import-sessions", self.base_url);
        let req = self.maybe_auth(self.http.post(&url));
        let res = req
            .json(&ImportSessionRequest {
                chain: chain.to_string(),
                name,
            })
            .send()
            .await?;
        Self::handle_res(res).await
    }

    pub async fn upload_wallet_ciphertext(
        &self,
        session_id: &str,
        ciphertext_hex: &str,
    ) -> Result<UploadWalletCiphertextResponse, ApiError> {
        let url = format!("{}/v1/wallets/import", self.base_url);
        let req = self.maybe_auth(self.http.post(&url));
        let res = req
            .json(&UploadWalletCiphertextRequest {
                session_id: session_id.to_string(),
                ciphertext_hex: ciphertext_hex.to_string(),
            })
            .send()
            .await?;
        Self::handle_res(res).await
    }

    // --- Access Key Endpoints ---

    pub async fn register_access_key(
        &self,
        public_key_hex: &str,
        name: Option<String>,
    ) -> Result<RegisterAccessKeyResponse, ApiError> {
        let url = format!("{}/v1/access-keys", self.base_url);
        let req = self.maybe_auth(self.http.post(&url));
        let res = req
            .json(&RegisterAccessKeyRequest {
                public_key_hex: public_key_hex.to_string(),
                name,
            })
            .send()
            .await?;
        Self::handle_res(res).await
    }
}
