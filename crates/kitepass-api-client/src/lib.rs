/// HTTP client for the Passport Gateway public API.
///
/// Implements typed request/response wrappers for all CLI-relevant endpoints.
/// Targets the published OpenAPI specification.

pub struct PassportClient {
    base_url: String,
    http: reqwest::Client,
    token: Option<String>,
}

impl PassportClient {
    pub fn new(base_url: impl Into<String>) -> Self {
        Self {
            base_url: base_url.into(),
            http: reqwest::Client::new(),
            token: None,
        }
    }

    pub fn with_token(mut self, token: String) -> Self {
        self.token = Some(token);
        self
    }
}
