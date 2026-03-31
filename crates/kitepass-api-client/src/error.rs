use reqwest::StatusCode;
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
