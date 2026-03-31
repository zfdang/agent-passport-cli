use anyhow::Error;
use kitepass_api_client::ApiError;
use kitepass_config::ConfigError;
use reqwest::StatusCode;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum CliError {
    #[error("Please run `kitepass login` first")]
    AuthenticationRequired,
    #[error("{0}")]
    InteractiveRequired(String),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum ExitCode {
    Success = 0,
    General = 1,
    Usage = 2,
    Authentication = 3,
    Upstream = 4,
    Local = 5,
}

impl ExitCode {
    pub fn as_u8(self) -> u8 {
        self as u8
    }
}

pub fn classify_error(err: &Error) -> ExitCode {
    if let Some(cli_error) = find_cause::<CliError>(err) {
        return match cli_error {
            CliError::AuthenticationRequired => ExitCode::Authentication,
            CliError::InteractiveRequired(_) => ExitCode::Usage,
        };
    }

    if let Some(api_error) = find_cause::<ApiError>(err) {
        return match api_error {
            ApiError::HttpStatus { status, .. }
                if *status == StatusCode::UNAUTHORIZED || *status == StatusCode::FORBIDDEN =>
            {
                ExitCode::Authentication
            }
            ApiError::HttpStatus { .. } | ApiError::Reqwest(_) | ApiError::Json(_) => {
                ExitCode::Upstream
            }
        };
    }

    if find_cause::<ConfigError>(err).is_some() || find_cause::<std::io::Error>(err).is_some() {
        return ExitCode::Local;
    }

    ExitCode::General
}

fn find_cause<T: std::error::Error + 'static>(err: &Error) -> Option<&T> {
    err.chain().find_map(|cause| cause.downcast_ref::<T>())
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::anyhow;

    #[test]
    fn classifies_missing_login_as_authentication_error() {
        let err = anyhow!(CliError::AuthenticationRequired);
        assert_eq!(classify_error(&err), ExitCode::Authentication);
    }

    #[test]
    fn classifies_interactive_errors_as_usage_errors() {
        let err = anyhow!(CliError::InteractiveRequired("stdin required".to_string()));
        assert_eq!(classify_error(&err), ExitCode::Usage);
    }

    #[test]
    fn classifies_api_forbidden_as_authentication_error() {
        let err = anyhow!(ApiError::HttpStatus {
            status: StatusCode::FORBIDDEN,
            message: "forbidden".to_string(),
        });
        assert_eq!(classify_error(&err), ExitCode::Authentication);
    }

    #[test]
    fn classifies_config_errors_as_local_failures() {
        let err = anyhow!(ConfigError::Io(std::io::Error::other("broken")));
        assert_eq!(classify_error(&err), ExitCode::Local);
    }
}
