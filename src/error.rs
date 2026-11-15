//! Crate-wide error type.

use std::fmt;

/// An error object returned by the remote Service (§4.4).
#[derive(Debug, Clone, PartialEq)]
pub struct ApiError {
    /// HTTP status code that accompanied the error.
    pub status: u16,
    /// Service error code (`Code`), `0` if the body could not be decoded.
    pub code: i64,
    /// Human readable message (`Error`).
    pub message: String,
    /// Optional `Details` JSON value.
    pub details: Option<serde_json::Value>,
}

impl ApiError {
    pub fn is_retryable_status(&self) -> bool {
        self.status == 429 || self.status >= 500
    }
}

impl fmt::Display for ApiError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "API error (HTTP {}, code {}): {}",
            self.status, self.code, self.message
        )
    }
}

impl std::error::Error for ApiError {}

/// Errors produced by the gateway library.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    Api(#[from] ApiError),

    #[error("network error: {0}")]
    Network(String),

    #[error("operation cancelled")]
    Cancelled,

    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("OpenPGP error: {0}")]
    Pgp(String),

    #[error("SRP error: {0}")]
    Srp(String),

    #[error("authentication failed: {0}")]
    Auth(String),

    #[error("human verification required (methods: {methods:?})")]
    HumanVerificationRequired { methods: Vec<String>, token: String },

    #[error("already logged in")]
    AlreadyLoggedIn,

    #[error("failed to unlock keys")]
    KeyUnlock,

    #[error("session is no longer valid (deauthenticated)")]
    Deauthenticated,

    #[error("invalid MIME message: {0}")]
    Mime(String),

    #[error("not found: {0}")]
    NotFound(String),

    #[error("not allowed: {0}")]
    NotAllowed(String),

    #[error("invalid input: {0}")]
    Invalid(String),

    #[error("limit exceeded: {0}")]
    Limit(String),

    #[error("TLS error: {0}")]
    Tls(String),

    #[error("{0}")]
    Other(String),
}

impl Error {
    /// The API error, if this is one.
    pub fn api(&self) -> Option<&ApiError> {
        match self {
            Error::Api(e) => Some(e),
            _ => None,
        }
    }

    /// HTTP status of an API error.
    pub fn status(&self) -> Option<u16> {
        self.api().map(|e| e.status)
    }

    /// True for errors that warrant application-level back-off (§4.6):
    /// HTTP 429 or ≥ 500.
    pub fn is_backoff_retryable(&self) -> bool {
        matches!(self.status(), Some(s) if s == 429 || s >= 500)
    }

    /// True for errors the event loop treats as transient (§12.2 step 5).
    pub fn is_transient(&self) -> bool {
        match self {
            Error::Cancelled | Error::Network(_) | Error::Json(_) => true,
            Error::Io(e) => e.kind() == std::io::ErrorKind::UnexpectedEof,
            Error::Api(e) => e.is_retryable_status(),
            _ => false,
        }
    }
}

impl From<pgp::errors::Error> for Error {
    fn from(e: pgp::errors::Error) -> Self {
        Error::Pgp(e.to_string())
    }
}

impl From<base64::DecodeError> for Error {
    fn from(e: base64::DecodeError) -> Self {
        Error::Invalid(format!("base64: {e}"))
    }
}

pub type Result<T, E = Error> = std::result::Result<T, E>;
