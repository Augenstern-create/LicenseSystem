use std::{error::Error, fmt};

use serde::Serialize;

/// Stable error code returned by online service and token operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum OnlineErrorCode {
    /// The LicenseId is not registered.
    UnknownLicense,
    /// The entitlement has been revoked.
    LicenseRevoked,
    /// The activation-device quota is exhausted.
    ActivationLimit,
    /// The installation must be activated first.
    ActivationRequired,
    /// Requested features are empty or outside the entitlement.
    FeatureDenied,
    /// The floating-seat quota is exhausted.
    LeaseLimit,
    /// Request shape, idempotency or configuration is invalid.
    InvalidRequest,
    /// A signed online token is malformed or untrusted.
    TokenInvalid,
    /// A signed online token is outside its validity window.
    TokenExpired,
    /// An older or conflicting token was replayed.
    TokenReplay,
    /// The token predates the client's minimum revocation epoch.
    RevocationEpochStale,
    /// Administrative authentication failed.
    Unauthorized,
    /// The operational request window is exhausted.
    RateLimited,
    /// The request body exceeds the configured maximum.
    PayloadTooLarge,
    /// Persistent state or another internal dependency failed closed.
    Internal,
}

/// Error returned by online services, HTTP adapters and token verification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OnlineError {
    code: OnlineErrorCode,
    detail: String,
}

impl OnlineError {
    pub(crate) fn new(code: OnlineErrorCode, detail: impl Into<String>) -> Self {
        Self {
            code,
            detail: detail.into(),
        }
    }

    /// Returns the stable public error code.
    pub const fn code(&self) -> OnlineErrorCode {
        self.code
    }
    /// Returns diagnostic detail intended for trusted logs or reference APIs.
    pub fn detail(&self) -> &str {
        &self.detail
    }
}

impl fmt::Display for OnlineError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{:?}: {}", self.code, self.detail)
    }
}

impl Error for OnlineError {}
