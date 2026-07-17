use std::{error::Error, fmt};

/// Stable high-level reason returned by offline License operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ErrorCode {
    /// The envelope, payload, schema or field shape is invalid.
    FormatInvalid,
    /// The digital signature is malformed or does not verify.
    SignatureInvalid,
    /// The License belongs to a different product.
    ProductMismatch,
    /// The License validity window has not started.
    NotYetValid,
    /// The License validity window has ended.
    Expired,
    /// The application version or build date is outside the allowed range.
    VersionNotAllowed,
    /// The local machine identity does not satisfy the signed policy.
    MachineMismatch,
    /// A requested feature is not enabled.
    FeatureDenied,
    /// A protected time anchor detected an unacceptable clock rollback.
    TimeRollback,
    /// The requested operation requires an online decision.
    OnlineRequired,
    /// The key is untrusted, too old, retired or revoked.
    KeyRevoked,
}

impl ErrorCode {
    /// Returns the stable `LIC_*` string used by product error mapping.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::FormatInvalid => "LIC_FORMAT_INVALID",
            Self::SignatureInvalid => "LIC_SIGNATURE_INVALID",
            Self::ProductMismatch => "LIC_PRODUCT_MISMATCH",
            Self::NotYetValid => "LIC_NOT_YET_VALID",
            Self::Expired => "LIC_EXPIRED",
            Self::VersionNotAllowed => "LIC_VERSION_NOT_ALLOWED",
            Self::MachineMismatch => "LIC_MACHINE_MISMATCH",
            Self::FeatureDenied => "LIC_FEATURE_DENIED",
            Self::TimeRollback => "LIC_TIME_ROLLBACK",
            Self::OnlineRequired => "LIC_ONLINE_REQUIRED",
            Self::KeyRevoked => "LIC_KEY_REVOKED",
        }
    }
}

/// Error returned by offline signing, decoding and validation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LicenseError {
    code: ErrorCode,
    detail: String,
}

impl LicenseError {
    pub(crate) fn new(code: ErrorCode, detail: impl Into<String>) -> Self {
        Self {
            code,
            detail: detail.into(),
        }
    }

    /// Returns the stable high-level error code.
    pub const fn code(&self) -> ErrorCode {
        self.code
    }

    /// Returns diagnostic detail intended for trusted logs.
    pub fn detail(&self) -> &str {
        &self.detail
    }
}

impl fmt::Display for LicenseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.code.as_str(), self.detail)
    }
}

impl Error for LicenseError {}
