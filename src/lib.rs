//! Commercial license primitives.
//!
//! The production path is the [`license`] module. The older AES/ECDSA/RSA
//! files remain algorithm demonstrations and are intentionally not exported.

/// Demonstration image SDK showing business-level authorization integration.
pub mod demo_sdk;
/// Offline License schema, signing, validation and governed issuance APIs.
pub mod license;
/// Machine signal collection, normalization and weighted identity derivation.
pub mod machine;
/// Online activation, lease, time-ticket, persistence and HTTP service APIs.
pub mod online;
/// Protected local time-anchor storage and rollback detection.
pub mod time_anchor;

pub use license::{
    Algorithm, AuthorizationContext, ErrorCode, GovernedLicense, GovernedSigner, IssuancePolicy,
    IssuanceReceipt, IssuanceRequest, KeyRing, KeyStatus, LicenseError, LicensePayload,
    LicenseType, MachineIdentity, MachineIdentityComponent, MachineMatchReport, MachinePolicy,
    MachineSignalKind, TrustedKey, ValidationInput, issue_license, validate_license,
};
