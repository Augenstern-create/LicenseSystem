//! Offline License data model, canonical CBOR format, signing and validation.
//!
//! Version 1 uses an `ALIC` envelope, Ed25519 signatures and the
//! `AUGENSTERN-LICENSE-V1\0` signing domain.

mod cbor;
mod error;
mod governance;
mod model;
mod signing;
mod validation;

pub use error::{ErrorCode, LicenseError};
pub use governance::{
    GovernedLicense, GovernedSigner, IssuancePolicy, IssuanceReceipt, IssuanceRequest,
};
pub use model::{
    Algorithm, AuthorizationContext, KeyStatus, LicensePayload, LicenseType, MachineIdentity,
    MachineIdentityComponent, MachineMatchReport, MachinePolicy, MachineSignalKind, TrustedKey,
    ValidationInput,
};
pub use signing::issue_license;
pub use validation::{KeyRing, validate_license};

pub(crate) const DOMAIN_SEPARATOR_V1: &[u8] = b"AUGENSTERN-LICENSE-V1\0";
pub(crate) const MAGIC: &str = "ALIC";
pub(crate) const FORMAT_VERSION: u16 = 1;
/// Maximum accepted encoded License size, including envelope and signature.
pub const MAX_LICENSE_SIZE: usize = 64 * 1024;
