use std::collections::{BTreeMap, HashMap, HashSet};

use ed25519_dalek::VerifyingKey;
use semver::Version;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uuid::Uuid;

use super::{ErrorCode, LicenseError};

/// Signature algorithm encoded in a License envelope.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Algorithm {
    /// Ed25519 over the versioned domain and canonical payload.
    Ed25519,
}

impl Algorithm {
    /// Returns the exact identifier stored in the envelope.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Ed25519 => "Ed25519",
        }
    }
}

/// Commercial License operating mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LicenseType {
    /// Short-lived evaluation entitlement.
    Trial,
    /// License bound to a signed machine policy.
    NodeLocked,
    /// Online-renewed subscription entitlement.
    Subscription,
    /// Concurrent floating-seat entitlement.
    Floating,
    /// Broad offline site entitlement.
    Site,
}

impl LicenseType {
    pub(crate) const fn as_u8(self) -> u8 {
        match self {
            Self::Trial => 0,
            Self::NodeLocked => 1,
            Self::Subscription => 2,
            Self::Floating => 3,
            Self::Site => 4,
        }
    }

    pub(crate) fn from_u8(value: u8) -> Option<Self> {
        match value {
            0 => Some(Self::Trial),
            1 => Some(Self::NodeLocked),
            2 => Some(Self::Subscription),
            3 => Some(Self::Floating),
            4 => Some(Self::Site),
            _ => None,
        }
    }
}

/// Signed weighted machine-matching policy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MachinePolicy {
    /// Allowed domain-separated component fingerprints.
    pub fingerprints: Vec<String>,
    /// Required weighted score from 1 through 100.
    pub threshold: u16,
}

/// Structured data signed into a version-1 License.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LicensePayload {
    /// Payload schema version; version 1 is currently supported.
    pub schema_version: u16,
    /// Globally unique License identifier.
    pub license_id: Uuid,
    /// Product identifier that must match the application.
    pub product_id: String,
    /// Commercial edition label.
    pub edition: String,
    /// Customer identifier used by trusted business systems.
    pub customer_id: String,
    /// UTC issuance time.
    #[serde(with = "time::serde::rfc3339")]
    pub issued_at: OffsetDateTime,
    /// Optional UTC start time; defaults to `issued_at`.
    #[serde(default, with = "time::serde::rfc3339::option")]
    pub not_before: Option<OffsetDateTime>,
    /// Optional UTC expiration; `None` represents permanence.
    #[serde(default, with = "time::serde::rfc3339::option")]
    pub expires_at: Option<OffsetDateTime>,
    /// Optional last build date eligible for maintenance upgrades.
    #[serde(default, with = "time::serde::rfc3339::option")]
    pub maintenance_until: Option<OffsetDateTime>,
    /// Operating mode controlling online and machine requirements.
    pub license_type: LicenseType,
    /// Named feature switches.
    #[serde(default)]
    pub features: BTreeMap<String, bool>,
    /// Named numeric limits consumed by product code.
    #[serde(default)]
    pub limits: BTreeMap<String, u64>,
    /// Named resource allowlists such as models or devices.
    #[serde(default)]
    pub resource_scope: BTreeMap<String, Vec<String>>,
    /// Optional signed machine-binding policy.
    #[serde(default)]
    pub machine_policy: Option<MachinePolicy>,
    /// Optional minimum accepted semantic application version.
    #[serde(default)]
    pub min_app_version: Option<String>,
    /// Optional maximum accepted semantic application version.
    #[serde(default)]
    pub max_app_version: Option<String>,
    /// Signed revocation generation known at issuance.
    #[serde(default)]
    pub revocation_epoch: u64,
    /// Bounded product-specific extension fields.
    #[serde(default)]
    pub custom: BTreeMap<String, String>,
}

/// Lifecycle state of a trusted signing key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyStatus {
    /// May sign new Licenses and verify existing ones.
    Active,
    /// May verify existing Licenses but must not sign.
    VerifyOnly,
    /// Compromised or administratively revoked.
    Revoked,
    /// Removed after the supported verification window.
    Retired,
}

/// Trusted Ed25519 public key and client lifecycle metadata.
#[derive(Debug, Clone)]
pub struct TrustedKey {
    /// Stable identifier encoded in License envelopes.
    pub key_id: String,
    /// Monotonic generation used to prevent downgrade.
    pub generation: u64,
    /// Current lifecycle state.
    pub status: KeyStatus,
    /// Ed25519 public key; private material is never stored here.
    pub public_key: VerifyingKey,
}

impl TrustedKey {
    /// Creates a generation-zero key for legacy or test compatibility.
    pub fn ed25519(key_id: impl Into<String>, status: KeyStatus, public_key: VerifyingKey) -> Self {
        Self {
            key_id: key_id.into(),
            generation: 0,
            status,
            public_key,
        }
    }

    /// Creates a trusted key with an explicit monotonic generation.
    pub fn ed25519_with_generation(
        key_id: impl Into<String>,
        generation: u64,
        status: KeyStatus,
        public_key: VerifyingKey,
    ) -> Self {
        Self {
            key_id: key_id.into(),
            generation,
            status,
            public_key,
        }
    }
}

/// Source kind for one machine identity component.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MachineSignalKind {
    /// Trusted Platform Module identity.
    Tpm,
    /// SMBIOS system UUID.
    SmbiosUuid,
    /// System volume serial number.
    SystemVolumeSerial,
    /// Processor identifier.
    CpuId,
    /// Windows MachineGuid.
    MachineGuid,
}

impl MachineSignalKind {
    /// Returns the stable lowercase name used in hashes and logs.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Tpm => "tpm",
            Self::SmbiosUuid => "smbios_uuid",
            Self::SystemVolumeSerial => "system_volume_serial",
            Self::CpuId => "cpu_id",
            Self::MachineGuid => "machine_guid",
        }
    }
}

/// One normalized, domain-separated machine identity component.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MachineIdentityComponent {
    kind: MachineSignalKind,
    fingerprint: String,
    weight: u16,
    high_confidence: bool,
}

impl MachineIdentityComponent {
    pub(crate) fn new(
        kind: MachineSignalKind,
        fingerprint: String,
        weight: u16,
        high_confidence: bool,
    ) -> Self {
        Self {
            kind,
            fingerprint,
            weight,
            high_confidence,
        }
    }

    /// Returns the source signal kind.
    pub const fn kind(&self) -> MachineSignalKind {
        self.kind
    }
    /// Returns the lowercase hexadecimal SHA-256 fingerprint.
    pub fn fingerprint(&self) -> &str {
        &self.fingerprint
    }
    /// Returns this component's contribution to the score.
    pub const fn weight(&self) -> u16 {
        self.weight
    }
    /// Returns whether the component is high confidence.
    pub const fn is_high_confidence(&self) -> bool {
        self.high_confidence
    }
}

/// Product-domain-separated collection of machine components.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MachineIdentity {
    components: Vec<MachineIdentityComponent>,
}

impl MachineIdentity {
    pub(crate) fn new(components: Vec<MachineIdentityComponent>) -> Self {
        Self { components }
    }

    /// Returns the deterministic component list.
    pub fn components(&self) -> &[MachineIdentityComponent] {
        &self.components
    }

    /// Evaluates this identity against a signed matching policy.
    pub fn match_policy(&self, policy: &MachinePolicy) -> MachineMatchReport {
        let allowed: HashSet<_> = policy.fingerprints.iter().map(String::as_str).collect();
        let mut matched_kinds = HashSet::new();
        let mut score = 0_u16;
        let mut high_confidence_match = false;
        for component in &self.components {
            if allowed.contains(component.fingerprint()) && matched_kinds.insert(component.kind()) {
                score = score.saturating_add(component.weight());
                high_confidence_match |= component.is_high_confidence();
            }
        }
        let mut matched_components: Vec<_> = matched_kinds.into_iter().collect();
        matched_components.sort_by_key(|kind| kind.as_str());
        MachineMatchReport {
            score,
            threshold: policy.threshold,
            high_confidence_match,
            matched_components,
        }
    }
}

/// Detailed result of machine policy evaluation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MachineMatchReport {
    /// Weighted score contributed by matching components.
    pub score: u16,
    /// Required score copied from the signed policy.
    pub threshold: u16,
    /// Whether a high-confidence component matched.
    pub high_confidence_match: bool,
    /// Signal kinds that matched without duplicate inflation.
    pub matched_components: Vec<MachineSignalKind>,
}

impl MachineMatchReport {
    /// Returns true when score and high-confidence requirements pass.
    pub const fn is_match(&self) -> bool {
        self.score >= self.threshold && self.high_confidence_match
    }
}

/// Runtime inputs supplied by a product during validation.
#[derive(Debug, Clone)]
pub struct ValidationInput {
    /// Product identifier expected by the application.
    pub expected_product_id: String,
    /// Trusted current UTC.
    pub now: OffsetDateTime,
    /// Optional running semantic version.
    pub app_version: Option<Version>,
    /// Optional UTC build date.
    pub build_date: Option<OffsetDateTime>,
    /// Optional locally derived machine identity.
    pub machine_identity: Option<MachineIdentity>,
}

impl ValidationInput {
    /// Creates input for a product and trusted current time.
    pub fn new(expected_product_id: impl Into<String>, now: OffsetDateTime) -> Self {
        Self {
            expected_product_id: expected_product_id.into(),
            now,
            app_version: None,
            build_date: None,
            machine_identity: None,
        }
    }
}

/// Immutable product-facing authorization data.
#[derive(Debug, Clone)]
pub struct AuthorizationContext {
    license_id: Uuid,
    product_id: String,
    edition: String,
    customer_id: String,
    expires_at: Option<OffsetDateTime>,
    features: HashMap<String, bool>,
    limits: HashMap<String, u64>,
    resource_scope: HashMap<String, Vec<String>>,
}

impl AuthorizationContext {
    pub(crate) fn from_payload(payload: LicensePayload) -> Self {
        Self {
            license_id: payload.license_id,
            product_id: payload.product_id,
            edition: payload.edition,
            customer_id: payload.customer_id,
            expires_at: payload.expires_at,
            features: payload.features.into_iter().collect(),
            limits: payload.limits.into_iter().collect(),
            resource_scope: payload.resource_scope.into_iter().collect(),
        }
    }

    /// Returns the validated License identifier.
    pub const fn license_id(&self) -> Uuid {
        self.license_id
    }
    /// Returns the validated product identifier.
    pub fn product_id(&self) -> &str {
        &self.product_id
    }
    /// Returns the commercial edition.
    pub fn edition(&self) -> &str {
        &self.edition
    }
    /// Returns the customer identifier.
    pub fn customer_id(&self) -> &str {
        &self.customer_id
    }
    /// Returns the optional expiration timestamp.
    pub const fn expires_at(&self) -> Option<OffsetDateTime> {
        self.expires_at
    }
    /// Returns whether a named feature is enabled.
    pub fn has_feature(&self, feature: &str) -> bool {
        self.features.get(feature).copied().unwrap_or(false)
    }
    /// Requires a feature or returns [`ErrorCode::FeatureDenied`].
    pub fn require_feature(&self, feature: &str) -> Result<(), LicenseError> {
        if self.has_feature(feature) {
            Ok(())
        } else {
            Err(LicenseError::new(
                ErrorCode::FeatureDenied,
                format!("功能 {feature} 未授权"),
            ))
        }
    }
    /// Returns a named numeric limit or `default`.
    pub fn get_limit(&self, name: &str, default: u64) -> u64 {
        self.limits.get(name).copied().unwrap_or(default)
    }
    /// Returns a named allowlist or an empty slice.
    pub fn get_resource_scope(&self, name: &str) -> &[String] {
        self.resource_scope
            .get(name)
            .map(Vec::as_slice)
            .unwrap_or(&[])
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct LicenseEnvelope {
    pub algorithm: Algorithm,
    pub key_id: String,
    pub payload: Vec<u8>,
    pub signature: Vec<u8>,
}
