//! Policy-enforced signing and non-secret issuance receipts.

use std::collections::BTreeSet;

use ed25519_dalek::SigningKey;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use time::{Duration, OffsetDateTime};
use uuid::Uuid;

use super::{ErrorCode, KeyStatus, LicenseError, LicensePayload, issue_license};

/// Thresholds that decide whether a request requires dual approval.
#[derive(Debug, Clone)]
pub struct IssuancePolicy {
    /// Longest validity treated as standard risk.
    pub maximum_standard_validity: Duration,
    /// Largest individual numeric limit treated as standard risk.
    pub maximum_standard_limit: u64,
}

impl Default for IssuancePolicy {
    fn default() -> Self {
        Self {
            maximum_standard_validity: Duration::days(366),
            maximum_standard_limit: 10_000,
        }
    }
}

/// Structured request accepted by the governed signer.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IssuanceRequest {
    /// Complete License payload to validate and sign.
    pub payload: LicensePayload,
    /// Authenticated identity requesting issuance.
    pub requested_by: String,
    /// Distinct authenticated identities approving the request.
    pub approved_by: BTreeSet<String>,
}

/// Non-secret audit receipt produced with a governed License.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct IssuanceReceipt {
    /// License identifier copied from the signed payload.
    pub license_id: Uuid,
    /// KeyId used for signing.
    pub key_id: String,
    /// Monotonic generation of the signing key.
    pub key_generation: u64,
    /// Authenticated requestor identity.
    pub requested_by: String,
    /// Submitted approval identities in deterministic order.
    pub approved_by: Vec<String>,
    /// UTC Unix timestamp recorded for signing.
    pub signed_at: i64,
    /// Lowercase hexadecimal SHA-256 of the encoded License.
    pub license_sha256: String,
    /// Whether the request crossed a high-risk threshold.
    pub high_risk: bool,
}

/// Encoded License bytes and their matching receipt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GovernedLicense {
    /// Canonical signed License file bytes.
    pub bytes: Vec<u8>,
    /// Metadata intended for external immutable audit storage.
    pub receipt: IssuanceReceipt,
}

/// Local policy-enforced Ed25519 signer for isolated signing environments.
pub struct GovernedSigner {
    key_id: String,
    generation: u64,
    status: KeyStatus,
    signing_key: SigningKey,
    policy: IssuancePolicy,
}

impl GovernedSigner {
    /// Creates a signer with explicit identity, lifecycle state and policy.
    pub fn new(
        key_id: impl Into<String>,
        generation: u64,
        status: KeyStatus,
        signing_key: SigningKey,
        policy: IssuancePolicy,
    ) -> Result<Self, LicenseError> {
        let key_id = key_id.into();
        if generation == 0 {
            return Err(invalid("受治理签发密钥 generation 必须大于零"));
        }
        if policy.maximum_standard_validity <= Duration::ZERO || policy.maximum_standard_limit == 0
        {
            return Err(invalid("签发策略阈值必须大于零"));
        }
        Ok(Self {
            key_id,
            generation,
            status,
            signing_key,
            policy,
        })
    }

    /// Enforces key state and approvals, then signs a structured request.
    ///
    /// Only [`KeyStatus::Active`] may issue. High-risk requests require two
    /// distinct approvers other than `requested_by`.
    pub fn issue(
        &self,
        request: &IssuanceRequest,
        signed_at: OffsetDateTime,
    ) -> Result<GovernedLicense, LicenseError> {
        if self.status != KeyStatus::Active {
            return Err(LicenseError::new(
                ErrorCode::KeyRevoked,
                "只有 ACTIVE 密钥可签发新 License",
            ));
        }
        validate_actor("requested_by", &request.requested_by)?;
        for approver in &request.approved_by {
            validate_actor("approved_by", approver)?;
        }
        let high_risk = self.is_high_risk(&request.payload);
        if high_risk {
            let independent_approvals = request
                .approved_by
                .iter()
                .filter(|actor| *actor != &request.requested_by)
                .count();
            if independent_approvals < 2 {
                return Err(invalid(
                    "永久、超期限或超额度 License 需要两个不同且非请求人的审批",
                ));
            }
        }
        let bytes = issue_license(&request.payload, &self.key_id, &self.signing_key)?;
        let receipt = IssuanceReceipt {
            license_id: request.payload.license_id,
            key_id: self.key_id.clone(),
            key_generation: self.generation,
            requested_by: request.requested_by.clone(),
            approved_by: request.approved_by.iter().cloned().collect(),
            signed_at: signed_at.unix_timestamp(),
            license_sha256: to_hex(&Sha256::digest(&bytes)),
            high_risk,
        };
        Ok(GovernedLicense { bytes, receipt })
    }

    fn is_high_risk(&self, payload: &LicensePayload) -> bool {
        let validity_is_high_risk = payload.expires_at.is_none_or(|expires_at| {
            expires_at - payload.issued_at > self.policy.maximum_standard_validity
        });
        validity_is_high_risk
            || payload
                .limits
                .values()
                .any(|limit| *limit > self.policy.maximum_standard_limit)
    }
}

fn validate_actor(name: &str, value: &str) -> Result<(), LicenseError> {
    if value.is_empty() || value.len() > 128 || value.chars().any(char::is_control) {
        return Err(invalid(format!("{name} 无效")));
    }
    Ok(())
}

fn to_hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    bytes.iter().fold(
        String::with_capacity(bytes.len() * 2),
        |mut output, byte| {
            write!(&mut output, "{byte:02x}").expect("writing to String cannot fail");
            output
        },
    )
}

fn invalid(detail: impl Into<String>) -> LicenseError {
    LicenseError::new(ErrorCode::FormatInvalid, detail)
}
