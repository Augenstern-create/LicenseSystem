use std::collections::{BTreeMap, BTreeSet};

use ed25519_dalek::SigningKey;
use license_system::{
    ErrorCode, GovernedSigner, IssuancePolicy, IssuanceRequest, KeyRing, KeyStatus, LicensePayload,
    LicenseType, TrustedKey, ValidationInput, issue_license, validate_license,
};
use sha2::{Digest, Sha256};
use time::{Duration, OffsetDateTime};
use uuid::Uuid;

const NOW: i64 = 1_800_300_000;

fn payload() -> LicensePayload {
    LicensePayload {
        schema_version: 1,
        license_id: Uuid::new_v4(),
        product_id: "governed-product".to_owned(),
        edition: "enterprise".to_owned(),
        customer_id: "governed-customer".to_owned(),
        issued_at: OffsetDateTime::from_unix_timestamp(NOW).unwrap(),
        not_before: None,
        expires_at: Some(OffsetDateTime::from_unix_timestamp(NOW + 30 * 86_400).unwrap()),
        maintenance_until: None,
        license_type: LicenseType::Site,
        features: BTreeMap::from([("solver".to_owned(), true)]),
        limits: BTreeMap::from([("max_jobs".to_owned(), 100)]),
        resource_scope: BTreeMap::new(),
        machine_policy: None,
        min_app_version: None,
        max_app_version: None,
        revocation_epoch: 0,
        custom: BTreeMap::new(),
    }
}

#[test]
fn minimum_generation_and_key_lifecycle_fail_closed() {
    let signing_key = SigningKey::from_bytes(&[51; 32]);
    let payload = payload();
    let file = issue_license(&payload, "generation-1", &signing_key).unwrap();
    let input = ValidationInput::new(
        "governed-product",
        OffsetDateTime::from_unix_timestamp(NOW + 1).unwrap(),
    );
    let mut ring = KeyRing::with_minimum_generation(2);
    ring.insert(TrustedKey::ed25519_with_generation(
        "generation-1",
        1,
        KeyStatus::Active,
        signing_key.verifying_key(),
    ))
    .unwrap();
    assert_eq!(
        validate_license(&file, &input, &ring).unwrap_err().code(),
        ErrorCode::KeyRevoked
    );

    let file = issue_license(&payload, "generation-2", &signing_key).unwrap();
    let mut ring = KeyRing::with_minimum_generation(2);
    ring.insert(TrustedKey::ed25519_with_generation(
        "generation-2",
        2,
        KeyStatus::VerifyOnly,
        signing_key.verifying_key(),
    ))
    .unwrap();
    assert!(validate_license(&file, &input, &ring).is_ok());

    let mut retired = KeyRing::new();
    retired
        .insert(TrustedKey::ed25519_with_generation(
            "generation-2",
            2,
            KeyStatus::Retired,
            signing_key.verifying_key(),
        ))
        .unwrap();
    assert_eq!(
        validate_license(&file, &input, &retired)
            .unwrap_err()
            .code(),
        ErrorCode::KeyRevoked
    );
}

#[test]
fn governed_signer_only_issues_with_an_active_key() {
    let signer = GovernedSigner::new(
        "verify-only-2",
        2,
        KeyStatus::VerifyOnly,
        SigningKey::from_bytes(&[52; 32]),
        IssuancePolicy::default(),
    )
    .unwrap();
    let error = signer
        .issue(
            &IssuanceRequest {
                payload: payload(),
                requested_by: "requester".to_owned(),
                approved_by: BTreeSet::new(),
            },
            OffsetDateTime::from_unix_timestamp(NOW).unwrap(),
        )
        .unwrap_err();
    assert_eq!(error.code(), ErrorCode::KeyRevoked);
}

#[test]
fn high_risk_issuance_requires_two_independent_approvers() {
    let signer = GovernedSigner::new(
        "active-3",
        3,
        KeyStatus::Active,
        SigningKey::from_bytes(&[53; 32]),
        IssuancePolicy {
            maximum_standard_validity: Duration::days(366),
            maximum_standard_limit: 1_000,
        },
    )
    .unwrap();
    let mut high_risk = payload();
    high_risk.expires_at = None;
    high_risk.limits.insert("max_jobs".to_owned(), 2_000);
    let mut request = IssuanceRequest {
        payload: high_risk,
        requested_by: "requester".to_owned(),
        approved_by: BTreeSet::from(["requester".to_owned(), "approver-a".to_owned()]),
    };
    assert_eq!(
        signer
            .issue(&request, OffsetDateTime::from_unix_timestamp(NOW).unwrap())
            .unwrap_err()
            .code(),
        ErrorCode::FormatInvalid
    );

    request.approved_by.insert("approver-b".to_owned());
    let issued = signer
        .issue(&request, OffsetDateTime::from_unix_timestamp(NOW).unwrap())
        .unwrap();
    assert!(issued.receipt.high_risk);
    assert_eq!(issued.receipt.key_generation, 3);
    assert_eq!(issued.receipt.requested_by, "requester");
    assert_eq!(issued.receipt.approved_by.len(), 3);
    assert_eq!(
        issued.receipt.license_sha256,
        to_hex(&Sha256::digest(&issued.bytes))
    );
    let receipt_json = serde_json::to_string(&issued.receipt).unwrap();
    assert!(!receipt_json.contains("governed-customer"));
}

#[test]
fn standard_issuance_does_not_require_dual_approval() {
    let signer = GovernedSigner::new(
        "active-4",
        4,
        KeyStatus::Active,
        SigningKey::from_bytes(&[54; 32]),
        IssuancePolicy::default(),
    )
    .unwrap();
    let issued = signer
        .issue(
            &IssuanceRequest {
                payload: payload(),
                requested_by: "requester".to_owned(),
                approved_by: BTreeSet::new(),
            },
            OffsetDateTime::from_unix_timestamp(NOW).unwrap(),
        )
        .unwrap();
    assert!(!issued.receipt.high_risk);
}

fn to_hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    bytes.iter().fold(String::new(), |mut output, byte| {
        write!(&mut output, "{byte:02x}").unwrap();
        output
    })
}
