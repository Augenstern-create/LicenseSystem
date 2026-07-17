use std::collections::BTreeMap;

use ed25519_dalek::SigningKey;
use license_system::{
    ErrorCode, KeyRing, KeyStatus, LicensePayload, LicenseType, MachinePolicy, MachineSignalKind,
    TrustedKey, ValidationInput, issue_license,
    machine::{MachineSignal, derive_machine_identity},
    validate_license,
};
use sha2::{Digest, Sha256};
use time::OffsetDateTime;
use uuid::Uuid;

const ISSUED_AT: i64 = 1_768_435_200;
const EXPIRES_AT: i64 = 1_800_000_000;

fn fixture() -> (LicensePayload, SigningKey, KeyRing, ValidationInput) {
    let signing_key = SigningKey::from_bytes(&[7_u8; 32]);
    let key_ring = KeyRing::from_key(TrustedKey::ed25519(
        "prod-2026-01",
        KeyStatus::Active,
        signing_key.verifying_key(),
    ))
    .unwrap();
    let payload = LicensePayload {
        schema_version: 1,
        license_id: Uuid::parse_str("2fd44c80-52ca-4b0a-9636-fd88b7d3cc0e").unwrap(),
        product_id: "image-sdk".to_owned(),
        edition: "enterprise".to_owned(),
        customer_id: "CUST-10086".to_owned(),
        issued_at: OffsetDateTime::from_unix_timestamp(ISSUED_AT).unwrap(),
        not_before: None,
        expires_at: Some(OffsetDateTime::from_unix_timestamp(EXPIRES_AT).unwrap()),
        maintenance_until: None,
        license_type: LicenseType::Site,
        features: BTreeMap::from([("gpu".to_owned(), true)]),
        limits: BTreeMap::from([("max_parallel_jobs".to_owned(), 8)]),
        resource_scope: BTreeMap::from([(
            "model_ids".to_owned(),
            vec!["M001".to_owned(), "M008".to_owned()],
        )]),
        machine_policy: None,
        min_app_version: None,
        max_app_version: None,
        revocation_epoch: 3,
        custom: BTreeMap::new(),
    };
    let input = ValidationInput::new(
        "image-sdk",
        OffsetDateTime::from_unix_timestamp(ISSUED_AT + 3600).unwrap(),
    );
    (payload, signing_key, key_ring, input)
}

#[test]
fn valid_license_builds_immutable_authorization_context() {
    let (payload, signing_key, keys, input) = fixture();
    let file = issue_license(&payload, "prod-2026-01", &signing_key).unwrap();
    let context = validate_license(&file, &input, &keys).unwrap();
    assert_eq!(context.license_id(), payload.license_id);
    assert!(context.has_feature("gpu"));
    assert!(!context.has_feature("unknown"));
    assert!(context.require_feature("gpu").is_ok());
    assert_eq!(
        context.require_feature("unknown").unwrap_err().code(),
        ErrorCode::FeatureDenied
    );
    assert_eq!(context.get_limit("max_parallel_jobs", 0), 8);
    assert_eq!(context.get_resource_scope("model_ids"), ["M001", "M008"]);
}

#[test]
fn issuing_the_same_payload_is_deterministic() {
    let (payload, signing_key, _, _) = fixture();
    let first = issue_license(&payload, "prod-2026-01", &signing_key).unwrap();
    let second = issue_license(&payload, "prod-2026-01", &signing_key).unwrap();
    assert_eq!(first, second);
}

#[test]
fn a_single_byte_signature_tamper_is_rejected() {
    let (payload, signing_key, keys, input) = fixture();
    let mut file = issue_license(&payload, "prod-2026-01", &signing_key).unwrap();
    *file.last_mut().unwrap() ^= 1;
    let error = validate_license(&file, &input, &keys).unwrap_err();
    assert_eq!(error.code(), ErrorCode::SignatureInvalid);
}

#[test]
fn an_untrusted_key_id_is_rejected() {
    let (payload, signing_key, keys, input) = fixture();
    let file = issue_license(&payload, "other-key", &signing_key).unwrap();
    let error = validate_license(&file, &input, &keys).unwrap_err();
    assert_eq!(error.code(), ErrorCode::KeyRevoked);
}

#[test]
fn a_revoked_key_is_rejected() {
    let (payload, signing_key, _, input) = fixture();
    let keys = KeyRing::from_key(TrustedKey::ed25519(
        "prod-2026-01",
        KeyStatus::Revoked,
        signing_key.verifying_key(),
    ))
    .unwrap();
    let file = issue_license(&payload, "prod-2026-01", &signing_key).unwrap();
    let error = validate_license(&file, &input, &keys).unwrap_err();
    assert_eq!(error.code(), ErrorCode::KeyRevoked);
}

#[test]
fn an_expired_license_is_rejected() {
    let (payload, signing_key, keys, mut input) = fixture();
    input.now = OffsetDateTime::from_unix_timestamp(EXPIRES_AT + 1).unwrap();
    let file = issue_license(&payload, "prod-2026-01", &signing_key).unwrap();
    let error = validate_license(&file, &input, &keys).unwrap_err();
    assert_eq!(error.code(), ErrorCode::Expired);
}

#[test]
fn a_product_mismatch_is_rejected() {
    let (payload, signing_key, keys, mut input) = fixture();
    input.expected_product_id = "another-product".to_owned();
    let file = issue_license(&payload, "prod-2026-01", &signing_key).unwrap();
    let error = validate_license(&file, &input, &keys).unwrap_err();
    assert_eq!(error.code(), ErrorCode::ProductMismatch);
}

#[test]
fn machine_policy_requires_threshold_and_high_confidence_match() {
    let (mut payload, signing_key, keys, mut input) = fixture();
    let full_identity = derive_machine_identity(
        "image-sdk",
        [
            MachineSignal::new(MachineSignalKind::SmbiosUuid, "HOST-A"),
            MachineSignal::new(MachineSignalKind::SystemVolumeSerial, "DISK-A"),
            MachineSignal::new(MachineSignalKind::CpuId, "CPU-A"),
            MachineSignal::new(MachineSignalKind::MachineGuid, "GUID-A"),
        ],
    )
    .unwrap();
    payload.license_type = LicenseType::NodeLocked;
    payload.machine_policy = Some(MachinePolicy {
        fingerprints: full_identity
            .components()
            .iter()
            .map(|component| component.fingerprint().to_owned())
            .collect(),
        threshold: 70,
    });
    let file = issue_license(&payload, "prod-2026-01", &signing_key).unwrap();
    assert_eq!(
        validate_license(&file, &input, &keys).unwrap_err().code(),
        ErrorCode::MachineMismatch
    );

    input.machine_identity = Some(
        derive_machine_identity(
            "image-sdk",
            [
                MachineSignal::new(MachineSignalKind::SystemVolumeSerial, "DISK-A"),
                MachineSignal::new(MachineSignalKind::CpuId, "CPU-A"),
                MachineSignal::new(MachineSignalKind::MachineGuid, "GUID-A"),
            ],
        )
        .unwrap(),
    );
    let error = validate_license(&file, &input, &keys).unwrap_err();
    assert_eq!(error.code(), ErrorCode::MachineMismatch);

    input.machine_identity = Some(full_identity);
    assert!(validate_license(&file, &input, &keys).is_ok());
}

#[test]
fn oversized_and_trailing_data_are_rejected() {
    let (_, _, keys, input) = fixture();
    let oversized = vec![0_u8; license_system::license::MAX_LICENSE_SIZE + 1];
    assert_eq!(
        validate_license(&oversized, &input, &keys)
            .unwrap_err()
            .code(),
        ErrorCode::FormatInvalid
    );

    let (payload, signing_key, keys, input) = fixture();
    let mut file = issue_license(&payload, "prod-2026-01", &signing_key).unwrap();
    file.push(0);
    assert_eq!(
        validate_license(&file, &input, &keys).unwrap_err().code(),
        ErrorCode::FormatInvalid
    );
}

#[test]
fn unknown_algorithm_is_rejected_before_verification() {
    let (payload, signing_key, keys, input) = fixture();
    let mut file = issue_license(&payload, "prod-2026-01", &signing_key).unwrap();
    let position = file
        .windows(7)
        .position(|window| window == b"Ed25519")
        .unwrap();
    file[position..position + 7].copy_from_slice(b"BadAlgo");
    let error = validate_license(&file, &input, &keys).unwrap_err();
    assert_eq!(error.code(), ErrorCode::FormatInvalid);
}

#[test]
fn validity_and_version_boundaries_fail_closed() {
    let (mut payload, signing_key, keys, mut input) = fixture();
    payload.not_before = Some(OffsetDateTime::from_unix_timestamp(ISSUED_AT + 7200).unwrap());
    let file = issue_license(&payload, "prod-2026-01", &signing_key).unwrap();
    assert_eq!(
        validate_license(&file, &input, &keys).unwrap_err().code(),
        ErrorCode::NotYetValid
    );

    payload.not_before = None;
    payload.min_app_version = Some("2.0.0".to_owned());
    input.app_version = Some(semver::Version::new(1, 9, 9));
    let file = issue_license(&payload, "prod-2026-01", &signing_key).unwrap();
    assert_eq!(
        validate_license(&file, &input, &keys).unwrap_err().code(),
        ErrorCode::VersionNotAllowed
    );

    payload.min_app_version = None;
    payload.max_app_version = Some("2.0.0".to_owned());
    input.app_version = Some(semver::Version::new(2, 0, 1));
    let file = issue_license(&payload, "prod-2026-01", &signing_key).unwrap();
    assert_eq!(
        validate_license(&file, &input, &keys).unwrap_err().code(),
        ErrorCode::VersionNotAllowed
    );

    payload.max_app_version = None;
    payload.maintenance_until = Some(OffsetDateTime::from_unix_timestamp(ISSUED_AT).unwrap());
    input.app_version = None;
    input.build_date = Some(OffsetDateTime::from_unix_timestamp(ISSUED_AT + 1).unwrap());
    let file = issue_license(&payload, "prod-2026-01", &signing_key).unwrap();
    assert_eq!(
        validate_license(&file, &input, &keys).unwrap_err().code(),
        ErrorCode::VersionNotAllowed
    );
}

#[test]
fn node_locked_and_field_shape_rules_are_enforced_before_signing() {
    let (mut payload, signing_key, _, _) = fixture();
    payload.license_type = LicenseType::NodeLocked;
    assert_eq!(
        issue_license(&payload, "prod-2026-01", &signing_key)
            .unwrap_err()
            .code(),
        ErrorCode::FormatInvalid
    );

    payload.license_type = LicenseType::Site;
    payload.product_id = "x".repeat(257);
    assert_eq!(
        issue_license(&payload, "prod-2026-01", &signing_key)
            .unwrap_err()
            .code(),
        ErrorCode::FormatInvalid
    );
}

#[test]
fn issuer_rejects_a_model_that_encodes_beyond_the_file_limit() {
    let (mut payload, signing_key, _, _) = fixture();
    payload.resource_scope.insert(
        "large".to_owned(),
        (0..1024).map(|index| format!("{index:0256}")).collect(),
    );
    assert_eq!(
        issue_license(&payload, "prod-2026-01", &signing_key)
            .unwrap_err()
            .code(),
        ErrorCode::FormatInvalid
    );
}

#[test]
fn duplicate_key_id_does_not_replace_the_original_trust_anchor() {
    let (payload, signing_key, _, input) = fixture();
    let mut keys = KeyRing::from_key(TrustedKey::ed25519(
        "prod-2026-01",
        KeyStatus::Active,
        signing_key.verifying_key(),
    ))
    .unwrap();
    let attacker_key = SigningKey::from_bytes(&[9_u8; 32]);
    assert_eq!(
        keys.insert(TrustedKey::ed25519(
            "prod-2026-01",
            KeyStatus::Active,
            attacker_key.verifying_key(),
        ))
        .unwrap_err()
        .code(),
        ErrorCode::FormatInvalid
    );

    let file = issue_license(&payload, "prod-2026-01", &signing_key).unwrap();
    assert!(validate_license(&file, &input, &keys).is_ok());
}

#[test]
fn fixed_v1_vector_is_available_for_other_languages() {
    let (payload, signing_key, _, _) = fixture();
    let file = issue_license(&payload, "prod-2026-01", &signing_key).unwrap();
    assert_eq!(
        to_hex(&signing_key.verifying_key().to_bytes()),
        "ea4a6c63e29c520abef5507b132ec5f9954776aebebe7b92421eea691446d22c"
    );
    assert_eq!(
        to_hex(&file),
        concat!(
            "a60064414c49430101026745643235353139036c70726f642d323032362d3031",
            "045887b2000101502fd44c8052ca4b0a9636fd88b7d3cc0e0269696d616765",
            "2d73646b036a656e7465727072697365046a435553542d3130303836051a6968",
            "2e0006f6071a6b49d20008f609040aa163677075f50ba1716d61785f70617261",
            "6c6c656c5f6a6f6273080ca1696d6f64656c5f69647382644d303031644d30",
            "30380df60ef60ff6100311a0055840203a0ec4266378d7236f48e410af5de22",
            "d3d2831df0e26b86ad5eda273cee9182e26bbc3241e6f28b188347d07a1462",
            "2e04ba269e816ff210e9c985a2a567401"
        )
    );
    assert_eq!(
        to_hex(&Sha256::digest(&file)),
        "fe1a8b232d17bbe969d7f1fc80312f3a7da73a8bc766b6d290d655db9c7b836f"
    );
}

fn to_hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    bytes.iter().fold(
        String::with_capacity(bytes.len() * 2),
        |mut output, byte| {
            write!(&mut output, "{byte:02x}").unwrap();
            output
        },
    )
}
