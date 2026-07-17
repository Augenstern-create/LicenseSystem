use std::{collections::BTreeSet, fs, process::Command};

use ed25519_dalek::SigningKey;
use license_system::{
    IssuanceRequest, KeyRing, KeyStatus, LicensePayload, TrustedKey, ValidationInput,
    validate_license,
};
use time::OffsetDateTime;
use uuid::Uuid;

#[test]
fn governed_cli_writes_a_verifiable_license_and_receipt() {
    let directory = std::path::PathBuf::from("target")
        .join("governed-cli-tests")
        .join(Uuid::new_v4().to_string());
    fs::create_dir_all(&directory).unwrap();
    let request_path = directory.join("request.json");
    let private_path = directory.join("private.key");
    let license_path = directory.join("output.lic");
    let receipt_path = directory.join("receipt.json");
    let mut payload: LicensePayload =
        serde_json::from_slice(include_bytes!("../licenses/payload.example.json")).unwrap();
    payload.license_id = Uuid::new_v4();
    payload.customer_id = "governed-cli-customer".to_owned();
    payload.expires_at = Some(payload.issued_at + time::Duration::days(30));
    payload.maintenance_until = payload.expires_at;
    let request = IssuanceRequest {
        payload: payload.clone(),
        requested_by: "cli-requester".to_owned(),
        approved_by: BTreeSet::new(),
    };
    fs::write(&request_path, serde_json::to_vec(&request).unwrap()).unwrap();
    let signing_key = SigningKey::from_bytes(&[71; 32]);
    fs::write(&private_path, signing_key.to_bytes()).unwrap();

    let result = Command::new(env!("CARGO_BIN_EXE_license_issue_governed"))
        .args([
            request_path.as_os_str(),
            private_path.as_os_str(),
            std::ffi::OsStr::new("governed-cli-key"),
            std::ffi::OsStr::new("7"),
            license_path.as_os_str(),
            receipt_path.as_os_str(),
        ])
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let receipt: serde_json::Value =
        serde_json::from_slice(&fs::read(&receipt_path).unwrap()).unwrap();
    assert_eq!(receipt["key_generation"], 7);
    assert_eq!(receipt["requested_by"], "cli-requester");
    assert!(receipt.get("private_key").is_none());

    let ring = KeyRing::from_key(TrustedKey::ed25519_with_generation(
        "governed-cli-key",
        7,
        KeyStatus::Active,
        signing_key.verifying_key(),
    ))
    .unwrap();
    let input = ValidationInput::new(
        &payload.product_id,
        OffsetDateTime::from_unix_timestamp(payload.issued_at.unix_timestamp() + 1).unwrap(),
    );
    assert!(validate_license(&fs::read(&license_path).unwrap(), &input, &ring).is_ok());
    fs::remove_dir_all(directory).unwrap();
}
