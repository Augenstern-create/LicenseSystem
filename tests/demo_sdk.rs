use std::{
    collections::BTreeMap,
    sync::{Arc, Barrier, Condvar, Mutex, mpsc},
    thread,
};

use ed25519_dalek::SigningKey;
use license_system::{
    KeyRing, KeyStatus, LicensePayload, LicenseType, TrustedKey, ValidationInput,
    demo_sdk::{AlgorithmKind, DemoImageSdk, SdkError},
    issue_license, validate_license,
};
use time::OffsetDateTime;
use uuid::Uuid;

const NOW: i64 = 1_780_000_000;

fn authorized_sdk() -> DemoImageSdk {
    sdk_with_limits(2, 2)
}

fn sdk_with_limits(max_parallel_jobs: u64, max_devices: u64) -> DemoImageSdk {
    let signing_key = SigningKey::from_bytes(&[11_u8; 32]);
    let payload = LicensePayload {
        schema_version: 1,
        license_id: Uuid::parse_str("9ac1e6da-665b-4fcc-85d2-26705e2d053a").unwrap(),
        product_id: "demo-image-sdk".to_owned(),
        edition: "professional".to_owned(),
        customer_id: "DEMO-CUSTOMER".to_owned(),
        issued_at: OffsetDateTime::from_unix_timestamp(NOW - 60).unwrap(),
        not_before: None,
        expires_at: Some(OffsetDateTime::from_unix_timestamp(NOW + 3600).unwrap()),
        maintenance_until: None,
        license_type: LicenseType::Site,
        features: BTreeMap::from([
            ("batch".to_owned(), true),
            ("deepzoom".to_owned(), false),
            ("gpu".to_owned(), true),
        ]),
        limits: BTreeMap::from([
            ("max_devices".to_owned(), max_devices),
            ("max_parallel_jobs".to_owned(), max_parallel_jobs),
        ]),
        resource_scope: BTreeMap::from([
            (
                "device_ids".to_owned(),
                vec![
                    "CAM-001".to_owned(),
                    "CAM-002".to_owned(),
                    "CAM-003".to_owned(),
                ],
            ),
            (
                "model_ids".to_owned(),
                vec!["M001".to_owned(), "M008".to_owned()],
            ),
        ]),
        machine_policy: None,
        min_app_version: None,
        max_app_version: None,
        revocation_epoch: 0,
        custom: BTreeMap::new(),
    };
    let file = issue_license(&payload, "demo-key", &signing_key).unwrap();
    let keys = KeyRing::from_key(TrustedKey::ed25519(
        "demo-key",
        KeyStatus::Active,
        signing_key.verifying_key(),
    ))
    .unwrap();
    let input = ValidationInput::new(
        "demo-image-sdk",
        OffsetDateTime::from_unix_timestamp(NOW).unwrap(),
    );
    let context = validate_license(&file, &input, &keys).unwrap();
    DemoImageSdk::new(context).unwrap()
}

#[test]
fn feature_flags_control_registration_and_high_value_calls() {
    let sdk = authorized_sdk();
    assert_eq!(
        sdk.registered_algorithms(),
        vec![AlgorithmKind::Cpu, AlgorithmKind::Gpu, AlgorithmKind::Batch]
    );
    assert_eq!(
        sdk.run_algorithm(AlgorithmKind::Gpu, "M001")
            .unwrap()
            .algorithm,
        AlgorithmKind::Gpu
    );
    assert_eq!(
        sdk.run_algorithm(AlgorithmKind::DeepZoom, "M001")
            .unwrap_err(),
        SdkError::AlgorithmUnavailable {
            algorithm: "deepzoom".to_owned()
        }
    );
}

#[test]
fn model_scope_is_consumed_by_the_processing_path() {
    let sdk = authorized_sdk();
    assert!(sdk.run_algorithm(AlgorithmKind::Cpu, "M008").is_ok());
    assert_eq!(
        sdk.run_algorithm(AlgorithmKind::Cpu, "M999").unwrap_err(),
        SdkError::ResourceDenied {
            kind: "model",
            id: "M999".to_owned()
        }
    );
}

#[test]
fn parallel_limit_is_enforced_and_raii_releases_capacity() {
    let sdk = authorized_sdk();
    let first = sdk.start_job().unwrap();
    let second = sdk.start_job().unwrap();
    assert_eq!(sdk.active_jobs(), 2);
    assert_eq!(
        sdk.start_job().unwrap_err(),
        SdkError::ParallelLimitReached { limit: 2 }
    );
    drop(first);
    assert_eq!(sdk.active_jobs(), 1);
    let replacement = sdk.start_job().unwrap();
    assert_eq!(sdk.active_jobs(), 2);
    drop((second, replacement));
    assert_eq!(sdk.active_jobs(), 0);
}

#[test]
fn parallel_limit_is_atomic_under_competing_threads() {
    const WORKERS: usize = 8;
    let sdk = Arc::new(authorized_sdk());
    let start = Arc::new(Barrier::new(WORKERS + 1));
    let release = Arc::new((Mutex::new(false), Condvar::new()));
    let (sender, receiver) = mpsc::channel();
    let mut workers = Vec::new();

    for _ in 0..WORKERS {
        let sdk = Arc::clone(&sdk);
        let start = Arc::clone(&start);
        let release = Arc::clone(&release);
        let sender = sender.clone();
        workers.push(thread::spawn(move || {
            start.wait();
            match sdk.start_job() {
                Ok(permit) => {
                    sender.send(true).unwrap();
                    let (lock, condition) = &*release;
                    let mut released = lock.lock().unwrap();
                    while !*released {
                        released = condition.wait(released).unwrap();
                    }
                    drop(permit);
                }
                Err(SdkError::ParallelLimitReached { limit: 2 }) => {
                    sender.send(false).unwrap();
                }
                Err(error) => panic!("unexpected scheduler error: {error}"),
            }
        }));
    }

    start.wait();
    let successes = (0..WORKERS)
        .map(|_| receiver.recv().unwrap())
        .filter(|success| *success)
        .count();
    assert_eq!(successes, 2);
    assert_eq!(sdk.active_jobs(), 2);

    let (lock, condition) = &*release;
    *lock.lock().unwrap() = true;
    condition.notify_all();
    for worker in workers {
        worker.join().unwrap();
    }
    assert_eq!(sdk.active_jobs(), 0);
}

#[test]
fn device_scope_limit_and_idempotency_are_all_enforced() {
    let sdk = authorized_sdk();
    assert!(sdk.connect_device("CAM-001").unwrap());
    assert!(!sdk.connect_device("CAM-001").unwrap());
    assert!(sdk.connect_device("CAM-002").unwrap());
    assert_eq!(sdk.connected_devices().unwrap(), 2);
    assert_eq!(
        sdk.connect_device("CAM-003").unwrap_err(),
        SdkError::DeviceLimitReached { limit: 2 }
    );
    assert_eq!(
        sdk.connect_device("CAM-999").unwrap_err(),
        SdkError::ResourceDenied {
            kind: "device",
            id: "CAM-999".to_owned()
        }
    );
    assert!(sdk.disconnect_device("CAM-001").unwrap());
    assert!(sdk.connect_device("CAM-003").unwrap());
}

#[test]
fn missing_parallel_entitlement_fails_sdk_construction() {
    let signing_key = SigningKey::from_bytes(&[12_u8; 32]);
    let mut payload = base_payload_without_helper();
    payload.limits.insert("max_parallel_jobs".to_owned(), 0);
    let file = issue_license(&payload, "demo-key", &signing_key).unwrap();
    let keys = KeyRing::from_key(TrustedKey::ed25519(
        "demo-key",
        KeyStatus::Active,
        signing_key.verifying_key(),
    ))
    .unwrap();
    let input = ValidationInput::new(
        "demo-image-sdk",
        OffsetDateTime::from_unix_timestamp(NOW).unwrap(),
    );
    let context = validate_license(&file, &input, &keys).unwrap();
    assert_eq!(
        DemoImageSdk::new(context).unwrap_err(),
        SdkError::InvalidLimit {
            name: "max_parallel_jobs",
            value: 0
        }
    );
}

fn base_payload_without_helper() -> LicensePayload {
    LicensePayload {
        schema_version: 1,
        license_id: Uuid::new_v4(),
        product_id: "demo-image-sdk".to_owned(),
        edition: "basic".to_owned(),
        customer_id: "DEMO".to_owned(),
        issued_at: OffsetDateTime::from_unix_timestamp(NOW - 60).unwrap(),
        not_before: None,
        expires_at: Some(OffsetDateTime::from_unix_timestamp(NOW + 3600).unwrap()),
        maintenance_until: None,
        license_type: LicenseType::Site,
        features: BTreeMap::new(),
        limits: BTreeMap::from([("max_devices".to_owned(), 0)]),
        resource_scope: BTreeMap::new(),
        machine_policy: None,
        min_app_version: None,
        max_app_version: None,
        revocation_epoch: 0,
        custom: BTreeMap::new(),
    }
}
