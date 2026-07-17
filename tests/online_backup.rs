use std::{collections::BTreeSet, fs, path::PathBuf};

use ed25519_dalek::SigningKey;
use license_system::online::{
    ActivationRequest, LeaseRequest, OnlineEntitlement, OnlineErrorCode, SqliteOnlineLicenseService,
};
use uuid::Uuid;

struct TestFiles {
    directory: PathBuf,
    source: PathBuf,
    backup: PathBuf,
}

impl TestFiles {
    fn new() -> Self {
        let directory = PathBuf::from("target")
            .join("online-backup-tests")
            .join(Uuid::new_v4().to_string());
        fs::create_dir_all(&directory).unwrap();
        Self {
            source: directory.join("source.sqlite"),
            backup: directory.join("backup.sqlite"),
            directory,
        }
    }
}

impl Drop for TestFiles {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.directory);
    }
}

fn open(path: &std::path::Path) -> SqliteOnlineLicenseService {
    SqliteOnlineLicenseService::open(path, "backup-test-key", SigningKey::from_bytes(&[41; 32]))
        .unwrap()
}

#[test]
fn online_backup_restores_state_and_idempotent_token() {
    let files = TestFiles::new();
    let service = open(&files.source);
    let license_id = Uuid::new_v4();
    let installation_id = Uuid::new_v4();
    service
        .register_entitlement(
            OnlineEntitlement {
                license_id,
                features: BTreeSet::from(["solver".to_owned()]),
                max_activations: 1,
                max_concurrent_leases: 1,
                revocation_epoch: 2,
            },
            "backup-test-admin",
            1_800_200_000,
        )
        .unwrap();
    service
        .activate(
            ActivationRequest {
                request_id: Uuid::new_v4(),
                license_id,
                installation_id,
            },
            1_800_200_000,
        )
        .unwrap();
    let request = LeaseRequest {
        request_id: Uuid::new_v4(),
        license_id,
        installation_id,
        features: BTreeSet::from(["solver".to_owned()]),
    };
    let original = service.issue_lease(request.clone(), 1_800_200_000).unwrap();
    service.backup_to(&files.backup).unwrap();
    SqliteOnlineLicenseService::verify_backup_identity(
        &files.backup,
        "backup-test-key",
        &service.verifying_key(),
    )
    .unwrap();
    assert!(
        SqliteOnlineLicenseService::verify_backup_identity(
            &files.backup,
            "wrong-key-id",
            &service.verifying_key(),
        )
        .is_err()
    );
    drop(service);

    let restored = open(&files.backup);
    assert_eq!(
        restored.issue_lease(request, 1_800_200_100).unwrap(),
        original
    );
    assert_eq!(restored.audit_events().unwrap().len(), 3);
}

#[test]
fn backup_refuses_overwrite_and_corruption_fails_closed() {
    let files = TestFiles::new();
    let service = open(&files.source);
    service.backup_to(&files.backup).unwrap();
    let overwrite = service.backup_to(&files.backup).unwrap_err();
    assert_eq!(overwrite.code(), OnlineErrorCode::InvalidRequest);
    drop(service);

    let mut bytes = fs::read(&files.backup).unwrap();
    bytes[0] ^= 0xff;
    fs::write(&files.backup, bytes).unwrap();
    assert!(SqliteOnlineLicenseService::verify_backup(&files.backup).is_err());
}
