use std::{fs, path::PathBuf, time::Duration};

use license_system::ErrorCode;
use license_system::time_anchor::{
    HmacStateProtector, StateProtector, TimeAnchorError, TimeAnchorStatus, TimeAnchorStore,
};
use time::OffsetDateTime;
use uuid::Uuid;

struct TestDirectory(PathBuf);

impl TestDirectory {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!("license-system-{}", Uuid::new_v4()));
        fs::create_dir_all(&path).unwrap();
        Self(path)
    }

    fn state_path(&self) -> PathBuf {
        self.0.join("anchor.state")
    }
}

impl Drop for TestDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn utc(timestamp: i64) -> OffsetDateTime {
    OffsetDateTime::from_unix_timestamp(timestamp).unwrap()
}

#[test]
fn hmac_protector_detects_tampering() {
    let protector = HmacStateProtector::new([17_u8; 32]);
    let protected = protector.protect(b"state").unwrap();
    assert_eq!(protector.unprotect(&protected).unwrap(), b"state");
    let mut tampered = protected;
    *tampered.last_mut().unwrap() ^= 1;
    assert!(matches!(
        protector.unprotect(&tampered),
        Err(TimeAnchorError::ProtectionFailed(_))
    ));
}

#[test]
fn first_observation_creates_anchor_and_forward_time_advances_it() {
    let directory = TestDirectory::new();
    let store = TimeAnchorStore::new(directory.state_path(), HmacStateProtector::new([18_u8; 32]));
    let license_id = Uuid::new_v4();
    let created = store
        .observe(license_id, utc(1_700_000_000), 1_000)
        .unwrap();
    assert_eq!(created.status, TimeAnchorStatus::Created);
    let advanced = store
        .observe(license_id, utc(1_700_000_100), 101_000)
        .unwrap();
    assert_eq!(advanced.status, TimeAnchorStatus::Advanced);
    assert_eq!(advanced.installation_id, created.installation_id);
    assert_eq!(advanced.trusted_utc, 1_700_000_100);
}

#[test]
fn small_clock_adjustment_is_tolerated_without_moving_anchor_backwards() {
    let directory = TestDirectory::new();
    let store = TimeAnchorStore::new(directory.state_path(), HmacStateProtector::new([19_u8; 32]));
    let license_id = Uuid::new_v4();
    store
        .observe(license_id, utc(1_700_010_000), 10_000)
        .unwrap();
    let adjusted = store
        .observe(license_id, utc(1_700_006_400), 11_000)
        .unwrap();
    assert_eq!(adjusted.status, TimeAnchorStatus::AdjustedWithinTolerance);
    assert_eq!(adjusted.trusted_utc, 1_700_010_000);
}

#[test]
fn large_utc_rollback_is_rejected_and_does_not_replace_anchor() {
    let directory = TestDirectory::new();
    let store = TimeAnchorStore::new(directory.state_path(), HmacStateProtector::new([20_u8; 32]));
    let license_id = Uuid::new_v4();
    store
        .observe(license_id, utc(1_700_100_000), 1_000)
        .unwrap();
    assert!(matches!(
        store.observe(license_id, utc(1_700_070_000), 2_000),
        Err(ref error) if error.code() == ErrorCode::TimeRollback
    ));
    let recovered = store
        .observe(license_id, utc(1_700_100_010), 11_000)
        .unwrap();
    assert_eq!(recovered.trusted_utc, 1_700_100_010);
}

#[test]
fn monotonic_elapsed_time_detects_a_hidden_wall_clock_rollback() {
    let directory = TestDirectory::new();
    let store = TimeAnchorStore::new(directory.state_path(), HmacStateProtector::new([21_u8; 32]))
        .with_rollback_tolerance(Duration::from_secs(60));
    let license_id = Uuid::new_v4();
    store
        .observe(license_id, utc(1_700_200_000), 1_000)
        .unwrap();
    assert!(matches!(
        store.observe(license_id, utc(1_700_200_100), 601_000),
        Err(TimeAnchorError::RollbackDetected { .. })
    ));
}

#[test]
fn tampered_state_fails_closed() {
    let directory = TestDirectory::new();
    let path = directory.state_path();
    let store = TimeAnchorStore::new(&path, HmacStateProtector::new([22_u8; 32]));
    let license_id = Uuid::new_v4();
    store
        .observe(license_id, utc(1_700_300_000), 1_000)
        .unwrap();
    let mut protected = fs::read(&path).unwrap();
    *protected.last_mut().unwrap() ^= 1;
    fs::write(&path, protected).unwrap();
    assert!(matches!(
        store.observe(license_id, utc(1_700_300_010), 11_000),
        Err(TimeAnchorError::ProtectionFailed(_))
    ));
}

#[test]
fn deleting_all_state_is_reported_as_a_new_installation() {
    let directory = TestDirectory::new();
    let path = directory.state_path();
    let store = TimeAnchorStore::new(&path, HmacStateProtector::new([23_u8; 32]));
    let license_id = Uuid::new_v4();
    let first = store
        .observe(license_id, utc(1_700_400_000), 1_000)
        .unwrap();
    fs::remove_file(&path).unwrap();
    let recreated = store
        .observe(license_id, utc(1_700_000_000), 2_000)
        .unwrap();
    assert_eq!(recreated.status, TimeAnchorStatus::Created);
    assert_ne!(recreated.installation_id, first.installation_id);
}

#[cfg(windows)]
#[test]
fn an_exclusive_transaction_lock_prevents_lost_updates() {
    use std::os::windows::fs::OpenOptionsExt;

    let directory = TestDirectory::new();
    let path = directory.state_path();
    let lock_path = path.with_file_name("anchor.state.lock");
    let _held_lock = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .share_mode(0)
        .open(lock_path)
        .unwrap();
    let store = TimeAnchorStore::new(&path, HmacStateProtector::new([24_u8; 32]));
    assert!(matches!(
        store.observe(Uuid::new_v4(), utc(1_700_500_000), 1_000),
        Err(TimeAnchorError::Busy)
    ));
}

#[cfg(windows)]
#[test]
fn dpapi_round_trip_is_bound_to_the_current_windows_user() {
    use license_system::time_anchor::DpapiStateProtector;

    let protected = DpapiStateProtector.protect(b"dpapi-state").unwrap();
    assert_ne!(protected, b"dpapi-state");
    assert_eq!(
        DpapiStateProtector.unprotect(&protected).unwrap(),
        b"dpapi-state"
    );
}
