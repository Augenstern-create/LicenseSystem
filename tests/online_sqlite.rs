use std::{
    collections::BTreeSet,
    fs,
    path::{Path, PathBuf},
    sync::Arc,
    thread,
};

use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use ed25519_dalek::SigningKey;
use license_system::online::{
    ActivationRequest, LeaseRequest, OnlineEntitlement, OnlineErrorCode,
    SqliteOnlineLicenseService, TimeTicketRequest, online_router,
};
use rusqlite::Connection;
use tower::ServiceExt;
use uuid::Uuid;

const NOW: i64 = 1_800_100_000;
const KEY_ID: &str = "sqlite-test-2026";

struct TestDatabase {
    path: PathBuf,
}

impl TestDatabase {
    fn new(name: &str) -> Self {
        let directory = Path::new("target").join("online-sqlite-tests");
        fs::create_dir_all(&directory).expect("test directory can be created");
        Self {
            path: directory.join(format!("{name}-{}.sqlite", Uuid::new_v4())),
        }
    }
}

impl Drop for TestDatabase {
    fn drop(&mut self) {
        for suffix in ["", "-wal", "-shm"] {
            let _ = fs::remove_file(format!("{}{}", self.path.display(), suffix));
        }
    }
}

fn open(path: &Path) -> SqliteOnlineLicenseService {
    SqliteOnlineLicenseService::open(path, KEY_ID, SigningKey::from_bytes(&[23; 32]))
        .expect("SQLite service opens")
}

fn features() -> BTreeSet<String> {
    BTreeSet::from(["export".to_owned(), "solver".to_owned()])
}

fn register(
    service: &SqliteOnlineLicenseService,
    license_id: Uuid,
    max_activations: u32,
    max_leases: u32,
) {
    service
        .register_entitlement(
            OnlineEntitlement {
                license_id,
                features: features(),
                max_activations,
                max_concurrent_leases: max_leases,
                revocation_epoch: 5,
            },
            "sqlite-test-admin",
            NOW,
        )
        .expect("entitlement is registered");
}

fn activate(
    service: &SqliteOnlineLicenseService,
    license_id: Uuid,
    installation_id: Uuid,
) -> ActivationRequest {
    let request = ActivationRequest {
        request_id: Uuid::new_v4(),
        license_id,
        installation_id,
    };
    service
        .activate(request.clone(), NOW)
        .expect("activation succeeds");
    request
}

#[test]
fn restart_preserves_state_idempotency_tokens_revocation_and_audit() {
    let database = TestDatabase::new("restart");
    let license_id = Uuid::new_v4();
    let installation_id = Uuid::new_v4();
    let activation_request;
    let activation_response;
    let lease_request = LeaseRequest {
        request_id: Uuid::new_v4(),
        license_id,
        installation_id,
        features: BTreeSet::from(["solver".to_owned()]),
    };
    let time_request = TimeTicketRequest {
        request_id: Uuid::new_v4(),
        license_id,
        installation_id,
    };
    let lease;
    let ticket;
    {
        let service = open(&database.path);
        register(&service, license_id, 1, 1);
        activation_request = ActivationRequest {
            request_id: Uuid::new_v4(),
            license_id,
            installation_id,
        };
        activation_response = service
            .activate(activation_request.clone(), NOW)
            .expect("activation succeeds");
        lease = service.issue_lease(lease_request.clone(), NOW).unwrap();
        ticket = service
            .issue_time_ticket(time_request.clone(), NOW)
            .unwrap();
        assert_eq!(service.audit_events().unwrap().len(), 3);
    }

    let service = open(&database.path);
    assert_eq!(
        service.activate(activation_request, NOW + 10).unwrap(),
        activation_response
    );
    assert_eq!(service.issue_lease(lease_request, NOW + 10).unwrap(), lease);
    assert_eq!(
        service.issue_time_ticket(time_request, NOW + 10).unwrap(),
        ticket
    );
    assert_eq!(service.audit_events().unwrap().len(), 3);
    assert_eq!(
        service
            .revoke_license(license_id, "sqlite-test-admin", "test revoke", NOW + 20)
            .unwrap(),
        6
    );
    drop(service);

    let service = open(&database.path);
    let error = service
        .issue_time_ticket(
            TimeTicketRequest {
                request_id: Uuid::new_v4(),
                license_id,
                installation_id,
            },
            NOW + 21,
        )
        .unwrap_err();
    assert_eq!(error.code(), OnlineErrorCode::LicenseRevoked);
    assert_eq!(service.audit_events().unwrap().len(), 4);
}

#[test]
fn independent_connections_do_not_over_allocate_leases() {
    let database = TestDatabase::new("concurrency");
    let first = open(&database.path);
    let second = open(&database.path);
    let license_id = Uuid::new_v4();
    register(&first, license_id, 16, 2);
    let installations: Vec<_> = (0..16).map(|_| Uuid::new_v4()).collect();
    for installation_id in &installations {
        activate(&first, license_id, *installation_id);
    }
    let first = Arc::new(first);
    let second = Arc::new(second);
    let handles: Vec<_> = installations
        .into_iter()
        .enumerate()
        .map(|(index, installation_id)| {
            let service = if index % 2 == 0 {
                Arc::clone(&first)
            } else {
                Arc::clone(&second)
            };
            thread::spawn(move || {
                service.issue_lease(
                    LeaseRequest {
                        request_id: Uuid::new_v4(),
                        license_id,
                        installation_id,
                        features: BTreeSet::from(["solver".to_owned()]),
                    },
                    NOW,
                )
            })
        })
        .collect();
    let results: Vec<_> = handles
        .into_iter()
        .map(|handle| handle.join().expect("worker does not panic"))
        .collect();
    assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 2);
    assert!(
        results
            .iter()
            .filter_map(|result| result.as_ref().err())
            .all(|error| error.code() == OnlineErrorCode::LeaseLimit)
    );
}

#[test]
fn expired_lease_is_reclaimed_after_restart() {
    let database = TestDatabase::new("expiry");
    let license_id = Uuid::new_v4();
    let first_installation = Uuid::new_v4();
    let second_installation = Uuid::new_v4();
    {
        let service = open(&database.path);
        register(&service, license_id, 2, 1);
        activate(&service, license_id, first_installation);
        activate(&service, license_id, second_installation);
        service
            .issue_lease(
                LeaseRequest {
                    request_id: Uuid::new_v4(),
                    license_id,
                    installation_id: first_installation,
                    features: BTreeSet::from(["solver".to_owned()]),
                },
                NOW,
            )
            .unwrap();
    }
    let service = open(&database.path);
    assert!(
        service
            .issue_lease(
                LeaseRequest {
                    request_id: Uuid::new_v4(),
                    license_id,
                    installation_id: second_installation,
                    features: BTreeSet::from(["solver".to_owned()]),
                },
                NOW + 301,
            )
            .is_ok()
    );
}

#[test]
fn newer_schema_and_epoch_outside_sqlite_range_are_rejected() {
    let database = TestDatabase::new("schema-version");
    let connection = Connection::open(&database.path).unwrap();
    connection.pragma_update(None, "user_version", 999).unwrap();
    drop(connection);
    let error = match SqliteOnlineLicenseService::open(
        &database.path,
        KEY_ID,
        SigningKey::from_bytes(&[23; 32]),
    ) {
        Ok(_) => panic!("newer schema must be rejected"),
        Err(error) => error,
    };
    assert_eq!(error.code(), OnlineErrorCode::Internal);

    let database = TestDatabase::new("epoch-range");
    let service = open(&database.path);
    let error = service
        .register_entitlement(
            OnlineEntitlement {
                license_id: Uuid::new_v4(),
                features: features(),
                max_activations: 1,
                max_concurrent_leases: 1,
                revocation_epoch: i64::MAX as u64 + 1,
            },
            "sqlite-test-admin",
            NOW,
        )
        .unwrap_err();
    assert_eq!(error.code(), OnlineErrorCode::InvalidRequest);
}

#[test]
fn restart_rejects_a_different_signing_identity() {
    let database = TestDatabase::new("signing-identity");
    drop(open(&database.path));
    let wrong_key = match SqliteOnlineLicenseService::open(
        &database.path,
        KEY_ID,
        SigningKey::from_bytes(&[24; 32]),
    ) {
        Ok(_) => panic!("different signing key must be rejected"),
        Err(error) => error,
    };
    assert_eq!(wrong_key.code(), OnlineErrorCode::Internal);
    let wrong_key_id = match SqliteOnlineLicenseService::open(
        &database.path,
        "another-key-id",
        SigningKey::from_bytes(&[23; 32]),
    ) {
        Ok(_) => panic!("different key id must be rejected"),
        Err(error) => error,
    };
    assert_eq!(wrong_key_id.code(), OnlineErrorCode::Internal);
}

#[test]
fn database_constraints_reject_orphan_and_duplicate_leases() {
    let database = TestDatabase::new("constraints");
    let license_id = Uuid::new_v4();
    let installation_id = Uuid::new_v4();
    {
        let service = open(&database.path);
        register(&service, license_id, 1, 1);
        activate(&service, license_id, installation_id);
    }
    let connection = Connection::open(&database.path).unwrap();
    connection
        .pragma_update(None, "foreign_keys", "ON")
        .unwrap();
    let orphan = connection.execute(
        "INSERT INTO leases (lease_id, license_id, installation_id, expires_at)
         VALUES (?1, ?2, ?3, ?4)",
        rusqlite::params![
            Uuid::new_v4().to_string(),
            license_id.to_string(),
            Uuid::new_v4().to_string(),
            NOW + 300,
        ],
    );
    assert!(orphan.is_err());

    connection
        .execute(
            "INSERT INTO leases (lease_id, license_id, installation_id, expires_at)
             VALUES (?1, ?2, ?3, ?4)",
            rusqlite::params![
                Uuid::new_v4().to_string(),
                license_id.to_string(),
                installation_id.to_string(),
                NOW + 300,
            ],
        )
        .unwrap();
    let duplicate = connection.execute(
        "INSERT INTO leases (lease_id, license_id, installation_id, expires_at)
         VALUES (?1, ?2, ?3, ?4)",
        rusqlite::params![
            Uuid::new_v4().to_string(),
            license_id.to_string(),
            installation_id.to_string(),
            NOW + 301,
        ],
    );
    assert!(duplicate.is_err());
}

#[tokio::test]
async fn sqlite_backend_uses_the_same_http_router_contract() {
    let database = TestDatabase::new("http");
    let service = open(&database.path);
    let license_id = Uuid::new_v4();
    let installation_id = Uuid::new_v4();
    register(&service, license_id, 1, 1);
    let body = serde_json::to_vec(&ActivationRequest {
        request_id: Uuid::new_v4(),
        license_id,
        installation_id,
    })
    .unwrap();
    let response = online_router(service)
        .oneshot(
            Request::post("/v1/activate")
                .header("content-type", "application/json")
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
}
