use std::{fs, path::PathBuf, time::Duration};

use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use ed25519_dalek::SigningKey;
use http_body_util::BodyExt;
use license_system::online::{
    AdminAuthenticator, OnlineLicenseService, OperationalMetrics, RequestGuard,
    SqliteOnlineLicenseService, admin_router, hardened_online_router, online_router,
};
use serde_json::{Value, json};
use tower::ServiceExt;
use uuid::Uuid;

const ADMIN_TOKEN: &str = "correct-admin-token-with-at-least-32-bytes";

struct TestPaths {
    directory: PathBuf,
    database: PathBuf,
}

impl TestPaths {
    fn new() -> Self {
        let directory = PathBuf::from("target")
            .join("online-admin-tests")
            .join(Uuid::new_v4().to_string());
        fs::create_dir_all(&directory).unwrap();
        let database = directory.join("service.sqlite");
        Self {
            directory,
            database,
        }
    }
}

impl Drop for TestPaths {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.directory);
    }
}

fn service(path: &TestPaths) -> SqliteOnlineLicenseService {
    SqliteOnlineLicenseService::open(
        &path.database,
        "admin-test-key",
        SigningKey::from_bytes(&[31; 32]),
    )
    .unwrap()
}

fn guard(maximum: u64, metrics: OperationalMetrics) -> RequestGuard {
    RequestGuard::new(maximum, Duration::from_secs(60), metrics).unwrap()
}

async fn request(
    router: axum::Router,
    method: &str,
    uri: &str,
    token: Option<&str>,
    body: Vec<u8>,
) -> axum::response::Response {
    let mut builder = Request::builder()
        .method(method)
        .uri(uri)
        .header("content-type", "application/json");
    if let Some(token) = token {
        builder = builder.header("authorization", format!("Bearer {token}"));
    }
    router
        .oneshot(builder.body(Body::from(body)).unwrap())
        .await
        .unwrap()
}

async fn json_body(response: axum::response::Response) -> Value {
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    serde_json::from_slice(&bytes).unwrap()
}

#[tokio::test]
async fn admin_routes_require_authentication_and_actor_comes_from_credential() {
    let paths = TestPaths::new();
    let service = service(&paths);
    let metrics = OperationalMetrics::default();
    let router = admin_router(
        service.clone(),
        AdminAuthenticator::new("ops-admin-01", ADMIN_TOKEN.as_bytes()).unwrap(),
        metrics.clone(),
        &paths.directory,
        guard(100, metrics),
    )
    .unwrap();
    let license_id = Uuid::new_v4();
    let body = serde_json::to_vec(&json!({
        "license_id": license_id,
        "features": ["solver"],
        "max_activations": 1,
        "max_concurrent_leases": 1,
        "revocation_epoch": 0
    }))
    .unwrap();

    let missing = request(
        router.clone(),
        "POST",
        "/admin/v1/entitlements",
        None,
        body.clone(),
    )
    .await;
    assert_eq!(missing.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(json_body(missing).await["code"], "UNAUTHORIZED");
    let wrong = request(
        router.clone(),
        "POST",
        "/admin/v1/entitlements",
        Some("wrong-admin-token-that-is-also-long-enough"),
        body.clone(),
    )
    .await;
    assert_eq!(wrong.status(), StatusCode::UNAUTHORIZED);

    let created = request(
        router.clone(),
        "POST",
        "/admin/v1/entitlements",
        Some(ADMIN_TOKEN),
        body,
    )
    .await;
    assert_eq!(created.status(), StatusCode::CREATED);
    let audit = request(
        router,
        "GET",
        "/admin/v1/audit",
        Some(ADMIN_TOKEN),
        Vec::new(),
    )
    .await;
    assert_eq!(audit.status(), StatusCode::OK);
    let audit_text = String::from_utf8(
        audit
            .into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes()
            .to_vec(),
    )
    .unwrap();
    assert!(audit_text.contains("ops-admin-01"));
    assert!(!audit_text.contains(ADMIN_TOKEN));
}

#[tokio::test]
async fn public_router_has_no_admin_routes_and_guard_reports_rate_limit() {
    let service =
        OnlineLicenseService::new("guard-test", SigningKey::from_bytes(&[32; 32])).unwrap();
    let public = online_router(service.clone());
    let hidden = request(public, "GET", "/admin/v1/audit", None, Vec::new()).await;
    assert_eq!(hidden.status(), StatusCode::NOT_FOUND);

    let metrics = OperationalMetrics::default();
    let guarded = hardened_online_router(service, guard(1, metrics.clone()));
    let body = serde_json::to_vec(&json!({
        "request_id": Uuid::new_v4(),
        "license_id": Uuid::new_v4(),
        "installation_id": Uuid::new_v4()
    }))
    .unwrap();
    let first = request(guarded.clone(), "POST", "/v1/activate", None, body.clone()).await;
    assert_eq!(first.status(), StatusCode::NOT_FOUND);
    let limited = request(guarded, "POST", "/v1/activate", None, body).await;
    assert_eq!(limited.status(), StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(json_body(limited).await["code"], "RATE_LIMITED");
    let snapshot = metrics.snapshot();
    assert_eq!(snapshot.requests_total, 2);
    assert_eq!(snapshot.responses_4xx, 2);
    assert_eq!(snapshot.rate_limited, 1);
    assert_eq!(snapshot.requests_in_flight, 0);
}

#[tokio::test]
async fn oversized_json_is_rejected_with_stable_code() {
    let service =
        OnlineLicenseService::new("body-test", SigningKey::from_bytes(&[33; 32])).unwrap();
    let body = format!(r#"{{"padding":"{}"}}"#, "x".repeat(70 * 1024)).into_bytes();
    let response = request(online_router(service), "POST", "/v1/activate", None, body).await;
    assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
    assert_eq!(json_body(response).await["code"], "PAYLOAD_TOO_LARGE");
}

#[tokio::test]
async fn authenticated_backup_uses_server_generated_path() {
    let paths = TestPaths::new();
    let service = service(&paths);
    let metrics = OperationalMetrics::default();
    let router = admin_router(
        service,
        AdminAuthenticator::new("backup-admin", ADMIN_TOKEN.as_bytes()).unwrap(),
        metrics.clone(),
        &paths.directory,
        guard(10, metrics),
    )
    .unwrap();
    let response = request(
        router,
        "POST",
        "/admin/v1/backup",
        Some(ADMIN_TOKEN),
        Vec::new(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let body = json_body(response).await;
    let file_name = body["file_name"].as_str().unwrap();
    assert!(!file_name.contains('/') && !file_name.contains('\\'));
    let backup = paths.directory.join(file_name);
    assert!(backup.is_file());
    SqliteOnlineLicenseService::verify_backup(backup).unwrap();
}
