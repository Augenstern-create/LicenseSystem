use std::collections::BTreeSet;

use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use ed25519_dalek::SigningKey;
use http_body_util::BodyExt;
use license_system::online::{
    ActivationRequest, LeaseRequest, OnlineEntitlement, OnlineLicenseService, TimeTicketRequest,
    online_router,
};
use serde_json::{Value, json};
use tower::ServiceExt;
use uuid::Uuid;

fn setup() -> (axum::Router, Uuid, Uuid) {
    let service = OnlineLicenseService::new("http-test", SigningKey::from_bytes(&[9; 32])).unwrap();
    let license_id = Uuid::new_v4();
    let installation_id = Uuid::new_v4();
    service
        .register_entitlement(
            OnlineEntitlement {
                license_id,
                features: BTreeSet::from(["solver".to_owned()]),
                max_activations: 1,
                max_concurrent_leases: 1,
                revocation_epoch: 0,
            },
            "http-test-admin",
            1_800_000_000,
        )
        .unwrap();
    (online_router(service), license_id, installation_id)
}

async fn post<T: serde::Serialize>(
    router: axum::Router,
    uri: &str,
    body: &T,
) -> axum::response::Response {
    router
        .oneshot(
            Request::post(uri)
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_vec(body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap()
}

async fn body_json(response: axum::response::Response) -> Value {
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    serde_json::from_slice(&bytes).unwrap()
}

#[tokio::test]
async fn public_http_flow_has_stable_json_contract() {
    let (router, license_id, installation_id) = setup();
    let activation = post(
        router.clone(),
        "/v1/activate",
        &ActivationRequest {
            request_id: Uuid::new_v4(),
            license_id,
            installation_id,
        },
    )
    .await;
    assert_eq!(activation.status(), StatusCode::OK);
    let activation = body_json(activation).await;
    assert_eq!(activation["license_id"], license_id.to_string());

    let lease = post(
        router.clone(),
        "/v1/lease",
        &LeaseRequest {
            request_id: Uuid::new_v4(),
            license_id,
            installation_id,
            features: BTreeSet::from(["solver".to_owned()]),
        },
    )
    .await;
    assert_eq!(lease.status(), StatusCode::OK);
    assert!(body_json(lease).await["token"].as_str().unwrap().len() > 100);

    let ticket = post(
        router,
        "/v1/time-ticket",
        &TimeTicketRequest {
            request_id: Uuid::new_v4(),
            license_id,
            installation_id,
        },
    )
    .await;
    assert_eq!(ticket.status(), StatusCode::OK);
    assert!(body_json(ticket).await["token"].is_string());
}

#[tokio::test]
async fn errors_are_json_and_admin_routes_are_not_public() {
    let (router, _, installation_id) = setup();
    let response = post(
        router.clone(),
        "/v1/activate",
        &ActivationRequest {
            request_id: Uuid::new_v4(),
            license_id: Uuid::new_v4(),
            installation_id,
        },
    )
    .await;
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    assert_eq!(body_json(response).await["code"], "UNKNOWN_LICENSE");

    let malformed = router
        .clone()
        .oneshot(
            Request::post("/v1/activate")
                .header("content-type", "application/json")
                .body(Body::from(br#"{"unknown":true}"#.to_vec()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(malformed.status(), StatusCode::BAD_REQUEST);
    assert_eq!(body_json(malformed).await["code"], "INVALID_REQUEST");

    let admin = post(router, "/v1/admin/revoke", &json!({})).await;
    assert_eq!(admin.status(), StatusCode::NOT_FOUND);
}
