use std::{collections::BTreeSet, sync::Arc, thread};

use base64::{Engine, engine::general_purpose::STANDARD as BASE64};
use ed25519_dalek::SigningKey;
use license_system::online::{
    ActivationRequest, AuditAction, LeaseRequest, OnlineEntitlement, OnlineErrorCode,
    OnlineLicenseService, OnlineTokenVerifier, TimeTicketRequest,
};
use uuid::Uuid;

const NOW: i64 = 1_800_000_000;

fn features(values: &[&str]) -> BTreeSet<String> {
    values.iter().map(|value| (*value).to_owned()).collect()
}

fn service(max_activations: u32, max_leases: u32) -> (OnlineLicenseService, Uuid) {
    let service = OnlineLicenseService::new("online-test-2026", SigningKey::from_bytes(&[7; 32]))
        .expect("test key id is valid");
    let license_id = Uuid::new_v4();
    service
        .register_entitlement(
            OnlineEntitlement {
                license_id,
                features: features(&["export", "solver"]),
                max_activations,
                max_concurrent_leases: max_leases,
                revocation_epoch: 3,
            },
            "test-admin",
            NOW,
        )
        .expect("entitlement registration succeeds");
    (service, license_id)
}

fn activate(service: &OnlineLicenseService, license_id: Uuid, installation_id: Uuid) {
    service
        .activate(
            ActivationRequest {
                request_id: Uuid::new_v4(),
                license_id,
                installation_id,
            },
            NOW,
        )
        .expect("activation succeeds");
}

#[test]
fn activation_is_idempotent_and_enforces_quota() {
    let (service, license_id) = service(1, 1);
    let installation_id = Uuid::new_v4();
    let request = ActivationRequest {
        request_id: Uuid::new_v4(),
        license_id,
        installation_id,
    };
    let first = service.activate(request.clone(), NOW).unwrap();
    let repeated = service.activate(request, NOW + 1).unwrap();
    assert_eq!(first, repeated);

    let reused = service
        .activate(
            ActivationRequest {
                request_id: Uuid::new_v4(),
                license_id,
                installation_id,
            },
            NOW + 2,
        )
        .unwrap();
    assert_eq!(first.activation_id, reused.activation_id);

    let error = service
        .activate(
            ActivationRequest {
                request_id: Uuid::new_v4(),
                license_id,
                installation_id: Uuid::new_v4(),
            },
            NOW + 3,
        )
        .unwrap_err();
    assert_eq!(error.code(), OnlineErrorCode::ActivationLimit);
}

#[test]
fn request_id_cannot_be_reused_for_different_content() {
    let (service, license_id) = service(2, 1);
    let request_id = Uuid::new_v4();
    activate(&service, license_id, Uuid::new_v4());
    let first = ActivationRequest {
        request_id,
        license_id,
        installation_id: Uuid::new_v4(),
    };
    service.activate(first, NOW).unwrap();
    let error = service
        .activate(
            ActivationRequest {
                request_id,
                license_id,
                installation_id: Uuid::new_v4(),
            },
            NOW,
        )
        .unwrap_err();
    assert_eq!(error.code(), OnlineErrorCode::InvalidRequest);
}

#[test]
fn lease_requires_activation_and_authorized_features() {
    let (service, license_id) = service(1, 1);
    let installation_id = Uuid::new_v4();
    let request = |requested_features| LeaseRequest {
        request_id: Uuid::new_v4(),
        license_id,
        installation_id,
        features: requested_features,
    };
    let error = service
        .issue_lease(request(features(&["solver"])), NOW)
        .unwrap_err();
    assert_eq!(error.code(), OnlineErrorCode::ActivationRequired);
    activate(&service, license_id, installation_id);
    let error = service
        .issue_lease(request(features(&["admin"])), NOW)
        .unwrap_err();
    assert_eq!(error.code(), OnlineErrorCode::FeatureDenied);
    assert!(
        service
            .issue_lease(request(features(&["solver"])), NOW)
            .is_ok()
    );
}

#[test]
fn concurrent_lease_allocation_never_exceeds_quota() {
    let (service, license_id) = service(16, 2);
    let service = Arc::new(service);
    let mut installations = Vec::new();
    for _ in 0..16 {
        let installation_id = Uuid::new_v4();
        activate(&service, license_id, installation_id);
        installations.push(installation_id);
    }
    let handles: Vec<_> = installations
        .into_iter()
        .map(|installation_id| {
            let service = Arc::clone(&service);
            thread::spawn(move || {
                service.issue_lease(
                    LeaseRequest {
                        request_id: Uuid::new_v4(),
                        license_id,
                        installation_id,
                        features: features(&["solver"]),
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
            .all(|error| { error.code() == OnlineErrorCode::LeaseLimit })
    );
}

#[test]
fn expired_lease_is_reclaimed_without_explicit_release() {
    let (service, license_id) = service(2, 1);
    let first_installation = Uuid::new_v4();
    let second_installation = Uuid::new_v4();
    activate(&service, license_id, first_installation);
    activate(&service, license_id, second_installation);
    service
        .issue_lease(
            LeaseRequest {
                request_id: Uuid::new_v4(),
                license_id,
                installation_id: first_installation,
                features: features(&["solver"]),
            },
            NOW,
        )
        .unwrap();
    assert!(
        service
            .issue_lease(
                LeaseRequest {
                    request_id: Uuid::new_v4(),
                    license_id,
                    installation_id: second_installation,
                    features: features(&["solver"]),
                },
                NOW + 301,
            )
            .is_ok()
    );
}

#[test]
fn active_installation_can_renew_without_consuming_another_seat() {
    let (service, license_id) = service(2, 1);
    let first_installation = Uuid::new_v4();
    let second_installation = Uuid::new_v4();
    activate(&service, license_id, first_installation);
    activate(&service, license_id, second_installation);
    let request = |installation_id| LeaseRequest {
        request_id: Uuid::new_v4(),
        license_id,
        installation_id,
        features: features(&["solver"]),
    };
    let original = service
        .issue_lease(request(first_installation), NOW)
        .unwrap();
    let renewed = service
        .issue_lease(request(first_installation), NOW + 1)
        .unwrap();
    assert_ne!(original, renewed);
    assert_eq!(
        service
            .issue_lease(request(second_installation), NOW + 1)
            .unwrap_err()
            .code(),
        OnlineErrorCode::LeaseLimit
    );
}

#[test]
fn client_verifies_tokens_and_rejects_tampering_expiry_and_stale_epoch() {
    let (service, license_id) = service(1, 1);
    let installation_id = Uuid::new_v4();
    activate(&service, license_id, installation_id);
    let lease = service
        .issue_lease(
            LeaseRequest {
                request_id: Uuid::new_v4(),
                license_id,
                installation_id,
                features: features(&["export"]),
            },
            NOW,
        )
        .unwrap();
    let ticket = service
        .issue_time_ticket(
            TimeTicketRequest {
                request_id: Uuid::new_v4(),
                license_id,
                installation_id,
            },
            NOW,
        )
        .unwrap();
    let verifier = OnlineTokenVerifier::new(service.key_id(), service.verifying_key()).unwrap();
    let claims = verifier
        .verify_lease(&lease, license_id, installation_id, NOW + 1, 3)
        .unwrap();
    assert_eq!(claims.features, features(&["export"]));
    assert!(
        verifier
            .verify_time_ticket(&ticket, license_id, installation_id, NOW + 1, 3)
            .is_ok()
    );
    assert_eq!(
        verifier
            .verify_lease(&lease, license_id, Uuid::new_v4(), NOW + 1, 3)
            .unwrap_err()
            .code(),
        OnlineErrorCode::TokenInvalid
    );
    assert_eq!(
        verifier
            .verify_lease(&lease, license_id, installation_id, NOW + 300, 3)
            .unwrap_err()
            .code(),
        OnlineErrorCode::TokenExpired
    );
    assert_eq!(
        verifier
            .verify_time_ticket(&ticket, license_id, installation_id, NOW + 1, 4)
            .unwrap_err()
            .code(),
        OnlineErrorCode::RevocationEpochStale
    );

    let mut bytes = BASE64.decode(&lease.token).unwrap();
    let last = bytes.len() - 1;
    bytes[last] ^= 1;
    let mut tampered = lease;
    tampered.token = BASE64.encode(bytes);
    assert_eq!(
        verifier
            .verify_lease(&tampered, license_id, installation_id, NOW + 1, 3)
            .unwrap_err()
            .code(),
        OnlineErrorCode::TokenInvalid
    );
}

#[test]
fn stale_tokens_are_rejected_but_exact_retries_are_idempotent() {
    let (service, license_id) = service(1, 2);
    let installation_id = Uuid::new_v4();
    activate(&service, license_id, installation_id);
    let lease_at = |at| {
        service
            .issue_lease(
                LeaseRequest {
                    request_id: Uuid::new_v4(),
                    license_id,
                    installation_id,
                    features: features(&["solver"]),
                },
                at,
            )
            .unwrap()
    };
    let old = lease_at(NOW);
    let new = lease_at(NOW + 1);
    let verifier = OnlineTokenVerifier::new(service.key_id(), service.verifying_key()).unwrap();
    verifier
        .verify_lease(&new, license_id, installation_id, NOW + 2, 3)
        .unwrap();
    verifier
        .verify_lease(&new, license_id, installation_id, NOW + 2, 3)
        .unwrap();
    assert_eq!(
        verifier
            .verify_lease(&old, license_id, installation_id, NOW + 2, 3)
            .unwrap_err()
            .code(),
        OnlineErrorCode::TokenReplay
    );

    let ticket_at = |at| {
        service
            .issue_time_ticket(
                TimeTicketRequest {
                    request_id: Uuid::new_v4(),
                    license_id,
                    installation_id,
                },
                at,
            )
            .unwrap()
    };
    let old_ticket = ticket_at(NOW);
    let new_ticket = ticket_at(NOW + 1);
    verifier
        .verify_time_ticket(&new_ticket, license_id, installation_id, NOW + 2, 3)
        .unwrap();
    verifier
        .verify_time_ticket(&new_ticket, license_id, installation_id, NOW + 2, 3)
        .unwrap();
    assert_eq!(
        verifier
            .verify_time_ticket(&old_ticket, license_id, installation_id, NOW + 2, 3)
            .unwrap_err()
            .code(),
        OnlineErrorCode::TokenReplay
    );
}

#[test]
fn revocation_blocks_operations_and_is_audited_without_raw_identifiers() {
    let (service, license_id) = service(1, 1);
    let installation_id = Uuid::new_v4();
    activate(&service, license_id, installation_id);
    let epoch = service
        .revoke_license(license_id, "security-admin", "contract ended", NOW + 1)
        .unwrap();
    assert_eq!(epoch, 4);
    let error = service
        .issue_time_ticket(
            TimeTicketRequest {
                request_id: Uuid::new_v4(),
                license_id,
                installation_id,
            },
            NOW + 2,
        )
        .unwrap_err();
    assert_eq!(error.code(), OnlineErrorCode::LicenseRevoked);

    let events = service.audit_events().unwrap();
    assert_eq!(
        events.first().unwrap().action,
        AuditAction::EntitlementRegistered
    );
    assert_eq!(events.last().unwrap().action, AuditAction::Revoked);
    assert!(events.iter().all(|event| event.actor.len() <= 256));
}
