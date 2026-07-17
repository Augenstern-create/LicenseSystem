use std::collections::BTreeSet;

use ed25519_dalek::SigningKey;
use license_system::online::{
    ActivationRequest, LeaseRequest, OnlineEntitlement, OnlineLicenseService, OnlineTokenVerifier,
    TimeTicketRequest,
};
use time::OffsetDateTime;
use uuid::Uuid;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let now = OffsetDateTime::now_utc().unix_timestamp();
    let service = OnlineLicenseService::new("demo-online-2026", SigningKey::from_bytes(&[42; 32]))?;
    let license_id = Uuid::new_v4();
    let installation_id = Uuid::new_v4();
    service.register_entitlement(
        OnlineEntitlement {
            license_id,
            features: BTreeSet::from(["solver".to_owned(), "export".to_owned()]),
            max_activations: 2,
            max_concurrent_leases: 1,
            revocation_epoch: 0,
        },
        "demo-admin",
        now,
    )?;
    let activation = service.activate(
        ActivationRequest {
            request_id: Uuid::new_v4(),
            license_id,
            installation_id,
        },
        now,
    )?;
    let lease = service.issue_lease(
        LeaseRequest {
            request_id: Uuid::new_v4(),
            license_id,
            installation_id,
            features: BTreeSet::from(["solver".to_owned()]),
        },
        now,
    )?;
    let ticket = service.issue_time_ticket(
        TimeTicketRequest {
            request_id: Uuid::new_v4(),
            license_id,
            installation_id,
        },
        now,
    )?;
    let verifier = OnlineTokenVerifier::new(service.key_id(), service.verifying_key())?;
    let lease_claims = verifier.verify_lease(&lease, license_id, installation_id, now, 0)?;
    let ticket_claims =
        verifier.verify_time_ticket(&ticket, license_id, installation_id, now, 0)?;

    println!("activation_id={}", activation.activation_id);
    println!(
        "lease_id={} expires_at={} features={:?}",
        lease_claims.lease_id, lease_claims.expires_at, lease_claims.features
    );
    println!("time_ticket_valid_until={}", ticket_claims.valid_until);
    let epoch = service.revoke_license(license_id, "demo-admin", "演示撤销", now + 1)?;
    let rejected = service
        .issue_time_ticket(
            TimeTicketRequest {
                request_id: Uuid::new_v4(),
                license_id,
                installation_id,
            },
            now + 1,
        )
        .expect_err("撤销后必须拒绝新票据");
    println!("revocation_epoch={epoch} rejected={:?}", rejected.code());
    println!("audit_events={}", service.audit_events()?.len());
    Ok(())
}
