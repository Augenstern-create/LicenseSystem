use std::collections::BTreeSet;

use ed25519_dalek::SigningKey;
use license_system::online::{OnlineEntitlement, OnlineLicenseService, online_router};
use time::OffsetDateTime;
use tokio::net::TcpListener;
use uuid::Uuid;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let address = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "127.0.0.1:3000".to_owned());
    let service =
        OnlineLicenseService::new("local-reference-only", SigningKey::from_bytes(&[42; 32]))?;
    let license_id = Uuid::new_v4();
    service.register_entitlement(
        OnlineEntitlement {
            license_id,
            features: BTreeSet::from(["solver".to_owned(), "export".to_owned()]),
            max_activations: 2,
            max_concurrent_leases: 1,
            revocation_epoch: 0,
        },
        "local-bootstrap",
        OffsetDateTime::now_utc().unix_timestamp(),
    )?;
    let listener = TcpListener::bind(&address).await?;
    let bound_address = listener.local_addr()?;
    println!("reference_server=http://{bound_address}");
    println!("license_id={license_id}");
    println!("key_id={}", service.key_id());
    println!("warning=in-memory state and fixed development key; never use in production");
    axum::serve(listener, online_router(service)).await?;
    Ok(())
}
