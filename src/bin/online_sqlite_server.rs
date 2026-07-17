use std::{collections::BTreeSet, path::PathBuf};

use ed25519_dalek::SigningKey;
use license_system::online::{
    OnlineEntitlement, OnlineErrorCode, SqliteOnlineLicenseService, online_router,
};
use time::OffsetDateTime;
use tokio::net::TcpListener;
use uuid::Uuid;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut arguments = std::env::args().skip(1);
    let database_path = arguments
        .next()
        .map(PathBuf::from)
        .ok_or("用法：online_sqlite_server <database_path> [listen_address] [license_id]")?;
    let address = arguments
        .next()
        .unwrap_or_else(|| "127.0.0.1:3000".to_owned());
    let requested_license_id = arguments
        .next()
        .map(|value| Uuid::parse_str(&value))
        .transpose()?;
    if arguments.next().is_some() {
        return Err("参数过多".into());
    }

    let service = SqliteOnlineLicenseService::open(
        &database_path,
        "local-sqlite-reference-only",
        SigningKey::from_bytes(&[42; 32]),
    )?;
    let license_id = requested_license_id.unwrap_or_else(Uuid::new_v4);
    match service.register_entitlement(
        OnlineEntitlement {
            license_id,
            features: BTreeSet::from(["solver".to_owned(), "export".to_owned()]),
            max_activations: 2,
            max_concurrent_leases: 1,
            revocation_epoch: 0,
        },
        "local-bootstrap",
        OffsetDateTime::now_utc().unix_timestamp(),
    ) {
        Ok(()) => println!("entitlement=created"),
        Err(error)
            if requested_license_id.is_some()
                && error.code() == OnlineErrorCode::InvalidRequest =>
        {
            println!("entitlement=existing");
        }
        Err(error) => return Err(error.into()),
    }
    let listener = TcpListener::bind(&address).await?;
    println!("reference_server=http://{}", listener.local_addr()?);
    println!("database={}", database_path.display());
    println!("license_id={license_id}");
    println!("key_id={}", service.key_id());
    println!("warning=fixed development key; never use in production");
    axum::serve(listener, online_router(service)).await?;
    Ok(())
}
