use std::{fs, net::SocketAddr, path::PathBuf, time::Duration};

use axum_server::tls_rustls::RustlsConfig;
use ed25519_dalek::SigningKey;
use license_system::online::{
    AdminAuthenticator, OperationalMetrics, RequestGuard, SqliteOnlineLicenseService, admin_router,
    hardened_online_router,
};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut arguments = std::env::args().skip(1);
    let database_path = required(&mut arguments, "database_path")?;
    let key_id = required(&mut arguments, "key_id")?;
    let signing_key_path = required(&mut arguments, "signing_key_file")?;
    let certificate_path = required(&mut arguments, "certificate_pem")?;
    let certificate_key_path = required(&mut arguments, "certificate_key_pem")?;
    let backup_directory = PathBuf::from(required(&mut arguments, "backup_directory")?);
    let public_address: SocketAddr = arguments
        .next()
        .unwrap_or_else(|| "0.0.0.0:3443".to_owned())
        .parse()?;
    let admin_address: SocketAddr = arguments
        .next()
        .unwrap_or_else(|| "127.0.0.1:3444".to_owned())
        .parse()?;
    if arguments.next().is_some() {
        return Err("参数过多".into());
    }
    if !admin_address.ip().is_loopback() {
        return Err("管理监听地址必须是 loopback；外部管理访问应经过受控代理或隧道".into());
    }

    let admin_token =
        std::env::var("LICENSE_ADMIN_TOKEN").map_err(|_| "缺少 LICENSE_ADMIN_TOKEN 环境变量")?;
    let credential_id = std::env::var("LICENSE_ADMIN_CREDENTIAL_ID")
        .unwrap_or_else(|_| "local-ops-admin".to_owned());
    let authenticator = AdminAuthenticator::new(credential_id, admin_token.as_bytes())?;
    drop(admin_token);

    fs::create_dir_all(&backup_directory)?;
    let signing_key = load_signing_key(signing_key_path)?;
    let service = SqliteOnlineLicenseService::open(database_path, key_id, signing_key)?;
    let tls = RustlsConfig::from_pem_file(certificate_path, certificate_key_path).await?;
    let metrics = OperationalMetrics::default();
    let public_guard = RequestGuard::new(1_000, Duration::from_secs(60), metrics.clone())?;
    let admin_guard = RequestGuard::new(100, Duration::from_secs(60), metrics.clone())?;
    let public = hardened_online_router(service.clone(), public_guard);
    let admin = admin_router(
        service,
        authenticator,
        metrics,
        backup_directory,
        admin_guard,
    )?;

    println!("public=https://{public_address}");
    println!("admin=https://{admin_address}");
    println!("admin_surface=loopback-only");
    let public_server =
        axum_server::bind_rustls(public_address, tls.clone()).serve(public.into_make_service());
    let admin_server =
        axum_server::bind_rustls(admin_address, tls).serve(admin.into_make_service());
    tokio::try_join!(public_server, admin_server)?;
    Ok(())
}

fn required(
    arguments: &mut impl Iterator<Item = String>,
    name: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    arguments.next().ok_or_else(|| {
        format!(
            "缺少 {name}；用法：online_secure_server <database_path> <key_id> \
             <signing_key_file> <certificate_pem> <certificate_key_pem> <backup_directory> \
             [public_address] [admin_address]"
        )
        .into()
    })
}

fn load_signing_key(
    path: impl AsRef<std::path::Path>,
) -> Result<SigningKey, Box<dyn std::error::Error>> {
    let bytes = fs::read(path)?;
    let secret: [u8; 32] = bytes
        .try_into()
        .map_err(|_| "Ed25519 私钥文件必须恰好为 32 字节")?;
    Ok(SigningKey::from_bytes(&secret))
}
