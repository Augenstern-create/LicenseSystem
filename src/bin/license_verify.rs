use std::{env, fs, io};

use ed25519_dalek::VerifyingKey;
#[cfg(windows)]
use license_system::machine::{WindowsMachineSignalCollector, collect_machine_identity};
use license_system::{KeyRing, KeyStatus, TrustedKey, ValidationInput, validate_license};
use time::OffsetDateTime;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();
    if args.len() != 5 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "用法: license_verify <license.lic> <public.key> <key-id> <expected-product-id>",
        )
        .into());
    }

    let public_bytes: [u8; 32] = fs::read(&args[2])?.try_into().map_err(|bytes: Vec<u8>| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("Ed25519 公钥必须为 32 字节，当前为 {} 字节", bytes.len()),
        )
    })?;
    let public_key = VerifyingKey::from_bytes(&public_bytes)?;
    let keys = KeyRing::from_key(TrustedKey::ed25519(
        args[3].clone(),
        KeyStatus::Active,
        public_key,
    ))?;
    let mut input = ValidationInput::new(&args[4], OffsetDateTime::now_utc());
    #[cfg(windows)]
    if let Ok(identity) = collect_machine_identity(&args[4], &WindowsMachineSignalCollector) {
        input.machine_identity = Some(identity);
    }
    let context = validate_license(&fs::read(&args[1])?, &input, &keys)?;

    println!("License 验证成功");
    println!("LicenseId: {}", context.license_id());
    println!("ProductId: {}", context.product_id());
    println!("Edition: {}", context.edition());
    println!("CustomerId: {}", context.customer_id());
    if let Some(expires_at) = context.expires_at() {
        println!("ExpiresAt: {expires_at}");
    } else {
        println!("ExpiresAt: perpetual");
    }
    Ok(())
}
