use std::{fs, path::Path};

use ed25519_dalek::VerifyingKey;
use license_system::online::SqliteOnlineLicenseService;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let arguments: Vec<String> = std::env::args().collect();
    if arguments.len() != 4 {
        return Err(
            "用法：online_backup_verify <backup.sqlite> <key_id> <ed25519_public_key_file>".into(),
        );
    }
    let bytes = fs::read(Path::new(&arguments[3]))?;
    let key_bytes: [u8; 32] = bytes
        .try_into()
        .map_err(|_| "Ed25519 公钥文件必须恰好为 32 字节")?;
    let verifying_key = VerifyingKey::from_bytes(&key_bytes)?;
    SqliteOnlineLicenseService::verify_backup_identity(
        Path::new(&arguments[1]),
        &arguments[2],
        &verifying_key,
    )?;
    println!("backup_integrity=ok");
    println!("schema=compatible");
    println!("signing_identity=matched");
    Ok(())
}
