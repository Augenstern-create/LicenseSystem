use std::{env, fs, io, path::Path};

use ed25519_dalek::SigningKey;
use license_system::{LicensePayload, issue_license};

const MAX_PAYLOAD_JSON_SIZE: u64 = 64 * 1024;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();
    if args.len() != 5 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "用法: license_issue <payload.json> <private.key> <key-id> <output.lic>",
        )
        .into());
    }

    let payload_path = Path::new(&args[1]);
    if fs::metadata(payload_path)?.len() > MAX_PAYLOAD_JSON_SIZE {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "payload JSON 超过 64 KiB").into());
    }
    let payload: LicensePayload = serde_json::from_slice(&fs::read(payload_path)?)?;
    let private_bytes: [u8; 32] = fs::read(&args[2])?.try_into().map_err(|bytes: Vec<u8>| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("Ed25519 私钥必须为 32 字节，当前为 {} 字节", bytes.len()),
        )
    })?;
    let signing_key = SigningKey::from_bytes(&private_bytes);
    let license = issue_license(&payload, &args[3], &signing_key)?;

    let output_path = Path::new(&args[4]);
    if let Some(parent) = output_path.parent() {
        fs::create_dir_all(parent)?;
    }
    let mut output = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(output_path)?;
    io::Write::write_all(&mut output, &license)?;

    println!("License 签发成功");
    println!("LicenseId: {}", payload.license_id);
    println!("KeyId: {}", args[3]);
    println!("输出: {}", output_path.display());
    Ok(())
}
