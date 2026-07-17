use std::{fs, io, path::Path};

use ed25519_dalek::SigningKey;
use license_system::{GovernedSigner, IssuancePolicy, IssuanceRequest, KeyStatus};
use time::OffsetDateTime;

const MAX_REQUEST_SIZE: u64 = 64 * 1024;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let arguments: Vec<String> = std::env::args().collect();
    if arguments.len() != 7 {
        return Err(
            "用法：license_issue_governed <request.json> <private.key> <key-id> <generation> \
             <output.lic> <receipt.json>"
                .into(),
        );
    }
    let request_path = Path::new(&arguments[1]);
    if fs::metadata(request_path)?.len() > MAX_REQUEST_SIZE {
        return Err("签发请求 JSON 超过 64 KiB".into());
    }
    let request: IssuanceRequest = serde_json::from_slice(&fs::read(request_path)?)?;
    let private_bytes: [u8; 32] = fs::read(&arguments[2])?
        .try_into()
        .map_err(|_| "Ed25519 私钥必须恰好为 32 字节")?;
    let generation: u64 = arguments[4].parse()?;
    let signer = GovernedSigner::new(
        &arguments[3],
        generation,
        KeyStatus::Active,
        SigningKey::from_bytes(&private_bytes),
        IssuancePolicy::default(),
    )?;
    let issued = signer.issue(&request, OffsetDateTime::now_utc())?;
    let receipt = serde_json::to_vec_pretty(&issued.receipt)?;
    let license_path = Path::new(&arguments[5]);
    let receipt_path = Path::new(&arguments[6]);
    if license_path == receipt_path {
        return Err("License 与 receipt 输出路径必须不同".into());
    }
    if license_path.exists() || receipt_path.exists() {
        return Err(io::Error::new(io::ErrorKind::AlreadyExists, "输出文件已存在").into());
    }
    if let Some(parent) = license_path.parent() {
        fs::create_dir_all(parent)?;
    }
    if let Some(parent) = receipt_path.parent() {
        fs::create_dir_all(parent)?;
    }
    write_new(license_path, &issued.bytes)?;
    if let Err(error) = write_new(receipt_path, &receipt) {
        let _ = fs::remove_file(license_path);
        return Err(error.into());
    }
    println!("governed_license_issued=true");
    println!("license_id={}", issued.receipt.license_id);
    println!("key_id={}", issued.receipt.key_id);
    println!("key_generation={}", issued.receipt.key_generation);
    println!("high_risk={}", issued.receipt.high_risk);
    println!("license_sha256={}", issued.receipt.license_sha256);
    Ok(())
}

fn write_new(path: &Path, bytes: &[u8]) -> io::Result<()> {
    use io::Write;
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)?;
    file.write_all(bytes)
}
