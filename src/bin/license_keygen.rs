use std::{
    env, fs,
    io::{self, Write},
    path::Path,
};

use ed25519_dalek::SigningKey;
use rand::{RngCore, rngs::OsRng};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();
    if args.len() != 3 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "用法: license_keygen <private-key-path> <public-key-path>",
        )
        .into());
    }

    let private_path = Path::new(&args[1]);
    let public_path = Path::new(&args[2]);
    if private_path.exists() || public_path.exists() {
        return Err(
            io::Error::new(io::ErrorKind::AlreadyExists, "密钥文件已存在，拒绝覆盖").into(),
        );
    }
    if let Some(parent) = private_path.parent() {
        fs::create_dir_all(parent)?;
    }
    if let Some(parent) = public_path.parent() {
        fs::create_dir_all(parent)?;
    }

    let mut secret = [0_u8; 32];
    OsRng.fill_bytes(&mut secret);
    let signing_key = SigningKey::from_bytes(&secret);
    write_new(private_path, &signing_key.to_bytes())?;
    write_new(public_path, &signing_key.verifying_key().to_bytes())?;

    println!("Ed25519 密钥对生成成功");
    println!("私钥: {}", private_path.display());
    println!("公钥: {}", public_path.display());
    println!("请将私钥迁移到受控签发环境，客户端只能分发公钥。");
    Ok(())
}

fn write_new(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)?;
    file.write_all(bytes)
}
