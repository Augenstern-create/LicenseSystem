use std::{
    fs,
    io,
    path::Path,
};

use base64::{
    Engine,
    engine::general_purpose::STANDARD as BASE64,
};

use p256::ecdsa::{
    Signature, SigningKey,
    signature::Signer,
};

const PRIVATE_KEY_PATH: &str = "keys/ecdsa_private.key";
const LICENSE_PATH: &str = "licenses/license.json";
const SIGNATURE_PATH: &str = "licenses/license.sig";

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let private_key_bytes = fs::read(PRIVATE_KEY_PATH)?;

    if private_key_bytes.len() != 32 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "ECDSA P-256 私钥必须是 32 字节，当前为 {} 字节",
                private_key_bytes.len()
            ),
        )
        .into());
    }

    // 从原始 32 字节私钥恢复 SigningKey。
    let signing_key = SigningKey::from_slice(&private_key_bytes)
        .map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "ecdsa_private.key 不是有效的 P-256 私钥",
            )
        })?;

    // 必须读取文件的原始字节。
    let license_data = fs::read(LICENSE_PATH)?;

    // ECDSA P-256 + SHA-256 签名。
    //
    // Signature 默认是固定长度 r || s 格式，共 64 字节。
    let signature: Signature = signing_key.sign(&license_data);

    let signature_bytes = signature.to_bytes();

    // 为了便于保存、复制和传输，将签名编码为 Base64。
    let signature_base64 = BASE64.encode(signature_bytes);

    if let Some(parent) = Path::new(SIGNATURE_PATH).parent() {
        fs::create_dir_all(parent)?;
    }

    fs::write(SIGNATURE_PATH, &signature_base64)?;

    println!("许可证签名成功");
    println!("许可证：{LICENSE_PATH}");
    println!("签名文件：{SIGNATURE_PATH}");
    println!("签名原始长度：{} 字节", signature_bytes.len());
    println!("签名 Base64：{signature_base64}");

    Ok(())
}