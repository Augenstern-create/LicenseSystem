use std::{
    fs,
    io,
};

use base64::{
    Engine,
    engine::general_purpose::STANDARD as BASE64,
};

use p256::ecdsa::{
    Signature, VerifyingKey,
    signature::Verifier,
};

const PUBLIC_KEY_BYTES: &[u8; 65] =
    include_bytes!("../keys/ecdsa_public.key");

pub fn verify_license(
    license_path: &str,
    signature_path: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    // 从编译进程序的 SEC1 公钥恢复 VerifyingKey。
    let verifying_key =
        VerifyingKey::from_sec1_bytes(PUBLIC_KEY_BYTES)
            .map_err(|_| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "内置 ECDSA 公钥格式不正确",
                )
            })?;

    // 读取许可证原始字节。
    let license_data = fs::read(license_path)?;

    // 签名文件是 Base64 文本。
    let signature_base64 = fs::read_to_string(signature_path)?;

    // trim() 用于去掉文件末尾可能存在的换行符。
    let signature_bytes = BASE64.decode(signature_base64.trim())?;

    if signature_bytes.len() != 64 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "ECDSA 签名必须为 64 字节，当前为 {} 字节",
                signature_bytes.len()
            ),
        )
        .into());
    }

    let signature =
        Signature::from_slice(&signature_bytes)
            .map_err(|_| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "签名数据格式不正确",
                )
            })?;

    verifying_key
        .verify(&license_data, &signature)
        .map_err(|_| {
            io::Error::new(
                io::ErrorKind::PermissionDenied,
                "签名无效：许可证被修改，或者签名不是由对应私钥生成",
            )
        })?;

    Ok(())
}