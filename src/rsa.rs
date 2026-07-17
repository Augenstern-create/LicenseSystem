use std::{
    error::Error,
    fs,
    io,
};

use base64::{
    Engine,
    engine::general_purpose::STANDARD as BASE64,
};

use rsa::{
    RsaPublicKey,
    pkcs8::DecodePublicKey,
    pss::{
        Signature,
        VerifyingKey,
    },
    signature::Verifier,
};

use sha2::Sha256;

const RSA_PUBLIC_KEY_DER: &[u8] =
    include_bytes!("../keys/rsa_public.der");

pub fn verify_rsa_license(
    license_path: &str,
    signature_path: &str,
) -> Result<(), Box<dyn Error>> {
    // 从内置的 SPKI DER 公钥恢复 RSA 公钥。
    let public_key =
        RsaPublicKey::from_public_key_der(
            RSA_PUBLIC_KEY_DER,
        )
        .map_err(|error| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "内置 RSA 公钥格式错误：{error}"
                ),
            )
        })?;

    // 构造 RSA-PSS + SHA-256 验签器。
    let verifying_key =
        VerifyingKey::<Sha256>::new(public_key);

    // 必须读取与签名时完全相同的原始字节。
    let license_data =
        fs::read(license_path)?;

    let signature_base64 =
        fs::read_to_string(signature_path)?;

    let signature_bytes =
        BASE64.decode(
            signature_base64.trim(),
        )?;

    if signature_bytes.len() != 256 {
        return Err(
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "RSA-2048 签名必须为 256 字节，当前为 {} 字节",
                    signature_bytes.len()
                ),
            )
            .into(),
        );
    }

    let signature =
        Signature::try_from(
            signature_bytes.as_slice(),
        )
        .map_err(|error| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "RSA 签名格式错误：{error}"
                ),
            )
        })?;

    verifying_key
        .verify(
            &license_data,
            &signature,
        )
        .map_err(|_| {
            io::Error::new(
                io::ErrorKind::PermissionDenied,
                "RSA 签名无效：许可证被修改，或者签名不是由对应私钥生成",
            )
        })?;

    Ok(())
}
