use std::{
    error::Error,
    fs,
    io,
    path::Path,
};

use base64::{
    Engine,
    engine::general_purpose::STANDARD as BASE64,
};

use rand::rngs::OsRng;

use rsa::{
    RsaPrivateKey,
    pkcs8::DecodePrivateKey,
    pss::{
        BlindedSigningKey,
        Signature,
    },
    signature::{
        RandomizedSigner,
        SignatureEncoding,
    },
};

use sha2::Sha256;

const PRIVATE_KEY_PATH: &str =
    "keys/rsa_private.der";

const LICENSE_PATH: &str =
    "licenses/license.json";

const SIGNATURE_PATH: &str =
    "licenses/license_rsa.sig";

fn main() -> Result<(), Box<dyn Error>> {
    // 读取 PKCS#8 DER 私钥。
    let private_key_der =
        fs::read(PRIVATE_KEY_PATH)?;

    let private_key =
        RsaPrivateKey::from_pkcs8_der(
            &private_key_der,
        )
        .map_err(|error| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "RSA 私钥格式不正确：{error}"
                ),
            )
        })?;

    // 构造 RSA-PSS + SHA-256 签名器。
    let signing_key =
        BlindedSigningKey::<Sha256>::new(
            private_key,
        );

    // 读取许可证原始字节。
    let license_data =
        fs::read(LICENSE_PATH)?;

    let mut rng = OsRng;

    // RSA-PSS 签名包含随机盐，因此同一份数据每次签名结果不同。
    let signature: Signature =
        signing_key.sign_with_rng(
            &mut rng,
            &license_data,
        );

    // RSA-2048 签名长度固定为 256 字节。
    let signature_bytes =
        signature.to_bytes();

    let signature_base64 =
        BASE64.encode(signature_bytes.as_ref());

    if let Some(parent) =
        Path::new(SIGNATURE_PATH).parent()
    {
        fs::create_dir_all(parent)?;
    }

    fs::write(
        SIGNATURE_PATH,
        &signature_base64,
    )?;

    println!("RSA-PSS 许可证签名成功");
    println!("哈希算法：SHA-256");
    println!("RSA 位数：2048");
    println!("许可证文件：{LICENSE_PATH}");
    println!("签名文件：{SIGNATURE_PATH}");
    println!(
        "签名原始长度：{} 字节",
        signature_bytes.as_ref().len()
    );
    println!(
        "签名 Base64 长度：{} 字符",
        signature_base64.len()
    );
    println!(
        "签名 Base64：{signature_base64}"
    );

    Ok(())
}