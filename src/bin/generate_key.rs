use std::{
    fs,
    io,
    path::Path,
};

use aes_gcm::{
    Aes256Gcm,
    aead::{AeadCore, Generate, Key},
};
use p256::ecdsa::{SigningKey, VerifyingKey};
use rand_core::OsRng;
use rsa::{
    RsaPrivateKey,
    RsaPublicKey,
    pkcs8::{
        EncodePrivateKey,
        EncodePublicKey,
    },
};

const RSA_BITS: usize = 2048;

const PRIVATE_KEY_PATH: &str = "keys/ecdsa_private.key";
const PUBLIC_KEY_PATH: &str = "keys/ecdsa_public.key";
const AES_KEY_PATH: &str = "keys/aes256.key";
const RSA_PRIVATE_KEY_PATH: &str = "keys/rsa_private.der";
const RSA_PUBLIC_KEY_PATH: &str = "keys/rsa_public.der";

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let private_key_path = Path::new(PRIVATE_KEY_PATH);
    let public_key_path = Path::new(PUBLIC_KEY_PATH);
    let aes_key_path = Path::new(AES_KEY_PATH);
    let rsa_private_key_path = Path::new(RSA_PRIVATE_KEY_PATH);
    let rsa_public_key_path = Path::new(RSA_PUBLIC_KEY_PATH);

    if private_key_path.exists() || public_key_path.exists() || aes_key_path.exists() || rsa_private_key_path.exists() || rsa_public_key_path.exists() {
        return Err(
            io::Error::new(
                io::ErrorKind::AlreadyExists,
                "密钥文件已存在，为避免覆盖旧密钥，停止生成",
            )
            .into(),
        );
    }

    fs::create_dir_all("keys")?;

    let mut rng = OsRng;

    // OsRng 从操作系统安全随机源获取随机数。
    let signing_key = SigningKey::random(&mut OsRng);

    let verifying_key = VerifyingKey::from(&signing_key);

    // P-256 私钥：32 字节。
    let private_key_bytes = signing_key.to_bytes();

    // SEC1 非压缩公钥：04 + X(32) + Y(32)，共 65 字节。
    let public_key_point = verifying_key.to_encoded_point(false);
    let public_key_bytes = public_key_point.as_bytes();
    let key = Key::<Aes256Gcm>::generate();
     // 生成 RSA-2048 私钥。
    //
    // RSA 密钥生成可能比 ECDSA 慢，这是正常现象。
    let private_key =
        RsaPrivateKey::new(&mut rng, RSA_BITS)?;

    // 从私钥计算公钥。
    let public_key =
        RsaPublicKey::from(&private_key);

    // 私钥采用 PKCS#8 DER 二进制格式。
    let private_der =
        private_key.to_pkcs8_der()?;

    // 公钥采用 SubjectPublicKeyInfo/SPKI DER 格式。
    let public_der =
        public_key.to_public_key_der()?;

    fs::write(aes_key_path, key.as_slice())?;

    fs::write(
        private_key_path,
        private_key_bytes.as_slice(),
    )?;

    fs::write(
        public_key_path,
        public_key_bytes,
    )?;

    fs::write(
        rsa_private_key_path,
        private_der.as_bytes(),
    )?;

    fs::write(
        rsa_public_key_path,
        public_der.as_ref(),
    )?;

    println!("ECDSA P-256 密钥对生成成功");
    println!("私钥：{}", private_key_path.display());
    println!("公钥：{}", public_key_path.display());
    println!("AES 密钥：{}", aes_key_path.display());
    println!("RSA 密钥生成成功");
    println!("密钥位数：{RSA_BITS}");
    println!(
        "私钥文件：{}",
        private_key_path.display()
    );
    println!(
        "公钥文件：{}",
        public_key_path.display()
    );
    println!(
        "私钥 DER 长度：{} 字节",
        private_der.as_bytes().len()
    );
    println!(
        "公钥 DER 长度：{} 字节",
        public_der.as_ref().len()
    );
    print_hex("Private Key", private_key_bytes.as_slice());
    print_hex("Public Key", public_key_bytes);
    print_hex("AES Key", key.as_slice());
    print_hex_preview(
        "公钥前 32 字节",
        public_der.as_ref(),
        32,
    );

    Ok(())
}

fn print_hex(name: &str, data: &[u8]) {
    print!("{name}：");

    for byte in data {
        print!("{byte:02X} ");
    }

    println!();
}
fn print_hex_preview(
    name: &str,
    data: &[u8],
    max_length: usize,
) {
    print!("{name}：");

    for byte in data.iter().take(max_length) {
        print!("{byte:02X} ");
    }

    if data.len() > max_length {
        print!("...");
    }

    println!();
}
