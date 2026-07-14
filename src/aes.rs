use aes_gcm::{
    Aes256Gcm, Nonce,
    aead::{Aead, AeadCore, Generate, KeyInit},
};

use base64::{
    Engine,
    engine::general_purpose::STANDARD as BASE64,
};

const AES_KEY: &[u8; 32] =
    include_bytes!("../keys/aes256.key");

pub fn encrypt(plaintext: &[u8]) -> Result<String, aes_gcm::Error> {
    let cipher = Aes256Gcm::new_from_slice(AES_KEY)
        .expect("AES-256 密钥必须为 32 字节");

    let nonce = Nonce::generate();

    let ciphertext = cipher.encrypt(&nonce, plaintext)?;

    let mut output = Vec::with_capacity(
        nonce.len() + ciphertext.len(),
    );

    output.extend_from_slice(nonce.as_slice());
    output.extend_from_slice(&ciphertext);

    Ok(BASE64.encode(output))
}

pub fn decrypt(encoded: &str) -> Result<Vec<u8>, String> {
    let encrypted = BASE64
        .decode(encoded)
        .map_err(|error| format!("Base64 解码失败：{error}"))?;

    if encrypted.len() <= 12 {
        return Err("加密数据长度不正确".to_string());
    }

    let cipher = Aes256Gcm::new_from_slice(AES_KEY)
        .map_err(|_| "AES 密钥长度不正确".to_string())?;

    let (nonce_bytes, ciphertext) = encrypted.split_at(12);

    let nonce = Nonce::from_slice(nonce_bytes);

    cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| {
            "解密失败：密钥错误或数据已被修改".to_string()
        })
}


