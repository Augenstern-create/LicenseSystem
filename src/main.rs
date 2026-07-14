mod aes;
mod ecdsa;
mod rsa;
use aes::{encrypt, decrypt};
use ecdsa::verify_license;
use rsa::verify_rsa_license;

const LICENSE_PATH: &str = "licenses/license.json";
const SIGNATURE_PATH: &str = "licenses/license.sig";
const RSA_SIGNATURE_PATH: &str = "licenses/license_rsa.sig";

#[cfg(windows)]
fn configure_console() {
    use windows_sys::Win32::System::Console::{
        SetConsoleCP,
        SetConsoleOutputCP,
    };

    const CP_UTF8: u32 = 65001;

    unsafe {
        SetConsoleCP(CP_UTF8);
        SetConsoleOutputCP(CP_UTF8);
    }
}

#[cfg(not(windows))]
fn configure_console() {}
fn main() -> Result<(), Box<dyn std::error::Error>> {

    configure_console();
    let plaintext = "你好，这是一段需要 AES 加密的数据。";

    println!("原始明文：{plaintext}");

    let encrypted = encrypt(plaintext.as_bytes())?;

    println!("加密结果：{encrypted}");

    let decrypted = decrypt(&encrypted)
        .map_err(std::io::Error::other)?;

    let decrypted = String::from_utf8(decrypted)?;

    println!("解密结果：{decrypted}");

    match verify_license(LICENSE_PATH, SIGNATURE_PATH) {
        Ok(()) => {
            println!("许可证签名有效");
            println!("许可证内容未被修改");
        }

        Err(error) => {
            eprintln!("许可证验证失败：{error}");
            std::process::exit(1);
        }
    }
    match verify_rsa_license(
        LICENSE_PATH,
        RSA_SIGNATURE_PATH,
    ) {
        Ok(()) => {
            println!("RSA 许可证签名验证成功");
            println!("许可证由合法私钥签发");
            println!("许可证内容未被修改");
        }

        Err(error) => {
            eprintln!(
                "RSA 许可证验证失败：{error}"
            );

            std::process::exit(1);
        }
    }

    Ok(())
}
