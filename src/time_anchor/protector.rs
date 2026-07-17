use hmac::{Hmac, Mac};
use sha2::Sha256;

use super::TimeAnchorError;

const HMAC_MAGIC: &[u8] = b"ATA-HMAC-V1\0";
const HMAC_TAG_SIZE: usize = 32;

/// Protects serialized time-anchor state from unauthorized modification.
pub trait StateProtector: Send + Sync {
    /// Authenticates or encrypts plaintext state for storage.
    fn protect(&self, plaintext: &[u8]) -> Result<Vec<u8>, TimeAnchorError>;
    /// Verifies and restores protected state.
    fn unprotect(&self, protected: &[u8]) -> Result<Vec<u8>, TimeAnchorError>;
}

/// Portable HMAC-SHA256 state protector.
///
/// It authenticates state but does not provide confidentiality.
#[derive(Clone)]
pub struct HmacStateProtector {
    key: [u8; 32],
}

impl HmacStateProtector {
    /// Creates a protector from an application-managed 32-byte key.
    pub const fn new(key: [u8; 32]) -> Self {
        Self { key }
    }

    fn mac(&self, plaintext: &[u8]) -> Hmac<Sha256> {
        let mut mac =
            Hmac::<Sha256>::new_from_slice(&self.key).expect("HMAC-SHA256 accepts a 32-byte key");
        mac.update(HMAC_MAGIC);
        mac.update(plaintext);
        mac
    }
}

impl StateProtector for HmacStateProtector {
    fn protect(&self, plaintext: &[u8]) -> Result<Vec<u8>, TimeAnchorError> {
        let tag = self.mac(plaintext).finalize().into_bytes();
        let mut output = Vec::with_capacity(HMAC_MAGIC.len() + HMAC_TAG_SIZE + plaintext.len());
        output.extend_from_slice(HMAC_MAGIC);
        output.extend_from_slice(&tag);
        output.extend_from_slice(plaintext);
        Ok(output)
    }

    fn unprotect(&self, protected: &[u8]) -> Result<Vec<u8>, TimeAnchorError> {
        let header = HMAC_MAGIC.len() + HMAC_TAG_SIZE;
        if protected.len() < header || &protected[..HMAC_MAGIC.len()] != HMAC_MAGIC {
            return Err(TimeAnchorError::ProtectionFailed(
                "HMAC 状态头不正确".to_owned(),
            ));
        }
        let tag = &protected[HMAC_MAGIC.len()..header];
        let plaintext = &protected[header..];
        self.mac(plaintext)
            .verify_slice(tag)
            .map_err(|_| TimeAnchorError::ProtectionFailed("HMAC 不匹配".to_owned()))?;
        Ok(plaintext.to_vec())
    }
}

#[cfg(windows)]
mod dpapi {
    use std::{io, ptr, slice};

    use windows_sys::Win32::{
        Foundation::LocalFree,
        Security::Cryptography::{
            CRYPT_INTEGER_BLOB, CRYPTPROTECT_UI_FORBIDDEN, CryptProtectData, CryptUnprotectData,
        },
    };

    use super::{StateProtector, TimeAnchorError};

    const ENTROPY: &[u8] = b"AUGENSTERN-TIME-ANCHOR-V1\0";

    /// Windows DPAPI protector bound to the current user and application entropy.
    #[derive(Debug, Default, Clone, Copy)]
    pub struct DpapiStateProtector;

    impl StateProtector for DpapiStateProtector {
        fn protect(&self, plaintext: &[u8]) -> Result<Vec<u8>, TimeAnchorError> {
            let input = blob(plaintext)?;
            let entropy = blob(ENTROPY)?;
            let mut output = CRYPT_INTEGER_BLOB::default();
            // SAFETY: all blobs reference valid memory for the call, optional pointers are null,
            // and `output` is released with LocalFree after it is copied.
            let success = unsafe {
                CryptProtectData(
                    &input,
                    ptr::null(),
                    &entropy,
                    ptr::null(),
                    ptr::null(),
                    CRYPTPROTECT_UI_FORBIDDEN,
                    &mut output,
                )
            };
            if success == 0 {
                return Err(TimeAnchorError::ProtectionFailed(
                    io::Error::last_os_error().to_string(),
                ));
            }
            copy_and_free(output)
        }

        fn unprotect(&self, protected: &[u8]) -> Result<Vec<u8>, TimeAnchorError> {
            let input = blob(protected)?;
            let entropy = blob(ENTROPY)?;
            let mut output = CRYPT_INTEGER_BLOB::default();
            let mut description = ptr::null_mut();
            // SAFETY: all blobs and output pointers satisfy the DPAPI contract. Both buffers
            // allocated by DPAPI are released with LocalFree.
            let success = unsafe {
                CryptUnprotectData(
                    &input,
                    &mut description,
                    &entropy,
                    ptr::null(),
                    ptr::null(),
                    CRYPTPROTECT_UI_FORBIDDEN,
                    &mut output,
                )
            };
            if !description.is_null() {
                // SAFETY: the description is allocated by DPAPI and owned by this call.
                unsafe { LocalFree(description.cast()) };
            }
            if success == 0 {
                return Err(TimeAnchorError::ProtectionFailed(
                    io::Error::last_os_error().to_string(),
                ));
            }
            copy_and_free(output)
        }
    }

    fn blob(bytes: &[u8]) -> Result<CRYPT_INTEGER_BLOB, TimeAnchorError> {
        let length = u32::try_from(bytes.len()).map_err(|_| TimeAnchorError::StateTooLarge)?;
        Ok(CRYPT_INTEGER_BLOB {
            cbData: length,
            pbData: bytes.as_ptr().cast_mut(),
        })
    }

    fn copy_and_free(output: CRYPT_INTEGER_BLOB) -> Result<Vec<u8>, TimeAnchorError> {
        if output.pbData.is_null() && output.cbData != 0 {
            return Err(TimeAnchorError::ProtectionFailed(
                "DPAPI 返回了空缓冲区".to_owned(),
            ));
        }
        // SAFETY: DPAPI returned `cbData` readable bytes at `pbData` on success.
        let result =
            unsafe { slice::from_raw_parts(output.pbData, output.cbData as usize) }.to_vec();
        if !output.pbData.is_null() {
            // SAFETY: the output buffer is allocated by DPAPI and has not been freed yet.
            unsafe { LocalFree(output.pbData.cast()) };
        }
        Ok(result)
    }
}

#[cfg(windows)]
pub use dpapi::DpapiStateProtector;
