use ed25519_dalek::{Signer, SigningKey};

use super::{
    Algorithm, DOMAIN_SEPARATOR_V1, ErrorCode, LicenseError, LicensePayload, MAX_LICENSE_SIZE,
    cbor::{encode_envelope, encode_payload},
    model::LicenseEnvelope,
    validation::validate_payload_shape,
};

/// Validates and signs a structured payload using canonical CBOR and Ed25519.
///
/// The signature covers the versioned domain separator and canonical payload,
/// never arbitrary caller-supplied bytes. Production workflows should prefer
/// [`crate::GovernedSigner`] for key-state, approval and receipt enforcement.
pub fn issue_license(
    payload: &LicensePayload,
    key_id: &str,
    signing_key: &SigningKey,
) -> Result<Vec<u8>, LicenseError> {
    validate_payload_shape(payload, key_id)?;
    let payload_bytes = encode_payload(payload)?;
    let mut signed_bytes = Vec::with_capacity(DOMAIN_SEPARATOR_V1.len() + payload_bytes.len());
    signed_bytes.extend_from_slice(DOMAIN_SEPARATOR_V1);
    signed_bytes.extend_from_slice(&payload_bytes);
    let signature = signing_key.sign(&signed_bytes);
    let file = encode_envelope(&LicenseEnvelope {
        algorithm: Algorithm::Ed25519,
        key_id: key_id.to_owned(),
        payload: payload_bytes,
        signature: signature.to_bytes().to_vec(),
    })?;
    if file.len() > MAX_LICENSE_SIZE {
        return Err(LicenseError::new(
            ErrorCode::FormatInvalid,
            format!("签发后的 License 超过 {MAX_LICENSE_SIZE} 字节"),
        ));
    }
    Ok(file)
}
