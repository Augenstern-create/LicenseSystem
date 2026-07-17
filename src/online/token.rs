use std::{collections::BTreeSet, convert::Infallible};

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use minicbor::{Decoder, Encoder};
use uuid::Uuid;

use super::{LeaseClaims, OnlineError, OnlineErrorCode, TimeTicketClaims};

const TOKEN_MAGIC: &str = "AOTK";
const TOKEN_VERSION: u16 = 1;
const LEASE_KIND: u8 = 1;
const TIME_TICKET_KIND: u8 = 2;
const LEASE_DOMAIN: &[u8] = b"AUGENSTERN-LEASE-V1\0";
const TIME_TICKET_DOMAIN: &[u8] = b"AUGENSTERN-TIME-TICKET-V1\0";

pub(crate) enum DecodedOnlineToken {
    Lease(LeaseClaims),
    TimeTicket(TimeTicketClaims),
}

pub(crate) fn sign_lease(
    claims: &LeaseClaims,
    key_id: &str,
    signing_key: &SigningKey,
) -> Result<Vec<u8>, OnlineError> {
    sign_payload(
        LEASE_KIND,
        key_id,
        encode_lease(claims)?,
        LEASE_DOMAIN,
        signing_key,
    )
}

pub(crate) fn sign_time_ticket(
    claims: &TimeTicketClaims,
    key_id: &str,
    signing_key: &SigningKey,
) -> Result<Vec<u8>, OnlineError> {
    sign_payload(
        TIME_TICKET_KIND,
        key_id,
        encode_time_ticket(claims)?,
        TIME_TICKET_DOMAIN,
        signing_key,
    )
}

pub(crate) fn verify_token(
    token: &[u8],
    expected_key_id: &str,
    verifying_key: &VerifyingKey,
) -> Result<DecodedOnlineToken, OnlineError> {
    let (kind, key_id, payload, signature) = decode_envelope(token)?;
    if key_id != expected_key_id {
        return Err(invalid("在线票据 KeyId 不受信任"));
    }
    if signature.len() != 64 {
        return Err(invalid("在线票据签名长度错误"));
    }
    let signature =
        Signature::from_slice(&signature).map_err(|_| invalid("在线票据签名格式错误"))?;
    let domain = match kind {
        LEASE_KIND => LEASE_DOMAIN,
        TIME_TICKET_KIND => TIME_TICKET_DOMAIN,
        _ => return Err(invalid("未知在线票据类型")),
    };
    let mut signed = Vec::with_capacity(domain.len() + payload.len());
    signed.extend_from_slice(domain);
    signed.extend_from_slice(&payload);
    verifying_key
        .verify_strict(&signed, &signature)
        .map_err(|_| invalid("在线票据签名无效"))?;
    match kind {
        LEASE_KIND => decode_lease(&payload).map(DecodedOnlineToken::Lease),
        TIME_TICKET_KIND => decode_time_ticket(&payload).map(DecodedOnlineToken::TimeTicket),
        _ => unreachable!("kind checked above"),
    }
}

fn sign_payload(
    kind: u8,
    key_id: &str,
    payload: Vec<u8>,
    domain: &[u8],
    signing_key: &SigningKey,
) -> Result<Vec<u8>, OnlineError> {
    let mut signed = Vec::with_capacity(domain.len() + payload.len());
    signed.extend_from_slice(domain);
    signed.extend_from_slice(&payload);
    let signature = signing_key.sign(&signed).to_bytes();
    encode_envelope(kind, key_id, &payload, &signature)
}

fn encode_envelope(
    kind: u8,
    key_id: &str,
    payload: &[u8],
    signature: &[u8],
) -> Result<Vec<u8>, OnlineError> {
    let mut encoder = Encoder::new(Vec::new());
    encoder.map(6).map_err(encode_error)?;
    encoder
        .u8(0)
        .and_then(|encoder| encoder.str(TOKEN_MAGIC))
        .map_err(encode_error)?;
    encoder
        .u8(1)
        .and_then(|encoder| encoder.u16(TOKEN_VERSION))
        .map_err(encode_error)?;
    encoder
        .u8(2)
        .and_then(|encoder| encoder.u8(kind))
        .map_err(encode_error)?;
    encoder
        .u8(3)
        .and_then(|encoder| encoder.str(key_id))
        .map_err(encode_error)?;
    encoder
        .u8(4)
        .and_then(|encoder| encoder.bytes(payload))
        .map_err(encode_error)?;
    encoder
        .u8(5)
        .and_then(|encoder| encoder.bytes(signature))
        .map_err(encode_error)?;
    Ok(encoder.into_writer())
}

fn decode_envelope(token: &[u8]) -> Result<(u8, String, Vec<u8>, Vec<u8>), OnlineError> {
    let mut decoder = Decoder::new(token);
    require_map(&mut decoder, 6)?;
    require_key(&mut decoder, 0)?;
    if decoder.str().map_err(decode_error)? != TOKEN_MAGIC {
        return Err(invalid("在线票据 magic 错误"));
    }
    require_key(&mut decoder, 1)?;
    if decoder.u16().map_err(decode_error)? != TOKEN_VERSION {
        return Err(invalid("在线票据版本不支持"));
    }
    require_key(&mut decoder, 2)?;
    let kind = decoder.u8().map_err(decode_error)?;
    require_key(&mut decoder, 3)?;
    let key_id = decoder.str().map_err(decode_error)?.to_owned();
    require_key(&mut decoder, 4)?;
    let payload = decoder.bytes().map_err(decode_error)?.to_vec();
    require_key(&mut decoder, 5)?;
    let signature = decoder.bytes().map_err(decode_error)?.to_vec();
    require_end(&decoder, token.len())?;
    if encode_envelope(kind, &key_id, &payload, &signature)? != token {
        return Err(invalid("在线票据信封不是规范 CBOR"));
    }
    Ok((kind, key_id, payload, signature))
}

fn encode_lease(claims: &LeaseClaims) -> Result<Vec<u8>, OnlineError> {
    let mut encoder = Encoder::new(Vec::new());
    encoder.map(8).map_err(encode_error)?;
    encode_uuid_field(&mut encoder, 0, claims.lease_id)?;
    encode_uuid_field(&mut encoder, 1, claims.license_id)?;
    encode_uuid_field(&mut encoder, 2, claims.installation_id)?;
    encoder
        .u8(3)
        .and_then(|encoder| encoder.array(claims.features.len() as u64))
        .map_err(encode_error)?;
    for feature in &claims.features {
        encoder.str(feature).map_err(encode_error)?;
    }
    encoder
        .u8(4)
        .and_then(|encoder| encoder.i64(claims.issued_at))
        .map_err(encode_error)?;
    encoder
        .u8(5)
        .and_then(|encoder| encoder.i64(claims.expires_at))
        .map_err(encode_error)?;
    encode_uuid_field(&mut encoder, 6, claims.server_nonce)?;
    encoder
        .u8(7)
        .and_then(|encoder| encoder.u64(claims.revocation_epoch))
        .map_err(encode_error)?;
    Ok(encoder.into_writer())
}

fn decode_lease(payload: &[u8]) -> Result<LeaseClaims, OnlineError> {
    let mut decoder = Decoder::new(payload);
    require_map(&mut decoder, 8)?;
    let lease_id = decode_uuid_field(&mut decoder, 0)?;
    let license_id = decode_uuid_field(&mut decoder, 1)?;
    let installation_id = decode_uuid_field(&mut decoder, 2)?;
    require_key(&mut decoder, 3)?;
    let features = decode_string_set(&mut decoder)?;
    require_key(&mut decoder, 4)?;
    let issued_at = decoder.i64().map_err(decode_error)?;
    require_key(&mut decoder, 5)?;
    let expires_at = decoder.i64().map_err(decode_error)?;
    let server_nonce = decode_uuid_field(&mut decoder, 6)?;
    require_key(&mut decoder, 7)?;
    let revocation_epoch = decoder.u64().map_err(decode_error)?;
    require_end(&decoder, payload.len())?;
    let claims = LeaseClaims {
        lease_id,
        license_id,
        installation_id,
        features,
        issued_at,
        expires_at,
        server_nonce,
        revocation_epoch,
    };
    if encode_lease(&claims)? != payload {
        return Err(invalid("Lease payload 不是规范 CBOR"));
    }
    Ok(claims)
}

fn encode_time_ticket(claims: &TimeTicketClaims) -> Result<Vec<u8>, OnlineError> {
    let mut encoder = Encoder::new(Vec::new());
    encoder.map(6).map_err(encode_error)?;
    encode_uuid_field(&mut encoder, 0, claims.license_id)?;
    encode_uuid_field(&mut encoder, 1, claims.installation_id)?;
    encoder
        .u8(2)
        .and_then(|encoder| encoder.i64(claims.server_time))
        .map_err(encode_error)?;
    encoder
        .u8(3)
        .and_then(|encoder| encoder.i64(claims.valid_until))
        .map_err(encode_error)?;
    encode_uuid_field(&mut encoder, 4, claims.nonce)?;
    encoder
        .u8(5)
        .and_then(|encoder| encoder.u64(claims.revocation_epoch))
        .map_err(encode_error)?;
    Ok(encoder.into_writer())
}

fn decode_time_ticket(payload: &[u8]) -> Result<TimeTicketClaims, OnlineError> {
    let mut decoder = Decoder::new(payload);
    require_map(&mut decoder, 6)?;
    let license_id = decode_uuid_field(&mut decoder, 0)?;
    let installation_id = decode_uuid_field(&mut decoder, 1)?;
    require_key(&mut decoder, 2)?;
    let server_time = decoder.i64().map_err(decode_error)?;
    require_key(&mut decoder, 3)?;
    let valid_until = decoder.i64().map_err(decode_error)?;
    let nonce = decode_uuid_field(&mut decoder, 4)?;
    require_key(&mut decoder, 5)?;
    let revocation_epoch = decoder.u64().map_err(decode_error)?;
    require_end(&decoder, payload.len())?;
    let claims = TimeTicketClaims {
        license_id,
        installation_id,
        server_time,
        valid_until,
        nonce,
        revocation_epoch,
    };
    if encode_time_ticket(&claims)? != payload {
        return Err(invalid("TimeTicket payload 不是规范 CBOR"));
    }
    Ok(claims)
}

fn encode_uuid_field(
    encoder: &mut Encoder<Vec<u8>>,
    key: u8,
    value: Uuid,
) -> Result<(), OnlineError> {
    encoder
        .u8(key)
        .and_then(|encoder| encoder.bytes(value.as_bytes()))
        .map_err(encode_error)?;
    Ok(())
}

fn decode_uuid_field(decoder: &mut Decoder<'_>, key: u8) -> Result<Uuid, OnlineError> {
    require_key(decoder, key)?;
    Uuid::from_slice(decoder.bytes().map_err(decode_error)?)
        .map_err(|_| invalid("在线票据 UUID 字段错误"))
}

fn decode_string_set(decoder: &mut Decoder<'_>) -> Result<BTreeSet<String>, OnlineError> {
    let length = decoder
        .array()
        .map_err(decode_error)?
        .and_then(|length| usize::try_from(length).ok())
        .filter(|length| *length <= 256)
        .ok_or_else(|| invalid("功能数组长度错误"))?;
    let mut values = BTreeSet::new();
    for _ in 0..length {
        let value = decoder.str().map_err(decode_error)?.to_owned();
        if value.is_empty() || value.len() > 128 || !values.insert(value) {
            return Err(invalid("功能数组包含空值、长值或重复值"));
        }
    }
    Ok(values)
}

fn require_map(decoder: &mut Decoder<'_>, length: u64) -> Result<(), OnlineError> {
    if decoder.map().map_err(decode_error)? != Some(length) {
        return Err(invalid("在线票据 Map 长度错误"));
    }
    Ok(())
}

fn require_key(decoder: &mut Decoder<'_>, key: u8) -> Result<(), OnlineError> {
    if decoder.u8().map_err(decode_error)? != key {
        return Err(invalid("在线票据字段缺失、乱序或未知"));
    }
    Ok(())
}

fn require_end(decoder: &Decoder<'_>, length: usize) -> Result<(), OnlineError> {
    if decoder.position() != length {
        return Err(invalid("在线票据存在尾随数据"));
    }
    Ok(())
}

fn encode_error(error: minicbor::encode::Error<Infallible>) -> OnlineError {
    invalid(format!("在线票据编码失败：{error}"))
}

fn decode_error(error: minicbor::decode::Error) -> OnlineError {
    invalid(format!("在线票据解码失败：{error}"))
}

fn invalid(detail: impl Into<String>) -> OnlineError {
    OnlineError::new(OnlineErrorCode::TokenInvalid, detail)
}
