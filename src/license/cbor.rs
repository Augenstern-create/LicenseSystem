use std::{collections::BTreeMap, convert::Infallible};

use minicbor::{Decoder, Encoder, data::Type};
use time::OffsetDateTime;
use uuid::Uuid;

use super::{
    Algorithm, ErrorCode, FORMAT_VERSION, LicenseError, LicensePayload, LicenseType, MAGIC,
    MachinePolicy, model::LicenseEnvelope,
};

const MAX_DECODE_COLLECTION_ITEMS: usize = 4096;

impl From<minicbor::encode::Error<Infallible>> for LicenseError {
    fn from(error: minicbor::encode::Error<Infallible>) -> Self {
        Self::new(ErrorCode::FormatInvalid, format!("CBOR 编码失败：{error}"))
    }
}

impl From<minicbor::decode::Error> for LicenseError {
    fn from(error: minicbor::decode::Error) -> Self {
        Self::new(ErrorCode::FormatInvalid, format!("CBOR 解码失败：{error}"))
    }
}

pub(crate) fn encode_payload(payload: &LicensePayload) -> Result<Vec<u8>, LicenseError> {
    let mut encoder = Encoder::new(Vec::new());
    encoder.map(18)?;
    encoder.u8(0)?.u16(payload.schema_version)?;
    encoder.u8(1)?.bytes(payload.license_id.as_bytes())?;
    encoder.u8(2)?.str(&payload.product_id)?;
    encoder.u8(3)?.str(&payload.edition)?;
    encoder.u8(4)?.str(&payload.customer_id)?;
    encoder.u8(5)?.i64(payload.issued_at.unix_timestamp())?;
    encoder.u8(6)?;
    encode_optional_time(&mut encoder, payload.not_before)?;
    encoder.u8(7)?;
    encode_optional_time(&mut encoder, payload.expires_at)?;
    encoder.u8(8)?;
    encode_optional_time(&mut encoder, payload.maintenance_until)?;
    encoder.u8(9)?.u8(payload.license_type.as_u8())?;
    encoder.u8(10)?;
    encode_bool_map(&mut encoder, &payload.features)?;
    encoder.u8(11)?;
    encode_u64_map(&mut encoder, &payload.limits)?;
    encoder.u8(12)?;
    encode_scope_map(&mut encoder, &payload.resource_scope)?;
    encoder.u8(13)?;
    encode_machine_policy(&mut encoder, payload.machine_policy.as_ref())?;
    encoder.u8(14)?;
    encode_optional_text(&mut encoder, payload.min_app_version.as_deref())?;
    encoder.u8(15)?;
    encode_optional_text(&mut encoder, payload.max_app_version.as_deref())?;
    encoder.u8(16)?.u64(payload.revocation_epoch)?;
    encoder.u8(17)?;
    encode_text_map(&mut encoder, &payload.custom)?;
    Ok(encoder.into_writer())
}

pub(crate) fn decode_payload(bytes: &[u8]) -> Result<LicensePayload, LicenseError> {
    let mut decoder = Decoder::new(bytes);
    require_map_len(&mut decoder, 18)?;

    require_key(&mut decoder, 0)?;
    let schema_version = decoder.u16()?;
    require_key(&mut decoder, 1)?;
    let license_id = decode_uuid(&mut decoder)?;
    require_key(&mut decoder, 2)?;
    let product_id = decoder.str()?.to_owned();
    require_key(&mut decoder, 3)?;
    let edition = decoder.str()?.to_owned();
    require_key(&mut decoder, 4)?;
    let customer_id = decoder.str()?.to_owned();
    require_key(&mut decoder, 5)?;
    let issued_at = decode_time(&mut decoder)?;
    require_key(&mut decoder, 6)?;
    let not_before = decode_optional_time(&mut decoder)?;
    require_key(&mut decoder, 7)?;
    let expires_at = decode_optional_time(&mut decoder)?;
    require_key(&mut decoder, 8)?;
    let maintenance_until = decode_optional_time(&mut decoder)?;
    require_key(&mut decoder, 9)?;
    let license_type = LicenseType::from_u8(decoder.u8()?)
        .ok_or_else(|| LicenseError::new(ErrorCode::FormatInvalid, "未知 license_type"))?;
    require_key(&mut decoder, 10)?;
    let features = decode_bool_map(&mut decoder)?;
    require_key(&mut decoder, 11)?;
    let limits = decode_u64_map(&mut decoder)?;
    require_key(&mut decoder, 12)?;
    let resource_scope = decode_scope_map(&mut decoder)?;
    require_key(&mut decoder, 13)?;
    let machine_policy = decode_machine_policy(&mut decoder)?;
    require_key(&mut decoder, 14)?;
    let min_app_version = decode_optional_text(&mut decoder)?;
    require_key(&mut decoder, 15)?;
    let max_app_version = decode_optional_text(&mut decoder)?;
    require_key(&mut decoder, 16)?;
    let revocation_epoch = decoder.u64()?;
    require_key(&mut decoder, 17)?;
    let custom = decode_text_map(&mut decoder)?;

    require_end(&decoder, bytes.len())?;
    let payload = LicensePayload {
        schema_version,
        license_id,
        product_id,
        edition,
        customer_id,
        issued_at,
        not_before,
        expires_at,
        maintenance_until,
        license_type,
        features,
        limits,
        resource_scope,
        machine_policy,
        min_app_version,
        max_app_version,
        revocation_epoch,
        custom,
    };

    // Re-encoding rejects alternate-but-decodable CBOR representations so every
    // implementation signs and verifies exactly one byte representation.
    if encode_payload(&payload)? != bytes {
        return Err(LicenseError::new(
            ErrorCode::FormatInvalid,
            "payload 不是规范化 CBOR 编码",
        ));
    }
    Ok(payload)
}

pub(crate) fn encode_envelope(envelope: &LicenseEnvelope) -> Result<Vec<u8>, LicenseError> {
    let mut encoder = Encoder::new(Vec::new());
    encoder.map(6)?;
    encoder.u8(0)?.str(MAGIC)?;
    encoder.u8(1)?.u16(FORMAT_VERSION)?;
    encoder.u8(2)?.str(envelope.algorithm.as_str())?;
    encoder.u8(3)?.str(&envelope.key_id)?;
    encoder.u8(4)?.bytes(&envelope.payload)?;
    encoder.u8(5)?.bytes(&envelope.signature)?;
    Ok(encoder.into_writer())
}

pub(crate) fn decode_envelope(bytes: &[u8]) -> Result<LicenseEnvelope, LicenseError> {
    let mut decoder = Decoder::new(bytes);
    require_map_len(&mut decoder, 6)?;
    require_key(&mut decoder, 0)?;
    if decoder.str()? != MAGIC {
        return Err(LicenseError::new(
            ErrorCode::FormatInvalid,
            "License magic 不正确",
        ));
    }
    require_key(&mut decoder, 1)?;
    if decoder.u16()? != FORMAT_VERSION {
        return Err(LicenseError::new(
            ErrorCode::FormatInvalid,
            "不支持的信封版本",
        ));
    }
    require_key(&mut decoder, 2)?;
    let algorithm = match decoder.str()? {
        "Ed25519" => Algorithm::Ed25519,
        _ => {
            return Err(LicenseError::new(
                ErrorCode::FormatInvalid,
                "算法不在白名单中",
            ));
        }
    };
    require_key(&mut decoder, 3)?;
    let key_id = decoder.str()?.to_owned();
    require_key(&mut decoder, 4)?;
    let payload = decoder.bytes()?.to_vec();
    require_key(&mut decoder, 5)?;
    let signature = decoder.bytes()?.to_vec();
    require_end(&decoder, bytes.len())?;

    let envelope = LicenseEnvelope {
        algorithm,
        key_id,
        payload,
        signature,
    };
    // The envelope is canonical independently of the already-canonical payload.
    if encode_envelope(&envelope)? != bytes {
        return Err(LicenseError::new(
            ErrorCode::FormatInvalid,
            "License 信封不是规范化 CBOR 编码",
        ));
    }
    Ok(envelope)
}

fn canonical_keys<V>(map: &BTreeMap<String, V>) -> Result<Vec<&String>, LicenseError> {
    let mut keys: Vec<_> = map.keys().collect();
    let mut encoded = BTreeMap::new();
    for key in &keys {
        let mut encoder = Encoder::new(Vec::new());
        encoder.str(key)?;
        encoded.insert((*key).clone(), encoder.into_writer());
    }
    keys.sort_by(|left, right| {
        let left = &encoded[*left];
        let right = &encoded[*right];
        left.len().cmp(&right.len()).then_with(|| left.cmp(right))
    });
    Ok(keys)
}

fn encode_bool_map(
    encoder: &mut Encoder<Vec<u8>>,
    map: &BTreeMap<String, bool>,
) -> Result<(), LicenseError> {
    encoder.map(map.len() as u64)?;
    for key in canonical_keys(map)? {
        encoder.str(key)?.bool(map[key])?;
    }
    Ok(())
}

fn encode_u64_map(
    encoder: &mut Encoder<Vec<u8>>,
    map: &BTreeMap<String, u64>,
) -> Result<(), LicenseError> {
    encoder.map(map.len() as u64)?;
    for key in canonical_keys(map)? {
        encoder.str(key)?.u64(map[key])?;
    }
    Ok(())
}

fn encode_text_map(
    encoder: &mut Encoder<Vec<u8>>,
    map: &BTreeMap<String, String>,
) -> Result<(), LicenseError> {
    encoder.map(map.len() as u64)?;
    for key in canonical_keys(map)? {
        encoder.str(key)?.str(&map[key])?;
    }
    Ok(())
}

fn encode_scope_map(
    encoder: &mut Encoder<Vec<u8>>,
    map: &BTreeMap<String, Vec<String>>,
) -> Result<(), LicenseError> {
    encoder.map(map.len() as u64)?;
    for key in canonical_keys(map)? {
        encoder.str(key)?.array(map[key].len() as u64)?;
        for value in &map[key] {
            encoder.str(value)?;
        }
    }
    Ok(())
}

fn encode_machine_policy(
    encoder: &mut Encoder<Vec<u8>>,
    policy: Option<&MachinePolicy>,
) -> Result<(), LicenseError> {
    let Some(policy) = policy else {
        encoder.null()?;
        return Ok(());
    };
    encoder
        .map(2)?
        .u8(0)?
        .array(policy.fingerprints.len() as u64)?;
    for fingerprint in &policy.fingerprints {
        encoder.str(fingerprint)?;
    }
    encoder.u8(1)?.u16(policy.threshold)?;
    Ok(())
}

fn encode_optional_time(
    encoder: &mut Encoder<Vec<u8>>,
    value: Option<OffsetDateTime>,
) -> Result<(), LicenseError> {
    if let Some(value) = value {
        encoder.i64(value.unix_timestamp())?;
    } else {
        encoder.null()?;
    }
    Ok(())
}

fn encode_optional_text(
    encoder: &mut Encoder<Vec<u8>>,
    value: Option<&str>,
) -> Result<(), LicenseError> {
    if let Some(value) = value {
        encoder.str(value)?;
    } else {
        encoder.null()?;
    }
    Ok(())
}

fn decode_bool_map(decoder: &mut Decoder<'_>) -> Result<BTreeMap<String, bool>, LicenseError> {
    let len = require_definite_map(decoder)?;
    let mut result = BTreeMap::new();
    for _ in 0..len {
        insert_unique(&mut result, decoder.str()?.to_owned(), decoder.bool()?)?;
    }
    Ok(result)
}

fn decode_u64_map(decoder: &mut Decoder<'_>) -> Result<BTreeMap<String, u64>, LicenseError> {
    let len = require_definite_map(decoder)?;
    let mut result = BTreeMap::new();
    for _ in 0..len {
        insert_unique(&mut result, decoder.str()?.to_owned(), decoder.u64()?)?;
    }
    Ok(result)
}

fn decode_text_map(decoder: &mut Decoder<'_>) -> Result<BTreeMap<String, String>, LicenseError> {
    let len = require_definite_map(decoder)?;
    let mut result = BTreeMap::new();
    for _ in 0..len {
        let key = decoder.str()?.to_owned();
        let value = decoder.str()?.to_owned();
        insert_unique(&mut result, key, value)?;
    }
    Ok(result)
}

fn decode_scope_map(
    decoder: &mut Decoder<'_>,
) -> Result<BTreeMap<String, Vec<String>>, LicenseError> {
    let len = require_definite_map(decoder)?;
    let mut result = BTreeMap::new();
    for _ in 0..len {
        let key = decoder.str()?.to_owned();
        let array_len = require_definite_array(decoder)?;
        let mut values = Vec::with_capacity(array_len);
        for _ in 0..array_len {
            values.push(decoder.str()?.to_owned());
        }
        insert_unique(&mut result, key, values)?;
    }
    Ok(result)
}

fn decode_machine_policy(decoder: &mut Decoder<'_>) -> Result<Option<MachinePolicy>, LicenseError> {
    if decoder.datatype()? == Type::Null {
        decoder.null()?;
        return Ok(None);
    }
    require_map_len(decoder, 2)?;
    require_key(decoder, 0)?;
    let len = require_definite_array(decoder)?;
    let mut fingerprints = Vec::with_capacity(len);
    for _ in 0..len {
        fingerprints.push(decoder.str()?.to_owned());
    }
    require_key(decoder, 1)?;
    let threshold = decoder.u16()?;
    Ok(Some(MachinePolicy {
        fingerprints,
        threshold,
    }))
}

fn decode_optional_time(decoder: &mut Decoder<'_>) -> Result<Option<OffsetDateTime>, LicenseError> {
    if decoder.datatype()? == Type::Null {
        decoder.null()?;
        Ok(None)
    } else {
        decode_time(decoder).map(Some)
    }
}

fn decode_optional_text(decoder: &mut Decoder<'_>) -> Result<Option<String>, LicenseError> {
    if decoder.datatype()? == Type::Null {
        decoder.null()?;
        Ok(None)
    } else {
        Ok(Some(decoder.str()?.to_owned()))
    }
}

fn decode_time(decoder: &mut Decoder<'_>) -> Result<OffsetDateTime, LicenseError> {
    OffsetDateTime::from_unix_timestamp(decoder.i64()?).map_err(|error| {
        LicenseError::new(ErrorCode::FormatInvalid, format!("时间戳越界：{error}"))
    })
}

fn decode_uuid(decoder: &mut Decoder<'_>) -> Result<Uuid, LicenseError> {
    Uuid::from_slice(decoder.bytes()?).map_err(|error| {
        LicenseError::new(
            ErrorCode::FormatInvalid,
            format!("license_id 不是 UUID：{error}"),
        )
    })
}

fn require_map_len(decoder: &mut Decoder<'_>, expected: u64) -> Result<(), LicenseError> {
    if decoder.map()? != Some(expected) {
        return Err(LicenseError::new(
            ErrorCode::FormatInvalid,
            "CBOR Map 字段数量不正确",
        ));
    }
    Ok(())
}

fn require_definite_map(decoder: &mut Decoder<'_>) -> Result<usize, LicenseError> {
    let len = decoder
        .map()?
        .and_then(|value| usize::try_from(value).ok())
        .ok_or_else(|| {
            LicenseError::new(ErrorCode::FormatInvalid, "不允许不定长或过大的 CBOR Map")
        })?;
    require_collection_bound(len, "Map")
}

fn require_definite_array(decoder: &mut Decoder<'_>) -> Result<usize, LicenseError> {
    let len = decoder
        .array()?
        .and_then(|value| usize::try_from(value).ok())
        .ok_or_else(|| {
            LicenseError::new(ErrorCode::FormatInvalid, "不允许不定长或过大的 CBOR Array")
        })?;
    require_collection_bound(len, "Array")
}

fn require_collection_bound(len: usize, kind: &str) -> Result<usize, LicenseError> {
    if len > MAX_DECODE_COLLECTION_ITEMS {
        return Err(LicenseError::new(
            ErrorCode::FormatInvalid,
            format!("CBOR {kind} 声明的元素数量超限"),
        ));
    }
    Ok(len)
}

fn require_key(decoder: &mut Decoder<'_>, expected: u8) -> Result<(), LicenseError> {
    if decoder.u8()? != expected {
        return Err(LicenseError::new(
            ErrorCode::FormatInvalid,
            "CBOR 字段缺失、乱序或未知",
        ));
    }
    Ok(())
}

fn require_end(decoder: &Decoder<'_>, input_len: usize) -> Result<(), LicenseError> {
    if decoder.position() != input_len {
        return Err(LicenseError::new(
            ErrorCode::FormatInvalid,
            "CBOR 对象后存在多余数据",
        ));
    }
    Ok(())
}

fn insert_unique<V>(
    map: &mut BTreeMap<String, V>,
    key: String,
    value: V,
) -> Result<(), LicenseError> {
    if map.insert(key, value).is_some() {
        return Err(LicenseError::new(
            ErrorCode::FormatInvalid,
            "Map 中存在重复键",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn declared_collection_length_is_bounded_before_allocation() {
        let encoded = [0x9a, 0xff, 0xff, 0xff, 0xff];
        let mut decoder = Decoder::new(&encoded);
        let error = require_definite_array(&mut decoder).unwrap_err();
        assert_eq!(error.code(), ErrorCode::FormatInvalid);
    }
}
