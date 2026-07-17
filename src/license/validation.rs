use std::collections::HashMap;

use ed25519_dalek::Signature;
use semver::Version;

use super::{
    AuthorizationContext, DOMAIN_SEPARATOR_V1, ErrorCode, KeyStatus, LicenseError, LicensePayload,
    LicenseType, MAX_LICENSE_SIZE, TrustedKey, ValidationInput,
    cbor::{decode_envelope, decode_payload},
};

const MAX_SHORT_TEXT: usize = 256;
const MAX_KEY_ID: usize = 64;
const MAX_MAP_ITEMS: usize = 256;
const MAX_SCOPE_VALUES: usize = 1024;
const MAX_FINGERPRINTS: usize = 16;

/// Trusted public-key set used to validate offline License files.
#[derive(Debug, Default)]
pub struct KeyRing {
    keys: HashMap<String, TrustedKey>,
    minimum_generation: u64,
}

impl KeyRing {
    /// Creates an empty key ring with minimum generation zero.
    pub fn new() -> Self {
        Self::default()
    }

    /// Inserts a trusted key, rejecting duplicate KeyIds.
    pub fn insert(&mut self, key: TrustedKey) -> Result<(), LicenseError> {
        validate_text("key_id", &key.key_id, MAX_KEY_ID)?;
        if self.keys.contains_key(&key.key_id) {
            return Err(LicenseError::new(ErrorCode::FormatInvalid, "重复的 key_id"));
        }
        self.keys.insert(key.key_id.clone(), key);
        Ok(())
    }

    /// Creates a key ring containing one trusted key.
    pub fn from_key(key: TrustedKey) -> Result<Self, LicenseError> {
        let mut result = Self::new();
        result.insert(key)?;
        Ok(result)
    }

    /// Creates an empty key ring that rejects older key generations.
    pub fn with_minimum_generation(minimum_generation: u64) -> Self {
        Self {
            keys: HashMap::new(),
            minimum_generation,
        }
    }

    /// Returns the minimum key generation accepted by this client.
    pub const fn minimum_generation(&self) -> u64 {
        self.minimum_generation
    }

    fn get(&self, key_id: &str) -> Option<&TrustedKey> {
        self.keys.get(key_id)
    }
}

/// Validates an encoded License and returns immutable authorization data.
///
/// Checks include canonical CBOR, trusted KeyId and generation, Ed25519
/// signature, product, validity, application version and machine policy.
pub fn validate_license(
    file: &[u8],
    input: &ValidationInput,
    keys: &KeyRing,
) -> Result<AuthorizationContext, LicenseError> {
    if file.is_empty() || file.len() > MAX_LICENSE_SIZE {
        return Err(LicenseError::new(
            ErrorCode::FormatInvalid,
            format!("License 文件大小必须为 1..={MAX_LICENSE_SIZE} 字节"),
        ));
    }

    let envelope = decode_envelope(file)?;
    validate_text("key_id", &envelope.key_id, MAX_KEY_ID)?;
    let trusted_key = keys
        .get(&envelope.key_id)
        .ok_or_else(|| LicenseError::new(ErrorCode::KeyRevoked, "KeyId 未受信任"))?;
    if trusted_key.generation < keys.minimum_generation {
        return Err(LicenseError::new(
            ErrorCode::KeyRevoked,
            "签发密钥代际低于客户端最低要求",
        ));
    }
    if matches!(trusted_key.status, KeyStatus::Revoked | KeyStatus::Retired) {
        return Err(LicenseError::new(
            ErrorCode::KeyRevoked,
            "签发密钥已撤销或退役",
        ));
    }
    if envelope.signature.len() != 64 {
        return Err(LicenseError::new(
            ErrorCode::SignatureInvalid,
            "Ed25519 签名长度不正确",
        ));
    }
    let signature = Signature::from_slice(&envelope.signature)
        .map_err(|_| LicenseError::new(ErrorCode::SignatureInvalid, "Ed25519 签名格式不正确"))?;
    let mut signed_bytes = Vec::with_capacity(DOMAIN_SEPARATOR_V1.len() + envelope.payload.len());
    signed_bytes.extend_from_slice(DOMAIN_SEPARATOR_V1);
    signed_bytes.extend_from_slice(&envelope.payload);
    trusted_key
        .public_key
        .verify_strict(&signed_bytes, &signature)
        .map_err(|_| LicenseError::new(ErrorCode::SignatureInvalid, "License 签名无效"))?;

    let payload = decode_payload(&envelope.payload)?;
    validate_payload_shape(&payload, &envelope.key_id)?;
    validate_business_rules(&payload, input)?;
    Ok(AuthorizationContext::from_payload(payload))
}

pub(crate) fn validate_payload_shape(
    payload: &LicensePayload,
    key_id: &str,
) -> Result<(), LicenseError> {
    if payload.schema_version != 1 {
        return Err(LicenseError::new(
            ErrorCode::FormatInvalid,
            "不支持的 payload schema_version",
        ));
    }
    validate_text("key_id", key_id, MAX_KEY_ID)?;
    validate_text("product_id", &payload.product_id, MAX_SHORT_TEXT)?;
    validate_text("edition", &payload.edition, MAX_SHORT_TEXT)?;
    validate_text("customer_id", &payload.customer_id, MAX_SHORT_TEXT)?;
    validate_map_len("features", payload.features.len())?;
    validate_map_len("limits", payload.limits.len())?;
    validate_map_len("resource_scope", payload.resource_scope.len())?;
    validate_map_len("custom", payload.custom.len())?;
    for key in payload.features.keys().chain(payload.limits.keys()) {
        validate_text("授权字段名", key, MAX_SHORT_TEXT)?;
    }
    for (key, values) in &payload.resource_scope {
        validate_text("resource_scope 字段名", key, MAX_SHORT_TEXT)?;
        if values.len() > MAX_SCOPE_VALUES {
            return Err(LicenseError::new(
                ErrorCode::FormatInvalid,
                "resource_scope 值数量超限",
            ));
        }
        for value in values {
            validate_text("resource_scope 值", value, MAX_SHORT_TEXT)?;
        }
    }
    for (key, value) in &payload.custom {
        validate_text("custom 字段名", key, MAX_SHORT_TEXT)?;
        validate_text("custom 值", value, MAX_SHORT_TEXT)?;
    }
    if let Some(policy) = &payload.machine_policy {
        if policy.fingerprints.is_empty() || policy.fingerprints.len() > MAX_FINGERPRINTS {
            return Err(LicenseError::new(
                ErrorCode::FormatInvalid,
                "机器指纹数量不正确",
            ));
        }
        if policy.threshold == 0 || policy.threshold > 100 {
            return Err(LicenseError::new(
                ErrorCode::FormatInvalid,
                "机器匹配阈值必须为 1..=100",
            ));
        }
        for fingerprint in &policy.fingerprints {
            validate_text("机器指纹", fingerprint, MAX_SHORT_TEXT)?;
        }
    }
    if payload.license_type == LicenseType::NodeLocked && payload.machine_policy.is_none() {
        return Err(LicenseError::new(
            ErrorCode::FormatInvalid,
            "node_locked License 必须包含 machine_policy",
        ));
    }
    validate_version(payload.min_app_version.as_deref())?;
    validate_version(payload.max_app_version.as_deref())?;
    if payload
        .not_before
        .is_some_and(|value| value < payload.issued_at)
    {
        return Err(LicenseError::new(
            ErrorCode::FormatInvalid,
            "not_before 早于 issued_at",
        ));
    }
    if payload
        .expires_at
        .is_some_and(|value| value < payload.issued_at)
    {
        return Err(LicenseError::new(
            ErrorCode::FormatInvalid,
            "expires_at 早于 issued_at",
        ));
    }
    Ok(())
}

fn validate_business_rules(
    payload: &LicensePayload,
    input: &ValidationInput,
) -> Result<(), LicenseError> {
    if payload.product_id != input.expected_product_id {
        return Err(LicenseError::new(
            ErrorCode::ProductMismatch,
            "License 不适用于当前产品",
        ));
    }
    if input.now < payload.not_before.unwrap_or(payload.issued_at) {
        return Err(LicenseError::new(
            ErrorCode::NotYetValid,
            "License 尚未生效",
        ));
    }
    if payload
        .expires_at
        .is_some_and(|expires_at| input.now > expires_at)
    {
        return Err(LicenseError::new(ErrorCode::Expired, "License 已到期"));
    }
    if let Some(minimum) = payload.min_app_version.as_deref() {
        require_app_version(input)?;
        if input
            .app_version
            .as_ref()
            .is_some_and(|version| version < &Version::parse(minimum).expect("validated version"))
        {
            return Err(LicenseError::new(
                ErrorCode::VersionNotAllowed,
                "应用版本低于 License 下限",
            ));
        }
    }
    if let Some(maximum) = payload.max_app_version.as_deref() {
        require_app_version(input)?;
        if input
            .app_version
            .as_ref()
            .is_some_and(|version| version > &Version::parse(maximum).expect("validated version"))
        {
            return Err(LicenseError::new(
                ErrorCode::VersionNotAllowed,
                "应用版本高于 License 上限",
            ));
        }
    }
    if let (Some(maintenance_until), Some(build_date)) =
        (payload.maintenance_until, input.build_date)
        && build_date > maintenance_until
    {
        return Err(LicenseError::new(
            ErrorCode::VersionNotAllowed,
            "当前构建不在维护升级期内",
        ));
    }
    if let Some(policy) = &payload.machine_policy {
        let machine_identity = input.machine_identity.as_ref().ok_or_else(|| {
            LicenseError::new(
                ErrorCode::MachineMismatch,
                "节点锁定 License 缺少本机身份组件",
            )
        })?;
        if !machine_identity.match_policy(policy).is_match() {
            return Err(LicenseError::new(
                ErrorCode::MachineMismatch,
                "机器指纹匹配未达到许可策略",
            ));
        }
    }
    Ok(())
}

fn require_app_version(input: &ValidationInput) -> Result<(), LicenseError> {
    if input.app_version.is_none() {
        return Err(LicenseError::new(
            ErrorCode::VersionNotAllowed,
            "License 要求提供当前应用版本",
        ));
    }
    Ok(())
}

fn validate_version(version: Option<&str>) -> Result<(), LicenseError> {
    if let Some(version) = version {
        validate_text("应用版本", version, MAX_SHORT_TEXT)?;
        Version::parse(version).map_err(|error| {
            LicenseError::new(
                ErrorCode::FormatInvalid,
                format!("应用版本不是 SemVer：{error}"),
            )
        })?;
    }
    Ok(())
}

fn validate_map_len(name: &str, len: usize) -> Result<(), LicenseError> {
    if len > MAX_MAP_ITEMS {
        return Err(LicenseError::new(
            ErrorCode::FormatInvalid,
            format!("{name} 字段数量超限"),
        ));
    }
    Ok(())
}

fn validate_text(name: &str, value: &str, max_len: usize) -> Result<(), LicenseError> {
    if value.is_empty() || value.len() > max_len || value.chars().any(char::is_control) {
        return Err(LicenseError::new(
            ErrorCode::FormatInvalid,
            format!("{name} 为空、过长或包含控制字符"),
        ));
    }
    Ok(())
}
