//! Machine signal collection and product-domain-separated identity derivation.

mod normalize;

#[cfg(windows)]
mod windows;

use std::{collections::HashSet, error::Error, fmt};

use sha2::{Digest, Sha256};

use crate::{MachineIdentity, MachineIdentityComponent, MachineSignalKind};

#[cfg(windows)]
pub use windows::WindowsMachineSignalCollector;

const MACHINE_DOMAIN_V1: &[u8] = b"AUGENSTERN-MACHINE-V1\0";

/// Raw machine signal collected before normalization and hashing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MachineSignal {
    /// Signal source kind.
    pub kind: MachineSignalKind,
    /// Platform-provided value; callers should avoid logging it.
    pub raw_value: String,
}

impl MachineSignal {
    /// Creates a raw machine signal.
    pub fn new(kind: MachineSignalKind, raw_value: impl Into<String>) -> Self {
        Self {
            kind,
            raw_value: raw_value.into(),
        }
    }
}

/// Platform adapter that collects available machine signals.
pub trait MachineSignalCollector {
    /// Collects raw signals without applying product-specific hashing.
    fn collect(&self) -> Result<Vec<MachineSignal>, MachineError>;
}

/// Failure returned while collecting or deriving a machine identity.
#[derive(Debug)]
pub enum MachineError {
    /// No non-placeholder signal remained after normalization.
    NoUsableSignals,
    /// Platform collection failed with diagnostic detail.
    Collection(String),
}

impl fmt::Display for MachineError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoUsableSignals => write!(formatter, "没有可用的机器身份信号"),
            Self::Collection(detail) => write!(formatter, "机器身份采集失败：{detail}"),
        }
    }
}

impl Error for MachineError {}

/// Collects signals and derives a machine identity for `product_id`.
pub fn collect_machine_identity(
    product_id: &str,
    collector: &impl MachineSignalCollector,
) -> Result<MachineIdentity, MachineError> {
    derive_machine_identity(product_id, collector.collect()?)
}

/// Normalizes, de-duplicates and hashes supplied machine signals.
///
/// Fingerprints are separated by product and signal kind so values cannot be
/// correlated directly across products or signal domains.
pub fn derive_machine_identity(
    product_id: &str,
    signals: impl IntoIterator<Item = MachineSignal>,
) -> Result<MachineIdentity, MachineError> {
    let mut seen_kinds = HashSet::new();
    let mut components = Vec::new();
    for signal in signals {
        if !seen_kinds.insert(signal.kind) {
            continue;
        }
        let Some(normalized) = normalize::normalize(&signal.raw_value) else {
            continue;
        };
        let fingerprint = fingerprint(product_id, signal.kind, &normalized);
        let (weight, high_confidence) = policy_for(signal.kind);
        components.push(MachineIdentityComponent::new(
            signal.kind,
            fingerprint,
            weight,
            high_confidence,
        ));
    }
    components.sort_by_key(|component| component.kind().as_str());
    if components.is_empty() {
        return Err(MachineError::NoUsableSignals);
    }
    Ok(MachineIdentity::new(components))
}

fn fingerprint(product_id: &str, kind: MachineSignalKind, normalized: &str) -> String {
    let mut digest = Sha256::new();
    digest.update(MACHINE_DOMAIN_V1);
    update_length_prefixed(&mut digest, product_id.as_bytes());
    update_length_prefixed(&mut digest, kind.as_str().as_bytes());
    update_length_prefixed(&mut digest, normalized.as_bytes());
    format!("{}:{}", kind.as_str(), encode_hex(&digest.finalize()))
}

fn update_length_prefixed(digest: &mut Sha256, value: &[u8]) {
    // Length prefixes make concatenation unambiguous across product, kind and value.
    digest.update((value.len() as u64).to_be_bytes());
    digest.update(value);
}

fn policy_for(kind: MachineSignalKind) -> (u16, bool) {
    match kind {
        MachineSignalKind::Tpm => (50, true),
        MachineSignalKind::SmbiosUuid => (30, true),
        MachineSignalKind::SystemVolumeSerial => (15, false),
        MachineSignalKind::CpuId => (10, false),
        MachineSignalKind::MachineGuid => (20, false),
    }
}

fn encode_hex(bytes: &[u8]) -> String {
    use fmt::Write;

    bytes.iter().fold(
        String::with_capacity(bytes.len() * 2),
        |mut output, byte| {
            write!(&mut output, "{byte:02x}").expect("writing to String cannot fail");
            output
        },
    )
}
