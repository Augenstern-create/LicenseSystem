use license_system::{
    MachinePolicy, MachineSignalKind,
    machine::{MachineSignal, derive_machine_identity},
};

fn full_identity(product_id: &str) -> license_system::MachineIdentity {
    derive_machine_identity(
        product_id,
        [
            MachineSignal::new(MachineSignalKind::Tpm, "TPM-EK-001"),
            MachineSignal::new(MachineSignalKind::SmbiosUuid, "ABCD-1234"),
            MachineSignal::new(MachineSignalKind::SystemVolumeSerial, "DISK-01"),
            MachineSignal::new(MachineSignalKind::CpuId, "CPU-01"),
            MachineSignal::new(MachineSignalKind::MachineGuid, "GUID-01"),
        ],
    )
    .unwrap()
}

#[test]
fn normalization_and_product_domain_separation_are_deterministic() {
    let first = derive_machine_identity(
        "image-sdk",
        [MachineSignal::new(
            MachineSignalKind::SmbiosUuid,
            "ab-cd 12",
        )],
    )
    .unwrap();
    let same = derive_machine_identity(
        "image-sdk",
        [MachineSignal::new(
            MachineSignalKind::SmbiosUuid,
            "AB:CD:12",
        )],
    )
    .unwrap();
    let other_product = derive_machine_identity(
        "another-product",
        [MachineSignal::new(MachineSignalKind::SmbiosUuid, "ABCD12")],
    )
    .unwrap();
    assert_eq!(
        first.components()[0].fingerprint(),
        same.components()[0].fingerprint()
    );
    assert_ne!(
        first.components()[0].fingerprint(),
        other_product.components()[0].fingerprint()
    );
}

#[test]
fn one_changed_medium_signal_still_passes_a_weighted_policy() {
    let licensed = full_identity("image-sdk");
    let policy = MachinePolicy {
        fingerprints: licensed
            .components()
            .iter()
            .map(|component| component.fingerprint().to_owned())
            .collect(),
        threshold: 70,
    };
    let current = derive_machine_identity(
        "image-sdk",
        [
            MachineSignal::new(MachineSignalKind::Tpm, "TPM-EK-001"),
            MachineSignal::new(MachineSignalKind::SmbiosUuid, "ABCD-1234"),
            MachineSignal::new(MachineSignalKind::SystemVolumeSerial, "NEW-DISK"),
            MachineSignal::new(MachineSignalKind::CpuId, "CPU-01"),
            MachineSignal::new(MachineSignalKind::MachineGuid, "GUID-01"),
        ],
    )
    .unwrap();
    let report = current.match_policy(&policy);
    assert!(report.is_match());
    assert_eq!(report.score, 110);
    assert!(report.high_confidence_match);
}

#[test]
fn score_or_high_confidence_failure_is_rejected() {
    let licensed = full_identity("image-sdk");
    let policy = MachinePolicy {
        fingerprints: licensed
            .components()
            .iter()
            .map(|component| component.fingerprint().to_owned())
            .collect(),
        threshold: 70,
    };
    let weak_only = derive_machine_identity(
        "image-sdk",
        [
            MachineSignal::new(MachineSignalKind::SystemVolumeSerial, "DISK-01"),
            MachineSignal::new(MachineSignalKind::CpuId, "CPU-01"),
            MachineSignal::new(MachineSignalKind::MachineGuid, "GUID-01"),
        ],
    )
    .unwrap();
    let report = weak_only.match_policy(&policy);
    assert!(!report.is_match());
    assert_eq!(report.score, 45);
    assert!(!report.high_confidence_match);
}

#[test]
fn duplicate_signal_kind_and_policy_entry_do_not_inflate_score() {
    let identity = derive_machine_identity(
        "image-sdk",
        [
            MachineSignal::new(MachineSignalKind::Tpm, "TPM-EK-001"),
            MachineSignal::new(MachineSignalKind::Tpm, "TPM-EK-002"),
            MachineSignal::new(MachineSignalKind::SmbiosUuid, "ABCD-1234"),
        ],
    )
    .unwrap();
    assert_eq!(identity.components().len(), 2);
    let tpm = identity
        .components()
        .iter()
        .find(|component| component.kind() == MachineSignalKind::Tpm)
        .unwrap()
        .fingerprint()
        .to_owned();
    let smbios = identity
        .components()
        .iter()
        .find(|component| component.kind() == MachineSignalKind::SmbiosUuid)
        .unwrap()
        .fingerprint()
        .to_owned();
    let policy = MachinePolicy {
        fingerprints: vec![tpm.clone(), tpm, smbios],
        threshold: 70,
    };
    let report = identity.match_policy(&policy);
    assert_eq!(report.score, 80);
    assert_eq!(report.matched_components.len(), 2);
}
