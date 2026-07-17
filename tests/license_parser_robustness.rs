use ed25519_dalek::SigningKey;
use license_system::{
    KeyRing, KeyStatus, LicensePayload, TrustedKey, ValidationInput, issue_license,
    validate_license,
};
use rand::{Rng, RngCore, SeedableRng, rngs::StdRng};
use time::OffsetDateTime;

#[test]
fn random_and_mutated_inputs_never_panic_or_exceed_input_budget() {
    let signing_key = SigningKey::from_bytes(&[61; 32]);
    let ring = KeyRing::from_key(TrustedKey::ed25519(
        "robustness-key",
        KeyStatus::Active,
        signing_key.verifying_key(),
    ))
    .unwrap();
    let input = ValidationInput::new(
        "image-sdk",
        OffsetDateTime::from_unix_timestamp(1_800_000_001).unwrap(),
    );
    let payload: LicensePayload =
        serde_json::from_slice(include_bytes!("../licenses/payload.example.json")).unwrap();
    let valid = issue_license(&payload, "robustness-key", &signing_key).unwrap();
    let mut random = StdRng::seed_from_u64(0xA11C_E5E5);

    for _ in 0..2_000 {
        let length = random.gen_range(0..=license_system::license::MAX_LICENSE_SIZE + 1);
        let mut bytes = vec![0; length];
        random.fill_bytes(&mut bytes);
        assert!(std::panic::catch_unwind(|| validate_license(&bytes, &input, &ring)).is_ok());
    }

    for _ in 0..2_000 {
        let mut bytes = valid.clone();
        match random.gen_range(0..3) {
            0 if !bytes.is_empty() => {
                let index = random.gen_range(0..bytes.len());
                bytes[index] ^= (random.next_u32() as u8).max(1);
            }
            1 if !bytes.is_empty() => {
                bytes.truncate(random.gen_range(0..bytes.len()));
            }
            _ => {
                let extra = random.gen_range(1..=32);
                bytes.extend(std::iter::repeat_with(|| random.next_u32() as u8).take(extra));
            }
        }
        assert!(std::panic::catch_unwind(|| validate_license(&bytes, &input, &ring)).is_ok());
    }
}
