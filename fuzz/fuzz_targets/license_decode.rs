#![no_main]

use libfuzzer_sys::fuzz_target;
use license_system::{KeyRing, ValidationInput, validate_license};
use time::OffsetDateTime;

fuzz_target!(|data: &[u8]| {
    if data.len() > license_system::license::MAX_LICENSE_SIZE + 1 {
        return;
    }
    let input = ValidationInput::new("fuzz-product", OffsetDateTime::UNIX_EPOCH);
    let _ = validate_license(data, &input, &KeyRing::new());
});
