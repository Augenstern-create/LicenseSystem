use std::{env, fs, io};

use ed25519_dalek::VerifyingKey;
use license_system::{
    KeyRing, KeyStatus, TrustedKey, ValidationInput,
    demo_sdk::{AlgorithmKind, DemoImageSdk},
    validate_license,
};
#[cfg(windows)]
use license_system::{
    machine::{WindowsMachineSignalCollector, collect_machine_identity},
    time_anchor::{DpapiStateProtector, TimeAnchorStore},
};
use time::OffsetDateTime;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();
    if args.len() != 7 && args.len() != 8 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            concat!(
                "用法: sdk_demo <license.lic> <public.key> <key-id> ",
                "<product-id> <model-id> <device-id> [time-anchor-path]"
            ),
        )
        .into());
    }

    let public_bytes: [u8; 32] = fs::read(&args[2])?.try_into().map_err(|bytes: Vec<u8>| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("Ed25519 公钥必须为 32 字节，当前为 {} 字节", bytes.len()),
        )
    })?;
    let key_ring = KeyRing::from_key(TrustedKey::ed25519(
        args[3].clone(),
        KeyStatus::Active,
        VerifyingKey::from_bytes(&public_bytes)?,
    ))?;
    let now = OffsetDateTime::now_utc();
    let mut input = ValidationInput::new(&args[4], now);
    #[cfg(windows)]
    if let Ok(identity) = collect_machine_identity(&args[4], &WindowsMachineSignalCollector) {
        input.machine_identity = Some(identity);
    }
    let authorization = validate_license(&fs::read(&args[1])?, &input, &key_ring)?;

    #[cfg(windows)]
    if let Some(state_path) = args.get(7) {
        use windows_sys::Win32::System::SystemInformation::GetTickCount64;

        let anchor = TimeAnchorStore::new(state_path, DpapiStateProtector);
        // SAFETY: GetTickCount64 has no preconditions.
        let monotonic_ms = unsafe { GetTickCount64() };
        let observation = anchor.observe(authorization.license_id(), now, monotonic_ms)?;
        println!(
            "时间锚: status={:?}, installation_id={}",
            observation.status, observation.installation_id
        );
    }

    #[cfg(not(windows))]
    if args.get(7).is_some() {
        return Err(
            io::Error::new(io::ErrorKind::Unsupported, "DPAPI 时间锚只支持 Windows").into(),
        );
    }
    let sdk = DemoImageSdk::new(authorization)?;

    let algorithms: Vec<_> = sdk
        .registered_algorithms()
        .into_iter()
        .map(AlgorithmKind::name)
        .collect();
    println!("SDK 启动成功，Edition: {}", sdk.authorization().edition());
    println!("已注册算法: {}", algorithms.join(", "));

    let algorithm = if sdk.registered_algorithms().contains(&AlgorithmKind::Gpu) {
        AlgorithmKind::Gpu
    } else {
        AlgorithmKind::Cpu
    };
    let _job = sdk.start_job()?;
    let receipt = sdk.run_algorithm(algorithm, &args[5])?;
    println!(
        "处理成功: algorithm={}, model={}",
        receipt.algorithm.name(),
        receipt.model_id
    );
    let newly_connected = sdk.connect_device(&args[6])?;
    println!(
        "设备连接成功: id={}, new={}, connected={}",
        args[6],
        newly_connected,
        sdk.connected_devices()?
    );
    Ok(())
}
