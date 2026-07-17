use std::{env, io, path::PathBuf};

#[cfg(windows)]
use license_system::time_anchor::{DpapiStateProtector, TimeAnchorStore};
#[cfg(windows)]
use time::OffsetDateTime;
#[cfg(windows)]
use uuid::Uuid;
#[cfg(windows)]
use windows_sys::Win32::System::SystemInformation::GetTickCount64;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();
    if args.len() != 3 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "用法: time_anchor_demo <state-path> <license-id>",
        )
        .into());
    }

    #[cfg(windows)]
    {
        let store = TimeAnchorStore::new(PathBuf::from(&args[1]), DpapiStateProtector);
        let license_id = Uuid::parse_str(&args[2])?;
        // SAFETY: GetTickCount64 has no preconditions and returns milliseconds since boot.
        let monotonic_ms = unsafe { GetTickCount64() };
        let observation = store.observe(license_id, OffsetDateTime::now_utc(), monotonic_ms)?;
        println!("时间锚检查成功");
        println!("状态: {:?}", observation.status);
        println!("InstallationId: {}", observation.installation_id);
        println!("TrustedUtc: {}", observation.trusted_utc);
        Ok(())
    }

    #[cfg(not(windows))]
    {
        let _ = PathBuf::from(&args[1]);
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "DPAPI 时间锚 Demo 只支持 Windows",
        )
        .into())
    }
}
