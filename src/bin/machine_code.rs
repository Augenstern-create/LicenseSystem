use std::{env, io};

#[cfg(windows)]
use license_system::machine::{WindowsMachineSignalCollector, collect_machine_identity};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();
    if args.len() != 2 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "用法: machine_code <product-id>",
        )
        .into());
    }

    #[cfg(windows)]
    {
        let identity = collect_machine_identity(&args[1], &WindowsMachineSignalCollector)?;
        println!("产品: {}", args[1]);
        println!("可用机器指纹组件: {}", identity.components().len());
        let mut total_weight = 0_u16;
        let mut has_high_confidence = false;
        for component in identity.components() {
            total_weight = total_weight.saturating_add(component.weight());
            has_high_confidence |= component.is_high_confidence();
            println!(
                "{} weight={} high_confidence={} fingerprint={}",
                component.kind().as_str(),
                component.weight(),
                component.is_high_confidence(),
                component.fingerprint()
            );
        }
        println!("可用总分: {total_weight}, 包含高可信组件: {has_high_confidence}");
        println!("签发时只复制 fingerprint，不要传输原始硬件标识。");
        Ok(())
    }

    #[cfg(not(windows))]
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "当前 machine_code Demo 只实现 Windows 信号采集",
    )
    .into())
}
