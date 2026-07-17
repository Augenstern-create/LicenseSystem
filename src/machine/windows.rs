use std::{env, ptr};

use windows_sys::Win32::{
    Storage::FileSystem::GetVolumeInformationW, System::SystemInformation::GetSystemFirmwareTable,
};
use winreg::{RegKey, enums::HKEY_LOCAL_MACHINE};

use crate::MachineSignalKind;

use super::{MachineError, MachineSignal, MachineSignalCollector};

/// Windows collector for MachineGuid, SMBIOS UUID, CPU and volume signals.
#[derive(Debug, Default, Clone, Copy)]
pub struct WindowsMachineSignalCollector;

impl MachineSignalCollector for WindowsMachineSignalCollector {
    fn collect(&self) -> Result<Vec<MachineSignal>, MachineError> {
        let local_machine = RegKey::predef(HKEY_LOCAL_MACHINE);
        let mut signals = Vec::new();

        push_registry_string(
            &local_machine,
            r"SOFTWARE\Microsoft\Cryptography",
            "MachineGuid",
            MachineSignalKind::MachineGuid,
            &mut signals,
        );
        if let Some(uuid) = smbios_system_uuid() {
            signals.push(MachineSignal::new(MachineSignalKind::SmbiosUuid, uuid));
        } else {
            push_registry_string(
                &local_machine,
                r"HARDWARE\DESCRIPTION\System\BIOS",
                "SystemUUID",
                MachineSignalKind::SmbiosUuid,
                &mut signals,
            );
        }
        push_registry_string(
            &local_machine,
            r"HARDWARE\DESCRIPTION\System\CentralProcessor\0",
            "Identifier",
            MachineSignalKind::CpuId,
            &mut signals,
        );
        if let Some(serial) = system_volume_serial() {
            signals.push(MachineSignal::new(
                MachineSignalKind::SystemVolumeSerial,
                format!("{serial:08X}"),
            ));
        }

        if signals.is_empty() {
            Err(MachineError::NoUsableSignals)
        } else {
            Ok(signals)
        }
    }
}

fn push_registry_string(
    root: &RegKey,
    path: &str,
    name: &str,
    kind: MachineSignalKind,
    output: &mut Vec<MachineSignal>,
) {
    if let Ok(key) = root.open_subkey(path)
        && let Ok(value) = key.get_value::<String, _>(name)
    {
        output.push(MachineSignal::new(kind, value));
    }
}

fn system_volume_serial() -> Option<u32> {
    let mut root = env::var("SystemDrive").unwrap_or_else(|_| "C:".to_owned());
    if !root.ends_with('\\') {
        root.push('\\');
    }
    let wide: Vec<u16> = root.encode_utf16().chain([0]).collect();
    let mut serial = 0_u32;
    // SAFETY: `wide` is NUL-terminated and lives for the duration of the call.
    // Optional output buffers are null and the serial pointer is valid.
    let success = unsafe {
        GetVolumeInformationW(
            wide.as_ptr(),
            ptr::null_mut(),
            0,
            &mut serial,
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
            0,
        )
    };
    (success != 0).then_some(serial)
}

fn smbios_system_uuid() -> Option<String> {
    const RAW_SMBIOS: u32 = u32::from_be_bytes(*b"RSMB");
    // SAFETY: a null buffer with size zero is the documented size-query form.
    let size = unsafe { GetSystemFirmwareTable(RAW_SMBIOS, 0, ptr::null_mut(), 0) };
    if size < 8 {
        return None;
    }
    let mut buffer = vec![0_u8; size as usize];
    // SAFETY: `buffer` has `size` writable bytes and remains alive for the call.
    let written = unsafe { GetSystemFirmwareTable(RAW_SMBIOS, 0, buffer.as_mut_ptr(), size) };
    if written < 8 || written as usize > buffer.len() {
        return None;
    }
    let table_length = u32::from_le_bytes(buffer[4..8].try_into().ok()?) as usize;
    let table_end = 8_usize.checked_add(table_length)?.min(written as usize);
    parse_type1_uuid(&buffer[8..table_end])
}

fn parse_type1_uuid(table: &[u8]) -> Option<String> {
    let mut position = 0_usize;
    while position.checked_add(4)? <= table.len() {
        let structure_type = table[position];
        let structure_length = table[position + 1] as usize;
        if structure_length < 4 || position.checked_add(structure_length)? > table.len() {
            return None;
        }
        if structure_type == 1 && structure_length >= 24 {
            let uuid = &table[position + 8..position + 24];
            if uuid.iter().all(|byte| *byte == 0) || uuid.iter().all(|byte| *byte == 0xff) {
                return None;
            }
            let data1 = u32::from_le_bytes(uuid[0..4].try_into().ok()?);
            let data2 = u16::from_le_bytes(uuid[4..6].try_into().ok()?);
            let data3 = u16::from_le_bytes(uuid[6..8].try_into().ok()?);
            return Some(format!(
                "{data1:08X}-{data2:04X}-{data3:04X}-{:02X}{:02X}-{}",
                uuid[8],
                uuid[9],
                uuid[10..]
                    .iter()
                    .map(|byte| format!("{byte:02X}"))
                    .collect::<String>()
            ));
        }
        let mut next = position + structure_length;
        while next + 1 < table.len() && !(table[next] == 0 && table[next + 1] == 0) {
            next += 1;
        }
        if next + 1 >= table.len() {
            return None;
        }
        position = next + 2;
        if structure_type == 127 {
            break;
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_smbios_type1_uuid_with_mixed_endian_fields() {
        let mut table = vec![1, 24, 0, 0, 1, 2, 3, 4];
        table.extend_from_slice(&[
            0x78, 0x56, 0x34, 0x12, 0xbc, 0x9a, 0xf0, 0xde, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66,
            0x77, 0x88,
        ]);
        table.extend_from_slice(&[0, 0]);
        assert_eq!(
            parse_type1_uuid(&table),
            Some("12345678-9ABC-DEF0-1122-334455667788".to_owned())
        );
    }

    #[test]
    fn rejects_invalid_or_placeholder_smbios_records() {
        assert_eq!(parse_type1_uuid(&[1, 3, 0, 0]), None);
        let mut zero_uuid = vec![1, 24, 0, 0, 1, 2, 3, 4];
        zero_uuid.extend_from_slice(&[0; 16]);
        zero_uuid.extend_from_slice(&[0, 0]);
        assert_eq!(parse_type1_uuid(&zero_uuid), None);
    }
}
