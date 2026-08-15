// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 sigmacatch contributors

//! Sysmon-compatible field synthesis (ProcessGuid, Hashes) + MachineGuid read.
//!
//! The synthesized Sysmon events carry a `ProcessGuid` that is stable for the
//! `(machine, process, create-time)` triple — the same algorithm Sysmon uses:
//! `MD5(machineGuid UTF-16LE ‖ CreateTime FILETIME (8B LE) ‖ PID (4B LE))`, the
//! 16-byte digest formatted as a GUID. Parent/child correlation within the ETW
//! stream therefore mirrors Sysmon's.
//!
//! Everything is fail-open: an unreadable MachineGuid simply yields absent
//! ProcessGuid fields (never a lost event).

use sha1::Sha1;
use sha2::{Digest, Sha256};

/// Sysmon-style ProcessGuid from the machine GUID + process create time + PID.
///
/// Deterministic per `(machine_guid, create_time, pid)`: the same process on
/// the same machine always produces the same GUID, so `ProcessGuid`/`ParentProcessGuid`
/// correlate like Sysmon's.
pub fn process_guid(machine_guid: &str, create_time: i64, pid: u32) -> String {
    let mut input: Vec<u8> = Vec::with_capacity(machine_guid.len() * 2 + 12);
    for unit in machine_guid.encode_utf16() {
        input.extend_from_slice(&unit.to_le_bytes());
    }
    input.extend_from_slice(&create_time.to_le_bytes());
    input.extend_from_slice(&pid.to_le_bytes());
    let digest = md5::compute(&input);
    let b = digest.0;
    format!(
        "{:02X}{:02X}{:02X}{:02X}-{:02X}{:02X}-{:02X}{:02X}-{:02X}{:02X}-{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}",
        b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7], b[8], b[9], b[10], b[11], b[12], b[13],
        b[14], b[15]
    )
}

/// Sysmon-style `Hashes` value: `SHA256=…,MD5=…,SHA1=…,IMPHASH=…` (uppercase hex).
pub fn format_hashes(sha256: &str, md5: &str, sha1: &str, imphash: &str) -> String {
    format!("SHA256={sha256},MD5={md5},SHA1={sha1},IMPHASH={imphash}")
}

/// Full-file hashes of a byte slice (SHA256/MD5/SHA1) as uppercase hex.
pub fn hash_bytes(data: &[u8]) -> (String, String, String) {
    (
        hex::encode_upper(Sha256::digest(data)),
        hex::encode_upper(md5::compute(data).0),
        hex::encode_upper(Sha1::digest(data)),
    )
}

/// Machine GUID from `HKLM\SOFTWARE\Microsoft\Cryptography\MachineGuid`
/// (REG_SZ), the seed of the Sysmon ProcessGuid algorithm. `None` on failure.
#[cfg(windows)]
pub fn read_machine_guid() -> Option<String> {
    use windows::core::PCWSTR;
    use windows::Win32::System::Registry::{
        RegGetValueW, HKEY_LOCAL_MACHINE, REG_ROUTINE_FLAGS, REG_SZ, REG_VALUE_TYPE, RRF_RT_REG_SZ,
        RRF_SUBKEY_WOW6464KEY,
    };

    let subkey: Vec<u16> = "SOFTWARE\\Microsoft\\Cryptography"
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();
    let value: Vec<u16> = "MachineGuid"
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();
    let flags: REG_ROUTINE_FLAGS = RRF_RT_REG_SZ | RRF_SUBKEY_WOW6464KEY;

    let mut size = 0u32;
    let rc = unsafe {
        RegGetValueW(
            HKEY_LOCAL_MACHINE,
            PCWSTR(subkey.as_ptr()),
            PCWSTR(value.as_ptr()),
            flags,
            None,
            None,
            Some(&mut size),
        )
    };
    if rc.0 != 0 || size == 0 || size > 128 {
        return None;
    }
    let mut buf = vec![0u16; (size as usize).div_ceil(2)];
    let mut actual = size;
    let mut ty: REG_VALUE_TYPE = Default::default();
    let rc = unsafe {
        RegGetValueW(
            HKEY_LOCAL_MACHINE,
            PCWSTR(subkey.as_ptr()),
            PCWSTR(value.as_ptr()),
            flags,
            Some(&mut ty),
            Some(buf.as_mut_ptr().cast()),
            Some(&mut actual),
        )
    };
    if rc.0 != 0 || ty != REG_SZ {
        return None;
    }
    let len = (actual as usize) / 2;
    let s = String::from_utf16_lossy(&buf[..len])
        .trim_end_matches('\0')
        .to_string();
    (!s.is_empty()).then_some(s)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_process_guid_deterministic() {
        let a = process_guid(
            "68d2ca68-ecb9-4f9b-a7a4-5f1b3f0e2d11",
            133_485_408_000_000_000,
            1234,
        );
        let b = process_guid(
            "68d2ca68-ecb9-4f9b-a7a4-5f1b3f0e2d11",
            133_485_408_000_000_000,
            1234,
        );
        assert_eq!(a, b);
        let (d1, d2) = a.split_once('-').unwrap();
        assert_eq!(d1.len(), 8);
        assert!(d2.chars().all(|c| c == '-' || c.is_ascii_hexdigit()));
    }

    #[test]
    fn test_process_guid_differs_across_pid() {
        let a = process_guid("m", 133_485_408_000_000_000, 1);
        let b = process_guid("m", 133_485_408_000_000_000, 2);
        assert_ne!(a, b);
    }

    #[test]
    fn test_process_guid_differs_across_machine() {
        let a = process_guid("machine-a", 133_485_408_000_000_000, 7);
        let b = process_guid("machine-b", 133_485_408_000_000_000, 7);
        assert_ne!(a, b);
    }

    #[test]
    fn test_format_hashes() {
        assert_eq!(
            format_hashes("AA", "BB", "CC", "DD"),
            "SHA256=AA,MD5=BB,SHA1=CC,IMPHASH=DD"
        );
    }

    #[test]
    fn test_hash_bytes_known() {
        let (sha256, md5, sha1) = hash_bytes(b"abc");
        assert_eq!(
            sha256,
            "BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F20015AD"
        );
        assert_eq!(md5, "900150983CD24FB0D6963F7D28E17F72");
        assert_eq!(sha1, "A9993E364706816ABA3E25717850C26C9CD0D89D");
    }
}
