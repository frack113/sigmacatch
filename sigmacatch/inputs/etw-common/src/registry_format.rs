// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 sigmacatch contributors

//! Pure formatting for registry telemetry: hive paths and value data.
//!
//! Kept free of any Windows dependency so the rules that matter — the hive
//! abbreviation Sigma rules are written against, and the `Details` spelling
//! (`DWORD (0x00000001)`, `Binary Data`) — are unit-tested on every build,
//! including the Linux CI job that never compiles the ETW collector.

/// `REG_*` value types, from `winnt.h`.
const REG_SZ: u32 = 1;
const REG_EXPAND_SZ: u32 = 2;
const REG_DWORD: u32 = 4;
const REG_DWORD_BIG_ENDIAN: u32 = 5;
const REG_LINK: u32 = 6;
const REG_MULTI_SZ: u32 = 7;
const REG_QWORD: u32 = 11;

/// Render value data the way Sysmon renders `Details`.
///
/// Rules are written against Sysmon's spelling — `DWORD (0x00000001)`, and
/// `Binary Data` for anything that is neither a string nor an integer — so
/// only that spelling is useful here.
pub fn format_value_data(value_type: u32, data: &[u8]) -> Option<String> {
    if data.is_empty() {
        return None;
    }
    let rendered = match value_type {
        REG_SZ | REG_EXPAND_SZ | REG_LINK => decode_utf16(data),
        REG_MULTI_SZ => decode_utf16(data)
            .split('\0')
            .filter(|entry| !entry.is_empty())
            .collect::<Vec<_>>()
            .join("\n"),
        REG_DWORD => format!("DWORD (0x{:08X})", u32::from_le_bytes(first_bytes(data)?)),
        REG_DWORD_BIG_ENDIAN => {
            format!("DWORD (0x{:08X})", u32::from_be_bytes(first_bytes(data)?))
        }
        REG_QWORD => format!("QWORD (0x{:016X})", u64::from_le_bytes(first_bytes(data)?)),
        // REG_NONE, REG_BINARY and anything this build has never seen.
        _ => "Binary Data".to_string(),
    };
    Some(rendered)
}

fn first_bytes<const N: usize>(data: &[u8]) -> Option<[u8; N]> {
    data.get(..N)?.try_into().ok()
}

/// Decode the UTF-16 payload of a string value, dropping the trailing NULs.
fn decode_utf16(data: &[u8]) -> String {
    let (pairs, _odd_trailing_byte) = data.as_chunks::<2>();
    let units: Vec<u16> = pairs.iter().copied().map(u16::from_le_bytes).collect();
    String::from_utf16_lossy(&units)
        .trim_end_matches('\0')
        .to_string()
}

/// Native registry path → Sysmon `TargetObject` form.
///
/// `\REGISTRY\MACHINE\SOFTWARE\X` becomes `HKLM\SOFTWARE\X`; the prefix is
/// matched case-insensitively because the provider emits both `\REGISTRY` and
/// `\Registry`.
pub fn abbreviate(path: &str) -> String {
    let rest = path
        .strip_prefix("\\REGISTRY\\")
        .or_else(|| path.strip_prefix("\\Registry\\"))
        .unwrap_or(path);
    if let Some(tail) = strip_prefix_ignore_case(rest, "MACHINE") {
        format!("HKLM{tail}")
    } else if let Some(tail) = strip_prefix_ignore_case(rest, "USER") {
        format!("HKU{tail}")
    } else {
        path.to_string()
    }
}

/// Case-insensitive `strip_prefix` for the two hive names.
fn strip_prefix_ignore_case<'a>(value: &'a str, prefix: &str) -> Option<&'a str> {
    if value.len() < prefix.len() || !value.is_char_boundary(prefix.len()) {
        return None;
    }
    let (head, tail) = value.split_at(prefix.len());
    head.eq_ignore_ascii_case(prefix).then_some(tail)
}

/// Decode a lowercase hex string back to bytes.
pub fn from_hex(hex: &str) -> Option<Vec<u8>> {
    if hex.is_empty() || !hex.len().is_multiple_of(2) {
        return None;
    }
    let bytes = hex.as_bytes();
    let mut out = Vec::with_capacity(bytes.len() / 2);
    for pair in bytes.as_chunks::<2>().0 {
        let high = (pair[0] as char).to_digit(16)?;
        let low = (pair[1] as char).to_digit(16)?;
        out.push(((high << 4) | low) as u8);
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn machine_hive_becomes_hklm() {
        assert_eq!(
            abbreviate(r"\REGISTRY\MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
            r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
        );
    }

    #[test]
    fn the_provider_mixes_the_case_of_its_own_prefix() {
        assert_eq!(
            abbreviate(r"\Registry\Machine\HARDWARE\DESCRIPTION\System"),
            r"HKLM\HARDWARE\DESCRIPTION\System"
        );
    }

    #[test]
    fn user_hive_becomes_hku_and_keeps_the_sid() {
        assert_eq!(
            abbreviate(r"\REGISTRY\USER\S-1-5-21-1-2-3-1001\Software\X"),
            r"HKU\S-1-5-21-1-2-3-1001\Software\X"
        );
    }

    fn utf16(text: &str) -> Vec<u8> {
        text.encode_utf16()
            .chain(std::iter::once(0))
            .flat_map(|unit| unit.to_le_bytes())
            .collect()
    }

    #[test]
    fn details_is_the_value_data_not_the_name() {
        assert_eq!(
            format_value_data(REG_SZ, &utf16("powershell -enc SQBFAFgA")).as_deref(),
            Some("powershell -enc SQBFAFgA")
        );
        assert_eq!(
            format_value_data(REG_DWORD, &1u32.to_le_bytes()).as_deref(),
            Some("DWORD (0x00000001)")
        );
        assert_eq!(
            format_value_data(REG_QWORD, &42u64.to_le_bytes()).as_deref(),
            Some("QWORD (0x000000000000002A)")
        );
        assert_eq!(
            format_value_data(7, &utf16("a\0b")).as_deref(),
            Some("a\nb"),
            "REG_MULTI_SZ entries are newline separated"
        );
        assert_eq!(
            format_value_data(3, &[0xde, 0xad]).as_deref(),
            Some("Binary Data")
        );
        assert_eq!(format_value_data(REG_SZ, &[]), None);
    }

    #[test]
    fn hex_round_trips() {
        assert_eq!(from_hex("0a2bff").as_deref(), Some(&[0x0a, 0x2b, 0xff][..]));
        assert_eq!(from_hex("0a2"), None);
        assert_eq!(from_hex(""), None);
    }
}
