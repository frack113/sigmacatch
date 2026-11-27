// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 sigmacatch contributors

//! Import hash (`IMPHASH`) of a PE file, the value Sysmon reports in `Hashes`.
//!
//! The algorithm is the one FireEye's `pefile` defines and Sysmon follows:
//! for every import descriptor, the lowercased DLL name without its
//! `.dll`/`.ocx`/`.sys` extension, then each imported function lowercased (or
//! `ord<NN>` for an import by ordinal), joined with `"%s.%s"`, the whole list
//! joined with commas and MD5-hashed.
//!
//! Only what the hash needs is parsed, and every read is bounds-checked: a
//! truncated or crafted file yields `None` rather than a panic or a wrong
//! value. Ordinals of `ws2_32.dll`/`oleaut32.dll` are hashed as `ord<NN>`
//! where `pefile` resolves them to a name — that difference is documented and
//! only affects binaries importing those two by ordinal.

use std::fmt::Write as _;

/// `IMAGE_DIRECTORY_ENTRY_IMPORT`.
const IMPORT_DIRECTORY: usize = 1;
/// Size of one `IMAGE_IMPORT_DESCRIPTOR`.
const IMPORT_DESCRIPTOR_SIZE: usize = 20;
/// Size of one section header.
const SECTION_HEADER_SIZE: usize = 40;

/// Read a little-endian `u16` at `offset`.
fn u16_at(bytes: &[u8], offset: usize) -> Option<u16> {
    bytes
        .get(offset..offset + 2)?
        .try_into()
        .ok()
        .map(u16::from_le_bytes)
}

/// Read a little-endian `u32` at `offset`.
fn u32_at(bytes: &[u8], offset: usize) -> Option<u32> {
    bytes
        .get(offset..offset + 4)?
        .try_into()
        .ok()
        .map(u32::from_le_bytes)
}

/// One section, as far as RVA translation needs it.
#[derive(Clone, Copy)]
struct Section {
    virtual_address: u32,
    virtual_size: u32,
    raw_size: u32,
    raw_pointer: u32,
}

/// Where the parts of a PE header live.
struct Layout {
    pe32_plus: bool,
    sections: Vec<Section>,
    import_rva: u32,
    import_size: u32,
}

/// Parse the headers, or `None` when this is not a PE file.
fn layout(bytes: &[u8]) -> Option<Layout> {
    if bytes.get(..2)? != b"MZ" {
        return None;
    }
    let pe_offset = u32_at(bytes, 0x3C)? as usize;
    if bytes.get(pe_offset..pe_offset + 4)? != b"PE\0\0" {
        return None;
    }
    let coff = pe_offset + 4;
    let section_count = u16_at(bytes, coff + 2)? as usize;
    let optional_size = u16_at(bytes, coff + 16)? as usize;
    let optional = coff + 20;
    let magic = u16_at(bytes, optional)?;
    // 0x10b: PE32, 0x20b: PE32+.
    let pe32_plus = match magic {
        0x10b => false,
        0x20b => true,
        _ => return None,
    };
    // Data directories start after a fixed-size optional header.
    let directories = optional + if pe32_plus { 112 } else { 96 };
    let entry = directories + IMPORT_DIRECTORY * 8;
    let import_rva = u32_at(bytes, entry)?;
    let import_size = u32_at(bytes, entry + 4)?;

    let sections_at = optional + optional_size;
    let mut sections = Vec::with_capacity(section_count.min(96));
    for index in 0..section_count {
        let at = sections_at + index * SECTION_HEADER_SIZE;
        let Some(raw_size) = u32_at(bytes, at + 16) else {
            break;
        };
        sections.push(Section {
            virtual_size: u32_at(bytes, at + 8)?,
            virtual_address: u32_at(bytes, at + 12)?,
            raw_size,
            raw_pointer: u32_at(bytes, at + 20)?,
        });
    }
    Some(Layout {
        pe32_plus,
        sections,
        import_rva,
        import_size,
    })
}

impl Layout {
    /// File offset of an RVA, or `None` when it points outside the sections.
    fn offset_of(&self, rva: u32) -> Option<usize> {
        for section in &self.sections {
            let span = section.virtual_size.max(section.raw_size);
            if rva >= section.virtual_address && rva < section.virtual_address.saturating_add(span)
            {
                let delta = rva - section.virtual_address;
                if delta >= section.raw_size {
                    return None;
                }
                return Some(section.raw_pointer as usize + delta as usize);
            }
        }
        None
    }

    /// NUL-terminated ASCII string at an RVA, lowercased.
    fn string_at(&self, bytes: &[u8], rva: u32) -> Option<String> {
        let offset = self.offset_of(rva)?;
        let rest = bytes.get(offset..)?;
        let end = rest.iter().position(|byte| *byte == 0)?;
        let text = std::str::from_utf8(&rest[..end]).ok()?;
        Some(text.to_ascii_lowercase())
    }
}

/// `IMPHASH` of a PE file, or `None` for a non-PE or one without imports.
pub fn imphash(bytes: &[u8]) -> Option<String> {
    let parsed = layout(bytes)?;
    if parsed.import_rva == 0 || parsed.import_size == 0 {
        return None;
    }
    let mut pairs: Vec<String> = Vec::new();
    // Walk the import descriptors until the all-zero terminator.
    let descriptors = parsed.import_size as usize / IMPORT_DESCRIPTOR_SIZE;
    for index in 0..descriptors {
        let at = parsed.offset_of(parsed.import_rva)? + index * IMPORT_DESCRIPTOR_SIZE;
        let original_thunk = u32_at(bytes, at)?;
        let name_rva = u32_at(bytes, at + 12)?;
        let first_thunk = u32_at(bytes, at + 16)?;
        if name_rva == 0 || (original_thunk == 0 && first_thunk == 0) {
            break;
        }
        let library = parsed.string_at(bytes, name_rva)?;
        let library = library
            .strip_suffix(".dll")
            .or_else(|| library.strip_suffix(".ocx"))
            .or_else(|| library.strip_suffix(".sys"))
            .unwrap_or(&library);
        let thunk_rva = if original_thunk != 0 {
            original_thunk
        } else {
            first_thunk
        };
        let Some(mut thunk) = parsed.offset_of(thunk_rva) else {
            continue;
        };
        // The thunk array holds addresses: 4 bytes for PE32, 8 for PE32+.
        let width = if parsed.pe32_plus { 8 } else { 4 };
        loop {
            let raw = if width == 8 {
                bytes
                    .get(thunk..thunk + 8)?
                    .try_into()
                    .ok()
                    .map(u64::from_le_bytes)
            } else {
                u32_at(bytes, thunk).map(u64::from)
            };
            let Some(raw) = raw else { break };
            if raw == 0 {
                break;
            }
            let by_ordinal = width == 8 && raw >> 63 == 1 || width == 4 && raw >> 31 == 1;
            if by_ordinal {
                let ordinal = raw & 0xFFFF;
                pairs.push(format!("{library}.ord{ordinal}"));
            } else {
                // IMAGE_IMPORT_BY_NAME: a hint, then the name.
                let Some(name) = parsed.string_at(bytes, raw as u32 + 2) else {
                    break;
                };
                pairs.push(format!("{library}.{name}"));
            }
            thunk += width;
        }
    }
    if pairs.is_empty() {
        return None;
    }
    let joined = pairs.join(",");
    use md5::{Digest, Md5};
    let mut hasher = Md5::new();
    hasher.update(joined.as_bytes());
    let digest = hasher.finalize();
    let mut hex = String::with_capacity(32);
    for byte in digest {
        let _ = write!(hex, "{byte:02x}");
    }
    Some(hex)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal PE32 with one section, one import descriptor and the
    /// given `(library, function)` pairs, all imported by name.
    fn synthetic_pe(library: &str, functions: &[&str]) -> Vec<u8> {
        // Layout: headers (0x400), then one section at RVA 0x1000 / raw 0x400.
        let section_raw = 0x400usize;
        let mut bytes = vec![0u8; section_raw + 0x400];
        bytes[..2].copy_from_slice(b"MZ");
        bytes[0x3C..0x40].copy_from_slice(&0x80u32.to_le_bytes());
        let pe = 0x80usize;
        bytes[pe..pe + 4].copy_from_slice(b"PE\0\0");
        let coff = pe + 4;
        bytes[coff + 2..coff + 4].copy_from_slice(&1u16.to_le_bytes()); // sections
        bytes[coff + 16..coff + 18].copy_from_slice(&224u16.to_le_bytes()); // optional size
        let optional = coff + 20;
        bytes[optional..optional + 2].copy_from_slice(&0x10bu16.to_le_bytes()); // PE32
        let directories = optional + 96;
        let import_entry = directories + IMPORT_DIRECTORY * 8;
        // One descriptor (20 bytes) + terminator, at RVA 0x1000.
        bytes[import_entry..import_entry + 4].copy_from_slice(&0x1000u32.to_le_bytes());
        bytes[import_entry + 4..import_entry + 8].copy_from_slice(&40u32.to_le_bytes());
        // Section header.
        let sections_at = optional + 224;
        bytes[sections_at..sections_at + 5].copy_from_slice(b".text");
        bytes[sections_at + 8..sections_at + 12].copy_from_slice(&0x400u32.to_le_bytes());
        bytes[sections_at + 12..sections_at + 16].copy_from_slice(&0x1000u32.to_le_bytes());
        bytes[sections_at + 16..sections_at + 20].copy_from_slice(&0x400u32.to_le_bytes());
        bytes[sections_at + 20..sections_at + 24].copy_from_slice(&0x400u32.to_le_bytes());

        // Section content, addressed by RVA - 0x1000 + 0x400.
        let at = |rva: usize| section_raw + (rva - 0x1000);
        // Descriptor: OriginalFirstThunk=0x1018, Name=0x1040, FirstThunk=0x1018.
        let descriptor = at(0x1000);
        bytes[descriptor..descriptor + 4].copy_from_slice(&0x1018u32.to_le_bytes());
        bytes[descriptor + 12..descriptor + 16].copy_from_slice(&0x1040u32.to_le_bytes());
        bytes[descriptor + 16..descriptor + 20].copy_from_slice(&0x1018u32.to_le_bytes());
        // Thunk array: one entry per function, then the terminator.
        let thunk_rva = 0x1018usize;
        let mut name_rva = 0x1080usize;
        for (index, function) in functions.iter().enumerate() {
            let entry = at(thunk_rva + index * 4);
            bytes[entry..entry + 4].copy_from_slice(&(name_rva as u32).to_le_bytes());
            let name_at = at(name_rva);
            bytes[name_at..name_at + 2].copy_from_slice(&0u16.to_le_bytes());
            bytes[name_at + 2..name_at + 2 + function.len()].copy_from_slice(function.as_bytes());
            name_rva += 2 + function.len() + 1;
        }
        let dll_at = at(0x1040);
        bytes[dll_at..dll_at + library.len()].copy_from_slice(library.as_bytes());
        bytes
    }

    #[test]
    fn a_single_import_matches_the_pefile_algorithm() {
        let pe = synthetic_pe("KERNEL32.dll", &["ExitProcess"]);
        assert_eq!(
            imphash(&pe).as_deref(),
            Some("f9ade0aa18f660a34a4fa23392e21838")
        );
    }

    #[test]
    fn the_extension_is_stripped_and_names_are_lowercased() {
        let pe = synthetic_pe("NTDLL.DLL", &["RtlUnwindEx"]);
        // "ntdll.rtlunwindex"
        assert_eq!(
            imphash(&pe).as_deref(),
            Some("b1c6297f460a797a0a5888102c70e21e")
        );
    }

    #[test]
    fn a_non_pe_is_rejected() {
        assert_eq!(imphash(b"not a pe"), None);
        assert_eq!(imphash(&[]), None);
    }

    #[test]
    fn a_truncated_pe_is_rejected() {
        let pe = synthetic_pe("KERNEL32.dll", &["ExitProcess"]);
        for cut in [0x10, 0x80, 0x100, 0x200, 0x3F0] {
            let _ = imphash(&pe[..cut]);
        }
    }
}
