// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 sigmacatch contributors

//! PE file metadata for Sysmon-style `Hashes` (SHA256/MD5/SHA1/IMPHASH) and
//! version info (`FileVersion`/`Description`/`Product`/`Company`/
//! `OriginalFilename`).
//!
//! The full file is hashed once (matching Sysmon), then the import table is
//! parsed in-memory to build the IMPHASH (pefile algorithm: lowercase module
//! names with `.dll`/`.ocx`/`.sys` stripped, `<module>.<function>` pairs in
//! file order, joined with `,`, MD5). Version info is read through the Win32
//! version-resource API, translated via `\VarFileInfo\Translation` with a
//! `040904b0` fallback.
//!
//! Everything is fail-open: an unreadable file, a file above [`MAX_PE_SIZE`],
//! a truncated header or a missing resource yields absent fields — never a
//! lost event.

// Parked 2026-08-23: callers not wired yet (see quality-plan-20260823.md P0-1).
// This self-removing expectation forces a revisit as soon as any item here is used.
#![cfg_attr(
    not(windows),
    expect(
        dead_code,
        reason = "alive only under the windows target; revisit >= 2026-09-30"
    )
)]

/// Max bytes of a PE we are willing to hash (fail-open above).
const MAX_PE_SIZE: u64 = 256 * 1024 * 1024;

/// Bounds for the string reads inside the import table.
const MAX_IMPORT_NAME_BYTES: usize = 512;

/// Metadata synthesized for one PE image.
#[derive(Debug, Clone, Default)]
pub struct PeInfo {
    /// Full-file SHA256, uppercase hex.
    pub sha256: String,
    /// Full-file MD5, uppercase hex.
    pub md5: String,
    /// Full-file SHA1, uppercase hex.
    pub sha1: String,
    /// Import hash (pefile algorithm), uppercase hex; empty when no imports.
    pub imphash: String,
    pub file_version: Option<String>,
    pub description: Option<String>,
    pub product: Option<String>,
    pub company: Option<String>,
    pub original_filename: Option<String>,
}

/// Hash + version info of the PE at `path`. `None` on failure (fail-open).
pub fn pe_info(path: &str) -> Option<PeInfo> {
    let data = read_bounded(path)?;
    let (sha256, md5, sha1) = super::sysmon::hash_bytes(&data);
    #[cfg(windows)]
    let version = version_info(path);
    #[cfg(not(windows))]
    let version = VersionInfo::default();
    Some(PeInfo {
        sha256,
        md5,
        sha1,
        imphash: imphash(&data),
        file_version: version.file_version,
        description: version.description,
        product: version.product,
        company: version.company,
        original_filename: version.original_filename,
    })
}

/// Read a file bounded by [`MAX_PE_SIZE`]. `None` if unreadable or too large.
fn read_bounded(path: &str) -> Option<Vec<u8>> {
    use std::io::Read;

    let file = std::fs::File::open(path).ok()?;
    let meta = file.metadata().ok()?;
    if meta.len() > MAX_PE_SIZE {
        return None;
    }
    let mut data = Vec::with_capacity(meta.len() as usize);
    file.take(MAX_PE_SIZE + 1).read_to_end(&mut data).ok()?;
    Some(data)
}

/// IMPHASH of a PE image (pefile algorithm). Empty string when the file is not
/// a parseable PE or has no imports.
///
/// Order matters: the import descriptors (and their thunks) are hashed in the
/// order they appear in the file, exactly like Sysmon/pefile — two binaries
/// with the same imports in a different order get different IMPHASHes.
pub fn imphash(data: &[u8]) -> String {
    let mut imports: Vec<String> = Vec::new();
    collect_imports(data, &mut imports);
    if imports.is_empty() {
        return String::new();
    }
    hex::encode_upper(md5::compute(imports.join(",")).0)
}

/// File offset of the PE signature (`PE\0\0`), via the DOS `e_lfanew` field.
fn pe_offset(data: &[u8]) -> Option<usize> {
    if data.len() < 0x40 || data[0] != b'M' || data[1] != b'Z' {
        return None;
    }
    let e_lfanew = u32_at(data, 0x3C)? as usize;
    if e_lfanew + 24 > data.len() || &data[e_lfanew..e_lfanew + 4] != b"PE\0\0" {
        return None;
    }
    Some(e_lfanew)
}

/// `(NumberOfSections, SizeOfOptionalHeader)` from the COFF header.
fn coff_info(data: &[u8], pe: usize) -> Option<(u16, u16)> {
    Some((u16_at(data, pe + 6)?, u16_at(data, pe + 20)?))
}

/// RVA → file offset through the section headers. `None` when not mapped.
fn rva_to_off(data: &[u8], sections: usize, num_sections: u16, rva: u32) -> Option<usize> {
    for i in 0..num_sections as usize {
        let s = sections + i * 40;
        let virtual_size = u32_at(data, s + 8)?;
        let virtual_address = u32_at(data, s + 12)?;
        let size_raw = u32_at(data, s + 16)?;
        let ptr_raw = u32_at(data, s + 20)?;
        let size = virtual_size.max(size_raw);
        if rva >= virtual_address && rva < virtual_address.saturating_add(size) {
            let off = (rva - virtual_address) as usize + ptr_raw as usize;
            if off < data.len() {
                return Some(off);
            }
        }
    }
    None
}

fn read_thunk(data: &[u8], off: usize, size: usize) -> Option<u64> {
    match size {
        4 => Some(u64::from(u32_at(data, off)?)),
        8 => {
            let b = data.get(off..off + 8)?;
            Some(u64::from_le_bytes(b.try_into().ok()?))
        }
        _ => None,
    }
}

/// Collect `<module>.<function>` strings for the import table, pefile style.
fn collect_imports(data: &[u8], out: &mut Vec<String>) {
    let Some(pe) = pe_offset(data) else { return };
    let Some((num_sections, opt_size)) = coff_info(data, pe) else {
        return;
    };
    let Some(magic) = u16_at(data, pe + 24) else {
        return;
    };
    let (thunk_size, ordinal_flag, num_rva_sizes_off) = match magic {
        // PE32: NumberOfRvaAndSizes at optional header offset 0x5C.
        0x010B => (4usize, 0x8000_0000u64, 92usize),
        // PE32+: 0x6C (ImageBase is 8 bytes, BaseOfData absent).
        0x020B => (8usize, 0x8000_0000_0000_0000u64, 108usize),
        _ => return,
    };
    let Some(num_rva_sizes) = u32_at(data, pe + 24 + num_rva_sizes_off) else {
        return;
    };
    if num_rva_sizes < 2 {
        return;
    }
    // Import Table is the second data directory (first at +0x04 past the count).
    let Some(import_rva) = u32_at(data, pe + 24 + num_rva_sizes_off + 12) else {
        return;
    };
    if import_rva == 0 {
        return;
    }
    let sections = pe + 24 + opt_size as usize;
    let Some(mut desc_off) = rva_to_off(data, sections, num_sections, import_rva) else {
        return;
    };

    while let (Some(name_rva), Some(oft_rva), Some(fth_rva)) = (
        u32_at(data, desc_off + 12),
        u32_at(data, desc_off),
        u32_at(data, desc_off + 16),
    ) {
        if name_rva == 0 && oft_rva == 0 && fth_rva == 0 {
            break; // terminator
        }
        let Some(name_off) = rva_to_off(data, sections, num_sections, name_rva) else {
            break;
        };
        let Some(dll_name) = cstr_at(data, name_off, MAX_IMPORT_NAME_BYTES) else {
            break;
        };
        let lib = normalized_lib_name(dll_name);

        let thunk_rva = if oft_rva != 0 { oft_rva } else { fth_rva };
        let Some(mut thunk_off) = rva_to_off(data, sections, num_sections, thunk_rva) else {
            break;
        };
        while let Some(raw) = read_thunk(data, thunk_off, thunk_size) {
            if raw == 0 {
                break;
            }
            if raw & ordinal_flag != 0 {
                let ordinal = (raw & 0xFFFF) as u16;
                out.push(format!("{lib}#{ordinal}"));
            } else if let Some(off) = rva_to_off(data, sections, num_sections, raw as u32)
                && let Some(func) = cstr_at(data, off + 2, MAX_IMPORT_NAME_BYTES)
            {
                out.push(format!("{lib}.{}", func.to_ascii_lowercase()));
            }
            thunk_off += thunk_size;
        }
        desc_off += 20;
    }
}

/// Lowercase module name with any `.dll`/`.ocx`/`.sys` extension stripped.
fn normalized_lib_name(dll: &str) -> String {
    let lower = dll.to_ascii_lowercase();
    let name = lower.rsplit(['\\', '/']).next().unwrap_or(&lower);
    match name.rsplit_once('.') {
        Some((stem, "dll" | "ocx" | "sys")) => stem.to_string(),
        _ => name.to_string(),
    }
}

fn cstr_at(data: &[u8], off: usize, max: usize) -> Option<&str> {
    let tail = data.get(off..)?;
    let end = tail.iter().take(max).position(|&b| b == 0)?;
    let bytes = data.get(off..off + end)?;
    std::str::from_utf8(bytes).ok()
}

fn u16_at(data: &[u8], off: usize) -> Option<u16> {
    let b = data.get(off..off + 2)?;
    Some(u16::from_le_bytes([b[0], b[1]]))
}

fn u32_at(data: &[u8], off: usize) -> Option<u32> {
    let b = data.get(off..off + 4)?;
    Some(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
}

/// Version-resource strings of a PE image (all fail-open).
#[derive(Debug, Clone, Default)]
struct VersionInfo {
    file_version: Option<String>,
    description: Option<String>,
    product: Option<String>,
    company: Option<String>,
    original_filename: Option<String>,
}

/// Upper bound on one version-resource value (WCHARs).
const MAX_VERSION_VALUE_WCHARS: usize = 1024;

/// Read the version resource of `path` via the Win32 version API.
///
/// The sub-block language/codepage comes from `\VarFileInfo\Translation`;
/// when absent, `040904b0` (en-US, Unicode) is assumed. All fields fail-open.
#[cfg(windows)]
fn version_info(path: &str) -> VersionInfo {
    use windows::Win32::Storage::FileSystem::{
        GetFileVersionInfoSizeW, GetFileVersionInfoW, VerQueryValueW,
    };
    use windows::core::PCWSTR;

    let path_w: Vec<u16> = path.encode_utf16().chain(std::iter::once(0)).collect();
    let size = unsafe { GetFileVersionInfoSizeW(PCWSTR(path_w.as_ptr()), None) };
    if size == 0 {
        return VersionInfo::default();
    }
    let mut buf = vec![0u8; size as usize];
    if unsafe { GetFileVersionInfoW(PCWSTR(path_w.as_ptr()), None, size, buf.as_mut_ptr().cast()) }
        .is_err()
    {
        return VersionInfo::default();
    }

    let trans_key: Vec<u16> = "\\VarFileInfo\\Translation"
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();
    let mut ptr: *mut core::ffi::c_void = core::ptr::null_mut();
    let mut len = 0u32;
    let ok = unsafe {
        VerQueryValueW(
            buf.as_ptr().cast(),
            PCWSTR(trans_key.as_ptr()),
            &mut ptr,
            &mut len,
        )
    };
    let (lang, cp) = if ok.as_bool() && !ptr.is_null() && len >= 4 {
        let pair = unsafe { &*ptr.cast::<[u16; 2]>() };
        (pair[0], pair[1])
    } else {
        (0x0409, 0x04b0)
    };

    let subblock = format!("\\StringFileInfo\\{lang:04x}{cp:04x}");
    let read_value = |key: &str| -> Option<String> {
        let k: Vec<u16> = format!("{subblock}\\{key}")
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();
        let mut ptr: *mut core::ffi::c_void = core::ptr::null_mut();
        let mut len = 0u32;
        let ok =
            unsafe { VerQueryValueW(buf.as_ptr().cast(), PCWSTR(k.as_ptr()), &mut ptr, &mut len) };
        if !ok.as_bool() || ptr.is_null() || len == 0 {
            return None;
        }
        // The returned pointer lives inside `buf`; bound the read by the
        // block so we never walk past it, then stop at the first NUL.
        // (`len` is the byte count, but treating it as a generous WCHAR bound
        // is safe because the NUL cut happens first.)
        let base = buf.as_ptr();
        let rel = unsafe { ptr.cast::<u8>().offset_from(base) };
        if rel < 0 {
            return None;
        }
        let avail = (size as usize).saturating_sub(rel as usize) / 2;
        let n = avail.min(MAX_VERSION_VALUE_WCHARS);
        if n == 0 {
            return None;
        }
        let slice = unsafe { std::slice::from_raw_parts(ptr.cast::<u16>(), n) };
        let end = slice.iter().position(|&c| c == 0).unwrap_or(n);
        let s = String::from_utf16_lossy(&slice[..end]);
        let s = s.trim().to_string();
        (!s.is_empty()).then_some(s)
    };

    VersionInfo {
        file_version: read_value("FileVersion"),
        description: read_value("FileDescription"),
        product: read_value("ProductName"),
        company: read_value("CompanyName"),
        original_filename: read_value("OriginalFilename"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Minimal valid PE (one section) with the given import descriptors.
    /// `imports` = `(dll name, function names)`.
    fn make_pe(imports: &[(&str, &[&str])]) -> Vec<u8> {
        make_pe_magic(imports, 0x010B)
    }

    /// PE32+ (x64) variant of [`make_pe`] — different optional-header layout.
    fn make_pe64(imports: &[(&str, &[&str])]) -> Vec<u8> {
        make_pe_magic(imports, 0x020B)
    }

    fn make_pe_magic(imports: &[(&str, &[&str])], magic: u16) -> Vec<u8> {
        const PE_OFF: usize = 0x80;
        const OPT_OFF: usize = PE_OFF + 24;
        const RAW: usize = 0x200;
        const RVA_BASE: u32 = 0x1000;
        const RAW_SIZE: u32 = 0x400;

        // NumberOfRvaAndSizes sits at optional header offset 0x5C (PE32) or
        // 0x6C (PE32+); the import table is the second data directory.
        let (opt_size, num_rva_off) = match magic {
            0x010B => (0xE0usize, 92usize),
            0x020B => (0xF0usize, 108usize),
            _ => unreachable!(),
        };
        let sect_off = OPT_OFF + opt_size;

        // Pass 1: lay out the strings (descriptors at 0x00, strings from 0x40,
        // thunks after the strings — no overlap). Each import-by-name reserves
        // the 2-byte hint before the function name.
        let mut layout: Vec<(usize, Vec<usize>)> = Vec::new();
        let mut cursor = 0x40usize;
        for (dll, funcs) in imports {
            let name_off = cursor;
            cursor += format!("{dll}\0").len();
            let mut funcs_off = Vec::new();
            for f in *funcs {
                funcs_off.push(cursor); // IMAGE_IMPORT_BY_NAME: hint then name
                cursor += 2 + format!("{f}\0").len();
            }
            layout.push((name_off, funcs_off));
        }
        let thunks_start = cursor;

        let mut data = vec![0u8; RAW + RAW_SIZE as usize];

        data[0] = b'M';
        data[1] = b'Z';
        data[0x3C..0x40].copy_from_slice(&(PE_OFF as u32).to_le_bytes());
        data[PE_OFF..PE_OFF + 4].copy_from_slice(b"PE\0\0");
        data[PE_OFF + 6..PE_OFF + 8].copy_from_slice(&1u16.to_le_bytes()); // NumberOfSections
        data[PE_OFF + 20..PE_OFF + 22].copy_from_slice(&(opt_size as u16).to_le_bytes());
        data[OPT_OFF..OPT_OFF + 2].copy_from_slice(&magic.to_le_bytes());
        data[OPT_OFF + num_rva_off..OPT_OFF + num_rva_off + 4].copy_from_slice(&2u32.to_le_bytes()); // NumberOfRvaAndSizes
        let import_dir_off = OPT_OFF + num_rva_off + 12; // data directory[1]
        data[import_dir_off..import_dir_off + 4].copy_from_slice(&RVA_BASE.to_le_bytes());
        data[sect_off + 8..sect_off + 12].copy_from_slice(&RAW_SIZE.to_le_bytes()); // VirtualSize
        data[sect_off + 12..sect_off + 16].copy_from_slice(&RVA_BASE.to_le_bytes()); // VirtualAddress
        data[sect_off + 16..sect_off + 20].copy_from_slice(&RAW_SIZE.to_le_bytes()); // SizeOfRawData
        data[sect_off + 20..sect_off + 24].copy_from_slice(&(RAW as u32).to_le_bytes()); // PointerToRawData

        // Pass 2: write strings + thunks + descriptors.
        let thunk_size = if magic == 0x020B { 8 } else { 4 };
        let mut desc_off = 0usize;
        let mut thunk_off = thunks_start;
        for ((dll, funcs), (name_off, funcs_off)) in imports.iter().zip(&layout) {
            let name_bytes = format!("{dll}\0").into_bytes();
            data[RAW + name_off..RAW + name_off + name_bytes.len()].copy_from_slice(&name_bytes);
            let name_rva = RVA_BASE + *name_off as u32;

            let mut entries = Vec::new();
            for (f, fo) in funcs.iter().zip(funcs_off) {
                let f_bytes = format!("{f}\0").into_bytes();
                data[RAW + fo + 2..RAW + fo + 2 + f_bytes.len()].copy_from_slice(&f_bytes);
                entries.push(u64::from(RVA_BASE + *fo as u32));
            }
            entries.push(0);

            let oft_rva = RVA_BASE + thunk_off as u32;
            let mut write_thunks = |dst: usize, vals: &[u64]| {
                for (i, e) in vals.iter().enumerate() {
                    match thunk_size {
                        4 => data[dst + i * 4..dst + i * 4 + 4]
                            .copy_from_slice(&(*e as u32).to_le_bytes()),
                        _ => data[dst + i * 8..dst + i * 8 + 8].copy_from_slice(&e.to_le_bytes()),
                    }
                }
            };
            write_thunks(RAW + thunk_off, &entries);
            let fth_off = thunk_off + entries.len() * thunk_size;
            write_thunks(RAW + fth_off, &entries);
            thunk_off += entries.len() * thunk_size * 2;

            let fth_rva = RVA_BASE + fth_off as u32;
            data[RAW + desc_off..RAW + desc_off + 4].copy_from_slice(&oft_rva.to_le_bytes());
            data[RAW + desc_off + 12..RAW + desc_off + 16].copy_from_slice(&name_rva.to_le_bytes());
            data[RAW + desc_off + 16..RAW + desc_off + 20].copy_from_slice(&fth_rva.to_le_bytes());
            desc_off += 20;
        }
        data
    }

    fn md5_upper(s: &str) -> String {
        hex::encode_upper(md5::compute(s).0)
    }

    #[test]
    fn test_imphash_order_sensitive() {
        let pe = make_pe(&[
            ("KERNEL32.dll", &["CreateFileW", "DeleteFileW"]),
            ("fltmgr.sys", &["FilterSendMessage"]),
        ]);
        let mut imports = Vec::new();
        collect_imports(&pe, &mut imports);
        let expected =
            md5_upper("kernel32.createfilew,kernel32.deletefilew,fltmgr.filtersendmessage");
        assert_eq!(imphash(&pe), expected);
    }

    #[test]
    fn test_imphash_different_order_differs() {
        let a = make_pe(&[("A.dll", &["X", "Y"]), ("B.dll", &["Z"])]);
        let b = make_pe(&[("B.dll", &["Z"]), ("A.dll", &["X", "Y"])]);
        assert_ne!(imphash(&a), imphash(&b));
    }

    #[test]
    fn test_imphash_deterministic() {
        let a = make_pe(&[("B.dll", &["One"])]);
        let b = make_pe(&[("B.dll", &["One"])]);
        assert_eq!(imphash(&a), imphash(&b));
    }

    #[test]
    fn test_imphash_pe32plus() {
        let pe = make_pe64(&[
            ("KERNEL32.dll", &["CreateFileW"]),
            ("ws2_32.dll", &["send"]),
        ]);
        let mut imports = Vec::new();
        collect_imports(&pe, &mut imports);
        imports.sort();
        let expected = md5_upper("kernel32.createfilew,ws2_32.send");
        assert_eq!(imphash(&pe), expected);
    }

    #[test]
    fn test_imphash_no_imports_empty() {
        assert_eq!(imphash(&make_pe(&[])), "");
    }

    #[test]
    fn test_imphash_not_pe_empty() {
        assert_eq!(imphash(b"this is not a pe image"), "");
    }

    #[test]
    fn test_imphash_ordinal_import() {
        // A function slot with the ordinal flag set → `module#ordinal`.
        let mut pe = make_pe(&[("ntdll.dll", &["NtReadFile"])]);
        // Rewrite the OFT array's first entry to an ordinal (0x8000_0000 | 7).
        const PE_OFF: usize = 0x80;
        let opt_size = u16_at(&pe, PE_OFF + 20).unwrap() as usize;
        let sections = PE_OFF + 24 + opt_size;
        let import_rva = u32_at(&pe, PE_OFF + 128).unwrap();
        let desc_off = rva_to_off(&pe, sections, 1, import_rva).unwrap();
        let oft_rva = u32_at(&pe, desc_off).unwrap();
        let oft_off = rva_to_off(&pe, sections, 1, oft_rva).unwrap();
        pe[oft_off..oft_off + 4].copy_from_slice(&(0x8000_0000u32 | 7u32).to_le_bytes());

        let expected = md5_upper("ntdll#7");
        assert_eq!(imphash(&pe), expected);
    }

    #[test]
    fn test_normalized_lib_name() {
        assert_eq!(normalized_lib_name("KERNEL32.dll"), "kernel32");
        assert_eq!(
            normalized_lib_name("C:\\Windows\\System32\\ntdll.DLL"),
            "ntdll"
        );
        assert_eq!(normalized_lib_name("fltmgr.sys"), "fltmgr");
        assert_eq!(normalized_lib_name("libfoo.so"), "libfoo.so");
        assert_eq!(normalized_lib_name("kernelbase"), "kernelbase");
    }
}
