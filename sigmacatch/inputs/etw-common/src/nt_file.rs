// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 sigmacatch contributors

//! Small file helpers for the NT paths the kernel sensor reports.
//!
//! The driver and the ETW kernel providers name files the way the kernel does
//! (`\Device\HarddiskVolume3\Users\…`), while user mode opens files through DOS
//! paths. The conversions here are all the mapping layer needs to *read* such a
//! file: a header check, or a hash.

use windows::Win32::Foundation::CloseHandle;
use windows::Win32::Storage::FileSystem::{
    CreateFileW, FILE_GENERIC_READ, FILE_NAME_NORMALIZED, FILE_READ_ATTRIBUTES, FILE_SHARE_DELETE,
    FILE_SHARE_READ, FILE_SHARE_WRITE, GETFINALPATHNAMEBYHANDLE_FLAGS, GetFinalPathNameByHandleW,
    OPEN_EXISTING, ReadFile, VOLUME_NAME_DOS, VOLUME_NAME_NT,
};
use windows::core::PCWSTR;

/// Upper bound on the bytes read for a hash; larger content is hashed from
/// its start only, which the callers document.
pub const HASH_LIMIT: usize = 16 * 1024 * 1024;

/// `\\?\GLOBALROOT` prefix: the documented way to open a device path from
/// user mode.
const GLOBALROOT: &str = r"\\?\GLOBALROOT";

/// Read up to `len` bytes from the start of the file at an NT path.
///
/// `None` means the file could not be opened or read: a race with a delete, a
/// path that is not a file, a permission. Callers treat that as "no
/// information", never as an answer.
pub fn read_prefix(nt_path: &str, len: usize) -> Option<Vec<u8>> {
    if !nt_path.starts_with('\\') {
        return None;
    }
    let wide: Vec<u16> = format!("{GLOBALROOT}{nt_path}")
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();
    read_wide(&wide, len)
}

/// Open the file named by `wide` (NUL-terminated) and read up to `len` bytes
/// from its start.
fn read_wide(wide: &[u16], len: usize) -> Option<Vec<u8>> {
    // SAFETY: `wide` is NUL-terminated and valid for the call.
    let handle = unsafe {
        CreateFileW(
            PCWSTR(wide.as_ptr()),
            FILE_GENERIC_READ.0,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            None,
            OPEN_EXISTING,
            Default::default(),
            None,
        )
    }
    .ok()?;
    let mut buffer = vec![0u8; len];
    let mut total = 0usize;
    while total < buffer.len() {
        let mut read = 0u32;
        // SAFETY: the handle comes from `CreateFileW`; `buffer` is sized for
        // `len - total` more bytes.
        let ok =
            unsafe { ReadFile(handle, Some(&mut buffer[total..]), Some(&mut read), None) }.is_ok();
        if !ok || read == 0 {
            break;
        }
        total += read as usize;
    }
    // SAFETY: the handle came from `CreateFileW` exactly once.
    let _ = unsafe { CloseHandle(handle) };
    buffer.truncate(total);
    (!buffer.is_empty()).then_some(buffer)
}

/// NT form (`\Device\HarddiskVolume3\…`) of a DOS path, or `None` when the
/// file cannot be opened.
///
/// `GetFinalPathNameByHandleW` with `VOLUME_NAME_NT` answers exactly the shape
/// the ETW kernel providers use, which is what a comparison needs; mapping the
/// drive letters by hand (`QueryDosDevice`) got it wrong in a way that is hard
/// to see from the outside.
pub fn nt_path_of_dos(dos_path: &str) -> Option<String> {
    let wide: Vec<u16> = format!(r"\\?\{dos_path}")
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();
    // SAFETY: `wide` is NUL-terminated and valid for the call.
    let handle = unsafe {
        CreateFileW(
            PCWSTR(wide.as_ptr()),
            FILE_READ_ATTRIBUTES.0,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            None,
            OPEN_EXISTING,
            Default::default(),
            None,
        )
    }
    .ok()?;
    let mut buffer = vec![0u16; 32768];
    // SAFETY: the handle comes from `CreateFileW`; `buffer` describes itself.
    let len = unsafe {
        GetFinalPathNameByHandleW(
            handle,
            &mut buffer,
            GETFINALPATHNAMEBYHANDLE_FLAGS(FILE_NAME_NORMALIZED.0 | VOLUME_NAME_NT.0),
        )
    } as usize;
    // SAFETY: the handle came from `CreateFileW` exactly once.
    let _ = unsafe { CloseHandle(handle) };
    if len == 0 || len > buffer.len() {
        return None;
    }
    Some(String::from_utf16_lossy(&buffer[..len]))
}

/// [`read_prefix`] for a DOS path, through the `\\?\` long-path prefix.
fn read_dos_prefix(dos_path: &str, len: usize) -> Option<Vec<u8>> {
    let wide: Vec<u16> = format!(r"\\?\{dos_path}")
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();
    read_wide(&wide, len)
}

/// Creation time of the file at an NT path, as FILETIME ticks.
pub fn creation_ticks(nt_path: &str) -> Option<i64> {
    let wide: Vec<u16> = format!("{GLOBALROOT}{nt_path}")
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();
    // SAFETY: `wide` is NUL-terminated and valid for the call.
    let handle = unsafe {
        CreateFileW(
            PCWSTR(wide.as_ptr()),
            FILE_GENERIC_READ.0,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            None,
            OPEN_EXISTING,
            Default::default(),
            None,
        )
    }
    .ok()?;
    let mut created = windows::Win32::Foundation::FILETIME::default();
    // SAFETY: `created` is a valid out-pointer for the handle.
    let read = unsafe {
        windows::Win32::Storage::FileSystem::GetFileTime(handle, Some(&raw mut created), None, None)
    };
    // SAFETY: the handle came from `CreateFileW` exactly once.
    let _ = unsafe { CloseHandle(handle) };
    read.ok()?;
    let ticks = (u64::from(created.dwHighDateTime) << 32) | u64::from(created.dwLowDateTime);
    i64::try_from(ticks).ok().filter(|ticks| *ticks > 0)
}

/// Hash a file the way Sysmon spells `Hashes` (`SHA1=…,SHA256=…,MD5=…`), from
/// the first bytes only — see `HASH_LIMIT`. `None` when the file cannot be
/// read, which a caller must treat as "no information", not as an answer.
///
/// Accepts the two path shapes the collectors see: the kernel's NT form and
/// the DOS form of a live process.
pub fn hashes_of(path: &str) -> Option<String> {
    let bytes = if path.starts_with('\\') {
        read_prefix(path, HASH_LIMIT)?
    } else {
        read_dos_prefix(path, HASH_LIMIT)?
    };
    let mut out = String::new();
    {
        use sha1::{Digest, Sha1};
        let mut hasher = Sha1::new();
        hasher.update(&bytes);
        let digest = hasher.finalize();
        out.push_str("SHA1=");
        for byte in digest.iter() {
            out.push_str(&format!("{byte:02x}"));
        }
    }
    {
        use sha2::{Digest as D2, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(&bytes);
        let digest = hasher.finalize();
        out.push_str(",SHA256=");
        for byte in digest.iter() {
            out.push_str(&format!("{byte:02x}"));
        }
    }
    {
        use md5::{Digest as D3, Md5};
        let mut hasher = Md5::new();
        hasher.update(&bytes);
        let digest = hasher.finalize();
        out.push_str(",MD5=");
        for byte in digest.iter() {
            out.push_str(&format!("{byte:02x}"));
        }
    }
    if let Some(imphash) = crate::pe_format::imphash(&bytes) {
        out.push_str(",IMPHASH=");
        out.push_str(&imphash);
    }
    Some(out)
}

/// DOS form (`C:\Windows\…`) of an NT device path.
///
/// The signature APIs take a path they open themselves, so the kernel name has
/// to be translated first; `GetFinalPathNameByHandleW` with `VOLUME_NAME_DOS`
/// is the reliable direction (enumerating drives by hand is not).
pub fn dos_path_of_nt(nt_path: &str) -> Option<String> {
    if !nt_path.starts_with('\\') {
        return Some(nt_path.to_string());
    }
    let wide: Vec<u16> = format!("{GLOBALROOT}{nt_path}")
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();
    // SAFETY: `wide` is NUL-terminated and valid for the call.
    let handle = unsafe {
        CreateFileW(
            PCWSTR(wide.as_ptr()),
            FILE_READ_ATTRIBUTES.0,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            None,
            OPEN_EXISTING,
            Default::default(),
            None,
        )
    }
    .ok()?;
    let mut buffer = vec![0u16; 32768];
    // SAFETY: the handle comes from `CreateFileW`; `buffer` describes itself.
    let len = unsafe {
        GetFinalPathNameByHandleW(
            handle,
            &mut buffer,
            GETFINALPATHNAMEBYHANDLE_FLAGS(FILE_NAME_NORMALIZED.0 | VOLUME_NAME_DOS.0),
        )
    } as usize;
    // SAFETY: the handle came from `CreateFileW` exactly once.
    let _ = unsafe { CloseHandle(handle) };
    if len == 0 || len > buffer.len() {
        return None;
    }
    let path = String::from_utf16_lossy(&buffer[..len]);
    Some(path.strip_prefix(r"\\?\").unwrap_or(&path).to_string())
}

/// Compare an NT image path with the DOS image path of a live process,
/// case-insensitively.
pub fn same_file(nt_path: &str, dos_path: &str) -> bool {
    nt_path_of_dos(dos_path).is_some_and(|path| path.eq_ignore_ascii_case(nt_path))
}
