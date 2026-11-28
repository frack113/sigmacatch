// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 sigmacatch contributors

//! Version resource of an image, the fields Sysmon reports on EID 7:
//! `FileVersion`, `Description`, `Product`, `Company`, `OriginalFileName`.
//!
//! The block is read through `GetFileVersionInfoW` and `VerQueryValueW`, once
//! per language/codepage pair the resource declares (the first pair wins). A
//! file without a version resource — most non-Microsoft binaries — yields
//! `None` and the fields stay absent, which is what Sysmon does.

use windows::Win32::Storage::FileSystem::{
    GetFileVersionInfoSizeW, GetFileVersionInfoW, VerQueryValueW,
};
use windows::core::PCWSTR;

/// The version strings Sysmon exposes, all optional.
#[derive(Debug, Clone, Default)]
pub struct VersionInfo {
    /// `FileVersion`.
    pub file_version: Option<String>,
    /// `Description`.
    pub description: Option<String>,
    /// `Product`.
    pub product: Option<String>,
    /// `Company`.
    pub company: Option<String>,
    /// `OriginalFileName`.
    pub original_filename: Option<String>,
}

impl VersionInfo {
    /// True when nothing was read.
    pub fn is_empty(&self) -> bool {
        self.file_version.is_none()
            && self.description.is_none()
            && self.product.is_none()
            && self.company.is_none()
            && self.original_filename.is_none()
    }
}

/// Read the version resource of the file at `path`.
pub fn of_file(path: &str) -> Option<VersionInfo> {
    let wide: Vec<u16> = path.encode_utf16().chain(std::iter::once(0)).collect();
    // SAFETY: the path is NUL-terminated; the call only reads.
    let size = unsafe { GetFileVersionInfoSizeW(PCWSTR(wide.as_ptr()), None) };
    if size == 0 {
        return None;
    }
    let mut block = vec![0u8; size as usize];
    // SAFETY: `block` is exactly `size` bytes, as the size call reported.
    unsafe { GetFileVersionInfoW(PCWSTR(wide.as_ptr()), None, size, block.as_mut_ptr().cast()) }
        .ok()?;

    // The resource declares its language and code page; use the first pair.
    let (language, code_page) = translation(&block)?;
    let prefix = format!(r"\StringFileInfo\{language:04x}{code_page:04x}\");

    let info = VersionInfo {
        file_version: string(&block, &format!("{prefix}FileVersion")),
        description: string(&block, &format!("{prefix}FileDescription")),
        product: string(&block, &format!("{prefix}ProductName")),
        company: string(&block, &format!("{prefix}CompanyName")),
        original_filename: string(&block, &format!("{prefix}OriginalFilename")),
    };
    (!info.is_empty()).then_some(info)
}

/// Raw pointer and byte length of one entry of the version block.
fn entry(block: &[u8], key: &str) -> Option<(*mut core::ffi::c_void, u32)> {
    let key: Vec<u16> = key.encode_utf16().chain(std::iter::once(0)).collect();
    let mut pointer: *mut core::ffi::c_void = core::ptr::null_mut();
    let mut length = 0u32;
    // SAFETY: `block` is the version block and `key` is NUL-terminated.
    let found = unsafe {
        VerQueryValueW(
            block.as_ptr().cast(),
            PCWSTR(key.as_ptr()),
            &raw mut pointer,
            &raw mut length,
        )
    };
    if !found.as_bool() || pointer.is_null() || length == 0 {
        return None;
    }
    Some((pointer, length))
}

/// The `\VarFileInfo\Translation` pairs, as `(language, code page)`.
fn translation(block: &[u8]) -> Option<(u16, u16)> {
    let (pointer, length) = entry(block, r"\VarFileInfo\Translation")?;
    if length < 4 {
        return None;
    }
    // SAFETY: the provider returned `length` bytes at `pointer`.
    let bytes = unsafe { core::slice::from_raw_parts(pointer.cast::<u8>(), length as usize) };
    Some((
        u16::from_le_bytes([bytes[0], bytes[1]]),
        u16::from_le_bytes([bytes[2], bytes[3]]),
    ))
}

/// One `StringFileInfo` value, empty strings dropped.
///
/// `VerQueryValueW` reports a *string* entry's size in characters, not in
/// bytes — halving it again silently truncated every value.
fn string(block: &[u8], key: &str) -> Option<String> {
    let (pointer, length) = entry(block, key)?;
    let units = length as usize;
    // SAFETY: the provider returned `length` bytes at `pointer`.
    let text = unsafe { core::slice::from_raw_parts(pointer.cast::<u16>(), units) };
    let text = String::from_utf16_lossy(text)
        .trim_matches('\0')
        .trim()
        .to_string();
    (!text.is_empty()).then_some(text)
}
