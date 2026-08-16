// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 sigmacatch contributors

//! NT device path → Win32 path translation (AD-8).
//!
//! Kernel ETW providers emit file names as NT device paths
//! (`\Device\HarddiskVolume3\WINDOWS\SYSTEM32\WER.DLL`). Sigma rules filter on
//! Win32 paths (`C:\Windows\System32\…`), so the translation is applied at
//! **synthesis time, in one place** — every path field of a synthesized event
//! goes through [`normalize`].
//!
//! The core is pure (testable on any platform); the mount table is built on
//! Windows by enumerating every volume (`FindFirstVolumeW`/`FindNextVolumeW`)
//! and resolving each via `QueryDosDeviceW` / `GetVolumePathNamesForVolumeNameW`.
//! Fail-open: untranslated paths are kept as-is (never an error).

/// Normalize a path against a mount table (longest-prefix match).
///
/// Handles, in order:
/// - `\??\C:\…` and `\\?\C:\…` → already Win32 → prefix stripped.
/// - `\\?\Volume{GUID}\…` → drive letter, via the mount-table entry whose
///   prefix is that exact volume name (added at snapshot time).
/// - `\Device\HarddiskVolumeN\…` → `C:\…` via the device→drive entries.
/// - anything else → returned unchanged (fail-open).
///
/// `mounts` is a list of `(prefix_with_trailing_backslash, replacement)`
/// where the replacement is a drive root such as `C:\`.
pub fn normalize(path: &str, mounts: &[(String, String)]) -> String {
    let p = path.trim();
    if p.is_empty() {
        return String::new();
    }

    // `\??\C:\…` and `\\?\C:\…` are already Win32-pathed (just quoted as NT
    // object names): strip the prefix and hand them back.
    let win32_form = p
        .strip_prefix("\\??\\")
        .or_else(|| p.strip_prefix("\\\\?\\"));
    if let Some(rest) = win32_form {
        if is_win32_rooted(rest) {
            return rest.to_string();
        }
        // Fall through for `\\?\Volume{GUID}\…` — matched against the table.
        if !rest.starts_with("Volume{") {
            return p.to_string();
        }
    }

    // Longest-prefix match over the mount table (device prefixes and volume
    // GUIDs alike — both stored with a trailing backslash). A bare device or
    // volume root (`\Device\HarddiskVolume4`, no trailing backslash) matches
    // the prefix with its backslash trimmed.
    let mut best: Option<(usize, &str)> = None;
    for (prefix, replacement) in mounts {
        if prefix.is_empty() {
            continue;
        }
        if p.starts_with(prefix.as_str()) {
            if best.is_none_or(|(best_len, _)| prefix.len() > best_len) {
                best = Some((prefix.len(), replacement.as_str()));
            }
        } else if let Some(noslash) = prefix.strip_suffix('\\')
            && p == noslash
            && best.is_none_or(|(best_len, _)| prefix.len() > best_len)
        {
            best = Some((prefix.len(), replacement.as_str()));
        }
    }

    match best {
        Some((prefix_len, replacement)) => {
            let rest = p.get(prefix_len..).unwrap_or("");
            format!("{replacement}{rest}")
        }
        None => p.to_string(),
    }
}

/// Whether `p` starts like a Win32 rooted path (`X:\…`).
fn is_win32_rooted(p: &str) -> bool {
    let b = p.as_bytes();
    b.len() >= 3 && b[1] == b':' && b[2] == b'\\'
}

/// Build the mount table on Windows with two passes:
///
/// 1. Every **drive letter** (`GetLogicalDriveStringsW`): resolves the device
///    target (`QueryDosDeviceW`) and the volume GUID mount point
///    (`GetVolumeNameForVolumeMountPointW`). This is the only pass that sees
///    non-`HarddiskVolume` devices — e.g. virtio-fs shared volumes whose target
///    is `\Device\Volume{…}`.
/// 2. Every **volume**, drive-lettered or not (`FindFirstVolumeW`/`FindNextVolumeW`):
///    resolves the device target and mount points
///    (`GetVolumePathNamesForVolumeNameW`). A letter-less volume (EFI, System
///    Reserved, …) falls back to its volume GUID — a valid Win32 path — instead
///    of leaking a raw NT device path.
///
/// The two passes overlap harmlessly (longest-prefix match in [`normalize`]).
#[cfg(windows)]
pub fn build_mounts() -> Vec<(String, String)> {
    use windows::Win32::Storage::FileSystem::{
        FindFirstVolumeW, FindNextVolumeW, FindVolumeClose, GetLogicalDriveStringsW,
        GetVolumeNameForVolumeMountPointW, GetVolumePathNamesForVolumeNameW, QueryDosDeviceW,
    };
    use windows::core::PCWSTR;

    let mut mounts: Vec<(String, String)> = Vec::new();

    // ── Pass 1: drive letters ────────────────────────────────────────────────
    let mut buf = [0u16; 128];
    let len = unsafe { GetLogicalDriveStringsW(Some(&mut buf)) };
    if len != 0 && (len as usize) <= buf.len() {
        // NUL-separated "C:\" strings, double-NUL terminated.
        for drive in buf[..len as usize]
            .split(|c| *c == 0)
            .filter(|s| !s.is_empty())
            .map(String::from_utf16_lossy)
        {
            let name = drive.trim_end_matches('\\'); // "C:"
            if name.len() != 2 || !name.ends_with(':') {
                continue;
            }
            // Drive letter → device target, e.g. `C:` → `\Device\HarddiskVolume3`.
            let name_w: Vec<u16> = name.encode_utf16().chain(std::iter::once(0)).collect();
            let mut target = [0u16; 260];
            let n = unsafe { QueryDosDeviceW(PCWSTR(name_w.as_ptr()), Some(&mut target)) };
            if n != 0 {
                let device = String::from_utf16_lossy(trim_utf16_nul(&target[..n as usize]));
                if device.starts_with('\\') {
                    mounts.push((with_trailing_sep(&device), format!("{name}\\")));
                }
            }
            // Volume GUID mount point, e.g. `C:\` → `\\?\Volume{…}\`.
            let drive_root = format!("{name}\\");
            let drive_root_w: Vec<u16> = drive_root
                .encode_utf16()
                .chain(std::iter::once(0))
                .collect();
            let mut volume = [0u16; 64];
            if unsafe {
                GetVolumeNameForVolumeMountPointW(PCWSTR(drive_root_w.as_ptr()), &mut volume)
            }
            .is_ok()
            {
                let vol = String::from_utf16_lossy(trim_utf16_nul(&volume));
                if vol.starts_with("\\\\?\\Volume{") {
                    mounts.push((with_trailing_sep(&vol), format!("{name}\\")));
                }
            }
        }
    }

    // ── Pass 2: every volume (incl. letter-less) ─────────────────────────────
    let mut vol_buf = [0u16; 1024];
    let find = match unsafe { FindFirstVolumeW(&mut vol_buf) } {
        Ok(h) => h,
        Err(_) => return mounts,
    };
    // Volume names are NUL-terminated `\\?\Volume{GUID}\` strings.
    let mut vol_name = String::from_utf16_lossy(trim_utf16_nul(&vol_buf));

    loop {
        let name_w: Vec<u16> = vol_name.encode_utf16().chain(std::iter::once(0)).collect();

        // Device target, e.g. `\Device\HarddiskVolumeN`. QueryDosDeviceW wants
        // the bare `Volume{GUID}` form (no `\\?\` prefix, no trailing backslash).
        let device_name = vol_name
            .strip_prefix("\\\\?\\")
            .unwrap_or(&vol_name)
            .trim_end_matches('\\');
        let device_name_w: Vec<u16> = device_name
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();
        let mut target = [0u16; 260];
        let n = unsafe { QueryDosDeviceW(PCWSTR(device_name_w.as_ptr()), Some(&mut target)) };
        let device =
            (n != 0).then(|| String::from_utf16_lossy(trim_utf16_nul(&target[..n as usize])));

        // Mount points (drive roots / mounted folders), NUL-separated multi-string.
        let mut paths_buf = [0u16; 1024];
        let mut paths_len: u32 = 0;
        let mut paths: Vec<String> = Vec::new();
        if unsafe {
            GetVolumePathNamesForVolumeNameW(
                PCWSTR(name_w.as_ptr()),
                Some(&mut paths_buf),
                &mut paths_len,
            )
        }
        .is_ok()
        {
            paths = paths_buf[..paths_len as usize]
                .split(|&c| c == 0)
                .filter(|s| !s.is_empty())
                .map(String::from_utf16_lossy)
                .collect();
        }

        // Prefer a drive-letter root (`X:\`) so Sigma path rules match; fall
        // back to a mounted folder, then to the volume GUID itself.
        let mut replacement = paths
            .iter()
            .find(|p| is_win32_rooted(p))
            .or_else(|| paths.first())
            .cloned()
            .unwrap_or_else(|| vol_name.clone());
        if !replacement.ends_with('\\') {
            replacement.push('\\');
        }

        if let Some(dev) = &device {
            if dev.starts_with('\\') {
                mounts.push((with_trailing_sep(dev), replacement.clone()));
            }
        }
        mounts.push((vol_name.clone(), replacement.clone()));

        match unsafe { FindNextVolumeW(find, &mut vol_buf) } {
            Ok(()) => vol_name = String::from_utf16_lossy(trim_utf16_nul(&vol_buf)),
            Err(_) => break,
        }
    }
    unsafe {
        let _ = FindVolumeClose(find);
    }
    mounts
}

/// Append a trailing backslash unless already present.
#[cfg(windows)]
fn with_trailing_sep(s: &str) -> String {
    let mut out = s.to_string();
    if !out.ends_with('\\') {
        out.push('\\');
    }
    out
}

/// The text of a NUL-terminated UTF-16 buffer.
#[cfg(windows)]
fn trim_utf16_nul(buf: &[u16]) -> &[u16] {
    &buf[..buf.iter().position(|&c| c == 0).unwrap_or(buf.len())]
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_mounts() -> Vec<(String, String)> {
        vec![
            (
                "\\Device\\HarddiskVolume3\\".to_string(),
                "C:\\".to_string(),
            ),
            (
                "\\Device\\HarddiskVolume4\\".to_string(),
                "D:\\".to_string(),
            ),
            (
                "\\\\?\\Volume{12345678-9abc-def0-1234-567890abcdef}\\".to_string(),
                "D:\\".to_string(),
            ),
        ]
    }

    #[test]
    fn test_device_prefix_translation() {
        // The WER.DLL false positive: device path → Win32 path.
        assert_eq!(
            normalize(
                "\\Device\\HarddiskVolume3\\WINDOWS\\SYSTEM32\\WER.DLL",
                &test_mounts()
            ),
            "C:\\WINDOWS\\SYSTEM32\\WER.DLL"
        );
    }

    #[test]
    fn test_longest_prefix_wins() {
        // A longer device prefix must win over a shorter one.
        let mounts = vec![
            (
                "\\Device\\HarddiskVolume3\\".to_string(),
                "C:\\".to_string(),
            ),
            (
                "\\Device\\HarddiskVolume3\\shadow\\".to_string(),
                "Z:\\".to_string(),
            ),
        ];
        assert_eq!(
            normalize("\\Device\\HarddiskVolume3\\shadow\\x.txt", &mounts),
            "Z:\\x.txt"
        );
        assert_eq!(
            normalize("\\Device\\HarddiskVolume3\\Windows\\x.txt", &mounts),
            "C:\\Windows\\x.txt"
        );
    }

    #[test]
    fn test_win32_quoted_prefixes() {
        assert_eq!(
            normalize("\\??\\C:\\Windows\\System32\\wer.dll", &test_mounts()),
            "C:\\Windows\\System32\\wer.dll"
        );
        assert_eq!(
            normalize("\\\\?\\C:\\Windows\\System32\\wer.dll", &test_mounts()),
            "C:\\Windows\\System32\\wer.dll"
        );
    }

    #[test]
    fn test_volume_guid_translation() {
        assert_eq!(
            normalize(
                "\\\\?\\Volume{12345678-9abc-def0-1234-567890abcdef}\\x.txt",
                &test_mounts()
            ),
            "D:\\x.txt"
        );
    }

    #[test]
    fn test_fail_open_keeps_untranslated() {
        assert_eq!(normalize("foo.txt", &test_mounts()), "foo.txt");
        assert_eq!(
            normalize("\\\\server\\share\\x.txt", &test_mounts()),
            "\\\\server\\share\\x.txt"
        );
        assert_eq!(normalize("", &test_mounts()), "");
    }

    #[test]
    fn test_device_root_no_file() {
        assert_eq!(
            normalize("\\Device\\HarddiskVolume3\\", &test_mounts()),
            "C:\\"
        );
        assert_eq!(
            normalize("\\Device\\HarddiskVolume4", &test_mounts()),
            "D:\\"
        );
    }

    #[test]
    fn test_empty_mounts_is_fail_open() {
        assert_eq!(
            normalize("\\Device\\HarddiskVolume3\\x.txt", &[]),
            "\\Device\\HarddiskVolume3\\x.txt"
        );
    }
}
