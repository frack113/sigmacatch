// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 sigmacatch contributors

//! Windows extended-length path support.
//!
//! On Windows, the default MAX_PATH limit is 260 characters. Paths exceeding
//! this must be prefixed with `\\?\` to use the extended-length API.
//!
//! This module provides `long_path()` which prepends the prefix when the path
//! is absolute and longer than 260 characters on Windows. On non-Windows
//! platforms the path is returned unchanged.

use std::path::{Path, PathBuf};

/// Return `path` with a `\\?\` prefix when it is an absolute Windows path
/// longer than 260 characters. Otherwise return `path` unchanged.
///
/// The `\\?\` prefix:
/// - Enables paths up to 32,767 characters on Windows
/// - Must precede the drive letter (e.g. `\\?\C:\foo`)
/// - Accepts forward slashes as path separators
/// - Does NOT work with relative paths or `.\` / `..\` prefixes
///
/// On non-Windows platforms this is a no-op.
pub(crate) fn long_path(path: &Path) -> PathBuf {
    #[cfg(windows)]
    {
        use std::path::Component;

        let s = path.to_string_lossy();
        if s.len() > 260 {
            // Only apply to absolute paths. Relative paths would become
            // `\\?\foo\bar` which is invalid — the caller must ensure the
            // path is absolute before using this helper.
            let is_absolute = path
                .components()
                .next()
                .is_some_and(|c| matches!(c, Component::Prefix(_) | Component::RootDir));
            if is_absolute && !s.starts_with(r"\\?\") {
                return PathBuf::from(format!(r"\\?\{}", s));
            }
        }
        path.to_path_buf()
    }
    #[cfg(not(windows))]
    {
        path.to_path_buf()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(windows)]
    #[test]
    fn long_path_short_returns_unchanged() {
        let p = Path::new(r"C:\short");
        assert_eq!(long_path(p), PathBuf::from(r"C:\short"));
    }

    #[cfg(windows)]
    #[test]
    fn long_path_already_prefixed_stays_unchanged() {
        let p = Path::new(r"\\?\C:\very\long\path");
        assert_eq!(long_path(p), PathBuf::from(r"\\?\C:\very\long\path"));
    }

    #[cfg(windows)]
    #[test]
    fn long_path_over_260_chars_adds_prefix() {
        let long_name = "a".repeat(300);
        let full_path = format!(r"C:\{}", long_name);
        assert!(full_path.len() > 260);
        let p = Path::new(&full_path);
        let result = long_path(p);
        assert!(
            result.to_string_lossy().starts_with(r"\\?\"),
            "long path should be prefixed"
        );
        assert_eq!(
            result.to_string_lossy().len(),
            full_path.len() + r"\\?\".len()
        );
    }

    #[cfg(not(windows))]
    #[test]
    fn long_path_is_noop_on_unix() {
        let p = Path::new("/a/very/long/path");
        assert_eq!(long_path(p), PathBuf::from("/a/very/long/path"));
    }
}
