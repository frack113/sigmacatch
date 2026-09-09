// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 sigmacatch contributors

//! Windows extended-length path support.
//!
//! On Windows, paths exceeding 260 characters must be prefixed with `\\?\`
//! to use the extended-length API.

use std::path::{Path, PathBuf};

/// Return `path` with a `\\?\` prefix when it is an absolute Windows path
/// longer than 260 characters. Otherwise return `path` unchanged.
pub(crate) fn long_path(path: &Path) -> PathBuf {
    #[cfg(windows)]
    {
        use std::path::Component;

        let s = path.to_string_lossy();
        if s.len() > 260 {
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
