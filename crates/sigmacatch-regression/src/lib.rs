// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 sigmacatch contributors

//! SigmaHQ-compatible regression data format and helpers.
//!
//! **Closed interface** — callers must only use `RegressionData` methods and
//! `list_all()`. No direct access to `info.yml`, data paths, or raw fields.

mod data;
mod evtx;
mod info;
mod logtype;
mod validate;

use std::path::{Path, PathBuf};
use tracing::warn;

pub use data::{build_skip_set, RegressionData};
pub use evtx::writer::write_evtx;
pub use logtype::LogType;
pub use validate::validate_rule_id;

/// Return paths to `info.yml` files under `dir`, recursively.
///
/// Only returns paths to valid `info.yml` files — callers decide what to do
/// with them. Failing to load an `info.yml` is silently ignored.
pub fn list_all(dir: &Path) -> Vec<PathBuf> {
    if !dir.exists() {
        warn!("list_all: directory does not exist: {}", dir.display());
        return Vec::new();
    }
    let mut paths = Vec::new();
    walk(dir, &mut paths, 0);
    paths.sort();
    paths
}

fn walk(dir: &Path, paths: &mut Vec<PathBuf>, depth: u32) {
    if depth > 64 {
        warn!("walk: depth limit at {:?}", dir);
        return;
    }
    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return,
    };
    for entry in entries.filter_map(|e| e.ok()) {
        let path = entry.path();
        if path.is_dir() {
            walk(&path, paths, depth + 1);
        } else if path.file_name().is_some_and(|n| n == "info.yml")
            && data::try_read_rule_id(&path).is_ok()
        {
            paths.push(path);
        }
    }
}
