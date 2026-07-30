// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 sigmacatch contributors

//! SigmaHQ-compatible regression data format and helpers.
//!
//! **Public API** — callers use `RegressionData`, `list_all()`,
//! `build_skip_set()`, and `clean_partial_artifacts()`.

mod data;
mod evtx;
mod info;
mod logtype;
mod validate;

use std::path::{Path, PathBuf};
use tracing::{info, warn};

pub use data::{build_skip_set, update_regression_tests_path, RegressionData};
pub use evtx::write_evtx;
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

/// Delete regression directories that contain generated files (.json/.evtx)
/// but no `info.yml`. Such directories are partial artifacts from a prior run
/// that aborted before committing; they are never part of the skip set and
/// must not be carried into the current run's commit.
pub fn clean_partial_artifacts(base: &Path) {
    if !base.exists() {
        return;
    }
    clean_recursive(base, 0);
}

const MAX_CLEAN_DEPTH: u32 = 64;

fn clean_recursive(dir: &Path, depth: u32) {
    if depth > MAX_CLEAN_DEPTH {
        warn!("clean_recursive: depth limit reached at {:?}", dir);
        return;
    }

    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(e) => {
            warn!("Failed to read {:?}: {}", dir, e);
            return;
        }
    };
    for entry in entries.filter_map(|e| e.ok()) {
        let path = entry.path();
        if let Ok(metadata) = path.symlink_metadata() {
            if metadata.file_type().is_symlink() {
                warn!("Skipping symlink at {:?}", path);
                continue;
            }
        }
        if path.is_dir() {
            let has_info = path.join("info.yml").exists();
            if !has_info {
                let dir_name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
                let has_generated = path.join(format!("{dir_name}.json")).exists()
                    || path.join(format!("{dir_name}.evtx")).exists();
                if !has_generated {
                    clean_recursive(&path, depth + 1);
                    continue;
                }
                match std::fs::remove_dir_all(&path) {
                    Ok(()) => info!("Cleaned partial regression dir {:?}", path),
                    Err(e) => warn!("Failed to clean partial regression dir {:?}: {}", path, e),
                }
            } else {
                clean_recursive(&path, depth + 1);
            }
        }
    }
}
