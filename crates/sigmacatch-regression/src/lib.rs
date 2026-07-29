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
use tracing::{info, warn};

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

/// Delete regression directories that contain generated files (.json/.evtx)
/// but no `info.yml`. Such directories are partial artifacts from a prior run
/// that aborted before committing; they are never part of the skip set and
/// must not be carried into the current run's commit.
pub fn clean_partial_artifacts(base: &Path) {
    if !base.exists() {
        return;
    }
    let walk = match std::fs::read_dir(base) {
        Ok(w) => w,
        Err(e) => {
            warn!("Failed to read regression base directory {:?}: {}", base, e);
            return;
        }
    };
    for entry in walk.flatten() {
        let sub = entry.path();
        if !sub.is_dir() {
            continue;
        }
        let inner_walk = match std::fs::read_dir(&sub) {
            Ok(w) => w,
            Err(e) => {
                warn!("Failed to read regression subdirectory {:?}: {}", sub, e);
                continue;
            }
        };
        for entry in inner_walk.flatten() {
            let dir = entry.path();
            if !dir.is_dir() {
                continue;
            }
            let has_info = dir.join("info.yml").exists();
            if !has_info {
                let dir_name = dir.file_name().and_then(|n| n.to_str()).unwrap_or("");
                let has_generated = dir.join(format!("{dir_name}.json")).exists()
                    || dir.join(format!("{dir_name}.evtx")).exists();
                if !has_generated {
                    continue;
                }
                match std::fs::remove_dir_all(&dir) {
                    Ok(()) => info!("Cleaned partial regression dir {:?}", dir),
                    Err(e) => warn!("Failed to clean partial regression dir {:?}: {}", dir, e),
                }
            }
        }
    }
}
