// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 sigmacatch contributors

//! Shared regression-data vocabulary, discovery and output seams.
//!
//! The state machine and the file writers live in `sigmacatch-output-regression`
//! and `sigmacatch-output-evtx`; this module keeps only what the runner, the
//! diagnostics and the output crates need: [`DataFormat`], the output seams,
//! cheap on-disk discovery and cleanup.

mod format;
mod sink;

pub use format::{DATA_EXTENSIONS, DataFormat, MAX_DATA_BLOB_SIZE};
pub use sink::{RegressionSink, RegressionSinkFactory};

// The schema, its canonical layout and the log-type vocabulary belong to
// `sigma-regression`; re-exported so existing paths keep working.
pub use sigma_regression::{info, logtype};

use rayon::prelude::*;
use sigma_regression::InfoYml;
use std::path::{Path, PathBuf};
use tracing::{info, warn};
use uuid::Uuid;

/// Errors produced while generating, reading or writing regression data.
#[derive(Debug, thiserror::Error)]
pub enum RegressionError {
    /// Filesystem failure.
    #[error("filesystem error: {0}")]
    Io(#[from] std::io::Error),
    /// JSON serialization/deserialization failure.
    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),
    /// YAML could not be parsed or serialized.
    #[error("yaml error: {0}")]
    Yaml(String),
    /// Structural contract violated by the data itself.
    #[error("{0}")]
    Invalid(String),
    /// EVTX export could not produce usable data for a rule this cycle;
    /// the rule is skipped and re-captured on a later cycle.
    #[error("{0}")]
    Export(String),
}

/// Crate-local result alias over [`RegressionError`].
pub type Result<T> = std::result::Result<T, RegressionError>;

impl From<sigma_regression::Error> for RegressionError {
    fn from(error: sigma_regression::Error) -> Self {
        match error {
            sigma_regression::Error::Io(error) => Self::Io(error),
            sigma_regression::Error::Yaml(message) => Self::Yaml(message),
            sigma_regression::Error::Invalid(message) => Self::Invalid(message),
        }
    }
}

/// True when the rule's committed data file exists and is non-empty.
pub fn data_file_exists(dir: &Path, rule_id: &Uuid, format: DataFormat) -> bool {
    let candidate =
        sigma_regression::long_path(&dir.join(format!("{rule_id}.{ext}", ext = format.ext())));
    std::fs::metadata(&candidate).is_ok_and(|m| m.len() > 0)
}

/// Rule ids with committed, non-empty regression data under `dir`.
pub fn committed_rule_ids(dir: &Path, format: DataFormat) -> Vec<Uuid> {
    list_all(dir)
        .into_iter()
        .filter_map(|path| {
            let info = InfoYml::load(&path).ok()?;
            let rule_id = info.rule_metadata.first()?.id;
            data_file_exists(path.parent()?, &rule_id, format).then_some(rule_id)
        })
        .collect()
}

/// Drop `.` and `..` components from a path before it is joined or written.
pub fn clean_path(p: &Path) -> PathBuf {
    p.components()
        .filter(|c| {
            !matches!(
                c,
                std::path::Component::CurDir | std::path::Component::ParentDir
            )
        })
        .collect()
}

/// First existing data file for `rule_id`, in validation-precedence order.
pub fn resolve_data_file(dir: &Path, rule_id: &Uuid) -> Option<PathBuf> {
    DATA_EXTENSIONS
        .iter()
        .map(|ext| dir.join(format!("{rule_id}.{ext}")))
        .find(|candidate| candidate.exists())
}

/// Parse a JSON export that is either a single document or newline-delimited
/// JSON. Returns `None` if the bytes hold no value or any value is malformed.
pub fn parse_json_stream(bytes: &[u8]) -> Option<Vec<serde_json::Value>> {
    let values: Vec<serde_json::Value> = serde_json::Deserializer::from_slice(bytes)
        .into_iter()
        .collect::<std::result::Result<Vec<_>, _>>()
        .ok()?;
    (!values.is_empty()).then_some(values)
}

/// Record the regression-data location in the rule's YAML, preserving the
/// rest of the document and its trailing newline.
pub fn update_regression_tests_path(rule_yaml_path: &Path, tests_path: &str) {
    let content = match std::fs::read_to_string(rule_yaml_path) {
        Ok(c) => c,
        Err(e) => {
            warn!("Failed to read {:?}: {}", rule_yaml_path, e);
            return;
        }
    };
    let expected_line = format!("regression_tests_path: {}", tests_path);
    if content.lines().any(|l| l.trim() == expected_line) {
        return;
    }
    let filtered: Vec<&str> = content
        .lines()
        .filter(|l| !l.trim().starts_with("regression_tests_path:"))
        .collect();
    let mut new_text = filtered.join("\n");
    if !new_text.is_empty() && !new_text.ends_with('\n') {
        new_text.push('\n');
    }
    new_text.push_str(&format!("{}\n", expected_line));
    if let Err(e) = std::fs::write(rule_yaml_path, new_text) {
        warn!(
            "Failed to update regression_tests_path in {:?}: {}",
            rule_yaml_path, e
        );
    }
}

/// Recursively list every parsable `info.yml` under `dir`, sorted.
pub fn list_all(dir: &Path) -> Vec<PathBuf> {
    load_all(dir).into_iter().map(|(path, _)| path).collect()
}

/// Recursively load every parsable `info.yml` under `dir` (one that declares at
/// least one `rule_metadata` entry), sorted by path. Each file is read and
/// parsed once, in parallel.
pub fn load_all(dir: &Path) -> Vec<(PathBuf, InfoYml)> {
    if !dir.exists() {
        warn!("list_all: directory does not exist: {}", dir.display());
        return Vec::new();
    }
    let mut candidates = Vec::new();
    walk(dir, &mut candidates, 0);
    let mut loaded: Vec<(PathBuf, InfoYml)> = candidates
        .into_par_iter()
        .filter_map(|path| match InfoYml::load(&path) {
            Ok(info) if !info.rule_metadata.is_empty() => Some((path, info)),
            _ => None,
        })
        .collect();
    loaded.sort_by(|a, b| a.0.cmp(&b.0));
    loaded
}

/// Collect every `info.yml` candidate under `dir` (symlinks are not followed).
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
        if let Ok(metadata) = path.symlink_metadata()
            && metadata.file_type().is_symlink()
        {
            continue;
        }
        if path.is_dir() {
            walk(&path, paths, depth + 1);
        } else if path.file_name().is_some_and(|n| n == "info.yml") {
            paths.push(path);
        }
    }
}

/// Remove partially written regression artifacts left by an interrupted run
/// (`*.part` files and empty directories).
pub fn clean_partial_artifacts(base: &Path) {
    if !base.exists() {
        return;
    }
    clean_recursive(base, 0);
}

const MAX_CLEAN_DEPTH: u32 = 64;

/// True when the directory holds any regression data file (`*.evtx`, `*.log`,
/// `*.raw`, `*.json`) regardless of its stem.
fn contains_data_file(dir: &Path) -> bool {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return false;
    };
    entries.filter_map(|e| e.ok()).any(|e| {
        let name = e.file_name();
        let name = name.to_string_lossy();
        DATA_EXTENSIONS
            .iter()
            .any(|ext| name.ends_with(&format!(".{ext}")))
    })
}

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
        if let Ok(metadata) = path.symlink_metadata()
            && metadata.file_type().is_symlink()
        {
            warn!("Skipping symlink at {:?}", path);
            continue;
        }
        if path.is_dir() {
            let has_info = path.join("info.yml").exists();
            if !has_info {
                if !contains_data_file(&path) {
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
