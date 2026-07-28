// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 sigmacatch contributors

use anyhow::{anyhow, Context, Result};
use serde_json::Value;
use sigmacatch_types::{Alert, RegressionHeader};
use std::collections::HashSet;
use std::path::{Path, PathBuf};
use tracing::warn;

use crate::info::InfoYml;
use crate::logtype::LogType;
use crate::validate::{read_rule_id, validate_rule_id};

/// Platform-agnostic regression data entry.
///
/// `info.yml` is the universal anchor. `data_path` is the resolved
/// data file (`{rule_id}.evtx`, `{rule_id}.json`, etc.).
#[derive(Debug)]
pub struct RegressionData {
    // Generation state (used when creating new regression data)
    pub header: RegressionHeader,
    pub alerts: Vec<Alert>,
    pub output_path: PathBuf,
    pub rule_rel_path: Option<PathBuf>,
    pub author: Option<String>,
    pub description: Option<String>,
    pub is_contrib: bool,
    // Loaded state (used when reading existing regression data from disk)
    pub info_path: PathBuf,
    pub info: InfoYml,
    pub rule_id: String,
    pub data_path: PathBuf,
    pub logtype: LogType,
    pub raw_data: Option<Vec<u8>>,
}

impl RegressionData {
    /// Create a new `RegressionData` for generation (writing output).
    pub fn new(
        header: RegressionHeader,
        output_path: &Path,
        rule_rel_path: Option<&Path>,
        author: Option<&str>,
        description: Option<&str>,
        is_contrib: bool,
    ) -> Self {
        Self {
            header,
            alerts: Vec::new(),
            output_path: output_path.to_path_buf(),
            rule_rel_path: rule_rel_path.map(|p| p.to_path_buf()),
            author: author.map(|s| s.to_string()),
            description: description.map(|s| s.to_string()),
            is_contrib,
            // Loaded state (unused when in generation mode)
            info_path: PathBuf::new(),
            info: InfoYml::new("", "", 0, "", "", "", ""),
            rule_id: String::new(),
            data_path: PathBuf::new(),
            logtype: LogType::Json,
            raw_data: None,
        }
    }

    /// Add an alert to this regression data.
    pub fn add_alert(&mut self, alert: Alert) {
        self.alerts.push(alert);
    }

    /// Resolve the output rule directory path.
    pub fn rule_dir(&self) -> Result<PathBuf> {
        if let Some(rel_path) = &self.rule_rel_path {
            return Ok(self.output_path.join(rel_path));
        }
        let rule_id = &self.header.rule_id;
        if rule_id.contains('/')
            || rule_id.contains('\\')
            || rule_id.contains("..")
            || rule_id.contains('\0')
        {
            anyhow::bail!(
                "Invalid rule_id '{}': contains forbidden characters",
                rule_id
            );
        }
        Ok(self.output_path.join("rules").join(rule_id))
    }

    /// Compute the sigma-relative directory path string.
    pub fn sigma_rel_dir(&self) -> Option<String> {
        self.rule_rel_path.as_ref().map(|rel_path| {
            let rel = rel_path.display().to_string().replace('\\', "/");
            if self.is_contrib {
                format!("sigma/regression_data/{}", rel)
            } else {
                format!("regression_data/{}", rel)
            }
        })
    }

    /// Check if regression data already exists on disk.
    pub fn exists(&self) -> bool {
        self.rule_dir().is_ok_and(|d| d.join("info.yml").exists())
    }

    /// Generate regression output (json, evtx, info.yml).
    pub fn generate<F>(&self, write_fn: F) -> Result<()>
    where
        F: Fn(&str, &str, Option<u64>, &Path) -> Result<()>,
    {
        let rule_dir = self.rule_dir()?;
        let rule_id = &self.header.rule_id;
        std::fs::create_dir_all(&rule_dir)
            .with_context(|| format!("Failed to create rule directory {:?}", rule_dir))?;

        let first = self.alerts.first();
        let match_count = if first.is_some() { 1 } else { 0 };

        if let Some(alert) = first {
            let raw_json_path = rule_dir.join(format!("{}.json", rule_id));
            let raw_json = serde_json::to_string_pretty(&alert.event_json)?;
            std::fs::write(&raw_json_path, raw_json)?;
            tracing::info!("Wrote JSON for rule {:?}", rule_id);

            let evtx_path = rule_dir.join(format!("{}.evtx", rule_id));
            write_fn(
                alert.raw_xml(),
                alert.channel(),
                alert.record_id(),
                &evtx_path,
            )
            .with_context(|| format!("Failed to write EVTX for rule {:?}", rule_id))?;
            tracing::info!("Wrote EVTX for rule {:?}", rule_id);
        }

        let sigma_evtx_path = if first.is_some() {
            let evtx_name = format!("{}.evtx", rule_id);
            format!("{}/{}", self.sigma_rel_dir().unwrap_or_default(), evtx_name)
        } else {
            String::new()
        };

        let author = self
            .author
            .as_deref()
            .unwrap_or("Sigma Regression Generator");

        let description = self.description.as_deref().unwrap_or("N/A");

        let provider = first
            .map(|a| a.provider())
            .unwrap_or("Microsoft-Windows-Sysmon");

        let info = InfoYml::new(
            rule_id,
            &self.header.rule_title,
            match_count,
            &sigma_evtx_path,
            author,
            description,
            provider,
        );
        let info_path = rule_dir.join("info.yml");
        info.save(&info_path)?;
        tracing::info!("Created info.yml at {:?}", info_path);

        tracing::info!(
            "Generated {} regression events for rule {:?}",
            self.alerts.len(),
            self.header.rule_id
        );
        Ok(())
    }

    /// Construct a new `RegressionData` from pre-built components.
    pub fn create(
        info_path: PathBuf,
        info: InfoYml,
        rule_id: String,
        data_path: PathBuf,
        logtype: LogType,
        raw_data: Option<Vec<u8>>,
    ) -> Self {
        Self {
            header: RegressionHeader::new(String::new(), String::new()),
            alerts: Vec::new(),
            output_path: PathBuf::new(),
            rule_rel_path: None,
            author: None,
            description: None,
            is_contrib: false,
            info_path,
            info,
            rule_id,
            data_path,
            logtype,
            raw_data,
        }
    }

    /// Load a `RegressionData` from an `info.yml` file.
    pub fn load(info_path: &Path) -> Result<Self> {
        let info =
            InfoYml::load(info_path).map_err(|e| anyhow!("Failed to load info.yml: {}", e))?;

        let rule_id = info
            .rule_metadata
            .first()
            .ok_or_else(|| anyhow!("No rule_metadata in {}", info_path.display()))?
            .id
            .clone();

        let logtype = match info
            .regression_tests_info
            .first()
            .map(|t| t.test_type.as_str())
        {
            Some("evtx") => LogType::Evtx,
            Some("json") => LogType::Json,
            Some("raw") => LogType::Raw,
            Some("log") => LogType::Log,
            Some(other) => {
                warn!("Unknown logtype '{}', defaulting to Json", other);
                LogType::Json
            }
            None => LogType::Json,
        };

        let dir = info_path
            .parent()
            .ok_or_else(|| anyhow!("info.yml has no parent dir: {}", info_path.display()))?;

        let data_path = resolve_data_file(dir, &rule_id)
            .ok_or_else(|| anyhow!("No data file for rule '{}' in {}", rule_id, dir.display()))?;

        let raw_data = std::fs::read(&data_path).ok();

        Ok(RegressionData {
            header: RegressionHeader::new(rule_id.clone(), String::new()),
            alerts: Vec::new(),
            output_path: PathBuf::new(),
            rule_rel_path: None,
            author: None,
            description: None,
            is_contrib: false,
            info_path: info_path.to_path_buf(),
            info,
            rule_id,
            data_path,
            logtype,
            raw_data,
        })
    }

    /// Save the `info.yml` back to disk.
    pub fn save(&self) -> Result<()> {
        self.info.save(&self.info_path)
    }

    /// Write the raw log data (evtx, json, raw bytes) to disk.
    pub fn save_log(&self, path: &Path) -> Result<()> {
        let data = match &self.raw_data {
            Some(d) => d.as_slice(),
            None => &std::fs::read(&self.data_path)?,
        };
        std::fs::write(path, data).map_err(|e| anyhow!("Failed to write log to {:?}: {}", path, e))
    }

    /// Export the data as pretty-printed JSON.
    pub fn export_json(&self) -> Result<String> {
        let json = match self.logtype {
            LogType::Json => {
                let text = std::fs::read_to_string(&self.data_path)?;
                let value: Value = serde_json::from_str(&text)?;
                serde_json::to_string_pretty(&value)?
            }
            _ => {
                let text = std::fs::read_to_string(&self.data_path).or_else(|_| {
                    self.raw_data
                        .as_ref()
                        .map(|d| String::from_utf8_lossy(d).to_string())
                        .ok_or_else(|| anyhow!("No raw data available"))
                })?;
                format!(
                    "{{\n  \"type\": \"{}\",\n  \"raw\": {}\n}}",
                    self.logtype.as_str(),
                    serde_json::to_string(&text).unwrap_or_default()
                )
            }
        };
        Ok(json)
    }

    /// Check if this regression entry is valid on disk.
    pub fn is_valid(&self) -> bool {
        self.info_path.exists() && self.data_path.exists()
    }
}

/// Data file extensions to look for, in priority order.
const DATA_EXTENSIONS: &[&str] = &["evtx", "json"];

/// Resolve the data file associated with a rule.
fn resolve_data_file(dir: &Path, rule_id: &str) -> Option<PathBuf> {
    for ext in DATA_EXTENSIONS {
        let candidate = dir.join(format!("{}.{}", rule_id, ext));
        if candidate.exists() {
            return Some(candidate);
        }
    }
    None
}

/// Build a skip set of rule IDs from directories containing regression data.
///
/// Walks directories recursively for `info.yml` files, extracts rule_id,
/// and returns a `HashSet` of valid rule IDs.
pub fn build_skip_set(dirs: &[(&str, &Path)], max_depth: u32) -> HashSet<String> {
    const DEFAULT_MAX_DEPTH: u32 = 64;
    let max_depth = if max_depth == 0 {
        DEFAULT_MAX_DEPTH
    } else {
        max_depth
    };

    if dirs.is_empty() {
        warn!("build_skip_set: no directories to scan");
        return HashSet::new();
    }

    let mut seen = HashSet::new();

    let mut sorted_dirs: Vec<_> = dirs.iter().collect();
    sorted_dirs.sort_by_key(|(label, _)| *label);

    for (label, dir) in sorted_dirs {
        if !dir.exists() {
            warn!("build_skip_set: directory not found: {:?}", dir);
            continue;
        }
        let Ok(entries) = std::fs::read_dir(dir) else {
            warn!("build_skip_set: permission denied: {:?}", dir);
            continue;
        };
        let mut entries_vec: Vec<_> = entries.filter_map(|e| e.ok()).collect();
        entries_vec.sort_by_key(|e| e.path());
        for entry in entries_vec {
            let path = entry.path();
            if path.is_dir() {
                collect_rule_ids(&path, &mut seen, label, 1, max_depth);
            }
        }
    }

    seen
}

fn collect_rule_ids(
    dir: &Path,
    seen: &mut HashSet<String>,
    label: &str,
    depth: u32,
    max_depth: u32,
) {
    if depth > max_depth {
        return;
    }

    if let Some(name) = dir.file_name().and_then(|n| n.to_str()) {
        if name == "rules-compliance" || name == "rules_compliance" {
            return;
        }
    }

    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    let mut entries_vec: Vec<_> = entries.filter_map(|e| e.ok()).collect();
    entries_vec.sort_by_key(|e| e.path());
    for entry in entries_vec {
        let path = entry.path();
        if path.is_dir() {
            collect_rule_ids(&path, seen, label, depth + 1, max_depth);
        } else if path.file_name() == Some(std::ffi::OsStr::new("info.yml")) {
            match read_rule_id(&path) {
                Ok(rule_id) => {
                    if validate_rule_id(&rule_id) {
                        seen.insert(rule_id);
                    } else {
                        warn!(
                            "build_skip_set: invalid rule_id '{}' at {} (source: {})",
                            rule_id,
                            path.display(),
                            label
                        );
                    }
                }
                Err(e) => {
                    warn!(
                        "build_skip_set: failed to read rule_id from {:?}: {}",
                        path, e
                    );
                }
            }
        }
    }
}

/// Load all regression entries from `regression_dir` recursively.
pub fn load_all(regression_dir: &Path) -> (Vec<RegressionData>, Vec<(PathBuf, anyhow::Error)>) {
    if !regression_dir.exists() {
        warn!(
            "load_all: directory does not exist: {}",
            regression_dir.display()
        );
        return (Vec::new(), Vec::new());
    }

    let mut results = Vec::new();
    let mut skipped = Vec::new();
    walk_recursive(regression_dir, &mut results, &mut skipped, 0);
    results.sort_by(|a, b| a.info_path.cmp(&b.info_path));
    (results, skipped)
}

fn walk_recursive(
    dir: &Path,
    results: &mut Vec<RegressionData>,
    skipped: &mut Vec<(PathBuf, anyhow::Error)>,
    depth: u32,
) {
    if depth > 64 {
        warn!("walk_recursive: depth limit reached at {:?}", dir);
        return;
    }

    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return,
    };

    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            walk_recursive(&path, results, skipped, depth + 1);
        } else if path.file_name().is_some_and(|n| n == "info.yml") {
            match RegressionData::load(&path) {
                Ok(data) => results.push(data),
                Err(e) => {
                    warn!("loader: skipping {}: {}", path.display(), e);
                    skipped.push((path.to_path_buf(), e));
                }
            }
        }
    }
}
