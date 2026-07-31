// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 sigmacatch contributors

//! SigmaHQ-compatible regression data format and helpers.

mod evtx;
mod info;
pub mod logtype;
pub mod validate;

use std::path::{Path, PathBuf};

use anyhow::{anyhow, Context, Result};
use serde_json::Value;
use sigmacatch_types::{Alert, RegressionHeader};
use std::collections::HashSet;
use std::ffi::OsStr;
use tracing::{error, info, info_span, warn};
use uuid::Uuid;

use crate::evtx::write_evtx;
use crate::info::InfoYml;
use crate::logtype::LogType;
use crate::validate::validate_rule_id;

/// Cached metadata for a single regression entry.
#[derive(Debug, Clone)]
pub struct RegressionEntry {
    pub rule_id: String,
    pub rule_name: String,
    pub logtype: LogType,
}

impl RegressionEntry {
    fn from_info(info: &InfoYml, info_path: &Path) -> Self {
        let rule_id = info
            .rule_metadata
            .first()
            .map(|m| m.id.clone())
            .unwrap_or_default();
        let rule_name = info_path
            .parent()
            .and_then(|p| p.file_name())
            .and_then(|n| n.to_str())
            .unwrap_or("unknown")
            .to_string();
        let logtype = info
            .regression_tests_info
            .first()
            .map(|t| match t.test_type.as_str() {
                "evtx" => LogType::Evtx,
                "json" => LogType::Json,
                "raw" => LogType::Raw,
                "log" => LogType::Log,
                other => {
                    warn!("Unknown logtype '{other}', defaulting to Json");
                    LogType::Json
                }
            })
            .unwrap_or(LogType::Json);
        Self {
            rule_id,
            rule_name,
            logtype,
        }
    }
}

/// Collection of regression data entries loaded from disk.
///
/// Create with `new()` to load from `./regression_data`, or
/// `new_from_path()` for custom directories (tests).
pub struct SigmahqRegression {
    entries: Vec<(PathBuf, InfoYml, RegressionEntry)>,
    author: String,
}

impl SigmahqRegression {
    /// Load all regression entries from `./sigma/regression_data`.
    pub fn new() -> Result<Self> {
        Self::new_from_path(Path::new("./sigma/regression_data"))
    }

    /// Load all regression entries from a custom directory.
    pub fn new_from_path(regression_path: &Path) -> Result<Self> {
        if !regression_path.exists() {
            anyhow::bail!(
                "Regression data directory does not exist: {:?}",
                regression_path
            );
        }
        let info_paths = list_all(regression_path);
        if info_paths.is_empty() {
            anyhow::bail!("No regression entries found in {:?}", regression_path);
        }
        let mut entries = Vec::with_capacity(info_paths.len());
        for path in &info_paths {
            if let Ok(info) = InfoYml::load(path) {
                let entry = RegressionEntry::from_info(&info, path);
                entries.push((path.clone(), info, entry));
            }
        }
        if entries.is_empty() {
            anyhow::bail!("No valid regression entries found in {:?}", regression_path);
        }
        Ok(Self {
            entries,
            author: String::new(),
        })
    }

    /// Set the author name for this regression collection.
    pub fn set_author(&mut self, author: String) {
        self.author = author;
    }

    /// Get the author name.
    pub fn author(&self) -> &str {
        &self.author
    }

    /// Return the number of regression entries.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Return whether there are no regression entries.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Iterate over the loaded (path, InfoYml) entries.
    pub fn iter(&self) -> impl Iterator<Item = (&PathBuf, &InfoYml)> {
        self.entries.iter().map(|(path, info, _)| (path, info))
    }

    /// Return all loaded InfoYml entries.
    pub fn infos(&self) -> impl Iterator<Item = &InfoYml> {
        self.entries.iter().map(|(_, info, _)| info)
    }

    /// Iterate over the cached regression entries.
    pub fn entries(&self) -> impl Iterator<Item = &RegressionEntry> {
        self.entries.iter().map(|(_, _, entry)| entry)
    }

    /// Return sorted list of rule UUIDs that have regression tests.
    pub fn list_sigma_id(regression_path: &Path) -> Vec<Uuid> {
        let string_ids = list_sigma_id(regression_path);
        string_ids
            .into_iter()
            .filter_map(|id| Uuid::parse_str(&id).ok())
            .collect()
    }

    /// Get the cached entry metadata for an index.
    pub fn get_entry(&self, index: usize) -> Option<&RegressionEntry> {
        self.entries.get(index).map(|(_, _, entry)| entry)
    }

    /// Find the index of an entry by its sigma rule ID.
    pub fn find_by_rule_id(&self, rule_id: &str) -> Option<usize> {
        self.entries
            .iter()
            .position(|(_, _, entry)| entry.rule_id == rule_id)
    }

    /// Get the raw data bytes for an entry by index.
    ///
    /// Reads the data file (.evtx/.json/.raw) from the same directory as info.yml.
    pub fn get_raw_data(&self, index: usize) -> Option<Vec<u8>> {
        let (info_path, info, _) = self.entries.get(index)?;
        let rule_id = info.rule_metadata.first()?.id.as_str();
        let dir = info_path.parent()?;
        let data_path = resolve_data_file(dir, rule_id)?;
        std::fs::read(&data_path).ok()
    }
}

/// Platform-agnostic regression data entry and per-alert generator.
///
/// Create with `new(path)`, configure with setters, then call
/// `generate_from_alert()` for each alert.
pub struct RegressionData {
    header: RegressionHeader,
    alerts: Vec<Alert>,
    output_path: PathBuf,
    sigma_repo_path: PathBuf,
    rule_rel_path: Option<PathBuf>,
    author: Option<String>,
    description: Option<String>,
    is_contrib: bool,
    retired: HashSet<String>,
    info: InfoYml,
    info_path: PathBuf,
    raw_data: Option<Vec<u8>>,
    logtype: LogType,
}

impl RegressionData {
    /// Create a new `RegressionData` for per-alert generation.
    ///
    /// Set `output_path` to the directory where regression data will be written
    /// (typically `<sigma_repo>/regression_data`). Configure with `set_author()`,
    /// `set_sigma_repo_path()`, `set_is_contrib()`, then call `generate_from_alert()`.
    pub fn new(output_path: &Path) -> Self {
        Self {
            header: RegressionHeader::new(String::new(), String::new()),
            alerts: Vec::new(),
            output_path: output_path.to_path_buf(),
            sigma_repo_path: PathBuf::new(),
            rule_rel_path: None,
            author: None,
            description: None,
            is_contrib: false,
            retired: HashSet::new(),
            info: InfoYml::new("", "", 0, "", "", "", ""),
            info_path: PathBuf::new(),
            raw_data: None,
            logtype: LogType::Json,
        }
    }

    /// Set the author for generated regression entries.
    pub fn set_author(&mut self, author: &str) {
        self.author = Some(author.to_string());
    }

    /// Set whether this is a contrib run (output inside the sigma repo).
    pub fn set_is_contrib(&mut self, is_contrib: bool) {
        self.is_contrib = is_contrib;
    }

    /// Set the sigma repo path (used to compute relative rule paths).
    pub fn set_sigma_repo_path(&mut self, path: &Path) {
        self.sigma_repo_path = path.to_path_buf();
    }

    /// Generate regression data for a single matched alert.
    ///
    /// Returns `None` if the rule already has regression data (either generated
    /// earlier in this run or found on disk). Returns `Some(files)` on success
    /// with the list of generated file paths (relative to the sigma repo root).
    pub fn generate_from_alert(&mut self, alert: &Alert) -> Option<Vec<String>> {
        let rule_id = &alert.rule_id;
        if self.retired.contains(rule_id) {
            return None;
        }

        let rule_rel_path = alert.rule_path.as_ref().and_then(|p| {
            p.strip_prefix(&self.sigma_repo_path)
                .ok()
                .map(|rel| rel.with_extension(""))
        });

        let mut reg = RegressionData::for_rule(
            &RegressionHeader::new(rule_id.clone(), alert.rule_title.clone()),
            &self.output_path,
            rule_rel_path.as_deref(),
            self.author.as_deref(),
            alert.description.as_deref(),
            self.is_contrib,
            &self.sigma_repo_path,
        );

        if reg.exists() {
            return None;
        }

        reg.add_alert(alert.clone());

        let _gen_span = info_span!("generate", rule_id = %rule_id).entered();
        match reg.generate(write_evtx) {
            Ok(_) => {
                let rel_dir = reg
                    .sigma_rel_dir()
                    .unwrap_or_else(|| format!("regression_data/rules/{rule_id}"));

                let rule_yaml_rel = alert
                    .rule_path
                    .as_ref()
                    .and_then(|p| p.strip_prefix(&self.sigma_repo_path).ok())
                    .and_then(|p| p.to_str())
                    .map(|s| s.to_string().replace('\\', "/"));

                let tests_path = format!("{}/info.yml", rel_dir.replace('\\', "/"));
                if let Some(ref rule_yaml_path) = alert.rule_path {
                    update_regression_tests_path(rule_yaml_path, &tests_path);
                }

                self.retired.insert(rule_id.clone());
                info!("Rule {rule_id} retired from detection engine");

                let mut files = vec![
                    format!("{}/{}.json", rel_dir, rule_id),
                    format!("{}/{}.evtx", rel_dir, rule_id),
                    format!("{}/info.yml", rel_dir),
                ];
                if let Some(ref yaml_rel) = rule_yaml_rel {
                    files.push(yaml_rel.clone());
                }

                Some(files)
            }
            Err(e) => {
                error!("Failed to generate regression for {}: {}", rule_id, e);
                None
            }
        }
    }

    /// Create a `RegressionData` for a single rule (internal helper).
    fn for_rule(
        header: &RegressionHeader,
        output_path: &Path,
        rule_rel_path: Option<&Path>,
        author: Option<&str>,
        description: Option<&str>,
        is_contrib: bool,
        sigma_repo_path: &Path,
    ) -> Self {
        Self {
            header: header.clone(),
            alerts: Vec::new(),
            output_path: output_path.to_path_buf(),
            sigma_repo_path: sigma_repo_path.to_path_buf(),
            rule_rel_path: rule_rel_path.map(|p| p.to_path_buf()),
            author: author.map(|s| s.to_string()),
            description: description.map(|s| s.to_string()),
            is_contrib,
            retired: HashSet::new(),
            info: InfoYml::new("", "", 0, "", "", "", ""),
            info_path: PathBuf::new(),
            raw_data: None,
            logtype: LogType::Json,
        }
    }

    /// Construct a new `RegressionData` from an `info.yml` path.
    pub fn from_info(info_path: &Path) -> Result<Self> {
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

        Ok(Self {
            header: RegressionHeader::new(rule_id.clone(), String::new()),
            alerts: Vec::new(),
            output_path: dir.to_path_buf(),
            sigma_repo_path: PathBuf::new(),
            rule_rel_path: None,
            author: None,
            description: None,
            is_contrib: false,
            retired: HashSet::new(),
            info,
            info_path: info_path.to_path_buf(),
            raw_data,
            logtype,
        })
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

    /// Write the raw log data to disk.
    pub fn save_log(&self, path: &Path) -> Result<()> {
        let data = match &self.raw_data {
            Some(d) => d.as_slice(),
            None => &std::fs::read(self.get_data_path())?,
        };
        std::fs::write(path, data).map_err(|e| anyhow!("Failed to write log to {:?}: {}", path, e))
    }

    /// Export the data as pretty-printed JSON.
    pub fn export_json(&self) -> Result<String> {
        let json = match self.logtype {
            LogType::Json => {
                let text = std::fs::read_to_string(self.get_data_path())?;
                let value: Value = serde_json::from_str(&text)?;
                serde_json::to_string_pretty(&value)?
            }
            _ => {
                let text = std::fs::read_to_string(self.get_data_path()).or_else(|_| {
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

    // ─── Accessors ────────────────────────────────────────────────────

    /// Return the rule ID.
    pub fn rule_id(&self) -> &str {
        self.header.rule_id.as_str()
    }

    /// Return the rule title.
    pub fn rule_title(&self) -> &str {
        self.header.rule_title.as_str()
    }

    /// Return the expected match count from `regression_tests_info`.
    pub fn expected_match_count(&self) -> usize {
        self.info
            .regression_tests_info
            .first()
            .map(|t| t.match_count)
            .unwrap_or(1)
            .max(1)
    }

    /// Check if this regression entry is valid on disk.
    pub fn is_valid(&self) -> bool {
        self.info_path.exists() && self.get_data_path().exists()
    }

    /// Return the raw data bytes (EVTX binary, JSON, or raw XML).
    ///
    /// Callers should use [`LogType`] to decide how to interpret the bytes.
    pub fn get_raw_data(&self) -> Option<&[u8]> {
        self.raw_data.as_deref()
    }

    /// Return the data format type.
    pub fn get_logtype(&self) -> LogType {
        self.logtype
    }

    /// Return whether this regression data was generated for a contrib run.
    pub fn is_contrib(&self) -> bool {
        self.is_contrib
    }

    // ─── Internal helpers ─────────────────────────────────────────────

    fn get_data_path(&self) -> PathBuf {
        let rule_dir = self.rule_dir().unwrap_or_default();
        let rule_id = self.rule_id();
        for ext in ["evtx", "json"] {
            let candidate = rule_dir.join(format!("{}.{}", rule_id, ext));
            if candidate.exists() {
                return candidate;
            }
        }
        rule_dir.join(format!("{}.json", rule_id))
    }
}

// ─── Tests ─────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_list_sigma_id_returns_uuids() {
        let regression_dir = std::env::current_dir().ok().and_then(|cwd| {
            cwd.parent()
                .map(|p| p.join("sigma").join("regression_data"))
        });
        if let Some(ref dir) = regression_dir {
            let ids = SigmahqRegression::list_sigma_id(dir);
            if !ids.is_empty() {
                let first = &ids[0];
                let first_str = first.to_string();
                assert!(
                    first_str.contains('-'),
                    "UUID should contain hyphens: {}",
                    first_str
                );
            }
        }
    }

    #[test]
    fn test_sigmahq_regression_len() {
        let regression_dir = std::env::current_dir().ok().and_then(|cwd| {
            cwd.parent()
                .map(|p| p.join("sigma").join("regression_data"))
        });
        if let Some(ref dir) = regression_dir {
            if let Ok(reg) = SigmahqRegression::new_from_path(dir) {
                assert!(reg.len() > 0, "should have regression entries");
            }
        }
    }

    #[test]
    fn test_sigmahq_regression_is_empty() {
        let regression_dir = std::env::current_dir().ok().and_then(|cwd| {
            cwd.parent()
                .map(|p| p.join("sigma").join("regression_data"))
        });
        if let Some(ref dir) = regression_dir {
            if let Ok(reg) = SigmahqRegression::new_from_path(dir) {
                assert!(!reg.is_empty(), "should not be empty");
            }
        }
    }

    #[test]
    fn test_sigmahq_regression_iter() {
        let regression_dir = std::env::current_dir().ok().and_then(|cwd| {
            cwd.parent()
                .map(|p| p.join("sigma").join("regression_data"))
        });
        if let Some(ref dir) = regression_dir {
            if let Ok(reg) = SigmahqRegression::new_from_path(dir) {
                let entries: Vec<(&PathBuf, &InfoYml)> = reg.iter().collect();
                assert_eq!(entries.len(), reg.len());
                for (path, info) in &entries {
                    assert!(
                        path.to_string_lossy().ends_with("info.yml"),
                        "path should end with info.yml: {:?}",
                        path
                    );
                    assert!(
                        !info.rule_metadata.is_empty(),
                        "info should have rule_metadata"
                    );
                }
            }
        }
    }
}

// ─── Free functions ────────────────────────────────────────────────────

/// Scan regression data directories and return all existing rule IDs.
///
/// Walks `output_base/rules/` recursively, finds `info.yml` files, extracts
/// and validates each `rule_id`. Returns a sorted list of valid rule IDs.
pub fn list_sigma_id(output_base: &Path) -> Vec<String> {
    if !output_base.exists() {
        warn!(
            "list_sigma_id: directory does not exist: {}",
            output_base.display()
        );
        return Vec::new();
    }

    let rules_dir = output_base.join("rules");
    if !rules_dir.exists() {
        return Vec::new();
    }

    let mut ids = Vec::new();
    collect_ids(&rules_dir, &mut ids, 0);
    ids.sort();
    ids
}

fn collect_ids(dir: &Path, ids: &mut Vec<String>, depth: u32) {
    if depth > 64 {
        warn!("collect_ids: depth limit at {:?}", dir);
        return;
    }

    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };

    for entry in entries.filter_map(|e| e.ok()) {
        let path = entry.path();
        if let Ok(metadata) = path.symlink_metadata() {
            if metadata.file_type().is_symlink() {
                continue;
            }
        }
        if path.is_dir() {
            collect_ids(&path, ids, depth + 1);
        } else if path.file_name() == Some(OsStr::new("info.yml")) {
            match try_read_rule_id(&path) {
                Ok(rule_id) => {
                    if validate_rule_id(&rule_id) {
                        ids.push(rule_id);
                    } else {
                        warn!(
                            "list_sigma_id: invalid rule_id '{}' at {}",
                            rule_id,
                            path.display()
                        );
                    }
                }
                Err(e) => {
                    warn!(
                        "list_sigma_id: failed to read rule_id from {:?}: {}",
                        path, e
                    );
                }
            }
        }
    }
}

/// Resolve the data file associated with a rule in a given directory.
fn resolve_data_file(dir: &Path, rule_id: &str) -> Option<PathBuf> {
    for ext in ["evtx", "json"] {
        let candidate = dir.join(format!("{}.{}", rule_id, ext));
        if candidate.exists() {
            return Some(candidate);
        }
    }
    None
}

/// Add or update the `regression_tests_path` line in a Sigma rule YAML file.
pub(crate) fn update_regression_tests_path(rule_yaml_path: &Path, tests_path: &str) {
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

/// Try to read rule_id from an `info.yml` file without full loading.
pub(crate) fn try_read_rule_id(info_path: &Path) -> Result<String> {
    let info = InfoYml::load(info_path)?;
    info.rule_metadata
        .first()
        .map(|m| m.id.clone())
        .ok_or_else(|| anyhow!("No rule_metadata in {}", info_path.display()))
}

// ─── list_all ──────────────────────────────────────────────────────────

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
        if let Ok(metadata) = path.symlink_metadata() {
            if metadata.file_type().is_symlink() {
                continue;
            }
        }
        if path.is_dir() {
            walk(&path, paths, depth + 1);
        } else if path.file_name().is_some_and(|n| n == "info.yml")
            && try_read_rule_id(&path).is_ok()
        {
            paths.push(path);
        }
    }
}

// ─── clean_partial_artifacts ───────────────────────────────────────────

/// Delete regression directories that contain generated files (.json/.evtx)
/// but no `info.yml`. Such directories are partial artifacts from a prior run
/// that aborted before committing; they must not be carried into the current
/// run's commit.
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
