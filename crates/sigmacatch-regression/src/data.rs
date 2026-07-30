// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 sigmacatch contributors

use anyhow::{anyhow, Context, Result};
use serde_json::Value;
use sigmacatch_types::{AggregatedRule, Alert, RegressionHeader};
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use tracing::{error, info, info_span, warn};

use crate::clean_partial_artifacts;
use crate::evtx::write_evtx;
use crate::info::InfoYml;
use crate::logtype::LogType;
use crate::validate::validate_rule_id;

/// Platform-agnostic regression data entry and batch generator.
///
/// Autonomous high-level interface — create with `new(path)`, configure
/// with setters, then call `generate_all()` for batch generation.
pub struct RegressionData {
    // Generation state
    header: RegressionHeader,
    alerts: Vec<Alert>,
    output_path: PathBuf,
    rule_rel_path: Option<PathBuf>,
    author: Option<String>,
    description: Option<String>,
    is_contrib: bool,
    // Loaded state
    info: InfoYml,
    info_path: PathBuf,
    raw_data: Option<Vec<u8>>,
    logtype: LogType,
}

impl RegressionData {
    /// Create a new `RegressionData` for batch generation.
    ///
    /// Set `output_path` to the directory where regression data will be written.
    /// Configure with `set_author()`, `set_is_contrib()`, then call `generate_all()`.
    pub fn new(output_path: &Path) -> Self {
        Self {
            header: RegressionHeader::new(String::new(), String::new()),
            alerts: Vec::new(),
            output_path: output_path.to_path_buf(),
            rule_rel_path: None,
            author: None,
            description: None,
            is_contrib: false,
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

    /// Generate regression data for all non-retired, non-existing rules.
    ///
    /// Returns a vec of `(rule_id, rel_dir, rule_yaml_rel)` for committed entries.
    pub fn generate_all(
        &self,
        aggregated: &HashMap<String, AggregatedRule>,
        sigma_repo_path: &Path,
        to_retire: &mut HashSet<String>,
    ) -> Vec<(String, String, Option<String>)> {
        clean_partial_artifacts(&self.output_path);

        let mut committed: Vec<(String, String, Option<String>)> = Vec::new();
        let author = self
            .author
            .as_deref()
            .unwrap_or("Sigma Regression Generator");

        for agg in aggregated.values() {
            let rule_id = &agg.header.rule_id;
            if to_retire.contains(rule_id) {
                continue;
            }

            let rule_rel_path = agg.rule_path.as_ref().and_then(|p| {
                p.strip_prefix(sigma_repo_path)
                    .ok()
                    .map(|rel| rel.with_extension(""))
            });

            let mut reg = RegressionData::for_rule(
                &agg.header,
                &self.output_path,
                rule_rel_path.as_deref(),
                Some(author),
                agg.description.as_deref(),
                self.is_contrib,
            );
            if reg.exists() {
                continue;
            }

            for alert in &agg.alerts {
                reg.add_alert(alert.clone());
            }

            let _gen_span = info_span!("generate", rule_id = %rule_id).entered();
            match reg.generate(write_evtx) {
                Ok(_) => {
                    let rel_dir = reg
                        .sigma_rel_dir()
                        .unwrap_or_else(|| format!("regression_data/rules/{rule_id}"));

                    let rule_yaml_rel = agg
                        .rule_path
                        .as_ref()
                        .and_then(|p| p.strip_prefix(sigma_repo_path).ok())
                        .and_then(|p| p.to_str())
                        .map(|s| s.to_string().replace('\\', "/"));

                    let tests_path = format!("{}/info.yml", rel_dir.replace('\\', "/"));
                    if let Some(ref rule_yaml_path) = agg.rule_path {
                        update_regression_tests_path(rule_yaml_path, &tests_path);
                    }

                    to_retire.insert(rule_id.clone());
                    info!("Rule {rule_id} retired from detection engine");

                    committed.push((rule_id.clone(), rel_dir, rule_yaml_rel));
                }
                Err(e) => {
                    error!("Failed to generate regression for {}: {}", rule_id, e);
                }
            }
        }

        committed
    }

    /// Create a `RegressionData` for a single rule (internal helper).
    fn for_rule(
        header: &RegressionHeader,
        output_path: &Path,
        rule_rel_path: Option<&Path>,
        author: Option<&str>,
        description: Option<&str>,
        is_contrib: bool,
    ) -> Self {
        Self {
            header: header.clone(),
            alerts: Vec::new(),
            output_path: output_path.to_path_buf(),
            rule_rel_path: rule_rel_path.map(|p| p.to_path_buf()),
            author: author.map(|s| s.to_string()),
            description: description.map(|s| s.to_string()),
            is_contrib,
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
            rule_rel_path: None,
            author: None,
            description: None,
            is_contrib: false,
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
        // Resolve from info.yml path or compute from rule_dir
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
            match try_read_rule_id(&path) {
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

/// Add or update the `regression_tests_path` line in a Sigma rule YAML file.
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

/// Try to read rule_id from an `info.yml` file without full loading.
pub(crate) fn try_read_rule_id(info_path: &Path) -> Result<String> {
    let info = InfoYml::load(info_path)?;
    info.rule_metadata
        .first()
        .map(|m| m.id.clone())
        .ok_or_else(|| anyhow::anyhow!("No rule_metadata in {}", info_path.display()))
}
