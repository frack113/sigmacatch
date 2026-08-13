// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 sigmacatch contributors

//! SigmaHQ-compatible regression data format and helpers.

mod evtx;
mod info;
pub mod logtype;
mod long_path;

use std::path::{Path, PathBuf};

use anyhow::{anyhow, Context, Result};
use sigmacatch_types::{Alert, RegressionHeader};
use std::collections::HashSet;
use tracing::{error, info, info_span, warn};
use uuid::Uuid;

pub use crate::evtx::write_evtx;
use crate::info::InfoYml;
use crate::logtype::LogType;

/// True when the rule's committed data file is valid: `.evtx` parses with
/// ≥ 1 record, else a non-empty `.json`. Broken data is excluded from the
/// skip set so the rule is re-captured.
fn data_file_is_valid(dir: &Path, rule_id: &Uuid) -> bool {
    let evtx = crate::long_path::long_path(&dir.join(format!("{}.evtx", rule_id)));
    if evtx.exists() {
        return match input_evtx::parse_evtx_file(&evtx) {
            Ok(events) => !events.is_empty(),
            Err(_) => false,
        };
    }
    let json = crate::long_path::long_path(&dir.join(format!("{}.json", rule_id)));
    if json.exists() {
        return std::fs::metadata(&json).is_ok_and(|m| m.len() > 0);
    }
    false
}

#[derive(Debug, Clone)]
pub struct RegressionEntry {
    pub rule_id: Uuid,
    pub rule_name: String,
    pub logtype: LogType,
}

impl RegressionEntry {
    fn from_info(info: &InfoYml, info_path: &Path) -> Self {
        let rule_id = info
            .rule_metadata
            .first()
            .map(|m| m.id)
            .unwrap_or(Uuid::nil());
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

#[derive(Default)]
pub struct SigmahqRegression {
    entries: Vec<(PathBuf, InfoYml, RegressionEntry)>,
    author: String,
    output_path: Option<PathBuf>,
    retired: HashSet<Uuid>,
}

impl SigmahqRegression {
    pub fn new() -> Result<Self> {
        Self::new_from_path(Path::new("./sigma/regression_data"))
    }

    pub fn new_from_path(regression_path: &Path) -> Result<Self> {
        let mut entries = Vec::new();
        if regression_path.exists() {
            let info_paths = list_all(regression_path);
            for path in &info_paths {
                if let Ok(info) = InfoYml::load(path) {
                    let entry = RegressionEntry::from_info(&info, path);
                    entries.push((path.clone(), info, entry));
                }
            }
        }
        Ok(Self {
            entries,
            author: String::new(),
            output_path: Some(regression_path.to_path_buf()),
            retired: HashSet::new(),
        })
    }

    pub fn set_author(&mut self, author: String) {
        self.author = author;
    }

    pub fn author(&self) -> &str {
        &self.author
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn iter(&self) -> impl Iterator<Item = (&PathBuf, &InfoYml)> {
        self.entries.iter().map(|(path, info, _)| (path, info))
    }

    pub fn infos(&self) -> impl Iterator<Item = &InfoYml> {
        self.entries.iter().map(|(_, info, _)| info)
    }

    pub fn entries(&self) -> impl Iterator<Item = &RegressionEntry> {
        self.entries.iter().map(|(_, _, entry)| entry)
    }

    pub fn get_entry(&self, index: usize) -> Option<&RegressionEntry> {
        self.entries.get(index).map(|(_, _, entry)| entry)
    }

    /// Rule ids with valid regression data (skippable). Broken data is excluded
    /// so the rule is re-captured and regenerated.
    pub fn get_sigma_id(&self) -> Vec<Uuid> {
        self.entries
            .iter()
            .filter_map(|(info_path, info, _)| {
                let rule_id = info.rule_metadata.first().map(|m| m.id)?;
                let dir = info_path.parent()?;
                data_file_is_valid(dir, &rule_id).then_some(rule_id)
            })
            .collect()
    }

    pub fn get_raw_data(&self, index: usize) -> Option<Vec<u8>> {
        let (info_path, info, _) = self.entries.get(index)?;
        let rule_id = info.rule_metadata.first()?.id;
        let dir = info_path.parent()?;
        let data_path = resolve_data_file(dir, &rule_id)?;
        std::fs::read(&data_path).ok()
    }

    /// Read the committed raw event JSON (`<rule_id>.json`), if present.
    pub fn get_json_data(&self, index: usize) -> Option<serde_json::Value> {
        let (info_path, info, _) = self.entries.get(index)?;
        let rule_id = info.rule_metadata.first()?.id;
        let dir = info_path.parent()?;
        let json_path = dir.join(format!("{}.json", rule_id));
        if !json_path.exists() {
            return None;
        }
        let content = std::fs::read_to_string(json_path).ok()?;
        serde_json::from_str(&content).ok()
    }

    pub fn add<F>(&mut self, alert: &Alert, write_fn: F) -> Option<Vec<String>>
    where
        F: Fn(&str, &str, Option<u64>, bool, &Path) -> Result<()>,
    {
        let output_path = self.output_path.as_ref()?;
        let rule_id = &alert.rule_id;
        if self.retired.contains(rule_id) {
            return None;
        }
        if rule_id.is_nil() {
            warn!(
                "Skipping regression for rule without a valid id: {:?}",
                alert.rule_title
            );
            return None;
        }

        let sigma_repo_path = Path::new("sigma");
        let rule_rel_path = alert.rule_path.as_ref().and_then(|p| {
            clean_path(p)
                .strip_prefix(sigma_repo_path)
                .ok()
                .map(|rel| rel.with_extension(""))
        });

        let mut reg = RegressionData::for_rule(
            &RegressionHeader::new(*rule_id, alert.rule_title.clone()),
            output_path,
            rule_rel_path.as_deref(),
            if self.author.is_empty() {
                None
            } else {
                Some(self.author.as_str())
            },
            alert.description.as_deref(),
        );

        if reg.exists() {
            return None;
        }

        reg.add_alert(alert.clone());

        let _gen_span = info_span!("generate", rule_id = %rule_id).entered();
        let evtx_ext = match reg.generate(write_fn) {
            Ok(ext) => ext,
            Err(e) => {
                error!("Failed to generate regression for {}: {}", rule_id, e);
                return None;
            }
        };
        let rel_dir = reg
            .sigma_rel_dir()
            .unwrap_or_else(|| format!("regression_data/rules/{rule_id}"));

        let rule_yaml_rel = alert
            .rule_path
            .as_ref()
            .and_then(|p| {
                clean_path(p)
                    .strip_prefix(sigma_repo_path)
                    .ok()
                    .map(|p| p.to_path_buf())
            })
            .and_then(|p| p.to_str().map(|s| s.to_string()))
            .map(|s| s.to_string().replace('\\', "/"));

        let tests_path = format!("{}/info.yml", rel_dir.replace('\\', "/"));
        if let Some(ref rule_yaml_path) = alert.rule_path {
            update_regression_tests_path(rule_yaml_path, &tests_path);
        }

        self.retired.insert(*rule_id);
        info!("Rule {rule_id} retired from detection engine");

        let mut files = vec![
            format!("{}/{}.json", rel_dir, rule_id),
            format!("{}/{}.{}", rel_dir, rule_id, evtx_ext),
            format!("{}/info.yml", rel_dir),
        ];
        if let Some(ref yaml_rel) = rule_yaml_rel {
            files.push(yaml_rel.clone());
        }

        Some(files)
    }
}

struct RegressionData {
    header: RegressionHeader,
    alerts: Vec<Alert>,
    output_path: PathBuf,
    rule_rel_path: Option<PathBuf>,
    author: Option<String>,
    description: Option<String>,
}

impl RegressionData {
    fn for_rule(
        header: &RegressionHeader,
        output_path: &Path,
        rule_rel_path: Option<&Path>,
        author: Option<&str>,
        description: Option<&str>,
    ) -> Self {
        Self {
            header: header.clone(),
            alerts: Vec::new(),
            output_path: output_path.to_path_buf(),
            rule_rel_path: rule_rel_path.map(|p| p.to_path_buf()),
            author: author.map(|s| s.to_string()),
            description: description.map(|s| s.to_string()),
        }
    }

    fn add_alert(&mut self, alert: Alert) {
        self.alerts.push(alert);
    }

    fn rule_dir(&self) -> Result<PathBuf> {
        if let Some(rel_path) = &self.rule_rel_path {
            return Ok(self.output_path.join(rel_path));
        }
        Ok(self
            .output_path
            .join("rules")
            .join(self.header.rule_id.to_string()))
    }

    fn sigma_rel_dir(&self) -> Option<String> {
        self.rule_rel_path.as_ref().map(|rel_path| {
            let rel = rel_path.display().to_string().replace('\\', "/");
            format!("regression_data/{}", rel)
        })
    }

    fn exists(&self) -> bool {
        self.rule_dir().is_ok_and(|d| {
            d.join("info.yml").exists() && data_file_is_valid(&d, &self.header.rule_id)
        })
    }

    fn generate<F>(&self, write_fn: F) -> Result<String>
    where
        F: Fn(&str, &str, Option<u64>, bool, &Path) -> Result<()>,
    {
        let rule_dir = self.rule_dir()?;
        let rule_dir = crate::long_path::long_path(&rule_dir);
        let rule_id = &self.header.rule_id;
        std::fs::create_dir_all(&rule_dir)
            .with_context(|| format!("Failed to create rule directory {:?}", rule_dir))?;

        let first = self.alerts.first();
        let match_count = if first.is_some() { 1 } else { 0 };

        let evtx_ext = "evtx";
        if let Some(alert) = first {
            let raw_json_path =
                crate::long_path::long_path(&rule_dir.join(format!("{}.json", rule_id)));
            let raw_json = serde_json::to_string_pretty(&alert.event_json_raw)?;
            std::fs::write(&raw_json_path, raw_json)?;
            tracing::info!("Wrote JSON for rule {:?}", rule_id);

            let evtx_path =
                crate::long_path::long_path(&rule_dir.join(format!("{}.evtx", rule_id)));
            if let Err(e) = write_fn(
                alert.raw_xml(),
                alert.channel(),
                alert.record_id(),
                alert.is_etw,
                &evtx_path,
            ) {
                // EVTX failed (empty export or non-Windows): drop the partial `.json`
                // and keep the rule loaded so it is re-captured later.
                let _ = std::fs::remove_file(&raw_json_path);
                return Err(e);
            }
            tracing::info!("Wrote EVTX for rule {:?}", rule_id);
        }

        let sigma_evtx_path = if first.is_some() {
            let evtx_name = format!("{}.{}", rule_id, evtx_ext);
            let rel_dir = self
                .sigma_rel_dir()
                .unwrap_or_else(|| format!("regression_data/rules/{rule_id}"));
            format!("{}/{}", rel_dir, evtx_name)
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
        let info_path = crate::long_path::long_path(&rule_dir.join("info.yml"));
        info.save(&info_path)?;
        tracing::info!("Created info.yml at {:?}", info_path);

        tracing::info!(
            "Generated {} regression events for rule {:?}",
            self.alerts.len(),
            self.header.rule_id
        );
        Ok(evtx_ext.to_string())
    }
}

// ─── Free functions ─────────────────────────────────────────────────────

fn clean_path(p: &Path) -> PathBuf {
    p.components()
        .filter(|c| {
            !matches!(
                c,
                std::path::Component::CurDir | std::path::Component::ParentDir
            )
        })
        .collect()
}

fn resolve_data_file(dir: &Path, rule_id: &Uuid) -> Option<PathBuf> {
    for ext in ["evtx", "json"] {
        let candidate = dir.join(format!("{}.{}", rule_id, ext));
        if candidate.exists() {
            return Some(candidate);
        }
    }
    None
}

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

pub(crate) fn try_read_rule_id(info_path: &Path) -> Result<Uuid> {
    let info = InfoYml::load(info_path)?;
    info.rule_metadata
        .first()
        .map(|m| m.id)
        .ok_or_else(|| anyhow!("No rule_metadata in {}", info_path.display()))
}

// ─── list_all ──────────────────────────────────────────────────────────

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_data_file_is_valid_detects_broken_evtx() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path();
        let id = Uuid::new_v4();

        assert!(!data_file_is_valid(dir, &id), "no data file → invalid");

        let evtx = dir.join(format!("{id}.evtx"));
        std::fs::write(&evtx, b"not-an-evtx").unwrap();
        assert!(!data_file_is_valid(dir, &id), "unparsable EVTX → invalid");

        std::fs::remove_file(&evtx).unwrap();
        let json = dir.join(format!("{id}.json"));
        std::fs::write(&json, b"").unwrap();
        assert!(!data_file_is_valid(dir, &id), "empty json → invalid");

        std::fs::write(&json, b"{}").unwrap();
        assert!(data_file_is_valid(dir, &id), "non-empty json → valid");
    }

    #[test]
    fn test_get_sigma_id_excludes_broken_evtx() {
        let tmp = tempfile::tempdir().unwrap();
        let base = tmp.path().join("regression_data");
        let good_dir = base.join("rules/win/good");
        let broken_dir = base.join("rules/win/broken");
        let missing_dir = base.join("rules/win/missing");
        for d in [&good_dir, &broken_dir, &missing_dir] {
            std::fs::create_dir_all(d).unwrap();
        }

        let good_id = Uuid::new_v4();
        let broken_id = Uuid::new_v4();
        let missing_id = Uuid::new_v4();

        let write_info = |dir: &Path, rule_id: Uuid| {
            InfoYml::new(
                &rule_id,
                "Test Rule",
                1,
                "regression_data/rules/win/x/1.evtx",
                "tester",
                "N/A",
                "Microsoft-Windows-Sysmon",
            )
            .save(&dir.join("info.yml"))
            .unwrap();
        };

        write_info(&good_dir, good_id);
        std::fs::write(good_dir.join(format!("{good_id}.json")), "{}").unwrap();

        write_info(&broken_dir, broken_id);
        std::fs::write(broken_dir.join(format!("{broken_id}.evtx")), b"x").unwrap();
        std::fs::write(broken_dir.join(format!("{broken_id}.json")), "{}").unwrap();

        write_info(&missing_dir, missing_id);

        let reg = SigmahqRegression::new_from_path(&base).unwrap();
        let ids = reg.get_sigma_id();
        assert_eq!(ids, vec![good_id]);
    }

    #[test]
    fn test_get_sigma_id_returns_uuids() {
        let regression_dir = std::env::current_dir().ok().and_then(|cwd| {
            cwd.parent()
                .map(|p| p.join("sigma").join("regression_data"))
        });
        if let Some(ref dir) = regression_dir {
            if let Ok(reg) = SigmahqRegression::new_from_path(dir) {
                let ids = reg.get_sigma_id();
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
    }

    #[test]
    fn test_new_from_path_missing_dir_is_empty() {
        let missing = std::env::temp_dir().join("sigmacatch-regression-missing-xyz");
        let reg = SigmahqRegression::new_from_path(&missing)
            .expect("lenient constructor: missing dir returns Ok");
        assert_eq!(reg.len(), 0);
        assert!(reg.is_empty());
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
