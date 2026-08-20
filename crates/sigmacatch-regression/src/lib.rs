// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 sigmacatch contributors

//! SigmaHQ-compatible regression data format and helpers.

mod evtx;
mod info;
pub mod logtype;
mod long_path;

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, anyhow};
use sigmacatch_types::{Alert, RegressionHeader};
use tracing::{error, info, info_span, warn};
use uuid::Uuid;

/// Maximum EVTX blob size the skip-set scan is willing to parse in memory
/// (64 MiB). Larger blobs are treated as broken so the rule gets re-captured
/// instead of consuming unbounded RAM on a corrupted or synthetic blob.
const MAX_EVTX_BLOB_SIZE: usize = 64 * 1024 * 1024;

/// A rule whose EVTX generation keeps failing is blocked (logged, dropped
/// from the active skip-set, no more re-capture) after this many consecutive
/// failed cycles. Configurable at runtime via `SigmahqRegression::set_max_failed_cycles`
/// (config.yaml `regression.max_failed_cycles`); this is the default.
pub const DEFAULT_MAX_FAILED_CYCLES: u32 = 3;

pub use crate::evtx::write_evtx;
use crate::info::{InfoYml, TestConfig};
use crate::logtype::LogType;

/// True when the rule's committed data file is valid: `.evtx` parses with
/// ≥ 1 record, else a non-empty `.json`. Broken data is excluded from the
/// skip set so the rule is re-captured.
fn data_file_is_valid(dir: &Path, rule_id: &Uuid) -> bool {
    let evtx = crate::long_path::long_path(&dir.join(format!("{}.evtx", rule_id)));
    if evtx.exists() {
        match std::fs::metadata(&evtx) {
            Ok(m) if m.len() as usize > MAX_EVTX_BLOB_SIZE => {
                warn!(
                    "rule {} excluded from skip-set: EVTX exceeds {} MiB (will be re-captured)",
                    rule_id,
                    MAX_EVTX_BLOB_SIZE / 1024 / 1024
                );
                return false;
            }
            Ok(_) => {}
            Err(e) => {
                warn!(
                    "rule {} excluded from skip-set: cannot stat {} ({}); will be re-captured",
                    rule_id,
                    evtx.display(),
                    e
                );
                return false;
            }
        }
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

pub struct SigmahqRegression {
    entries: Vec<(PathBuf, InfoYml, RegressionEntry)>,
    author: String,
    output_path: Option<PathBuf>,
    retired: HashSet<Uuid>,
    failed_cycles: HashMap<Uuid, u32>,
    failed_this_cycle: HashSet<Uuid>,
    blocked: Vec<Uuid>,
    max_failed_cycles: u32,
    /// Extension of the per-rule regression data file: `evtx` (Windows
    /// Winevt/ETW, re-exported from the live log) or `log` (non-EVTX sources
    /// like auditd, written from the event's original lines).
    data_ext: String,
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
            failed_cycles: HashMap::new(),
            failed_this_cycle: HashSet::new(),
            blocked: Vec::new(),
            max_failed_cycles: DEFAULT_MAX_FAILED_CYCLES,
            data_ext: "evtx".to_string(),
        })
    }

    /// Set the regression data file extension for the active collector
    /// (`evtx` for Windows Winevt/ETW, `log` for non-EVTX sources like
    /// auditd). Default: `evtx`.
    pub fn set_data_ext(&mut self, ext: &str) {
        self.data_ext = ext.to_string();
    }

    /// Configure the consecutive-failure bound after which a rule is blocked.
    /// Clamped to a minimum of 1. Default: `DEFAULT_MAX_FAILED_CYCLES` (3).
    pub fn set_max_failed_cycles(&mut self, max: u32) {
        self.max_failed_cycles = max.max(1);
    }

    pub fn max_failed_cycles(&self) -> u32 {
        self.max_failed_cycles
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

    /// Rules whose EVTX generation failed for the configured number of
    /// consecutive cycles. Drain so the caller can drop them from the active
    /// engine (no more re-capture). In-memory only — reset on the next startup.
    pub fn take_blocked(&mut self) -> Vec<Uuid> {
        std::mem::take(&mut self.blocked)
    }

    /// Open a new failure-counting cycle. Called once per batch by the
    /// orchestrator; ensures a rule counts at most one failed generation per
    /// cycle (multiple alerts for the same rule in one batch).
    pub fn begin_cycle(&mut self) {
        self.failed_this_cycle.clear();
    }

    /// Track a failed EVTX generation. After `self.max_failed_cycles`
    /// consecutive failures the rule is blocked: logged as `error!` and
    /// retired so it is no longer re-captured. At most one failure per rule
    /// per cycle is counted (`begin_cycle` opens a new cycle), so a rule with
    /// several matching events in a single batch is not blocked early.
    fn note_generation_failure(&mut self, rule_id: &Uuid) {
        if !self.failed_this_cycle.insert(*rule_id) {
            return;
        }
        let count = self.failed_cycles.entry(*rule_id).or_insert(0);
        *count += 1;
        if *count >= self.max_failed_cycles {
            error!(
                "Rule {} blocked after {} consecutive EVTX generation failures — no more re-capture",
                rule_id, *count
            );
            self.failed_cycles.remove(rule_id);
            self.retired.insert(*rule_id);
            self.blocked.push(*rule_id);
        }
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
            &self.data_ext,
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
                self.note_generation_failure(rule_id);
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
    data_ext: String,
}

impl RegressionData {
    fn for_rule(
        header: &RegressionHeader,
        output_path: &Path,
        rule_rel_path: Option<&Path>,
        author: Option<&str>,
        description: Option<&str>,
        data_ext: &str,
    ) -> Self {
        Self {
            header: header.clone(),
            alerts: Vec::new(),
            output_path: output_path.to_path_buf(),
            rule_rel_path: rule_rel_path.map(|p| p.to_path_buf()),
            author: author.map(|s| s.to_string()),
            description: description.map(|s| s.to_string()),
            data_ext: data_ext.to_string(),
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

        let data_ext = &self.data_ext;
        if let Some(alert) = first {
            let raw_json_path =
                crate::long_path::long_path(&rule_dir.join(format!("{}.json", rule_id)));
            let raw_json = serde_json::to_string_pretty(&alert.event_json_raw)?;
            std::fs::write(&raw_json_path, raw_json)?;
            tracing::info!("Wrote JSON for rule {:?}", rule_id);

            let data_path =
                crate::long_path::long_path(&rule_dir.join(format!("{}.{}", rule_id, data_ext)));
            let result = if data_ext == "evtx" {
                write_fn(
                    alert.raw_xml(),
                    alert.channel(),
                    alert.record_id(),
                    alert.is_etw,
                    &data_path,
                )
            } else {
                std::fs::write(&data_path, &alert.event_raw)
                    .map_err(|e| anyhow::anyhow!("Failed to write {data_ext} data: {e}"))
            };
            if let Err(e) = result {
                // Data generation failed (EVTX export empty or non-Windows):
                // drop the partial `.json` and data file so the rule is
                // re-captured later without orphaned files.
                let _ = std::fs::remove_file(&raw_json_path);
                let _ = std::fs::remove_file(&data_path);
                return Err(e);
            }
            tracing::info!("Wrote {data_ext} data for rule {:?}", rule_id);
        }

        let sigma_data_path = if first.is_some() {
            let data_name = format!("{}.{}", rule_id, data_ext);
            let rel_dir = self
                .sigma_rel_dir()
                .unwrap_or_else(|| format!("regression_data/rules/{rule_id}"));
            format!("{}/{}", rel_dir, data_name)
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
            &sigma_data_path,
            author,
            description,
            &TestConfig {
                test_type: data_ext.to_string(),
                provider: provider.to_string(),
            },
        );
        let info_path = crate::long_path::long_path(&rule_dir.join("info.yml"));
        info.save(&info_path)?;
        tracing::info!("Created info.yml at {:?}", info_path);

        tracing::info!(
            "Generated {} regression events for rule {:?}",
            self.alerts.len(),
            self.header.rule_id
        );
        Ok(data_ext.to_string())
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
    for ext in ["evtx", "json", "log", "raw"] {
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
        if let Ok(metadata) = path.symlink_metadata()
            && metadata.file_type().is_symlink()
        {
            continue;
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
        if let Ok(metadata) = path.symlink_metadata()
            && metadata.file_type().is_symlink()
        {
            warn!("Skipping symlink at {:?}", path);
            continue;
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
    use sigmacatch_types::Event;

    /// Build an alert that mirrors what the ETW path produces: an event
    /// synthesized from raw ETW data (Story 1.2/1.3) with a synthetic record
    /// id and `is_etw = true`, matched by the detection engine.
    fn synthetic_etw_alert(rule_id: Uuid) -> Alert {
        let xml = r#"<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Kernel-Process" Guid="{22FB2CD6-0E7B-422B-A0C7-2FAD1FD0E716}"/>
    <EventID>1</EventID>
    <Version>5</Version>
    <Level>4</Level>
    <Task>1</Task>
    <Opcode>0</Opcode>
    <Keywords>0x8000000000000000</Keywords>
    <TimeCreated SystemTime="2024-01-01T00:00:00.0000000Z"/>
    <EventRecordID>7</EventRecordID>
    <Channel>Microsoft-Windows-Sysmon/Operational</Channel>
    <Computer>localhost</Computer>
  </System>
  <EventData>
    <Data Name="Image">C:\Windows\System32\cmd.exe</Data>
    <Data Name="CommandLine">cmd.exe /c whoami</Data>
  </EventData>
</Event>"#;
        let event = Event::from_xml(xml).expect("synthetic ETW XML must parse");
        Alert {
            rule_id,
            rule_title: "Test ETW Rule".to_string(),
            description: Some("integration test".to_string()),
            rule_path: None,
            severity: "critical".to_string(),
            event_json_raw: event.event_json_raw.clone(),
            event_json: event.event_json.clone(),
            event_raw: event.event_raw.clone(),
            is_etw: true,
        }
    }

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
                &TestConfig {
                    test_type: "evtx".to_string(),
                    provider: "Microsoft-Windows-Sysmon".to_string(),
                },
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
        if let Some(ref dir) = regression_dir
            && let Ok(reg) = SigmahqRegression::new_from_path(dir)
        {
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
        if let Some(ref dir) = regression_dir
            && let Ok(reg) = SigmahqRegression::new_from_path(dir)
        {
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

    /// End-to-end downstream pipeline for an ETW alert (AC 9): the existing
    /// regression pipeline turns the alert into a valid json+evtx+info.yml
    /// triplet without any pipeline-aval change. `rule_path` is `None` so no
    /// sigma rule file is touched; everything lives in a tempdir.
    #[test]
    fn test_etw_alert_generates_valid_triplet() {
        let tmp = tempfile::tempdir().unwrap();
        let base = tmp.path().join("regression_data");
        let mut reg = SigmahqRegression::new_from_path(&base).unwrap();
        let rule_id = Uuid::parse_str("7595ba94-cf3b-4471-aa03-4f6baa9e5fad").unwrap();
        let alert = synthetic_etw_alert(rule_id);

        // Mirrors the `write_evtx` ETW branch: pure-Rust writer + re-parse
        // validation (the retry sleep loop is Windows-only).
        let write_fn = |xml: &str,
                        _channel: &str,
                        record_id: Option<u64>,
                        is_etw: bool,
                        path: &Path|
         -> anyhow::Result<()> {
            assert!(is_etw, "only the ETW writer path is exercised");
            let rid = record_id.unwrap_or(1);
            sigmacatch_evtx_writer::write_evtx_from_xml(xml, rid, path)?;
            let events = input_evtx::parse_evtx_file(path)?;
            if events.is_empty() {
                let _ = std::fs::remove_file(path);
                anyhow::bail!("evtx-writer produced an empty EVTX");
            }
            Ok(())
        };

        let files = reg.add(&alert, write_fn).expect("triplet generated");

        assert_eq!(files.len(), 3, "triplet = json + evtx + info.yml");

        let rule_dir = base.join("rules").join(rule_id.to_string());
        let json_path = rule_dir.join(format!("{rule_id}.json"));
        let evtx_path = rule_dir.join(format!("{rule_id}.evtx"));
        let info_path = rule_dir.join("info.yml");

        assert!(info_path.exists());
        let info = InfoYml::load(&info_path).unwrap();
        assert_eq!(info.rule_metadata[0].id, rule_id);
        assert_eq!(info.regression_tests_info[0].test_type, "evtx");
        assert_eq!(
            info.regression_tests_info[0].path,
            format!("regression_data/rules/{rule_id}/{rule_id}.evtx")
        );

        assert!(json_path.exists());
        let json: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&json_path).unwrap()).unwrap();
        assert_eq!(json["Event"]["System"]["EventRecordID"], 7);
        assert_eq!(
            json["Event"]["EventData"]["CommandLine"],
            "cmd.exe /c whoami"
        );

        assert!(evtx_path.exists());
        let events = input_evtx::parse_evtx_file(&evtx_path).unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].record_id(), Some(7));
    }

    /// Raw-mode generation (auditd): with `data_ext = "log"` the triplet is
    /// json + `.log` (the complete original audit event lines) + info.yml with
    /// `test_type: log`, and no EVTX writer is invoked.
    #[test]
    fn test_log_alert_generates_valid_triplet() {
        let tmp = tempfile::tempdir().unwrap();
        let base = tmp.path().join("regression_data");
        let mut reg = SigmahqRegression::new_from_path(&base).unwrap();
        reg.set_data_ext("log");
        let rule_id = Uuid::parse_str("ca94a6db-8106-4737-9ed2-3e3bb826af0a").unwrap();

        let raw_line =
            b"type=EXECVE msg=audit(1717056137.482:90412): argc=2 a0=\"passwd\" a1=\"-S\"\n";
        let event_json_raw = serde_json::json!({
            "stamp": { "timestamp": 1717056137482u64, "sequence": 90412 },
            "type": "EXECVE",
            "fields": { "argc": "2", "a0": "passwd", "a1": "-S" }
        });
        let event_json = serde_json::json!({
            "type": "EXECVE",
            "argc": "2",
            "a0": "passwd",
            "a1": "-S",
            "product": "linux",
            "service": "auditd"
        });
        let alert = Alert {
            rule_id,
            rule_title: "Password Policy Discovery - Linux".to_string(),
            description: Some("log-mode test".to_string()),
            rule_path: None,
            severity: "low".to_string(),
            event_json_raw: event_json_raw.clone(),
            event_json,
            event_raw: raw_line.to_vec(),
            is_etw: false,
        };

        // write_fn must never be called in log mode.
        let write_fn =
            |_: &str, _: &str, _: Option<u64>, _: bool, _: &Path| -> anyhow::Result<()> {
                panic!("EVTX writer must not be called in log mode")
            };

        let files = reg.add(&alert, write_fn).expect("triplet generated");
        assert_eq!(files.len(), 3, "triplet = json + log + info.yml");

        let rule_dir = base.join("rules").join(rule_id.to_string());
        let json_path = rule_dir.join(format!("{rule_id}.json"));
        let log_path = rule_dir.join(format!("{rule_id}.log"));
        let info_path = rule_dir.join("info.yml");

        assert!(info_path.exists());
        let info = InfoYml::load(&info_path).unwrap();
        assert_eq!(info.regression_tests_info[0].test_type, "log");
        assert_eq!(
            info.regression_tests_info[0].path,
            format!("regression_data/rules/{rule_id}/{rule_id}.log")
        );

        assert!(json_path.exists());
        let json: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&json_path).unwrap()).unwrap();
        assert_eq!(json["type"], "EXECVE");
        assert_eq!(json["fields"]["a1"], "-S");

        assert!(log_path.exists());
        assert_eq!(std::fs::read(&log_path).unwrap(), raw_line);

        // The generated rule is now skippable: a fresh regression instance sees
        // it as existing valid data.
        let fresh = SigmahqRegression::new_from_path(&base).unwrap();
        assert!(fresh.get_sigma_id().contains(&rule_id));
    }

    /// A rule whose EVTX generation keeps failing is blocked after the
    /// configured number of consecutive failed cycles (AC 7): logged, retired,
    /// no more re-capture. Multiple failing alerts in one batch count as a
    /// single failed cycle.
    #[test]
    fn test_failed_cycles_blocks_rule_after_max() {
        let tmp = tempfile::tempdir().unwrap();
        let base = tmp.path().join("regression_data");
        let mut reg = SigmahqRegression::new_from_path(&base).unwrap();
        let rule_id = Uuid::new_v4();
        let alert = synthetic_etw_alert(rule_id);

        let failing = |_xml: &str,
                       _channel: &str,
                       _record_id: Option<u64>,
                       _is_etw: bool,
                       _path: &Path|
         -> anyhow::Result<()> { anyhow::bail!("generation failure") };

        // Cycle 1: two failing alerts for the same rule count as one failure.
        assert!(reg.add(&alert, failing).is_none());
        assert!(reg.add(&alert, failing).is_none());
        assert!(reg.take_blocked().is_empty(), "not blocked yet");
        reg.begin_cycle();

        // Cycle 2.
        assert!(reg.add(&alert, failing).is_none());
        assert!(reg.take_blocked().is_empty(), "not blocked yet");
        reg.begin_cycle();

        // Cycle 3: default bound (3) reached → blocked.
        assert!(reg.add(&alert, failing).is_none());
        assert_eq!(reg.take_blocked(), vec![rule_id]);

        // Retired: any further attempt is short-circuited without generating.
        assert!(reg.add(&alert, failing).is_none());
        assert!(reg.take_blocked().is_empty());
    }

    /// The block bound is configurable via `set_max_failed_cycles` and
    /// clamped to a minimum of 1.
    #[test]
    fn test_max_failed_cycles_configurable() {
        let tmp = tempfile::tempdir().unwrap();
        let base = tmp.path().join("regression_data");
        let mut reg = SigmahqRegression::new_from_path(&base).unwrap();
        let rule_id = Uuid::new_v4();
        let alert = synthetic_etw_alert(rule_id);

        let failing = |_xml: &str,
                       _channel: &str,
                       _record_id: Option<u64>,
                       _is_etw: bool,
                       _path: &Path|
         -> anyhow::Result<()> { anyhow::bail!("generation failure") };

        reg.set_max_failed_cycles(2);
        assert_eq!(reg.max_failed_cycles(), 2);

        assert!(reg.add(&alert, failing).is_none());
        assert!(
            reg.take_blocked().is_empty(),
            "bound 2: not blocked after 1"
        );
        reg.begin_cycle();
        assert!(reg.add(&alert, failing).is_none());
        assert_eq!(reg.take_blocked(), vec![rule_id]);

        // Clamp: 0 is not allowed, so it becomes 1.
        let second_id = Uuid::new_v4();
        let second_alert = synthetic_etw_alert(second_id);
        reg.set_max_failed_cycles(0);
        assert_eq!(reg.max_failed_cycles(), 1);
        assert!(reg.add(&second_alert, failing).is_none());
        assert_eq!(reg.take_blocked(), vec![second_id]);
    }

    /// The `MAX_EVTX_BLOB_SIZE` guard (AC 8/10) also applies to the local
    /// skip-set scan: an oversized blob is treated as broken so the rule is
    /// re-captured instead of parsing unbounded memory.
    #[test]
    fn test_oversized_evtx_is_treated_as_broken() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path();
        let id = Uuid::new_v4();
        let evtx = dir.join(format!("{id}.evtx"));
        let file = std::fs::File::create(&evtx).unwrap();
        file.set_len((MAX_EVTX_BLOB_SIZE as u64) + 1).unwrap();
        drop(file);

        assert!(!data_file_is_valid(dir, &id));
    }
}
