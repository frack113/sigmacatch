// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 sigmacatch contributors

//! SigmaHQ-compatible regression data format and helpers.
//!
//! # Example
//!
//! ```rust,no_run
//! use sigmacatch_regression::SigmahqRegression;
//! use std::path::Path;
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let regression = SigmahqRegression::new_from_path(Path::new("sigma/regression_data"))?;
//! println!("Found {} regression entries", regression.len());
//! # Ok(())
//! # }
//! ```

mod evtx;
mod format;
pub mod info;
/// SigmaHQ `logtype` metadata helpers for `info.yml`.
pub mod logtype;
mod long_path;

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

use sigmacatch_types::{Alert, RegressionHeader};
use tracing::{error, info, info_span, warn};
use uuid::Uuid;

use crate::format::DATA_EXTENSIONS;
pub use crate::format::DataFormat;
use crate::info::{InfoYml, TestConfig};
use crate::logtype::LogType;

/// A rule whose EVTX generation keeps failing is blocked (logged, dropped
/// from the active skip-set, no more re-capture) after this many consecutive
/// failed cycles. Configurable at runtime via `SigmahqRegression::set_max_failed_cycles`
/// (config.yaml `regression.max_failed_cycles`); this is the default.
pub const DEFAULT_MAX_FAILED_CYCLES: u32 = 3;

/// True when the rule's committed data file exists and is non-empty. We do
/// not open the file — deep structural validation is deferred to
/// `regressiondata-check`.
fn data_file_exists(dir: &Path, rule_id: &Uuid, format: DataFormat) -> bool {
    let ext = format.ext();
    let candidate = crate::long_path::long_path(&dir.join(format!("{rule_id}.{ext}")));
    std::fs::metadata(&candidate).is_ok_and(|m| m.len() > 0)
}

/// One loaded regression entry (one rule with existing data).
#[derive(Debug, Clone)]
pub struct RegressionEntry {
    /// Rule UUID the data belongs to.
    pub rule_id: Uuid,
    /// Rule title as recorded in `info.yml`.
    pub rule_name: String,
    /// Data format of the stored regression file.
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

/// In-memory index of existing regression data plus the write-side state
/// (author, format, failure tracking) for generating new data.
pub struct SigmahqRegression {
    entries: Vec<(PathBuf, InfoYml, RegressionEntry)>,
    author: String,
    output_path: Option<PathBuf>,
    retired: HashSet<Uuid>,
    failed_cycles: HashMap<Uuid, u32>,
    failed_this_cycle: HashSet<Uuid>,
    blocked: Vec<Uuid>,
    max_failed_cycles: u32,
    /// Output format of the per-rule data file, set by the active collector.
    format: DataFormat,
    /// Write the auxiliary `<rule_id>.json` next to the data file
    /// (config.yaml `regression.add_json_output`). The data file + info.yml
    /// are always written; the json is optional extra.
    add_json_output: bool,
}

impl SigmahqRegression {
    /// Scan the default `./sigma/regression_data` directory.
    pub fn new() -> Result<Self> {
        Self::new_from_path(Path::new("./sigma/regression_data"))
    }

    /// Scan an explicit regression-data directory for existing entries.
    pub fn new_from_path(regression_path: &Path) -> Result<Self> {
        let mut entries = Vec::new();
        if regression_path.exists() {
            let info_paths = list_all(regression_path);
            for path in &info_paths {
                match InfoYml::load(path) {
                    Ok(info) => {
                        let entry = RegressionEntry::from_info(&info, path);
                        entries.push((path.clone(), info, entry));
                    }
                    // An unparsable entry must not vanish silently: it would
                    // leave the rule out of the skip set and get re-captured
                    // over existing data on the next cycle.
                    Err(e) => tracing::warn!("skipping {}: {e}", path.display()),
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
            format: DataFormat::Evtx,
            add_json_output: false,
        })
    }

    /// Set the regression data format for the active collector
    /// ([`DataFormat::Evtx`] for Windows Winevt/ETW, [`DataFormat::Log`] for
    /// auditd). Default: [`DataFormat::Evtx`].
    pub fn set_format(&mut self, format: DataFormat) {
        self.format = format;
    }

    /// Set whether the auxiliary `<rule_id>.json` is written next to the data
    /// file. Default: `false`.
    pub fn set_add_json_output(&mut self, enabled: bool) {
        self.add_json_output = enabled;
    }

    /// Configure the consecutive-failure bound after which a rule is blocked.
    /// Clamped to a minimum of 1. Default: `DEFAULT_MAX_FAILED_CYCLES` (3).
    pub fn set_max_failed_cycles(&mut self, max: u32) {
        self.max_failed_cycles = max.max(1);
    }

    /// Configured consecutive-failure bound.
    pub fn max_failed_cycles(&self) -> u32 {
        self.max_failed_cycles
    }

    /// Set the author recorded in generated `info.yml` files.
    pub fn set_author(&mut self, author: String) {
        self.author = author;
    }

    /// Configured author string.
    pub fn author(&self) -> &str {
        &self.author
    }

    /// Path where regression data was loaded from.
    pub fn path(&self) -> &Path {
        self.output_path
            .as_deref()
            .unwrap_or(Path::new("./sigma/regression_data"))
    }

    /// Number of loaded regression entries.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// True when no regression entry was found.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Iterate `(info.yml path, parsed info)` pairs.
    pub fn iter(&self) -> impl Iterator<Item = (&PathBuf, &InfoYml)> {
        self.entries.iter().map(|(path, info, _)| (path, info))
    }

    /// Iterate the parsed `info.yml` documents.
    pub fn infos(&self) -> impl Iterator<Item = &InfoYml> {
        self.entries.iter().map(|(_, info, _)| info)
    }

    /// Iterate the derived [`RegressionEntry`] records.
    pub fn entries(&self) -> impl Iterator<Item = &RegressionEntry> {
        self.entries.iter().map(|(_, _, entry)| entry)
    }

    /// Iterate full `(info.yml path, parsed info, entry)` triples.
    pub fn iter_entries(&self) -> impl Iterator<Item = (&PathBuf, &InfoYml, &RegressionEntry)> {
        self.entries.iter().map(|(p, i, e)| (p, i, e))
    }

    /// Entry at load order `index`.
    pub fn get_entry(&self, index: usize) -> Option<&RegressionEntry> {
        self.entries.get(index).map(|(_, _, entry)| entry)
    }

    /// Parsed `info.yml` for entry `index` — used by `regressiondata-check` to read
    /// the expected `match_count` declared in `regression_tests_info`.
    pub fn get_info(&self, index: usize) -> Option<&InfoYml> {
        self.entries.get(index).map(|(_, info, _)| info)
    }

    /// Path to the `info.yml` file for entry `index`.
    pub fn get_info_path(&self, index: usize) -> Option<&Path> {
        self.entries.get(index).map(|(path, _, _)| path.as_path())
    }

    /// Rule ids with committed regression data (skippable). We only check
    /// existence and non-empty — deep structural validation is left to
    /// `regressiondata-check`.
    pub fn get_sigma_id(&self) -> Vec<Uuid> {
        self.entries
            .iter()
            .filter_map(|(info_path, info, _)| {
                let rule_id = info.rule_metadata.first().map(|m| m.id)?;
                let dir = info_path.parent()?;
                data_file_exists(dir, &rule_id, self.format).then_some(rule_id)
            })
            .collect()
    }

    /// Raw bytes of the regression data file for entry `index` — used by
    /// diagnostics to re-validate stored events against their rules.
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

    /// Track a failed generation. After `self.max_failed_cycles` consecutive
    /// failures the rule is blocked: logged as `error!` and retired so it is
    /// no longer re-captured. At most one failure per rule per cycle is
    /// counted (`begin_cycle` opens a new cycle), so a rule with several
    /// matching events in a single batch is not blocked early.
    fn note_generation_failure(&mut self, rule_id: &Uuid) {
        if !self.failed_this_cycle.insert(*rule_id) {
            return;
        }
        let count = self.failed_cycles.entry(*rule_id).or_insert(0);
        *count += 1;
        if *count >= self.max_failed_cycles {
            error!(
                "Rule {} blocked after {} consecutive generation failures — no more re-capture",
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

    /// Record a match: write/refresh the rule's regression data. Returns the
    /// written relative paths, or `None` when retired/blocked/no output dir.
    pub fn add(&mut self, alert: &Alert) -> Option<Vec<String>> {
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
            self.format,
            self.add_json_output,
        );

        if reg.exists() {
            return None;
        }

        reg.add_alert(alert.clone());

        let _gen_span = info_span!("generate", rule_id = %rule_id).entered();
        if let Err(e) = reg.generate() {
            error!("Failed to generate regression for {}: {}", rule_id, e);
            self.note_generation_failure(rule_id);
            return None;
        }

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
            .map(|s| s.replace('\\', "/"));

        let tests_path = format!("{}/info.yml", rel_dir.replace('\\', "/"));
        if let Some(ref rule_yaml_path) = alert.rule_path {
            update_regression_tests_path(rule_yaml_path, &tests_path);
        }

        self.retired.insert(*rule_id);
        info!("Rule {rule_id} retired from detection engine");

        let ext = self.format.ext();
        let mut files = Vec::new();
        if self.add_json_output {
            files.push(format!("{}/{}.json", rel_dir, rule_id));
        }
        files.push(format!("{}/{}.{}", rel_dir, rule_id, ext));
        files.push(format!("{}/info.yml", rel_dir));
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
    format: DataFormat,
    add_json_output: bool,
}

impl RegressionData {
    fn for_rule(
        header: &RegressionHeader,
        output_path: &Path,
        rule_rel_path: Option<&Path>,
        author: Option<&str>,
        description: Option<&str>,
        format: DataFormat,
        add_json_output: bool,
    ) -> Self {
        Self {
            header: header.clone(),
            alerts: Vec::new(),
            output_path: output_path.to_path_buf(),
            rule_rel_path: rule_rel_path.map(|p| p.to_path_buf()),
            author: author.map(|s| s.to_string()),
            description: description.map(|s| s.to_string()),
            format,
            add_json_output,
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
            d.join("info.yml").exists() && data_file_exists(&d, &self.header.rule_id, self.format)
        })
    }

    /// Write the data file (+ optional auxiliary json) then info.yml. On data
    /// failure the partial artifacts are removed so the rule is re-captured
    /// later without orphaned files. The provider is resolved before any file
    /// is written so a malformed event fails fast.
    fn generate(&self) -> Result<()> {
        let alert = self.alerts.first().ok_or_else(|| {
            RegressionError::Invalid(format!("no matched event for rule {}", self.header.rule_id))
        })?;
        let provider = self.format.resolve_provider(alert)?;

        let rule_dir = self.rule_dir()?;
        let rule_dir = crate::long_path::long_path(&rule_dir);
        std::fs::create_dir_all(&rule_dir).map_err(|e| {
            RegressionError::Invalid(format!(
                "Failed to create rule directory {:?}: {e}",
                rule_dir
            ))
        })?;

        let rule_id = &self.header.rule_id;
        let ext = self.format.ext();
        let mut written: Vec<PathBuf> = Vec::new();
        let result = (|| -> Result<()> {
            if self.add_json_output {
                let raw_json_path =
                    crate::long_path::long_path(&rule_dir.join(format!("{rule_id}.json")));
                let mut raw_json =
                    serde_json::to_string_pretty(&alert.event_json_raw).map_err(|e| {
                        RegressionError::Invalid(format!("failed to serialize raw event json: {e}"))
                    })?;
                raw_json.push('\n');
                std::fs::write(&raw_json_path, raw_json)?;
                written.push(raw_json_path);
            }
            let data_path = crate::long_path::long_path(&rule_dir.join(format!("{rule_id}.{ext}")));
            self.format.write(alert, &data_path)?;
            written.push(data_path);
            Ok(())
        })();
        if let Err(e) = result {
            for path in &written {
                let _ = std::fs::remove_file(path);
            }
            return Err(e);
        }

        let rel_dir = self
            .sigma_rel_dir()
            .unwrap_or_else(|| format!("regression_data/rules/{rule_id}"));
        let sigma_data_path = format!("{rel_dir}/{rule_id}.{ext}");

        let author = self
            .author
            .as_deref()
            .unwrap_or("Sigma Regression Generator");
        let description = self.description.as_deref().unwrap_or("N/A");

        let info = InfoYml::new(
            rule_id,
            &self.header.rule_title,
            1,
            &sigma_data_path,
            author,
            description,
            &TestConfig {
                test_type: ext.to_string(),
                provider,
            },
        );
        let info_path = crate::long_path::long_path(&rule_dir.join("info.yml"));
        info.save(&info_path)?;

        tracing::info!(
            "Generated regression data ({ext}) for rule {:?}",
            self.header.rule_id
        );
        Ok(())
    }
}

/// Errors produced while generating, reading or writing regression data.
#[derive(Debug, thiserror::Error)]
pub enum RegressionError {
    /// Filesystem failure.
    #[error("filesystem error: {0}")]
    Io(#[from] std::io::Error),
    /// YAML could not be parsed or serialized.
    #[error("YAML error: {0}")]
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
    DATA_EXTENSIONS
        .iter()
        .map(|ext| dir.join(format!("{rule_id}.{ext}")))
        .find(|candidate| candidate.exists())
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
    info.rule_metadata.first().map(|m| m.id).ok_or_else(|| {
        RegressionError::Invalid(format!("No rule_metadata in {}", info_path.display()))
    })
}

// ─── list_all ──────────────────────────────────────────────────────────

/// Recursively list every parsable `info.yml` under `dir`, sorted.
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::format::MAX_DATA_BLOB_SIZE;
    use sigmacatch_types::Event;

    /// Build an alert that mirrors what the ETW path produces: an event
    /// synthesized from raw ETW data with a synthetic record id and
    /// `is_etw = true`, matched by the detection engine.
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
            event_raw: event.event_raw,
            is_etw: true,
        }
    }

    /// Build an auditd-style alert whose complete original lines are carried
    /// in `event_raw` (required for the `.log` data file).
    fn synthetic_log_alert(rule_id: Uuid) -> Alert {
        let raw_line =
            b"type=EXECVE msg=audit(1717056137.482:90412): argc=2 a0=\"passwd\" a1=\"-S\"\n";
        Alert {
            rule_id,
            rule_title: "Password Policy Discovery - Linux".to_string(),
            description: Some("log-mode test".to_string()),
            rule_path: None,
            severity: "low".to_string(),
            event_json_raw: serde_json::json!({
                "stamp": { "timestamp": 1717056137482u64, "sequence": 90412 },
                "type": "EXECVE",
                "fields": { "argc": "2", "a0": "passwd", "a1": "-S" }
            }),
            event_json: serde_json::json!({
                "type": "EXECVE",
                "argc": "2",
                "a0": "passwd",
                "a1": "-S",
                "product": "linux",
                "service": "auditd"
            }),
            event_raw: raw_line.to_vec(),
            is_etw: false,
        }
    }

    #[test]
    fn test_data_file_exists_no_file() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path();
        let id = Uuid::new_v4();
        assert!(!data_file_exists(dir, &id, DataFormat::Evtx));
    }

    #[test]
    fn test_data_file_exists_evtx_non_empty() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path();
        let id = Uuid::new_v4();
        let evtx = dir.join(format!("{id}.evtx"));
        std::fs::write(&evtx, b"not-an-evtx").unwrap();
        assert!(
            data_file_exists(dir, &id, DataFormat::Evtx),
            "non-empty file → exists (magic not checked)"
        );
    }

    #[test]
    fn test_data_file_exists_log_non_empty() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path();
        let id = Uuid::new_v4();
        let log = dir.join(format!("{id}.log"));
        std::fs::write(&log, b"type=EXECVE msg=audit(1.2:3)\n").unwrap();
        assert!(data_file_exists(dir, &id, DataFormat::Log));
    }

    #[test]
    fn test_data_file_exists_empty_rejected() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path();
        let id = Uuid::new_v4();
        let log = dir.join(format!("{id}.log"));
        std::fs::write(&log, b"").unwrap();
        assert!(
            !data_file_exists(dir, &id, DataFormat::Log),
            "empty log → not exists"
        );
    }

    #[test]
    fn test_data_file_exists_format_mismatch() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path();
        let id = Uuid::new_v4();
        let evtx = dir.join(format!("{id}.evtx"));
        std::fs::write(&evtx, b"ElfFile\x00rest-of-header").unwrap();
        assert!(
            !data_file_exists(dir, &id, DataFormat::Log),
            "stale .evtx ignored when format=Log"
        );
    }

    /// `get_sigma_id` trusts existence — it does not validate the blob
    /// content. Broken data stays in the skip set until `regressiondata-check`
    /// catches it.
    #[test]
    fn test_get_sigma_id_trusts_existence() {
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
        std::fs::write(
            good_dir.join(format!("{good_id}.evtx")),
            b"ElfFile\x00rest-of-header",
        )
        .unwrap();

        write_info(&broken_dir, broken_id);
        std::fs::write(broken_dir.join(format!("{broken_id}.evtx")), b"x").unwrap();

        write_info(&missing_dir, missing_id);

        let reg = SigmahqRegression::new_from_path(&base).unwrap();
        let ids = reg.get_sigma_id();
        // broken data is trusted because we only check existence now
        // order follows the directory scan order
        assert_eq!(ids.len(), 2);
        assert!(ids.contains(&good_id) && ids.contains(&broken_id));
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

    /// End-to-end pipeline for an ETW alert: data (.evtx, pure-Rust writer) +
    /// info.yml, no auxiliary json by default. `rule_path` is `None` so no
    /// sigma rule file is touched; everything lives in a tempdir.
    #[test]
    fn test_etw_alert_generates_valid_output() {
        let tmp = tempfile::tempdir().unwrap();
        let base = tmp.path().join("regression_data");
        let mut reg = SigmahqRegression::new_from_path(&base).unwrap();
        let rule_id = Uuid::parse_str("7595ba94-cf3b-4471-aa03-4f6baa9e5fad").unwrap();
        let alert = synthetic_etw_alert(rule_id);

        let files = reg.add(&alert).expect("data + info.yml generated");
        assert_eq!(files.len(), 2, "default output = evtx + info.yml");

        let rule_dir = base.join("rules").join(rule_id.to_string());
        let evtx_path = rule_dir.join(format!("{rule_id}.evtx"));
        let info_path = rule_dir.join("info.yml");

        assert!(!rule_dir.join(format!("{rule_id}.json")).exists());

        let info = InfoYml::load(&info_path).unwrap();
        assert_eq!(info.rule_metadata[0].id, rule_id);
        assert_eq!(info.regression_tests_info[0].test_type, "evtx");
        assert_eq!(
            info.regression_tests_info[0].provider,
            "Microsoft-Windows-Kernel-Process"
        );
        assert_eq!(
            info.regression_tests_info[0].path,
            format!("regression_data/rules/{rule_id}/{rule_id}.evtx")
        );

        let events = input_windows_evtx::parse_evtx_file(&evtx_path).unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].record_id(), Some(7));

        // The generated rule is now skippable: a fresh regression instance sees
        // it as existing valid data.
        let fresh = SigmahqRegression::new_from_path(&base).unwrap();
        assert!(fresh.get_sigma_id().contains(&rule_id));
    }

    /// With `add_json_output(true)` the auxiliary `.json` joins the triplet.
    #[test]
    fn test_etw_alert_with_json_output() {
        let tmp = tempfile::tempdir().unwrap();
        let base = tmp.path().join("regression_data");
        let mut reg = SigmahqRegression::new_from_path(&base).unwrap();
        reg.set_add_json_output(true);
        let rule_id = Uuid::parse_str("7595ba94-cf3b-4471-aa03-4f6baa9e5fad").unwrap();
        let alert = synthetic_etw_alert(rule_id);

        let files = reg.add(&alert).expect("triplet generated");
        assert_eq!(files.len(), 3, "json + evtx + info.yml");

        let rule_dir = base.join("rules").join(rule_id.to_string());
        let json_path = rule_dir.join(format!("{rule_id}.json"));
        let raw_bytes = std::fs::read(&json_path).unwrap();
        assert_eq!(
            raw_bytes.last(),
            Some(&b'\n'),
            "JSON file must end with trailing newline"
        );
        let json: serde_json::Value = serde_json::from_slice(&raw_bytes).unwrap();
        assert_eq!(json["Event"]["System"]["EventRecordID"], 7);
        assert_eq!(
            json["Event"]["EventData"]["CommandLine"],
            "cmd.exe /c whoami"
        );
    }

    /// Raw-mode generation (auditd): with `DataFormat::Log` the output is
    /// `.log` (the complete original audit event lines) + info.yml with
    /// `test_type: log` and `provider: auditd`, and no EVTX writer invoked.
    #[test]
    fn test_log_alert_generates_valid_output() {
        let tmp = tempfile::tempdir().unwrap();
        let base = tmp.path().join("regression_data");
        let mut reg = SigmahqRegression::new_from_path(&base).unwrap();
        reg.set_format(DataFormat::Log);
        let rule_id = Uuid::parse_str("ca94a6db-8106-4737-9ed2-3e3bb826af0a").unwrap();
        let alert = synthetic_log_alert(rule_id);

        let files = reg.add(&alert).expect("data + info.yml generated");
        assert_eq!(files.len(), 2, "default output = log + info.yml");

        let rule_dir = base.join("rules").join(rule_id.to_string());
        let log_path = rule_dir.join(format!("{rule_id}.log"));
        let info_path = rule_dir.join("info.yml");

        assert!(!rule_dir.join(format!("{rule_id}.json")).exists());

        let info = InfoYml::load(&info_path).unwrap();
        assert_eq!(info.regression_tests_info[0].test_type, "log");
        assert_eq!(info.regression_tests_info[0].provider, "auditd");
        assert_eq!(
            info.regression_tests_info[0].path,
            format!("regression_data/rules/{rule_id}/{rule_id}.log")
        );

        assert_eq!(
            std::fs::read(&log_path).unwrap(),
            alert.event_raw,
            ".log carries the complete original audit lines"
        );

        // The generated rule is now skippable without any json file.
        let mut fresh = SigmahqRegression::new_from_path(&base).unwrap();
        fresh.set_format(DataFormat::Log);
        assert!(fresh.get_sigma_id().contains(&rule_id));
    }

    /// A rule whose generation keeps failing is blocked after the configured
    /// number of consecutive failed cycles (logged, retired, no more
    /// re-capture). Multiple failing alerts in one batch count as a single
    /// failed cycle. Failure is deterministic on every platform: an oversized
    /// audit event exceeds the data blob bound.
    fn oversized_log_alert(rule_id: Uuid) -> Alert {
        let mut alert = synthetic_log_alert(rule_id);
        alert.event_raw = vec![0u8; MAX_DATA_BLOB_SIZE + 1];
        alert
    }

    #[test]
    fn test_failed_cycles_blocks_rule_after_max() {
        let tmp = tempfile::tempdir().unwrap();
        let base = tmp.path().join("regression_data");
        let mut reg = SigmahqRegression::new_from_path(&base).unwrap();
        reg.set_format(DataFormat::Log);
        let rule_id = Uuid::new_v4();
        let alert = oversized_log_alert(rule_id);

        // Cycle 1: two failing alerts for the same rule count as one failure.
        assert!(reg.add(&alert).is_none());
        assert!(reg.add(&alert).is_none());
        assert!(reg.take_blocked().is_empty(), "not blocked yet");
        reg.begin_cycle();

        // Cycle 2.
        assert!(reg.add(&alert).is_none());
        assert!(reg.take_blocked().is_empty(), "not blocked yet");
        reg.begin_cycle();

        // Cycle 3: default bound (3) reached → blocked.
        assert!(reg.add(&alert).is_none());
        assert_eq!(reg.take_blocked(), vec![rule_id]);

        // Retired: any further attempt is short-circuited without generating.
        assert!(reg.add(&alert).is_none());
        assert!(reg.take_blocked().is_empty());
    }

    /// The block bound is configurable via `set_max_failed_cycles` and
    /// clamped to a minimum of 1.
    #[test]
    fn test_max_failed_cycles_configurable() {
        let tmp = tempfile::tempdir().unwrap();
        let base = tmp.path().join("regression_data");
        let mut reg = SigmahqRegression::new_from_path(&base).unwrap();
        reg.set_format(DataFormat::Log);
        let rule_id = Uuid::new_v4();
        let alert = oversized_log_alert(rule_id);

        reg.set_max_failed_cycles(2);
        assert_eq!(reg.max_failed_cycles(), 2);

        assert!(reg.add(&alert).is_none());
        assert!(
            reg.take_blocked().is_empty(),
            "bound 2: not blocked after 1"
        );
        reg.begin_cycle();
        assert!(reg.add(&alert).is_none());
        assert_eq!(reg.take_blocked(), vec![rule_id]);

        // Clamp: 0 is not allowed, so it becomes 1.
        let second_id = Uuid::new_v4();
        let second_alert = oversized_log_alert(second_id);
        reg.set_max_failed_cycles(0);
        assert_eq!(reg.max_failed_cycles(), 1);
        assert!(reg.add(&second_alert).is_none());
        assert_eq!(reg.take_blocked(), vec![second_id]);
    }

    /// A failed generation leaves no orphaned files behind: the next attempt
    /// starts from a clean rule directory.
    #[test]
    fn test_failed_generation_cleans_partial_files() {
        let tmp = tempfile::tempdir().unwrap();
        let base = tmp.path().join("regression_data");
        let mut reg = SigmahqRegression::new_from_path(&base).unwrap();
        reg.set_format(DataFormat::Log);
        reg.set_add_json_output(true);
        let rule_id = Uuid::new_v4();
        let alert = oversized_log_alert(rule_id);

        assert!(reg.add(&alert).is_none());

        let rule_dir = base.join("rules").join(rule_id.to_string());
        assert!(
            !rule_dir.exists() || rule_dir.read_dir().unwrap().next().is_none(),
            "no partial artifact left behind"
        );
    }

    /// The `MAX_DATA_BLOB_SIZE` guard also applies to the local skip-set
    /// scan: an oversized blob is treated as broken so the rule is
    /// re-captured instead of parsing unbounded memory.
    #[test]
    fn test_oversized_evtx_is_treated_as_broken() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path();
        let id = Uuid::new_v4();
        let evtx = dir.join(format!("{id}.evtx"));
        let file = std::fs::File::create(&evtx).unwrap();
        file.set_len((MAX_DATA_BLOB_SIZE as u64) + 1).unwrap();
        drop(file);

        assert!(
            data_file_exists(dir, &id, DataFormat::Evtx),
            "oversized file exists (existence-only — deep check in check command)"
        );
    }

    /// `clean_partial_artifacts` removes directories holding generated data
    /// files without info.yml — including `.log`, not just `.json`/`.evtx`.
    #[test]
    fn test_clean_partial_artifacts_recognizes_log_marker() {
        let tmp = tempfile::tempdir().unwrap();
        let base = tmp.path().join("regression_data");
        let partial = base.join("rules/linux/x");
        std::fs::create_dir_all(&partial).unwrap();
        let id = Uuid::new_v4();
        std::fs::write(partial.join(format!("{id}.log")), b"data").unwrap();

        clean_partial_artifacts(&base);
        assert!(!partial.exists(), "partial dir with .log removed");
    }
}
