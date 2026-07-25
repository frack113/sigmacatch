// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 sigmacatch contributors

//! Detection engine — thin wrapper around rsigma-eval for loading pipelines and
//! rules, then evaluating events. No filtering, no skip sets — just the bare
//! essentials for testing and validation.

use anyhow::{anyhow, Result};
use rsigma_eval::event::JsonEvent;
use rsigma_eval::pipeline::parse_pipeline;
use rsigma_eval::Engine;
use rsigma_parser::{parse_sigma_yaml, SigmaCollection};
use sigmacatch_types::{Alert, Event};
#[cfg(unix)]
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use tracing::{info, warn};

/// Default flatten-winevt pipeline YAML used to prep processing of raw Winevt XML events.
pub const FLATTEN_WINEVT_PIPELINE: &str = include_str!("../pipelines/flatten_winevt.yml");

/// Default Windows pipeline YAML for SigmaHQ rule transformation (logsource → Sysmon EventID conditions).
pub const WINDOWS_PIPELINE: &str = include_str!("../pipelines/windows.yml");

/// Detection engine — pipelines + rules + FIFO piles d'events et alerts.
pub struct DetectionEngine {
    engine: Engine,
    events: Vec<Event>,
    alerts: Vec<Alert>,
}

impl DetectionEngine {
    /// Create a new engine with embedded pipelines loaded automatically.
    pub fn new() -> Self {
        let mut engine = Engine::new();
        engine.set_include_event(true);
        let flatten_pipeline =
            parse_pipeline(FLATTEN_WINEVT_PIPELINE).expect("flatten_winevt pipeline YAML is valid");
        engine.add_pipeline(flatten_pipeline);
        let windows_pipeline =
            parse_pipeline(WINDOWS_PIPELINE).expect("windows pipeline YAML is valid");
        engine.add_pipeline(windows_pipeline);

        Self {
            engine,
            events: Vec::new(),
            alerts: Vec::new(),
        }
    }

    /// Create a new engine and load rules from a directory in one call.
    pub fn from_rules_dir(dir: &Path) -> Result<Self> {
        let mut de = Self::new();
        de.load_rules_recursive(dir, 0)?;
        Ok(de)
    }

    /// Create a new engine and load rules from multiple directories.
    /// Non-existent directories are silently skipped.
    pub fn from_rules_dirs(dirs: &[&Path]) -> Result<Self> {
        let mut de = Self::new();
        for dir in dirs {
            de.load_rules_recursive(dir, 0)?;
        }
        Ok(de)
    }

    /// Load a pre-built `SigmaCollection` into this engine.
    /// Rules are parsed by the embedded pipelines during loading.
    pub fn load_collection(&mut self, collection: SigmaCollection) -> Result<()> {
        self.engine
            .add_collection(&collection)
            .map_err(|e| anyhow!("Engine add_collection failed: {e}"))
    }

    /// Number of rules currently loaded in the engine.
    pub fn rule_count(&self) -> usize {
        self.engine.rule_count()
    }

    // ─── FIFO API ─────────────────────────────────────────────────────────

    /// Push events into the internal event pile.
    pub fn put_events(&mut self, events: Vec<Event>) {
        self.events.extend(events);
    }

    /// Pop and return all events from the pile.
    pub fn get_events(&mut self) -> Vec<Event> {
        std::mem::take(&mut self.events)
    }

    /// Evaluate all events in the pile against loaded rules.
    pub fn process_events(&mut self) {
        for event in std::mem::take(&mut self.events) {
            let json_event = JsonEvent::borrow(&event.event_json);
            let matches = self.engine.evaluate(&json_event);
            for result in matches {
                let alert = Alert::from_evaluation_result(result, &event);
                self.alerts.push(alert);
            }
        }
    }

    /// Pop and return all accumulated alerts.
    pub fn get_alerts(&mut self) -> Vec<Alert> {
        std::mem::take(&mut self.alerts)
    }

    // ─── private helpers ─────────────────────────────────────────────────

    fn load_rules_recursive(&mut self, dir: &Path, depth: u32) -> Result<()> {
        if depth > 16 {
            return Ok(());
        }

        if !dir.exists() {
            warn!("Rules directory does not exist: {:?}", dir);
            return Ok(());
        }

        let mut collection = SigmaCollection::default();

        let entries = match std::fs::read_dir(dir) {
            Ok(e) => e,
            Err(_) => return Ok(()),
        };

        for entry in entries.flatten() {
            let ep = entry.path();
            if ep.is_file() {
                if let Some(ext) = ep.extension().and_then(|e| e.to_str()) {
                    if ext == "yml" || ext == "yaml" {
                        if let Some(name) = ep.file_name().and_then(|n| n.to_str()) {
                            if name == "index.yml" {
                                continue;
                            }
                        }
                        match std::fs::read_to_string(&ep) {
                            Ok(content) => match parse_sigma_yaml(&content) {
                                Ok(c) => collection.rules.extend(c.rules),
                                Err(e) => {
                                    info!("Failed to parse {:?}: {}", ep, e);
                                }
                            },
                            Err(e) => {
                                info!("Failed to read {:?}: {}", ep, e);
                            }
                        }
                    }
                }
            } else if ep.is_dir() {
                self.load_rules_recursive(&ep, depth + 1)?;
            }
        }

        if !collection.rules.is_empty() {
            self.engine.add_collection(&collection).map_err(|e| {
                anyhow!(
                    "Engine add_collection failed for {:?}: {}",
                    dir.display(),
                    e
                )
            })?;
        }

        Ok(())
    }
}

impl Default for DetectionEngine {
    fn default() -> Self {
        Self::new()
    }
}

// ─── Rules directory discovery ──────────────────────────────────────────────

/// Scan `root` for `rules` / `rules-*` directories (excludes `rules-compliance`).
///
/// Returns directories that contain Sigma rule YAML files, suitable for
/// passing to [`DetectionEngine::from_rules_dirs`].
pub fn find_rules_dirs(root: &Path) -> Result<Vec<PathBuf>> {
    let mut dirs = Vec::new();
    let mut excluded = Vec::new();
    #[cfg(unix)]
    let mut visited_inodes = std::collections::HashSet::new();
    #[cfg(not(unix))]
    let mut visited_paths = std::collections::HashSet::new();
    if !root.exists() {
        warn!("Root directory does not exist: {:?}", root);
        return Ok(dirs);
    }

    let entries = std::fs::read_dir(root)?;
    for entry_result in entries {
        match entry_result {
            Ok(entry) => {
                let path = entry.path();
                if path.is_dir() {
                    #[cfg(unix)]
                    {
                        let inode = path.metadata().ok().map(|m| m.ino());
                        if let Some(id) = inode {
                            if !visited_inodes.insert(id) {
                                warn!("Skipping symlink cycle detected at: {:?}", path);
                                continue;
                            }
                        }
                    }
                    #[cfg(not(unix))]
                    {
                        let abs_path = dunce::canonicalize(&path).ok();
                        if let Some(abs) = abs_path {
                            if !visited_paths.insert(abs) {
                                warn!("Skipping symlink cycle detected at: {:?}", path);
                                continue;
                            }
                        }
                    }
                    if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
                        if name == "rules" || name.starts_with("rules-") {
                            if name.starts_with("rules-compliance") {
                                excluded.push(name.to_string());
                                continue;
                            }
                            if name.starts_with("rules-") && !has_yml_files(&path, 0) {
                                continue;
                            }
                            info!("Found rules directory: {:?}", path);
                            dirs.push(path);
                        }
                    } else {
                        warn!("Skipping non-UTF8 directory name: {:?}", path);
                    }
                }
            }
            Err(e) => {
                warn!("Skipping entry due to error: {}", e);
            }
        }
    }

    if dirs.is_empty() {
        warn!("No 'rules*' directories found in {:?}", root);
    }
    if !excluded.is_empty() {
        info!("Excluded non-detection directories: {:?}", excluded);
    }

    Ok(dirs)
}

fn has_yml_files(dir: &Path, depth: u32) -> bool {
    if depth > 8 {
        return false;
    }
    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(e) => {
            warn!(
                "Cannot read directory {:?} while scanning for rules: {}",
                dir, e
            );
            return false;
        }
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            if has_yml_files(&path, depth + 1) {
                return true;
            }
        } else if let Some(ext) = path
            .extension()
            .and_then(|e| e.to_str())
            .map(|e| e.to_ascii_lowercase())
        {
            if ext == "yml" || ext == "yaml" {
                return true;
            }
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    const MINIMAL_RULE_YAML: &str = r#"title: Test Rule
id: test-rule-001
status: test
description: A minimal test rule
author: Test Author
logsource:
  product: test
detection:
  selection:
    event_id: 1
  condition: selection
"#;

    fn write_rule_to_dir(dir: &TempDir, name: &str, yaml: &str) -> std::path::PathBuf {
        let path = dir.path().join(name);
        std::fs::write(&path, yaml).expect("write rule file");
        path
    }

    #[test]
    fn test_new_engine_has_pipelines() {
        let dir = tempfile::tempdir().unwrap();
        write_rule_to_dir(&dir, "pipeline_test.yml", MINIMAL_RULE_YAML);
        let engine = DetectionEngine::from_rules_dir(dir.path()).unwrap();
        let count = engine.rule_count();
        assert_eq!(
            count, 1,
            "engine should have 1 rule after loading with pipelines, got {}",
            count
        );
    }

    #[test]
    fn test_from_rules_dir_nonexistent() {
        let result = DetectionEngine::from_rules_dir(Path::new("/nonexistent"));
        assert!(
            result.is_ok(),
            "from_rules_dir should succeed for nonexistent dir"
        );
        let engine = result.unwrap();
        assert_eq!(
            engine.rule_count(),
            0,
            "engine should have 0 rules when loaded from nonexistent directory"
        );
    }

    #[test]
    fn test_rule_count() {
        let dir = tempfile::tempdir().unwrap();
        write_rule_to_dir(&dir, "test_rule.yml", MINIMAL_RULE_YAML);

        let engine = DetectionEngine::from_rules_dir(dir.path()).unwrap();
        let count = engine.rule_count();
        assert_eq!(
            count, 1,
            "engine should have exactly 1 rule loaded, got {}",
            count
        );
    }

    #[test]
    fn test_load_rules_depth_limit() {
        let tmp = tempfile::tempdir().unwrap();
        let mut current = tmp.path().to_path_buf();
        for i in 0..20 {
            current = current.join(format!("level_{}", i));
            std::fs::create_dir(&current).unwrap();
        }
        let rule_content = MINIMAL_RULE_YAML.replace("test-rule", "deep-rule");
        std::fs::write(current.join("deep.yml"), rule_content).unwrap();

        let engine = DetectionEngine::from_rules_dir(tmp.path()).unwrap();
        assert_eq!(
            engine.rule_count(),
            0,
            "rules beyond depth 16 should not be loaded"
        );
    }

    #[test]
    fn test_load_rules_at_depth_limit() {
        let tmp = tempfile::tempdir().unwrap();
        let mut current = tmp.path().to_path_buf();
        for i in 0..15 {
            current = current.join(format!("level_{}", i));
            std::fs::create_dir(&current).unwrap();
        }
        let rule_content = MINIMAL_RULE_YAML.replace("test-rule", "edge-rule");
        std::fs::write(current.join("edge.yml"), rule_content).unwrap();

        let engine = DetectionEngine::from_rules_dir(tmp.path()).unwrap();
        assert_eq!(engine.rule_count(), 1, "rules at depth 16 should be loaded");
    }
}
