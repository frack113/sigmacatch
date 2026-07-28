// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 sigmacatch contributors

//! Detection engine — thin wrapper around rsigma-eval for loading pipelines and
//! rules, then evaluating events. No filtering, no skip sets — just the bare
//! essentials for testing and validation.

use anyhow::{anyhow, Result};
use rsigma_eval::event::JsonEvent;
use rsigma_eval::pipeline::parse_pipeline;
use rsigma_eval::{Engine, LogSourceExtractor};
use rsigma_parser::{parse_sigma_yaml, SigmaCollection};
use sigmacatch_types::{Alert, Event, Product};
#[cfg(unix)]
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use tracing::{info, warn};

/// Embedded pipeline for flattening Winevt XML event structure.
pub const FLATTEN_WINEVT_PIPELINE: &str = include_str!("../pipelines/flatten_winevt.yml");

/// Embedded pipeline for Windows Sigma rule transformation.
pub const WINDOWS_PIPELINE: &str = include_str!("../pipelines/windows.yml");

/// Map of product → rule IDs for efficient product-scoped rule access.
#[derive(Debug, Clone, Default)]
pub struct RuleIndex {
    index: std::collections::HashMap<Product, Vec<String>>,
}

impl RuleIndex {
    /// Create a new empty rule index.
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a rule ID under the given product.
    pub fn add_rule(&mut self, product: Product, rule_id: String) {
        self.index.entry(product).or_default().push(rule_id);
    }

    /// Get all rule IDs for the given product. Returns empty vec if no rules.
    pub fn get(&self, product: &Product) -> &[String] {
        self.index
            .get(product)
            .map(Vec::as_slice)
            .unwrap_or_default()
    }

    /// Check if there are any rules for the given product.
    pub fn has_rules(&self, product: &Product) -> bool {
        self.index.get(product).is_some_and(|v| !v.is_empty())
    }

    /// Total number of rule entries across all products.
    pub fn len(&self) -> usize {
        self.index.values().map(Vec::len).sum()
    }

    /// Whether there are no rules at all.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Iterate over all (product, rule_ids) pairs.
    pub fn iter(&self) -> impl Iterator<Item = (&sigmacatch_types::Product, &[String])> {
        self.index.iter().map(|(k, v)| (k, v.as_slice()))
    }
}

/// Detection engine — pipelines + rules + FIFO piles d'events et alerts.
pub struct DetectionEngine {
    engine: Engine,
    events: Vec<Event>,
    alerts: Vec<Alert>,
    stats: EngineStats,
    rule_index: RuleIndex,
}

impl DetectionEngine {
    /// Create a new engine with the two embedded pipelines loaded.
    ///
    /// Enables bloom pre-filtering and logsource-based rule pruning for
    /// optimal evaluation performance.
    pub fn new() -> Self {
        let mut engine = Engine::new();
        engine.set_include_event(true);

        // Enable bloom pre-filter: short-circuits positive substring matchers
        // (Contains, StartsWith, EndsWith) when the field value cannot possibly
        // match based on trigram extraction. ~1µs per field probe.
        engine.set_bloom_prefilter(true);

        // Enable logsource pruning: extracts product/service/category from the
        // event JSON and skips rules whose logsource conflicts. Fails open —
        // an event without logsource fields evaluates all rules.
        engine.set_logsource_extractor(Some(LogSourceExtractor::new()));

        let flatten =
            parse_pipeline(FLATTEN_WINEVT_PIPELINE).expect("flatten_winevt pipeline is valid");
        engine.add_pipeline(flatten);

        let windows = parse_pipeline(WINDOWS_PIPELINE).expect("windows pipeline is valid");
        engine.add_pipeline(windows);

        Self {
            engine,
            events: Vec::new(),
            alerts: Vec::new(),
            stats: EngineStats::default(),
            rule_index: RuleIndex::new(),
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

    /// Access the inner rsigma-eval engine for introspection (compiled rules, etc.).
    pub fn engine(&self) -> &Engine {
        &self.engine
    }

    /// Get the rule index for product-scoped rule access.
    pub fn rule_index(&self) -> &RuleIndex {
        &self.rule_index
    }

    /// Return the current engine stats (events_processed, alerts_generated).
    pub fn stats(&self) -> EngineStats {
        self.stats.clone()
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
    ///
    /// Events must have logsource fields (product, service, category) already
    /// injected by the collector via `Event::inject_logsource_fields()`.
    /// The bloom pre-filter and logsource pruning are both active.
    pub fn process_events(&mut self) {
        let events = std::mem::take(&mut self.events);
        self.stats.events_processed += events.len() as u64;
        for event in events {
            let json_event = JsonEvent::borrow(&event.event_json);
            let matches = self.engine.evaluate(&json_event);
            for result in matches {
                let alert = Alert {
                    rule_id: result
                        .header
                        .rule_id
                        .clone()
                        .unwrap_or_else(|| "unknown".to_string()),
                    rule_title: result.header.rule_title.clone(),
                    severity: result
                        .header
                        .level
                        .as_ref()
                        .map(|l| format!("{:?}", l))
                        .unwrap_or_else(|| "unknown".to_string()),
                    event_json: event.event_json.clone(),
                    event_raw: event.event_raw.clone(),
                };
                self.alerts.push(alert);
            }
        }
    }

    /// Pop and return all accumulated alerts.
    pub fn get_alerts(&mut self) -> Vec<Alert> {
        let alerts = std::mem::take(&mut self.alerts);
        self.stats.alerts_generated += alerts.len() as u64;
        alerts
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
                                Ok(c) => {
                                    for rule in c.rules {
                                        let product =
                                            rule.logsource.product.as_deref().unwrap_or("unknown");
                                        if let Ok(parsed) = product.parse::<Product>() {
                                            self.rule_index.add_rule(
                                                parsed,
                                                rule.id.clone().unwrap_or_default(),
                                            );
                                        }
                                        if rule.logsource.product.as_deref() == Some("windows") {
                                            if rule.id.is_none() {
                                                warn!(
                                                    "Rule without 'id' field loaded from {:?}: {}",
                                                    dir.display(),
                                                    rule.title
                                                );
                                            }
                                            collection.rules.push(rule);
                                        }
                                    }
                                }
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

// ─── Engine Stats ─────────────────────────────────────────────────────────

/// Statistics for input/output tracking.
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct EngineStats {
    /// Total events processed against rules.
    pub events_processed: u64,
    /// Total alerts generated.
    pub alerts_generated: u64,
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
  product: windows
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

    // ─── RuleIndex tests ─────────────────────────────────────────────────

    #[test]
    fn test_rule_index_new_is_empty() {
        let index = RuleIndex::new();
        assert!(index.is_empty());
        assert_eq!(index.len(), 0);
    }

    #[test]
    fn test_rule_index_add_and_get() {
        let mut index = RuleIndex::new();
        index.add_rule(Product::Windows, "rule1".to_string());
        index.add_rule(Product::Windows, "rule2".to_string());
        index.add_rule(Product::Linux, "rule3".to_string());

        assert_eq!(index.len(), 3);
        assert!(!index.is_empty());

        let windows_rules = index.get(&Product::Windows);
        assert_eq!(windows_rules.len(), 2);
        assert!(windows_rules.contains(&"rule1".to_string()));
        assert!(windows_rules.contains(&"rule2".to_string()));

        let linux_rules = index.get(&Product::Linux);
        assert_eq!(linux_rules.len(), 1);
        assert_eq!(linux_rules[0], "rule3");

        let macos_rules = index.get(&Product::Macos);
        assert!(macos_rules.is_empty());
    }

    #[test]
    fn test_rule_index_has_rules() {
        let mut index = RuleIndex::new();
        assert!(!index.has_rules(&Product::Windows));

        index.add_rule(Product::Windows, "rule1".to_string());
        assert!(index.has_rules(&Product::Windows));
        assert!(!index.has_rules(&Product::Linux));
    }

    #[test]
    fn test_rule_index_iter() {
        let mut index = RuleIndex::new();
        index.add_rule(Product::Windows, "rule1".to_string());
        index.add_rule(Product::Linux, "rule2".to_string());

        let mut count = 0;
        for (product, rules) in index.iter() {
            assert!(matches!(product, Product::Windows | Product::Linux));
            assert!(!rules.is_empty());
            count += rules.len();
        }
        assert_eq!(count, 2);
    }

    #[test]
    fn test_engine_rule_index_populated() {
        let dir = tempfile::tempdir().unwrap();
        write_rule_to_dir(&dir, "win_rule.yml", MINIMAL_RULE_YAML);

        let engine = DetectionEngine::from_rules_dir(dir.path()).unwrap();
        let index = engine.rule_index();

        assert!(!index.is_empty());
        assert!(index.has_rules(&Product::Windows));
        let windows_rules = index.get(&Product::Windows);
        assert!(windows_rules.iter().any(|r| r.contains("test-rule")));
    }

    // ─── FIFO API tests ──────────────────────────────────────────────────

    #[test]
    fn test_put_events_and_process() {
        let mut engine = DetectionEngine::new();
        engine.put_events(vec![
            Event::new(serde_json::json!({}), Vec::new()),
            Event::new(serde_json::json!({}), Vec::new()),
        ]);

        engine.process_events();

        let stats = engine.stats();
        assert_eq!(stats.events_processed, 2);
    }

    #[test]
    fn test_process_events_and_get_alerts() {
        let dir = tempfile::tempdir().unwrap();
        write_rule_to_dir(&dir, "test_rule.yml", MINIMAL_RULE_YAML);

        let mut engine = DetectionEngine::from_rules_dir(dir.path()).unwrap();
        let event = Event::new(serde_json::json!({"event_id": 1}), Vec::new());
        engine.put_events(vec![event]);
        engine.process_events();

        let alerts = engine.get_alerts();
        let stats = engine.stats();
        assert_eq!(stats.alerts_generated, alerts.len() as u64);
    }
}
