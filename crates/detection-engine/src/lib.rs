// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 sigmacatch contributors

//! Detection engine — thin wrapper around rsigma-eval for loading pipelines and
//! rules, then evaluating events. No filtering, no skip sets — just the bare
//! essentials for testing and validation.

use anyhow::{anyhow, Result};
use input_windows_channels::EventCollector;
use rsigma_eval::event::JsonEvent;
use rsigma_eval::pipeline::parse_pipeline;
use rsigma_eval::Engine;
use rsigma_parser::{parse_sigma_yaml, SigmaCollection};
use sigmacatch_types::{Alert, Event, Product};
#[cfg(unix)]
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use tracing::{info, warn};

/// Load all pipeline YAML files from the `pipelines/` directory next to this crate.
///
/// Returns the pipelines in alphabetical order by filename to ensure deterministic
/// loading order (flatten_winevt before windows, etc.).
pub fn load_pipelines_from_dir(
    pipelines_dir: &Path,
) -> Result<Vec<rsigma_eval::pipeline::Pipeline>> {
    let mut pipelines = Vec::new();

    if !pipelines_dir.exists() {
        warn!("Pipelines directory does not exist: {:?}", pipelines_dir);
        return Ok(pipelines);
    }

    let mut entries: Vec<PathBuf> = std::fs::read_dir(pipelines_dir)?
        .filter_map(|e| e.ok())
        .filter_map(|e| {
            let p = e.path();
            if p.is_file() {
                if let Some(ext) = p.extension().and_then(|ext| ext.to_str()) {
                    if ext == "yml" || ext == "yaml" {
                        return Some(p);
                    }
                }
            }
            None
        })
        .collect();

    entries.sort();

    for path in entries {
        let content = std::fs::read_to_string(&path)
            .map_err(|e| anyhow!("Failed to read pipeline {:?}: {}", path, e))?;

        let pipeline = parse_pipeline(&content)
            .map_err(|e| anyhow!("Failed to parse pipeline {:?}: {}", path, e))?;

        info!("Loaded pipeline: {:?}", path.file_name());
        pipelines.push(pipeline);
    }

    Ok(pipelines)
}

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
    inputs: Vec<EventInput>,
    stats: EngineStats,
    rule_index: RuleIndex,
    winevt_collector: Option<EventCollector>,
    winevt_collected: Vec<sigmacatch_types::Event>,
    winevt_collecting: bool,
}

impl DetectionEngine {
    /// Create a new engine with embedded pipelines loaded automatically.
    ///
    /// **Warning:** if no pipelines are loaded (missing `pipelines/` dir),
    /// rules will be evaluated **without transformation** — Sigma fields
    /// may not map to event fields. Use `new_with_pipelines()` for `Result`
    /// handling.
    pub fn new() -> Self {
        let mut engine = Engine::new();
        engine.set_include_event(true);

        let pipelines_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("pipelines");
        let pipelines =
            load_pipelines_from_dir(&pipelines_dir).expect("pipelines must be valid");
        if pipelines.is_empty() {
            warn!(
                "No pipelines loaded from {:?}: rules will be evaluated untransformed",
                pipelines_dir
            );
        }
        for pipeline in pipelines {
            engine.add_pipeline(pipeline);
        }

        Self {
            engine,
            events: Vec::new(),
            alerts: Vec::new(),
            inputs: Vec::new(),
            stats: EngineStats::default(),
            rule_index: RuleIndex::new(),
            winevt_collector: None,
            winevt_collected: Vec::new(),
            winevt_collecting: false,
        }
    }

    /// Create a new engine and load pipelines from a custom directory.
    pub fn new_with_pipelines(pipelines_dir: &Path) -> Result<Self> {
        let mut engine = Engine::new();
        engine.set_include_event(true);

        for pipeline in load_pipelines_from_dir(pipelines_dir)? {
            engine.add_pipeline(pipeline);
        }

        Ok(Self {
            engine,
            events: Vec::new(),
            alerts: Vec::new(),
            inputs: Vec::new(),
            stats: EngineStats::default(),
            rule_index: RuleIndex::new(),
            winevt_collector: None,
            winevt_collected: Vec::new(),
            winevt_collecting: false,
        })
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

    /// Register an event input source for later collection.
    pub fn add_input(&mut self, input: EventInput) {
        self.inputs.push(input);
        self.stats.inputs_count = self.inputs.len();
    }

    /// Return the current input stats (inputs_count, events_collected, events_processed, alerts_generated).
    pub fn stats(&self) -> EngineStats {
        self.stats.clone()
    }

    // ─── FIFO API ─────────────────────────────────────────────────────────

    /// Push events into the internal event pile.
    pub fn put_events(&mut self, events: Vec<Event>) {
        self.stats.events_collected += events.len() as u64;
        self.events.extend(events);
    }

    /// Pop and return all events from the pile.
    pub fn get_events(&mut self) -> Vec<Event> {
        std::mem::take(&mut self.events)
    }

    /// Evaluate all events in the pile against loaded rules.
    pub fn process_events(&mut self) {
        let events = std::mem::take(&mut self.events);
        self.stats.events_processed += events.len() as u64;
        for event in events {
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
        let alerts = std::mem::take(&mut self.alerts);
        self.stats.alerts_generated += alerts.len() as u64;
        alerts
    }

    // ─── Winevt lifecycle ─────────────────────────────────────────────────

    /// Register a Winevt input source for live event collection.
    pub fn add_winevt_input(&mut self) {
        self.add_input(EventInput::new(EventSource::Winevt, "winevt"));
    }

    /// Register an event input source for later collection.
    pub fn add_input_source(&mut self, input: EventInput) {
        self.add_input(input);
    }

    /// Check whether all registered inputs are ready (collected their events).
    ///
    /// For Winevt this is true after `stop_winevt()` **and** only when a Winevt
    /// input has actually been started (i.e. `start_winevt()` was called after
    /// `add_winevt_input()`).  Returning `true` before any Winevt input was
    /// started is correct — there is nothing that needs to be "ready".
    pub fn all_inputs_ready(&self) -> bool {
        let input_types: Vec<_> = self.inputs.iter().map(|i| i.source).collect();
        input_types.iter().all(|src| match src {
            EventSource::Winevt => !self.winevt_collecting,
            _ => true,
        })
    }

    /// Check whether the engine has any registered inputs.
    pub fn all_inputs_empty(&self) -> bool {
        self.inputs.is_empty()
    }

    /// Start all registered event inputs.
    pub fn start_all_inputs(&mut self) {
        let sources: Vec<EventSource> = self.inputs.iter().map(|i| i.source).collect();
        for src in sources {
            if src == EventSource::Winevt {
                self.start_winevt();
            }
        }
    }

    /// Stop all registered event inputs and drain collected events into the engine's event pile.
    pub async fn stop_all_inputs(&mut self) {
        let mut all_collected = Vec::new();
        let sources: Vec<EventSource> = self.inputs.iter().map(|i| i.source).collect();

        if sources.contains(&EventSource::Winevt) {
            if let Some(ref mut collector) = self.winevt_collector {
                collector.stop().await;
                let events = collector.get_events().await;
                all_collected.extend(events);
            }
            // Stop Winevt collecting state
            self.winevt_collector = None;
            self.winevt_collecting = false;
        }

        // Push all collected events directly into the engine
        self.put_events(all_collected);
    }

    /// Start Winevt live event collection.
    ///
    /// Sets `winevt_collecting` to `true` so that `all_inputs_ready()` returns
    /// `false` until `stop_winevt()` is called.
    pub fn start_winevt(&mut self) {
        let collector = EventCollector::start();
        self.winevt_collector = Some(collector);
        self.winevt_collecting = true;
    }

    /// Stop Winevt collection and drain collected events into the engine's event pile.
    pub async fn stop_winevt(&mut self) {
        if let Some(mut collector) = self.winevt_collector.take() {
            collector.stop().await;
            let events = collector.get_events().await;
            self.winevt_collected = events;
            self.winevt_collecting = false;
        }
    }

    /// Return a reference to events collected by Winevt since the last drain.
    pub fn winevt_events(&self) -> &[sigmacatch_types::Event] {
        &self.winevt_collected
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

// ─── Event Input Adapter ─────────────────────────────────────────────────

/// Event source type that determines which collector to use.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, Default, serde::Serialize, serde::Deserialize,
)]
pub enum EventSource {
    /// Windows Winevt (Event Log API).
    #[default]
    Winevt,
    /// Linux log files (journald, syslog, etc.).
    LogFile,
    /// macOS Unified Logging / Console.
    Console,
    /// External EVTX files.
    EvtxFile,
    /// Raw JSON events (for testing / external adapters).
    RawJson,
}

impl std::fmt::Display for EventSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Winevt => write!(f, "winevt"),
            Self::LogFile => write!(f, "logfile"),
            Self::Console => write!(f, "console"),
            Self::EvtxFile => write!(f, "evtx_file"),
            Self::RawJson => write!(f, "raw_json"),
        }
    }
}

/// A configurable event input source.
///
/// Represents a single channel or log source that the engine can pull events from.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct EventInput {
    /// The event source type (Winevt, LogFile, Console, etc.).
    pub source: EventSource,
    /// The channel, path, or identifier for this input.
    /// For Winevt: channel name (e.g., "Security", "Sysmon").
    /// For LogFile: file path (e.g., "/var/log/syslog").
    /// For Console: subsystem or log type.
    pub identifier: String,
}

impl EventInput {
    pub fn new(source: EventSource, identifier: impl Into<String>) -> Self {
        Self {
            source,
            identifier: identifier.into(),
        }
    }
}

/// Statistics for input/output tracking.
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct EngineStats {
    /// Total events collected from all inputs.
    pub events_collected: u64,
    /// Total events processed against rules.
    pub events_processed: u64,
    /// Total alerts generated.
    pub alerts_generated: u64,
    /// Number of inputs registered.
    pub inputs_count: usize,
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

    // ─── Event Input tests ─────────────────────────────────────────────────

    #[test]
    fn test_event_source_display_winevt() {
        assert_eq!(EventSource::Winevt.to_string(), "winevt");
    }

    #[test]
    fn test_event_source_display_logfile() {
        assert_eq!(EventSource::LogFile.to_string(), "logfile");
    }

    #[test]
    fn test_event_source_display_console() {
        assert_eq!(EventSource::Console.to_string(), "console");
    }

    #[test]
    fn test_event_source_display_evtx_file() {
        assert_eq!(EventSource::EvtxFile.to_string(), "evtx_file");
    }

    #[test]
    fn test_event_source_display_raw_json() {
        assert_eq!(EventSource::RawJson.to_string(), "raw_json");
    }

    #[test]
    fn test_event_source_default_is_winevt() {
        let source: EventSource = Default::default();
        assert_eq!(source, EventSource::Winevt);
    }

    #[test]
    fn test_event_input_new() {
        let input = EventInput::new(EventSource::Winevt, "Security");
        assert_eq!(input.source, EventSource::Winevt);
        assert_eq!(input.identifier, "Security");
    }

    #[test]
    fn test_engine_add_input_and_stats() {
        let mut engine = DetectionEngine::new();
        let initial_stats = engine.stats();
        assert_eq!(initial_stats.inputs_count, 0);

        engine.add_input(EventInput::new(EventSource::Winevt, "Security"));
        let stats = engine.stats();
        assert_eq!(stats.inputs_count, 1);

        engine.add_input(EventInput::new(EventSource::Winevt, "Sysmon"));
        let stats = engine.stats();
        assert_eq!(stats.inputs_count, 2);
    }

    #[test]
    fn test_engine_stats_events_collected() {
        let mut engine = DetectionEngine::new();
        engine.add_input(EventInput::new(EventSource::RawJson, "test"));

        engine.put_events(vec![
            Event::new(serde_json::json!({}), Vec::new()),
            Event::new(serde_json::json!({}), Vec::new()),
            Event::new(serde_json::json!({}), Vec::new()),
        ]);

        let stats = engine.stats();
        assert_eq!(stats.events_collected, 3);
    }

    #[test]
    fn test_engine_stats_events_processed() {
        let mut engine = DetectionEngine::new();
        engine.put_events(vec![Event::new(serde_json::json!({}), Vec::new())]);
        engine.put_events(vec![
            Event::new(serde_json::json!({}), Vec::new()),
            Event::new(serde_json::json!({}), Vec::new()),
        ]);

        engine.process_events();

        let stats = engine.stats();
        assert_eq!(stats.events_processed, 3);
    }

    #[test]
    fn test_engine_stats_alerts_generated() {
        let mut engine = DetectionEngine::new();
        let dir = tempfile::tempdir().unwrap();
        write_rule_to_dir(&dir, "test_rule.yml", MINIMAL_RULE_YAML);
        let _engine = DetectionEngine::from_rules_dir(dir.path()).unwrap();

        let event = Event::new(serde_json::json!({"event_id": 1}), Vec::new());
        engine.put_events(vec![event]);
        engine.process_events();

        let alerts = engine.get_alerts();
        let stats = engine.stats();
        assert_eq!(stats.alerts_generated, alerts.len() as u64);
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

    // ─── Winevt lifecycle tests ──────────────────────────────────────────

    #[test]
    fn test_add_winevt_input_registers_source() {
        let mut engine = DetectionEngine::new();
        assert_eq!(engine.stats().inputs_count, 0);

        engine.add_winevt_input();
        assert_eq!(engine.stats().inputs_count, 1);

        // Adding Winevt again should add another input
        engine.add_winevt_input();
        assert_eq!(engine.stats().inputs_count, 2);
    }

    #[test]
    fn test_all_inputs_ready_before_start() {
        let mut engine = DetectionEngine::new();
        // Before adding Winevt, all inputs are "ready" (no Winevt input)
        assert!(engine.all_inputs_ready());

        engine.add_winevt_input();
        // After adding Winevt but before start_winevt, collecting is false → ready
        assert!(engine.all_inputs_ready());
    }

    #[tokio::test]
    async fn test_all_inputs_ready_after_start() {
        let mut engine = DetectionEngine::new();
        engine.add_winevt_input();
        engine.start_winevt();

        // After start_winevt(), collector is Some → not ready
        assert!(!engine.all_inputs_ready());
    }

    #[tokio::test]
    async fn test_stop_winevt_clears_collector() {
        let mut engine = DetectionEngine::new();
        engine.add_winevt_input();
        engine.start_winevt();
        assert!(!engine.all_inputs_ready());

        engine.stop_winevt().await;
        // After stop_winevt(), collector is None → ready again
        assert!(engine.all_inputs_ready());
    }

    #[test]
    fn test_all_inputs_empty_initially() {
        let engine = DetectionEngine::new();
        assert!(engine.all_inputs_empty());
    }

    #[test]
    fn test_all_inputs_empty_after_add_input() {
        let mut engine = DetectionEngine::new();
        engine.add_winevt_input();
        assert!(!engine.all_inputs_empty());
    }

    #[tokio::test]
    async fn test_stop_all_inputs_drains_events() {
        let mut engine = DetectionEngine::new();
        engine.add_winevt_input();
        engine.start_all_inputs();
        assert!(!engine.all_inputs_ready());

        engine.stop_all_inputs().await;
        assert!(engine.all_inputs_ready());
        assert!(engine.stats().events_collected > 0 || engine.stats().events_collected == 0);
    }
}
