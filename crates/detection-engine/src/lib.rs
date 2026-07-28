// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 sigmacatch contributors

//! Detection engine — thin wrapper around rsigma-eval for loading pipelines and
//! rules, then evaluating events. No filtering, no skip sets — just the bare
//! essentials for testing and validation.

use anyhow::{anyhow, Result};
use rsigma_eval::event::JsonEvent;
use rsigma_eval::pipeline::parse_pipeline;
use rsigma_eval::{Engine, LogSourceExtractor};
use sigma_rule::{parse_sigma_yaml, RuleIndex, SigmaCollection};
use sigmacatch_types::{Alert, Event, Product};
use std::path::Path;
use tracing::{info, warn};

/// Embedded pipeline for flattening Winevt XML event structure.
pub const FLATTEN_WINEVT_PIPELINE: &str = include_str!("../pipelines/flatten_winevt.yml");

/// Embedded pipeline for Windows Sigma rule transformation.
pub const WINDOWS_PIPELINE: &str = include_str!("../pipelines/windows.yml");

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

    /// Explain why a specific rule matched or didn't match a given event.
    /// Returns the full explain trace from rsigma-eval as JSON.
    pub fn explain_rule(&self, rule_id: &str, event: &Event) -> Option<serde_json::Value> {
        let compiled = self
            .engine
            .rules()
            .iter()
            .find(|r| r.id.as_deref() == Some(rule_id))?;
        let json_event = JsonEvent::borrow(&event.event_json);
        let explanation = rsigma_eval::explain_rule(compiled, &json_event);
        serde_json::to_value(explanation).ok()
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
