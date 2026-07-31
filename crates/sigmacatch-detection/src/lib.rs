// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 sigmacatch contributors

//! Detection engine — thin wrapper around rsigma-eval for loading pipelines and
//! rules, then evaluating events. Consumes rules from `RuleIndex` in read-only
//! mode. No filtering, no skip sets — just the bare essentials for testing and
//! validation.

use anyhow::{anyhow, Result};
use rsigma_eval::event::JsonEvent;
use rsigma_eval::pipeline::parse_pipeline;
use rsigma_eval::{Engine, LogSourceExtractor};
use sigmacatch_rule::RuleIndex;
use sigmacatch_types::{Alert, Event};

/// Embedded pipeline for flattening Winevt XML event structure.
pub const FLATTEN_WINEVT_PIPELINE: &str = include_str!("../pipelines/flatten_winevt.yml");

/// Embedded pipeline for Windows Sigma rule transformation.
pub const WINDOWS_PIPELINE: &str = include_str!("../pipelines/windows.yml");

/// Detection engine — pipelines + rsigma-eval Engine + FIFO piles d'events et alerts.
///
/// Created from a `RuleIndex` (read-only consumption). The rsigma-eval `Engine`
/// holds the compiled rules; `DetectionEngine` is a thin wrapper that adds
/// pipelines, bloom pre-filter, and logsource pruning, then provides the FIFO
/// API (`put_events` / `process_events` / `get_alerts`).
pub struct DetectionEngine {
    engine: Engine,
    events: Vec<Event>,
    alerts: Vec<Alert>,
    stats: EngineStats,
}

impl DetectionEngine {
    /// Create a new engine from a `RuleIndex`, loading all rules into rsigma-eval.
    ///
    /// Enables bloom pre-filtering and logsource-based rule pruning for
    /// optimal evaluation performance. Pipelines (flatten_winevt + windows)
    /// are loaded automatically.
    pub fn new(rule_index: &RuleIndex) -> Result<Self> {
        let mut engine = Self::create_engine()?;
        engine
            .add_collection(rule_index.get_collection())
            .map_err(|e| anyhow!("Engine add_collection failed: {e}"))?;

        Ok(Self {
            engine,
            events: Vec::new(),
            alerts: Vec::new(),
            stats: EngineStats::default(),
        })
    }

    /// Reload rules from an updated `RuleIndex` (e.g. after `exclude_rule_id`).
    ///
    /// Creates a fresh rsigma-eval `Engine` with pipelines + bloom pre-filter,
    /// then loads the current collection from `rule_index`. This drops all
    /// previously compiled rules and recompiles from the updated set.
    pub fn reload_rules(&mut self, rule_index: &RuleIndex) -> Result<()> {
        let mut engine = Self::create_engine()?;
        engine
            .add_collection(rule_index.get_collection())
            .map_err(|e| anyhow!("Engine reload_rules failed: {e}"))?;
        self.engine = engine;
        Ok(())
    }

    /// Create a fresh rsigma-eval Engine with pipelines + optimizations.
    fn create_engine() -> Result<Engine> {
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

        Ok(engine)
    }

    /// Number of rules currently loaded in the engine.
    pub fn rule_count(&self) -> usize {
        self.engine.rule_count()
    }

    /// Access the inner rsigma-eval engine for introspection (compiled rules, etc.).
    pub fn engine(&self) -> &Engine {
        &self.engine
    }

    /// Mutable access to the inner rsigma-eval engine.
    pub fn engine_mut(&mut self) -> &mut Engine {
        &mut self.engine
    }

    /// Serialize compiled rules as a HIR blob for cheap engine cloning.
    pub fn save_hir(&self) -> Result<Vec<u8>> {
        self.engine
            .save_hir()
            .map_err(|e| anyhow!("save_hir failed: {e}"))
    }

    /// Load compiled rules from a HIR blob previously saved by `save_hir`.
    pub fn load_hir(&mut self, blob: &[u8]) -> Result<()> {
        self.engine
            .load_hir(blob)
            .map_err(|e| anyhow!("load_hir failed: {e}"))
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
                    description: None,
                    rule_path: None,
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
    use sigmacatch_rule::{LoadFilter, RuleIndex};
    use std::collections::HashSet;
    use std::fs;

    const MINIMAL_RULE_YAML: &str = r#"title: Test Rule
id: test-rule-001
status: stable
description: A minimal test rule
author: Test Author
logsource:
  product: windows
detection:
  selection:
    event_id: 1
  condition: selection
"#;

    fn write_rule_to_dir(dir: &tempfile::TempDir, name: &str, yaml: &str) {
        let path = dir.path().join(name);
        std::fs::write(&path, yaml).expect("write rule file");
    }

    #[test]
    fn test_engine_with_rule_index() {
        let dir = tempfile::tempdir().unwrap();
        let rules_dir = dir.path().join("rules");
        fs::create_dir(&rules_dir).unwrap();
        write_rule_to_dir(&dir, "rules/win_rule.yml", MINIMAL_RULE_YAML);

        let mut rule_index = RuleIndex::new();
        rule_index
            .load_from_dirs(
                &[rules_dir.as_path()],
                &HashSet::new(),
                &LoadFilter::default(),
            )
            .unwrap();

        let engine = DetectionEngine::new(&rule_index).unwrap();
        assert_eq!(engine.rule_count(), 1);
    }

    #[test]
    fn test_put_events_and_process() {
        let rule_index = RuleIndex::new();
        let mut engine = DetectionEngine::new(&rule_index).unwrap();
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
        let rules_dir = dir.path().join("rules");
        fs::create_dir(&rules_dir).unwrap();
        write_rule_to_dir(&dir, "rules/test_rule.yml", MINIMAL_RULE_YAML);

        let mut rule_index = RuleIndex::new();
        rule_index
            .load_from_dirs(
                &[rules_dir.as_path()],
                &HashSet::new(),
                &LoadFilter::default(),
            )
            .unwrap();

        let mut engine = DetectionEngine::new(&rule_index).unwrap();
        let event = Event::new(serde_json::json!({"event_id": 1}), Vec::new());
        engine.put_events(vec![event]);
        engine.process_events();

        let alerts = engine.get_alerts();
        let stats = engine.stats();
        assert_eq!(stats.alerts_generated, alerts.len() as u64);
    }

    #[test]
    fn test_reload_rules_after_exclude() {
        let dir = tempfile::tempdir().unwrap();
        let rules_dir = dir.path().join("rules");
        fs::create_dir(&rules_dir).unwrap();
        write_rule_to_dir(&dir, "rules/win_rule.yml", MINIMAL_RULE_YAML);

        let mut rule_index = RuleIndex::new();
        rule_index
            .load_from_dirs(
                &[rules_dir.as_path()],
                &HashSet::new(),
                &LoadFilter::default(),
            )
            .unwrap();

        let mut engine = DetectionEngine::new(&rule_index).unwrap();
        assert_eq!(engine.rule_count(), 1);

        rule_index.exclude_rule_id("test-rule-001");
        engine.reload_rules(&rule_index).unwrap();
        assert_eq!(engine.rule_count(), 0);
    }
}
