// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 sigmacatch contributors

//! Detection engine — thin wrapper around rsigma-eval for loading pipelines and
//! rules, then evaluating events. Consumes rules from `SigmahqRules` in
//! read-only mode. No filtering, no skip sets — just the bare essentials for
//! testing and validation.

use anyhow::{anyhow, Result};
use rsigma_eval::event::JsonEvent;
use rsigma_eval::pipeline::parse_pipeline;
use rsigma_eval::{Engine, LogSourceExtractor};
use sigmacatch_rule::SigmahqRules;
use sigmacatch_types::{Alert, Event};
use uuid::Uuid;

/// Embedded pipeline for flattening Winevt XML event structure.
pub const FLATTEN_WINEVT_PIPELINE: &str = include_str!("../pipelines/flatten_winevt.yml");

/// Embedded pipeline for Windows Sigma rule transformation.
pub const WINDOWS_PIPELINE: &str = include_str!("../pipelines/windows.yml");

pub struct DetectionEngine {
    engine: Engine,
    events: Vec<Event>,
    alerts: Vec<Alert>,
    stats: EngineStats,
}

impl DetectionEngine {
    pub fn new(rules: &SigmahqRules) -> Result<Self> {
        let mut engine = Self::create_engine()?;
        engine
            .add_collection(&rules.to_collection())
            .map_err(|e| anyhow!("Engine add_collection failed: {e}"))?;

        Ok(Self {
            engine,
            events: Vec::new(),
            alerts: Vec::new(),
            stats: EngineStats::default(),
        })
    }

    pub fn reload_rules(&mut self, rules: &SigmahqRules) -> Result<()> {
        let mut engine = Self::create_engine()?;
        engine
            .add_collection(&rules.to_collection())
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

    pub fn rule_count(&self) -> usize {
        self.engine.rule_count()
    }

    pub fn engine(&self) -> &Engine {
        &self.engine
    }

    pub fn engine_mut(&mut self) -> &mut Engine {
        &mut self.engine
    }

    pub fn save_hir(&self) -> Result<Vec<u8>> {
        self.engine
            .save_hir()
            .map_err(|e| anyhow!("save_hir failed: {e}"))
    }

    pub fn load_hir(&mut self, blob: &[u8]) -> Result<()> {
        self.engine
            .load_hir(blob)
            .map_err(|e| anyhow!("load_hir failed: {e}"))
    }

    pub fn stats(&self) -> EngineStats {
        self.stats.clone()
    }

    pub fn explain_rule(&self, rule_id: &Uuid, event: &Event) -> Option<serde_json::Value> {
        let rule_id_str = rule_id.to_string();
        let compiled = self
            .engine
            .rules()
            .iter()
            .find(|r| r.id.as_deref() == Some(rule_id_str.as_str()))?;
        let json_event = JsonEvent::borrow(&event.event_json);
        let explanation = rsigma_eval::explain_rule(compiled, &json_event);
        serde_json::to_value(explanation).ok()
    }

    // ─── FIFO API ─────────────────────────────────────────────────────────

    pub fn put_events(&mut self, events: Vec<Event>) {
        self.events.extend(events);
    }

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
                        .as_deref()
                        .and_then(|id| Uuid::parse_str(id).ok())
                        .unwrap_or(Uuid::nil()),
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

    pub fn get_alerts(&mut self) -> Vec<Alert> {
        let alerts = std::mem::take(&mut self.alerts);
        self.stats.alerts_generated += alerts.len() as u64;
        alerts
    }
}

// ─── Engine Stats ─────────────────────────────────────────────────────────

#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct EngineStats {
    pub events_processed: u64,
    pub alerts_generated: u64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use sigmacatch_rule::SigmahqRules;
    use std::fs;

    const MINIMAL_RULE_YAML: &str = r#"title: Test Rule
id: 11111111-1111-1111-1111-111111111111
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

    #[test]
    fn test_engine_with_rule_index() {
        let dir = tempfile::tempdir().unwrap();
        let sigma_dir = dir.path().join("sigma");
        let rules_dir = sigma_dir.join("rules");
        fs::create_dir_all(&rules_dir).unwrap();
        fs::write(rules_dir.join("win_rule.yml"), MINIMAL_RULE_YAML).unwrap();

        let rules = SigmahqRules::new_from_path(&sigma_dir).unwrap();

        let engine = DetectionEngine::new(&rules).unwrap();
        assert_eq!(engine.rule_count(), 1);
    }

    #[test]
    fn test_put_events_and_process() {
        let rules = SigmahqRules::default();
        let mut engine = DetectionEngine::new(&rules).unwrap();
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
        let sigma_dir = dir.path().join("sigma");
        let rules_dir = sigma_dir.join("rules");
        fs::create_dir_all(&rules_dir).unwrap();
        fs::write(rules_dir.join("test_rule.yml"), MINIMAL_RULE_YAML).unwrap();

        let rules = SigmahqRules::new_from_path(&sigma_dir).unwrap();

        let mut engine = DetectionEngine::new(&rules).unwrap();
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
        let sigma_dir = dir.path().join("sigma");
        let rules_dir = sigma_dir.join("rules");
        fs::create_dir_all(&rules_dir).unwrap();
        fs::write(rules_dir.join("win_rule.yml"), MINIMAL_RULE_YAML).unwrap();

        let mut rules = SigmahqRules::new_from_path(&sigma_dir).unwrap();

        let mut engine = DetectionEngine::new(&rules).unwrap();
        assert_eq!(engine.rule_count(), 1);

        let rule_id = Uuid::parse_str("11111111-1111-1111-1111-111111111111").unwrap();
        rules.remove_id(&rule_id);
        engine.reload_rules(&rules).unwrap();
        assert_eq!(engine.rule_count(), 0);
    }
}
