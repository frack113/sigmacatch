// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 sigmacatch contributors

//! Detection engine — thin wrapper around rsigma-eval for loading pipelines and
//! rules, then evaluating events. Consumes rules from `SigmahqRules` in
//! read-only mode. No filtering, no skip sets — just the bare essentials for
//! testing and validation.

use anyhow::{anyhow, Result};
use rsigma_eval::event::JsonEvent;
use rsigma_eval::pipeline::{parse_pipeline, Pipeline};
use rsigma_eval::{Engine, LogSourceExtractor};
use sigmacatch_rule::SigmahqRules;
use sigmacatch_types::{Alert, Event};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use uuid::Uuid;

/// Embedded pipeline for flattening Winevt XML event structure.
pub const FLATTEN_WINEVT_PIPELINE: &str = include_str!("../pipelines/flatten_winevt.yml");

/// Embedded pipeline for Windows Sigma rule transformation.
pub const WINDOWS_PIPELINE: &str = include_str!("../pipelines/windows.yml");

mod channel_resolver;

pub struct DetectionEngine {
    engine: Engine,
    /// Cached parsed pipelines — cloned (not re-parsed) on reload_rules to
    /// avoid YAML parsing overhead each cycle.
    flatten_pipeline: Pipeline,
    windows_pipeline: Pipeline,
    events: Vec<Event>,
    alerts: Vec<Alert>,
    stats: EngineStats,
    /// UUID → file path, shared via Arc to avoid cloning on reload.
    rule_paths: Arc<HashMap<Uuid, PathBuf>>,
    /// rule_id string → Uuid, built once for O(1) lookup in the hot path.
    rule_id_map: HashMap<String, Uuid>,
}

impl DetectionEngine {
    pub fn new(rules: &SigmahqRules) -> Result<Self> {
        let flatten = parse_pipeline(FLATTEN_WINEVT_PIPELINE)
            .map_err(|e| anyhow!("flatten_winevt pipeline: {e}"))?;
        let windows =
            parse_pipeline(WINDOWS_PIPELINE).map_err(|e| anyhow!("windows pipeline: {e}"))?;
        let mut engine = Self::create_engine(&flatten, &windows)?;

        // Use add_rules (references) instead of add_collection(&to_collection())
        // to avoid cloning the entire Vec<SigmaRule> — add_rules takes &[SigmaRule]
        // and rebuilds indexes once at the end.
        let errors = engine.add_rules(rules.rules());
        if !errors.is_empty() {
            for (idx, err) in &errors {
                tracing::error!("Rule at index {idx} failed to compile: {err}");
            }
            anyhow::bail!(
                "Engine add_rules: {} rule(s) failed to compile out of {}",
                errors.len(),
                rules.len()
            );
        }

        let rule_paths = Arc::new(rules.rule_paths().clone());
        let rule_id_map = Self::build_rule_id_map(&rule_paths);

        Ok(Self {
            engine,
            flatten_pipeline: flatten,
            windows_pipeline: windows,
            events: Vec::new(),
            alerts: Vec::new(),
            stats: EngineStats::default(),
            rule_paths,
            rule_id_map,
        })
    }

    pub fn reload_rules(&mut self, rules: &SigmahqRules) -> Result<()> {
        // Reuse cached pipelines (clone, not re-parse YAML) for the new engine.
        let mut engine = Self::create_engine(&self.flatten_pipeline, &self.windows_pipeline)?;

        let errors = engine.add_rules(rules.rules());
        if !errors.is_empty() {
            for (idx, err) in &errors {
                tracing::warn!("Rule at index {idx} failed to compile: {err}");
            }
        }

        self.engine = engine;
        let rule_paths = rules.rule_paths().clone();
        self.rule_id_map = Self::build_rule_id_map(&rule_paths);
        self.rule_paths = Arc::new(rule_paths);
        Ok(())
    }

    /// Build the rule_id string → Uuid lookup map directly from the HashMap keys,
    /// avoiding redundant Uuid::parse_str on file stems. The `rule_paths` keys
    /// are already parsed UUIDs from `rule.id`, so we just stringify them.
    fn build_rule_id_map(rule_paths: &HashMap<Uuid, PathBuf>) -> HashMap<String, Uuid> {
        let mut map: HashMap<String, Uuid> = HashMap::with_capacity(rule_paths.len());
        for uuid in rule_paths.keys() {
            map.insert(uuid.to_string(), *uuid);
        }
        map
    }

    /// Create a fresh rsigma-eval Engine with pipelines + optimizations.
    fn create_engine(flatten: &Pipeline, windows: &Pipeline) -> Result<Engine> {
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

        engine.add_pipeline(flatten.clone());
        engine.add_pipeline(windows.clone());

        Ok(engine)
    }

    pub fn rule_count(&self) -> usize {
        self.engine.rule_count()
    }

    /// Resolve the Windows event channels to collect, reading the
    /// post-pipeline logsource of the compiled rules (#437). The `windows`
    /// pipeline rewrites sysmon categories to `service: sysmon`, so this
    /// needs no duplicated category → service mapping.
    pub fn resolve_channels(&self, custom_map: &HashMap<String, String>) -> Vec<String> {
        channel_resolver::resolve_channels(self.engine.rules(), custom_map)
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
                let rule_id = result
                    .header
                    .rule_id
                    .as_deref()
                    .and_then(|id| self.rule_id_map.get(id).copied())
                    .unwrap_or(Uuid::nil());
                let rule_path = self.rule_paths.get(&rule_id).cloned();
                let alert = Alert {
                    rule_id,
                    rule_title: result.header.rule_title.clone(),
                    description: None,
                    rule_path,
                    severity: result
                        .header
                        .level
                        .as_ref()
                        .map(|l| format!("{:?}", l))
                        .unwrap_or_else(|| "unknown".to_string()),
                    event_json_raw: event.event_json_raw.clone(),
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
            Event::new(
                serde_json::json!({}).clone(),
                serde_json::json!({}),
                Vec::new(),
            ),
            Event::new(
                serde_json::json!({}).clone(),
                serde_json::json!({}),
                Vec::new(),
            ),
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
        let event_json = serde_json::json!({"event_id": 1});
        let event = Event::new(event_json.clone(), event_json, Vec::new());
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

    fn rule_with_category(id: &str, category: &str) -> String {
        format!(
            r#"title: {category} rule
id: {id}
status: stable
level: critical
author: Test Author
logsource:
  product: windows
  category: {category}
detection:
  selection:
    foo: bar
  condition: selection
"#
        )
    }

    fn evaluate_eventid(category: &str, event_id: u32) -> usize {
        let dir = tempfile::tempdir().unwrap();
        let sigma_dir = dir.path().join("sigma");
        let rules_dir = sigma_dir.join("rules");
        fs::create_dir_all(&rules_dir).unwrap();
        fs::write(
            rules_dir.join("cat_rule.yml"),
            rule_with_category("11111111-1111-1111-1111-111111111111", category),
        )
        .unwrap();

        let rules = SigmahqRules::new_from_path(&sigma_dir).unwrap();
        let mut engine = DetectionEngine::new(&rules).unwrap();
        let event_json = serde_json::json!({
            "Event": { "System": { "EventID": event_id } },
            "foo": "bar"
        });
        let event = Event::new(event_json.clone(), event_json, Vec::new());
        engine.put_events(vec![event]);
        engine.process_events();
        engine.get_alerts().len()
    }

    #[test]
    fn test_list_valued_add_condition_wmi_event() {
        assert_eq!(evaluate_eventid("wmi_event", 19), 1);
        assert_eq!(evaluate_eventid("wmi_event", 20), 1);
        assert_eq!(evaluate_eventid("wmi_event", 21), 1);
        assert_eq!(evaluate_eventid("wmi_event", 1), 0);
    }

    #[test]
    fn test_list_valued_add_condition_sysmon_status() {
        assert_eq!(evaluate_eventid("sysmon_status", 4), 1);
        assert_eq!(evaluate_eventid("sysmon_status", 16), 1);
        assert_eq!(evaluate_eventid("sysmon_status", 1), 0);
    }

    #[test]
    fn test_list_valued_add_condition_pipe_created() {
        assert_eq!(evaluate_eventid("pipe_created", 17), 1);
        assert_eq!(evaluate_eventid("pipe_created", 18), 1);
        assert_eq!(evaluate_eventid("pipe_created", 1), 0);
    }

    #[test]
    fn test_list_valued_add_condition_registry_event() {
        assert_eq!(evaluate_eventid("registry_event", 12), 1);
        assert_eq!(evaluate_eventid("registry_event", 13), 1);
        assert_eq!(evaluate_eventid("registry_event", 14), 1);
        assert_eq!(evaluate_eventid("registry_event", 1), 0);
    }

    #[test]
    fn test_ps_module_pruned_for_unmapped_powershell_eventid() {
        // The reference SigmaHQ harness maps ps_module to EventID 4103 only.
        // ps_module rules carry no EventID condition in windows.yml (only
        // sysmon categories get one), so without the injected category
        // sentinel an unrelated PowerShell console error (EID 4100) would be
        // evaluated against them — a real FP committed on sigmacatch/20260807.
        let dir = tempfile::tempdir().unwrap();
        let sigma_dir = dir.path().join("sigma");
        let rules_dir = sigma_dir.join("rules");
        fs::create_dir_all(&rules_dir).unwrap();
        fs::write(
            rules_dir.join("ps_module_rule.yml"),
            rule_with_category("11111111-1111-1111-1111-111111111111", "ps_module"),
        )
        .unwrap();

        let rules = SigmahqRules::new_from_path(&sigma_dir).unwrap();
        let mut engine = DetectionEngine::new(&rules).unwrap();

        let ps_event = |event_id: u32| {
            let json = serde_json::json!({
                "Event": {
                    "System": {
                        "Provider": { "#attributes": { "Name": "Microsoft-Windows-PowerShell" } },
                        "EventID": event_id,
                        "Channel": "Microsoft-Windows-PowerShell/Operational"
                    },
                    "EventData": { "ContextInfo": "Application hôte = powershell.exe" }
                },
                "foo": "bar"
            });
            let mut event = Event::new(json.clone(), json.clone(), Vec::new());
            event.inject_logsource_fields();
            event
        };

        // EID 4100 console error: injected category sentinel prunes the rule.
        engine.put_events(vec![ps_event(4100)]);
        engine.process_events();
        assert_eq!(engine.get_alerts().len(), 0);

        // EID 4103 module logging: category matches, rule evaluated, alert.
        engine.put_events(vec![ps_event(4103)]);
        engine.process_events();
        assert_eq!(engine.get_alerts().len(), 1);
    }

    fn channels_for(logsource: &str) -> Vec<String> {
        let dir = tempfile::tempdir().unwrap();
        let sigma_dir = dir.path().join("sigma");
        let rules_dir = sigma_dir.join("rules");
        fs::create_dir_all(&rules_dir).unwrap();
        let yaml = format!(
            r#"title: channel rule
id: 11111111-1111-1111-1111-111111111111
status: stable
author: Test Author
logsource:
{logsource}
detection:
  selection:
    foo: bar
  condition: selection
"#
        );
        fs::write(rules_dir.join("chan_rule.yml"), yaml).unwrap();
        let rules = SigmahqRules::new_from_path(&sigma_dir).unwrap();
        let engine = DetectionEngine::new(&rules).unwrap();
        engine.resolve_channels(&HashMap::new())
    }

    #[test]
    fn test_resolve_channels_pipeline_rewrites_sysmon_category() {
        // process_creation is routed to service: sysmon by the windows
        // pipeline (#437) → the Security channel is no longer collected.
        let channels = channels_for("  product: windows\n  category: process_creation\n");
        assert_eq!(channels, vec!["Microsoft-Windows-Sysmon/Operational"]);
    }

    #[test]
    fn test_resolve_channels_sysmon_subcategory() {
        let channels = channels_for("  product: windows\n  category: registry_delete\n");
        assert_eq!(channels, vec!["Microsoft-Windows-Sysmon/Operational"]);
    }

    #[test]
    fn test_resolve_channels_service_only() {
        let channels = channels_for("  product: windows\n  service: sysmon\n");
        assert_eq!(channels, vec!["Microsoft-Windows-Sysmon/Operational"]);
    }

    #[test]
    fn test_resolve_channels_service_security() {
        let channels = channels_for("  product: windows\n  service: security\n");
        assert_eq!(channels, vec!["Security"]);
    }

    #[test]
    fn test_resolve_channels_unmapped_category() {
        // A category absent from CATEGORY_CHANNELS (login was removed — not a
        // valid Sigma taxonomy category) resolves to no channels (fail-closed).
        let channels = channels_for("  product: windows\n  category: login\n");
        assert!(channels.is_empty());
    }

    #[test]
    fn test_resolve_channels_ps_module() {
        let channels = channels_for("  product: windows\n  category: ps_module\n");
        assert_eq!(
            channels,
            vec![
                "Microsoft-Windows-PowerShell/Operational".to_string(),
                "PowerShellCore/Operational".to_string()
            ]
        );
    }

    #[test]
    fn test_resolve_channels_custom_map() {
        let dir = tempfile::tempdir().unwrap();
        let sigma_dir = dir.path().join("sigma");
        let rules_dir = sigma_dir.join("rules");
        fs::create_dir_all(&rules_dir).unwrap();
        fs::write(
            rules_dir.join("chan_rule.yml"),
            rule_with_category("11111111-1111-1111-1111-111111111111", "process_creation"),
        )
        .unwrap();
        let rules = SigmahqRules::new_from_path(&sigma_dir).unwrap();
        let engine = DetectionEngine::new(&rules).unwrap();
        let mut custom_map = HashMap::new();
        custom_map.insert(
            "Custom-Channel/Operational".to_string(),
            "sysmon".to_string(),
        );
        let channels = engine.resolve_channels(&custom_map);
        assert_eq!(
            channels,
            vec![
                "Custom-Channel/Operational".to_string(),
                "Microsoft-Windows-Sysmon/Operational".to_string()
            ]
        );
    }

    #[test]
    fn test_resolve_channels_union_across_rules() {
        let dir = tempfile::tempdir().unwrap();
        let sigma_dir = dir.path().join("sigma");
        let rules_dir = sigma_dir.join("rules");
        fs::create_dir_all(&rules_dir).unwrap();
        fs::write(
            rules_dir.join("a_proc.yml"),
            rule_with_category("11111111-1111-1111-1111-111111111111", "process_creation"),
        )
        .unwrap();
        let yaml = rule_with_category("22222222-2222-2222-2222-222222222222", "login")
            .replace("category: login", "category: login\n  service: security");
        fs::write(rules_dir.join("b_login.yml"), yaml).unwrap();
        let rules = SigmahqRules::new_from_path(&sigma_dir).unwrap();
        let engine = DetectionEngine::new(&rules).unwrap();
        let channels = engine.resolve_channels(&HashMap::new());
        assert_eq!(
            channels,
            vec![
                "Microsoft-Windows-Sysmon/Operational".to_string(),
                "Security".to_string()
            ]
        );
    }

    #[test]
    fn test_resolve_channels_ignores_non_windows() {
        let channels = channels_for("  product: linux\n  category: process_creation\n");
        assert!(channels.is_empty());
    }

    #[test]
    fn test_resolve_channels_unknown_service() {
        let channels = channels_for("  product: windows\n  service: nonexistent\n");
        assert!(channels.is_empty());
    }

    #[test]
    fn test_resolve_channels_service_case_insensitive() {
        // "Sysmon" (mixed case) must resolve just like "sysmon".
        let channels = channels_for("  product: windows\n  service: Sysmon\n");
        assert_eq!(channels, vec!["Microsoft-Windows-Sysmon/Operational"]);
    }

    #[test]
    fn test_resolve_channels_category_case_insensitive() {
        // "Ps_Module" (mixed case) must resolve just like "ps_module".
        let channels = channels_for("  product: windows\n  category: Ps_Module\n");
        assert_eq!(
            channels,
            vec![
                "Microsoft-Windows-PowerShell/Operational".to_string(),
                "PowerShellCore/Operational".to_string()
            ]
        );
    }
}
