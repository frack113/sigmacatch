// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 sigmacatch contributors

//! Detection engine — thin wrapper around rsigma-eval for loading pipelines and
//! rules, then evaluating events. Consumes rules from `SigmahqRules` in
//! read-only mode. No filtering, no skip sets — just the bare essentials for
//! testing and validation.
//!
//! # Example
//!
//! ```rust,no_run
//! use sigmacatch_detection::DetectionEngine;
//! use sigmacatch_rule::SigmahqRules;
//! use std::path::Path;
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let rules = SigmahqRules::new_from_path(Path::new("sigma"))?;
//! let engine = DetectionEngine::new(&rules)?;
//! # Ok(())
//! # }
//! ```
//!
//! For validation tools that must tolerate a few broken rules, use `new_lenient`:
//!
//! ```rust,no_run
//! use sigmacatch_detection::DetectionEngine;
//! use sigmacatch_rule::SigmahqRules;
//! use std::path::Path;
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let rules = SigmahqRules::new_from_path(Path::new("sigma"))?;
//! let (engine, failed) = DetectionEngine::new_lenient(&rules)?;
//! if !failed.is_empty() {
//!     eprintln!("{} rules failed to compile", failed.len());
//! }
//! # Ok(())
//! # }
//! ```

use rsigma_eval::event::JsonEvent;
use rsigma_eval::pipeline::{Pipeline, parse_pipeline};
use rsigma_eval::{Engine, LogSourceExtractor};
use sigmacatch_rule::SigmahqRules;
use sigmacatch_types::{Alert, Event};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use thiserror::Error;
use uuid::Uuid;

/// Windows logsource add_condition + change_logsource transformations.
pub const WIN_LOGSOURCE_PIPELINE: &str = include_str!("../pipelines/1_win_logsource.yml");

/// Windows field_name_mapping transformations.
pub const WIN_FIELD_PIPELINE: &str = include_str!("../pipelines/2_win_field_name.yml");

/// Linux logsource add_condition + change_logsource transformations.
pub const LNX_LOGSOURCE_PIPELINE: &str = include_str!("../pipelines/3_lnx_logsource.yml");

/// Linux field_name_mapping transformations.
pub const LNX_FIELD_PIPELINE: &str = include_str!("../pipelines/4_lnx_field_name.yml");

mod channel_resolver;

/// Sigma evaluation engine wrapper: compiled rule set + per-platform
/// pipelines + a small FIFO of pending events and alerts.
pub struct DetectionEngine {
    engine: Engine,
    /// Cached parsed pipelines — cloned (not re-parsed) on reload_rules to
    /// avoid YAML parsing overhead each cycle.
    win_logsource_pipeline: Pipeline,
    win_field_pipeline: Pipeline,
    /// Linux-specific pipelines for Sysmon-for-Linux events (product: linux).
    lnx_logsource_pipeline: Pipeline,
    lnx_field_pipeline: Pipeline,
    events: Vec<Event>,
    alerts: Vec<Alert>,
    stats: EngineStats,
    /// UUID → file path, shared via Arc to avoid cloning on reload.
    rule_paths: Arc<HashMap<Uuid, PathBuf>>,
    /// rule_id string → Uuid, built once for O(1) lookup in the hot path.
    rule_id_map: HashMap<String, Uuid>,
}

/// Errors produced by the detection engine while building or persisting it.
#[derive(Debug, Error)]
pub enum DetectionError {
    /// A bundled platform pipeline failed to parse.
    #[error("pipeline {name}: {source}")]
    Pipeline {
        /// Pipeline identifier.
        name: &'static str,
        /// The underlying parse error.
        source: rsigma_eval::EvalError,
    },
    /// Some rules failed to compile into the engine.
    #[error("Engine add_rules: {count} rule(s) failed to compile out of {total}")]
    AddRules {
        /// Number of rules that failed to compile.
        count: usize,
        /// Total number of rules attempted.
        total: usize,
    },
    /// HIR (compiled engine) serialization failed.
    #[error("save_hir failed: {0}")]
    SaveHir(#[source] rsigma_eval::EvalError),
    /// HIR blob deserialization failed.
    #[error("load_hir failed: {0}")]
    LoadHir(#[source] rsigma_eval::EvalError),
}

impl DetectionEngine {
    /// Parse the four platform pipelines and create an engine.
    /// Returns (engine, win_logsource, win_field, lnx_logsource, lnx_field).
    fn create_engine_with_pipelines()
    -> Result<(Engine, Pipeline, Pipeline, Pipeline, Pipeline), DetectionError> {
        let win_logsource =
            parse_pipeline(WIN_LOGSOURCE_PIPELINE).map_err(|source| DetectionError::Pipeline {
                name: "win_logsource",
                source,
            })?;
        let win_field =
            parse_pipeline(WIN_FIELD_PIPELINE).map_err(|source| DetectionError::Pipeline {
                name: "win_field",
                source,
            })?;
        let lnx_logsource =
            parse_pipeline(LNX_LOGSOURCE_PIPELINE).map_err(|source| DetectionError::Pipeline {
                name: "lnx_logsource",
                source,
            })?;
        let lnx_field =
            parse_pipeline(LNX_FIELD_PIPELINE).map_err(|source| DetectionError::Pipeline {
                name: "lnx_field",
                source,
            })?;

        let engine = Self::create_engine(&win_logsource, &win_field, &lnx_logsource, &lnx_field)?;

        Ok((engine, win_logsource, win_field, lnx_logsource, lnx_field))
    }

    /// Compile `rules` and load the embedded platform pipelines.
    pub fn new(rules: &SigmahqRules) -> Result<Self, DetectionError> {
        let (mut engine, win_logsource, win_field, lnx_logsource, lnx_field) =
            Self::create_engine_with_pipelines()?;

        // add_rules (&[SigmaRule]) instead of add_collection avoids cloning the
        // whole Vec; indexes are rebuilt once at the end.
        let errors = engine.add_rules(rules.rules());
        if !errors.is_empty() {
            for (idx, err) in &errors {
                tracing::error!("Rule at index {idx} failed to compile: {err}");
            }
            return Err(DetectionError::AddRules {
                count: errors.len(),
                total: rules.len(),
            });
        }

        let rule_paths = Arc::new(rules.rule_paths().clone());
        let rule_id_map = Self::build_rule_id_map(&rule_paths);

        Ok(Self {
            engine,
            win_logsource_pipeline: win_logsource,
            win_field_pipeline: win_field,
            lnx_logsource_pipeline: lnx_logsource,
            lnx_field_pipeline: lnx_field,
            events: Vec::new(),
            alerts: Vec::new(),
            stats: EngineStats::default(),
            rule_paths,
            rule_id_map,
        })
    }

    /// Compile `rules` like [`Self::new`] but skip rules that fail to compile
    /// instead of returning an error.  Suitable for validation tools where a
    /// handful of bad rules should not prevent checking the rest.
    ///
    /// Returns the engine plus a vector of (rule_index, error) for rules that
    /// failed to compile, allowing callers to surface the failures.
    pub fn new_lenient(
        rules: &SigmahqRules,
    ) -> Result<(Self, Vec<(usize, DetectionError)>), DetectionError> {
        let (mut engine, win_logsource, win_field, lnx_logsource, lnx_field) =
            Self::create_engine_with_pipelines()?;

        let errors = engine.add_rules(rules.rules());
        let failed: Vec<(usize, DetectionError)> = errors
            .into_iter()
            .map(|(idx, err)| {
                tracing::warn!("Rule at index {idx} failed to compile (lenient): {err}");
                (
                    idx,
                    DetectionError::AddRules {
                        count: 1,
                        total: rules.len(),
                    },
                )
            })
            .collect();

        let rule_paths = Arc::new(rules.rule_paths().clone());
        let rule_id_map = Self::build_rule_id_map(&rule_paths);

        Ok((
            Self {
                engine,
                win_logsource_pipeline: win_logsource,
                win_field_pipeline: win_field,
                lnx_logsource_pipeline: lnx_logsource,
                lnx_field_pipeline: lnx_field,
                events: Vec::new(),
                alerts: Vec::new(),
                stats: EngineStats::default(),
                rule_paths,
                rule_id_map,
            },
            failed,
        ))
    }

    /// Swap in a freshly compiled rule set without re-parsing pipelines.
    pub fn reload_rules(&mut self, rules: &SigmahqRules) -> Result<(), DetectionError> {
        // Reuse cached pipelines (clone, not re-parse YAML) for the new engine.
        let mut engine = Self::create_engine(
            &self.win_logsource_pipeline,
            &self.win_field_pipeline,
            &self.lnx_logsource_pipeline,
            &self.lnx_field_pipeline,
        )?;

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

    /// Build the rule_id string → Uuid map from the HashMap keys — already
    /// parsed UUIDs, so stringifying avoids redundant Uuid::parse_str.
    fn build_rule_id_map(rule_paths: &HashMap<Uuid, PathBuf>) -> HashMap<String, Uuid> {
        let mut map: HashMap<String, Uuid> = HashMap::with_capacity(rule_paths.len());
        for uuid in rule_paths.keys() {
            map.insert(uuid.to_string(), *uuid);
        }
        map
    }

    /// Create a fresh rsigma-eval Engine with pipelines + optimizations.
    fn create_engine(
        win_logsource: &Pipeline,
        win_field: &Pipeline,
        lnx_logsource: &Pipeline,
        lnx_field: &Pipeline,
    ) -> Result<Engine, DetectionError> {
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

        engine.add_pipeline(win_logsource.clone());
        engine.add_pipeline(win_field.clone());
        engine.add_pipeline(lnx_logsource.clone());
        engine.add_pipeline(lnx_field.clone());

        Ok(engine)
    }

    /// Number of compiled rules currently loaded.
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

    /// Read-only access to the underlying rsigma engine.
    pub fn engine(&self) -> &Engine {
        &self.engine
    }

    /// Mutable access to the underlying rsigma engine.
    pub fn engine_mut(&mut self) -> &mut Engine {
        &mut self.engine
    }

    /// Serialize the compiled engine (HIR cache).
    pub fn save_hir(&self) -> Result<Vec<u8>, DetectionError> {
        self.engine.save_hir().map_err(DetectionError::SaveHir)
    }

    /// Restore a previously saved HIR blob.
    pub fn load_hir(&mut self, blob: &[u8]) -> Result<(), DetectionError> {
        self.engine.load_hir(blob).map_err(DetectionError::LoadHir)
    }

    /// Copy of the processing counters.
    pub fn stats(&self) -> EngineStats {
        self.stats.clone()
    }

    /// Per-field match explanation for diagnostics (`regressiondata-check` deep mode).
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

    /// Append collected events to the pending FIFO.
    pub fn put_events(&mut self, events: Vec<Event>) {
        self.events.extend(events);
    }

    /// Drain the pending events FIFO.
    pub fn get_events(&mut self) -> Vec<Event> {
        std::mem::take(&mut self.events)
    }

    /// Evaluate all events in the pile against loaded rules.
    ///
    /// Events must have logsource fields (product, service, category) already
    /// injected by the collector via `Event::inject_logsource_fields()`.
    /// The bloom pre-filter and logsource pruning are both active.
    ///
    /// The engine carries BOTH the Windows and Linux pipelines; each
    /// transformation is gated by rule_conditions (product/service), so a
    /// single evaluation pass routes Windows and Sysmon-for-Linux events
    /// correctly — no per-product engine needed here.
    pub fn process_events(&mut self) {
        let events = std::mem::take(&mut self.events);
        if events.is_empty() {
            return;
        }
        tracing::info!(events = events.len(), "processing events");
        self.stats.events_processed += events.len() as u64;

        for event in events {
            let json_event = JsonEvent::borrow(&event.event_json);
            let matches = self.engine.evaluate(&json_event);
            if !matches.is_empty() {
                tracing::debug!(
                    product = ?event.event_json.get("product"),
                    matches = matches.len(),
                    "event matched"
                );
            }
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
                    is_etw: event.is_etw,
                };
                self.alerts.push(alert);
            }
        }
    }

    /// Drain matched alerts (updates [`EngineStats::alerts_generated`]).
    pub fn get_alerts(&mut self) -> Vec<Alert> {
        let alerts = std::mem::take(&mut self.alerts);
        self.stats.alerts_generated += alerts.len() as u64;
        alerts
    }
}

// ─── Engine Stats ─────────────────────────────────────────────────────────

/// Cumulative processing counters.
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct EngineStats {
    /// Total events evaluated so far.
    pub events_processed: u64,
    /// Total alerts produced so far.
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
            Event::new(serde_json::json!({}), serde_json::json!({}), Vec::new()),
            Event::new(serde_json::json!({}), serde_json::json!({}), Vec::new()),
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
            let mut event = Event::new(json.clone(), json, Vec::new());
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

    /// Regression: WMI rule `win_wmi_persistence` with `filter_scmevent` must
    /// exclude SCM Event Provider events. Before the fix, the pipeline mapped
    /// `Provider` → `Event.System.Provider.#attributes.Name` (the WMI-Activity
    /// provider) instead of `Event.UserData.Operation_EssStarted.Provider` (the
    /// SCM filter field), so `filter_scmevent` never fired — false positive.
    #[test]
    fn test_wmi_filter_scmevent_excludes_scm_event() {
        let sigma_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("..")
            .join("sigma");
        let wmi_rule_path = sigma_dir.join("rules/windows/builtin/wmi/win_wmi_persistence.yml");
        if !wmi_rule_path.exists() {
            return; // sigma submodule not cloned — skip
        }
        let dir = tempfile::tempdir().unwrap();
        let test_sigma = dir.path().join("sigma");
        let test_rules = test_sigma.join("rules/windows/builtin/wmi");
        fs::create_dir_all(&test_rules).unwrap();
        fs::copy(&wmi_rule_path, test_rules.join("win_wmi_persistence.yml")).unwrap();

        let rules = SigmahqRules::new_from_path(&test_sigma).unwrap();
        let mut engine = DetectionEngine::new(&rules).unwrap();

        // SCM Event Provider event that should be excluded by filter_scmevent.
        let event_json = serde_json::json!({
            "Event": {
                "System": {
                    "Provider": { "#attributes": { "Name": "Microsoft-Windows-WMI-Activity" } },
                    "EventID": 5859,
                    "Channel": "Microsoft-Windows-WMI-Activity/Operational"
                },
                "UserData": {
                    "Operation_EssStarted": {
                        "Provider": "SCM Event Provider",
                        "Query": "select * from MSFT_SCMEventLogEvent",
                        "User": "S-1-5-32-544",
                        "PossibleCause": "Permanent"
                    }
                }
            },
            "product": "windows",
            "service": "wmi"
        });
        let mut event = Event::new(event_json.clone(), event_json, Vec::new());
        event.inject_logsource_fields();
        engine.put_events(vec![event]);
        engine.process_events();
        let alerts = engine.get_alerts();
        assert_eq!(
            alerts.len(),
            0,
            "SCM Event Provider event must be excluded by filter_scmevent"
        );
    }

    /// Regression: shellcode injection rule must match Sysmon EventID 10 with
    /// GrantedAccess=0x1f3fff and CallTrace containing 'UNKNOWN'.
    #[test]
    fn test_shellcode_injection_matches_calltrace_unknown() {
        let sigma_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("..")
            .join("sigma");
        let rule_path = sigma_dir.join(
            "rules-threat-hunting/windows/process_access/proc_access_win_susp_potential_shellcode_injection.yml",
        );
        if !rule_path.exists() {
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        let test_sigma = dir.path().join("sigma");
        let test_rules = test_sigma.join("rules-threat-hunting/windows/process_access");
        fs::create_dir_all(&test_rules).unwrap();
        fs::copy(
            &rule_path,
            test_rules.join("proc_access_win_susp_potential_shellcode_injection.yml"),
        )
        .unwrap();

        let rules = SigmahqRules::new_from_path(&test_sigma).unwrap();
        let mut engine = DetectionEngine::new(&rules).unwrap();

        let event_json = serde_json::json!({
            "Event": {
                "System": {
                    "Provider": { "#attributes": { "Name": "Microsoft-Windows-Sysmon" } },
                    "EventID": 10,
                    "Channel": "Microsoft-Windows-Sysmon/Operational"
                },
                "EventData": {
                    "SourceImage": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                    "TargetImage": "C:\\WINDOWS\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                    "GrantedAccess": "0x1f3fff",
                    "CallTrace": "C:\\WINDOWS\\SYSTEM32\\ntdll.dll+160844|UNKNOWN(00007FF8E480D033)"
                }
            },
            "product": "windows",
            "category": "process_access"
        });
        let mut event = Event::new(event_json.clone(), event_json, Vec::new());
        event.inject_logsource_fields();
        engine.put_events(vec![event]);
        engine.process_events();
        let alerts = engine.get_alerts();
        assert_eq!(
            alerts.len(),
            1,
            "shellcode injection rule must match CallTrace with UNKNOWN"
        );
    }

    /// Regression: elevated system shell rule must match Sysmon EventID 1 with
    /// User containing 'AUTORI' and LogonId 0x3e7.
    #[test]
    fn test_elevated_system_shell_matches_user_autori() {
        let sigma_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("..")
            .join("sigma");
        let rule_path = sigma_dir.join(
            "rules/windows/process_creation/proc_creation_win_susp_elevated_system_shell_uncommon_parent.yml",
        );
        if !rule_path.exists() {
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        let test_sigma = dir.path().join("sigma");
        let test_rules = test_sigma.join("rules/windows/process_creation");
        fs::create_dir_all(&test_rules).unwrap();
        fs::copy(
            &rule_path,
            test_rules.join("proc_creation_win_susp_elevated_system_shell_uncommon_parent.yml"),
        )
        .unwrap();

        let rules = SigmahqRules::new_from_path(&test_sigma).unwrap();
        let mut engine = DetectionEngine::new(&rules).unwrap();

        let event_json = serde_json::json!({
            "Event": {
                "System": {
                    "Provider": { "#attributes": { "Name": "Microsoft-Windows-Sysmon" } },
                    "EventID": 1,
                    "Channel": "Microsoft-Windows-Sysmon/Operational"
                },
                "EventData": {
                    "Image": "C:\\Windows\\SysWOW64\\cmd.exe",
                    "OriginalFileName": "Cmd.Exe",
                    "CommandLine": "cmd.exe",
                    "CurrentDirectory": "C:\\WINDOWS\\system32\\",
                    "User": "AUTORITE NT\\Système",
                    "LogonId": "0x3e7",
                    "ParentImage": "C:\\Windows\\DOBOsAEp.exe",
                    "ParentCommandLine": "C:\\WINDOWS\\DOBOsAEp.exe"
                }
            },
            "product": "windows",
            "category": "process_creation"
        });
        let mut event = Event::new(event_json.clone(), event_json, Vec::new());
        event.inject_logsource_fields();
        engine.put_events(vec![event]);
        engine.process_events();
        let alerts = engine.get_alerts();
        assert_eq!(
            alerts.len(),
            1,
            "elevated system shell rule must match User with AUTORI"
        );
    }

    /// Regression: registry_event_add_local_hidden_user rule must match
    /// Sysmon EventID 13 with TargetObject containing SAM path and Image
    /// ending with lsass.exe.
    #[test]
    fn test_registry_hidden_user_matches() {
        let sigma_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("..")
            .join("sigma");
        let rule_path = sigma_dir
            .join("rules/windows/registry/registry_event/registry_event_add_local_hidden_user.yml");
        if !rule_path.exists() {
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        let test_sigma = dir.path().join("sigma");
        let test_rules = test_sigma.join("rules/windows/registry/registry_event");
        fs::create_dir_all(&test_rules).unwrap();
        fs::copy(
            &rule_path,
            test_rules.join("registry_event_add_local_hidden_user.yml"),
        )
        .unwrap();

        let rules = SigmahqRules::new_from_path(&test_sigma).unwrap();
        let mut engine = DetectionEngine::new(&rules).unwrap();

        let event_json = serde_json::json!({
            "Event": {
                "System": {
                    "Provider": { "#attributes": { "Name": "Microsoft-Windows-Sysmon" } },
                    "EventID": 13,
                    "Channel": "Microsoft-Windows-Sysmon/Operational"
                },
                "EventData": {
                    "RuleName": "Hidden Local Account Created",
                    "EventType": "SetValue",
                    "Image": "C:\\Windows\\system32\\lsass.exe",
                    "TargetObject": "HKLM\\SAM\\SAM\\Domains\\Account\\Users\\Names\\hideme0007$\\(Default)",
                    "Details": "Binary Data"
                }
            },
            "product": "windows",
            "category": "registry_event"
        });
        let mut event = Event::new(event_json.clone(), event_json, Vec::new());
        event.inject_logsource_fields();
        engine.put_events(vec![event]);
        engine.process_events();
        let alerts = engine.get_alerts();
        assert_eq!(
            alerts.len(),
            1,
            "registry hidden user rule must match Sysmon EventID 13 with SAM path"
        );
    }

    /// Debug: explain why the registry hidden user rule does or doesn't match.
    #[test]
    fn debug_registry_hidden_user_explain() {
        let sigma_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("..")
            .join("sigma");
        let rule_path = sigma_dir
            .join("rules/windows/registry/registry_event/registry_event_add_local_hidden_user.yml");
        if !rule_path.exists() {
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        let test_sigma = dir.path().join("sigma");
        let test_rules = test_sigma.join("rules/windows/registry/registry_event");
        fs::create_dir_all(&test_rules).unwrap();
        fs::copy(
            &rule_path,
            test_rules.join("registry_event_add_local_hidden_user.yml"),
        )
        .unwrap();

        let rules = SigmahqRules::new_from_path(&test_sigma).unwrap();
        let engine = DetectionEngine::new(&rules).unwrap();

        let rule_id = Uuid::parse_str("460479f3-80b7-42da-9c43-2cc1d54dbccd").unwrap();
        let event_json = serde_json::json!({
            "Event": {
                "System": {
                    "Provider": { "#attributes": { "Name": "Microsoft-Windows-Sysmon" } },
                    "EventID": 13,
                    "Channel": "Microsoft-Windows-Sysmon/Operational"
                },
                "EventData": {
                    "RuleName": "Hidden Local Account Created",
                    "EventType": "SetValue",
                    "Image": "C:\\Windows\\system32\\lsass.exe",
                    "TargetObject": "HKLM\\SAM\\SAM\\Domains\\Account\\Users\\Names\\hideme0007$\\(Default)",
                    "Details": "Binary Data"
                }
            },
            "product": "windows",
            "category": "registry_event"
        });
        let mut event = Event::new(event_json.clone(), event_json, Vec::new());
        event.inject_logsource_fields();

        if let Some(explanation) = engine.explain_rule(&rule_id, &event) {
            eprintln!(
                "EXPLAIN: {}",
                serde_json::to_string_pretty(&explanation).unwrap()
            );
        } else {
            eprintln!("EXPLAIN: no explanation available (rule not found in engine)");
        }
    }

    /// Debug: test registry rule WITHOUT bloom filter to isolate the issue.
    #[test]
    fn debug_registry_without_bloom() {
        use rsigma_eval::event::JsonEvent;
        use rsigma_eval::pipeline::parse_pipeline;
        use rsigma_eval::{Engine, LogSourceExtractor};

        let sigma_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("..")
            .join("sigma");
        let rule_path = sigma_dir
            .join("rules/windows/registry/registry_event/registry_event_add_local_hidden_user.yml");
        if !rule_path.exists() {
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        let test_sigma = dir.path().join("sigma");
        let test_rules = test_sigma.join("rules/windows/registry/registry_event");
        fs::create_dir_all(&test_rules).unwrap();
        fs::copy(
            &rule_path,
            test_rules.join("registry_event_add_local_hidden_user.yml"),
        )
        .unwrap();

        let rules = SigmahqRules::new_from_path(&test_sigma).unwrap();

        // Build engine WITHOUT bloom filter
        let win_logsource = parse_pipeline(WIN_LOGSOURCE_PIPELINE).unwrap();
        let win_field = parse_pipeline(WIN_FIELD_PIPELINE).unwrap();
        let lnx_logsource = parse_pipeline(LNX_LOGSOURCE_PIPELINE).unwrap();
        let lnx_field = parse_pipeline(LNX_FIELD_PIPELINE).unwrap();
        let mut engine = Engine::new();
        engine.set_include_event(true);
        engine.set_bloom_prefilter(false); // DISABLE bloom
        engine.set_logsource_extractor(Some(LogSourceExtractor::new()));
        engine.add_pipeline(win_logsource);
        engine.add_pipeline(win_field);
        engine.add_pipeline(lnx_logsource);
        engine.add_pipeline(lnx_field);
        let _errors = engine.add_rules(rules.rules());

        let event_json = serde_json::json!({
            "Event": {
                "System": {
                    "Provider": { "#attributes": { "Name": "Microsoft-Windows-Sysmon" } },
                    "EventID": 13,
                    "Channel": "Microsoft-Windows-Sysmon/Operational"
                },
                "EventData": {
                    "RuleName": "Hidden Local Account Created",
                    "EventType": "SetValue",
                    "Image": "C:\\Windows\\system32\\lsass.exe",
                    "TargetObject": "HKLM\\SAM\\SAM\\Domains\\Account\\Users\\Names\\hideme0007$\\(Default)",
                    "Details": "Binary Data"
                }
            },
            "product": "windows",
            "category": "registry_event"
        });
        let mut event = Event::new(event_json.clone(), event_json, Vec::new());
        event.inject_logsource_fields();
        let json_event = JsonEvent::borrow(&event.event_json);
        let matches = engine.evaluate(&json_event);
        eprintln!("Matches without bloom: {}", matches.len());
        for m in &matches {
            eprintln!("  Rule: {:?}", m.header.rule_id);
        }
        assert_eq!(matches.len(), 1, "must match without bloom filter");
    }

    /// Debug: test registry rule WITH bloom but WITHOUT logsource pruning.
    #[test]
    fn debug_registry_without_logsource_pruning() {
        use rsigma_eval::Engine;
        use rsigma_eval::event::JsonEvent;
        use rsigma_eval::pipeline::parse_pipeline;

        let sigma_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("..")
            .join("sigma");
        let rule_path = sigma_dir
            .join("rules/windows/registry/registry_event/registry_event_add_local_hidden_user.yml");
        if !rule_path.exists() {
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        let test_sigma = dir.path().join("sigma");
        let test_rules = test_sigma.join("rules/windows/registry/registry_event");
        fs::create_dir_all(&test_rules).unwrap();
        fs::copy(
            &rule_path,
            test_rules.join("registry_event_add_local_hidden_user.yml"),
        )
        .unwrap();

        let rules = SigmahqRules::new_from_path(&test_sigma).unwrap();

        let win_logsource = parse_pipeline(WIN_LOGSOURCE_PIPELINE).unwrap();
        let win_field = parse_pipeline(WIN_FIELD_PIPELINE).unwrap();
        let lnx_logsource = parse_pipeline(LNX_LOGSOURCE_PIPELINE).unwrap();
        let lnx_field = parse_pipeline(LNX_FIELD_PIPELINE).unwrap();
        let mut engine = Engine::new();
        engine.set_include_event(true);
        engine.set_bloom_prefilter(true); // bloom ON
        engine.set_logsource_extractor(None); // DISABLE logsource pruning
        engine.add_pipeline(win_logsource);
        engine.add_pipeline(win_field);
        engine.add_pipeline(lnx_logsource);
        engine.add_pipeline(lnx_field);
        let _errors = engine.add_rules(rules.rules());

        let event_json = serde_json::json!({
            "Event": {
                "System": {
                    "Provider": { "#attributes": { "Name": "Microsoft-Windows-Sysmon" } },
                    "EventID": 13,
                    "Channel": "Microsoft-Windows-Sysmon/Operational"
                },
                "EventData": {
                    "RuleName": "Hidden Local Account Created",
                    "EventType": "SetValue",
                    "Image": "C:\\Windows\\system32\\lsass.exe",
                    "TargetObject": "HKLM\\SAM\\SAM\\Domains\\Account\\Users\\Names\\hideme0007$\\(Default)",
                    "Details": "Binary Data"
                }
            },
            "product": "windows",
            "category": "registry_event"
        });
        let mut event = Event::new(event_json.clone(), event_json, Vec::new());
        event.inject_logsource_fields();
        let json_event = JsonEvent::borrow(&event.event_json);
        let matches = engine.evaluate(&json_event);
        eprintln!("Matches without logsource pruning: {}", matches.len());
        for m in &matches {
            eprintln!("  Rule: {:?}", m.header.rule_id);
        }
        assert_eq!(matches.len(), 1, "must match without logsource pruning");
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

    #[test]
    fn test_new_lenient_skips_failing_rules() {
        // Rule with invalid modifier combination (conflicting |contains and |fieldref)
        // This triggers "at most one operator may be set per field" error.
        let bad_rule = r#"title: Bad Rule
id: bbbbbbbb-bbbb-4bbb-9bbb-bbbbbbbbbbbb
status: experimental
level: low
author: Test
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    Image|contains|fieldref: "foo"
  condition: selection
"#;
        let good_rule = r#"title: Good Rule
id: aaaaaaaa-aaaa-4aaa-9aaa-aaaaaaaaaaaa
status: stable
level: low
author: Test
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    Image: "foo"
  condition: selection
"#;

        let dir = tempfile::tempdir().unwrap();
        let sigma_dir = dir.path().join("sigma");
        let rules_dir = sigma_dir.join("rules");
        fs::create_dir_all(&rules_dir).unwrap();
        fs::write(rules_dir.join("bad_rule.yml"), bad_rule).unwrap();
        fs::write(rules_dir.join("good_rule.yml"), good_rule).unwrap();

        let rules = SigmahqRules::new_from_path(&sigma_dir).unwrap();

        // new_lenient should succeed and return the engine plus failed rules
        let (engine, failed) = DetectionEngine::new_lenient(&rules).unwrap();

        // Good rule should be loaded
        assert_eq!(engine.rule_count(), 1);

        // One rule should have failed
        assert_eq!(failed.len(), 1);
        let (idx, _err) = &failed[0];
        // The bad rule is at some index; verify it's captured
        assert!(*idx < rules.len());
    }
}
