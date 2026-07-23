use anyhow::Result;
use serde_json::Value;
use std::collections::{HashMap, HashSet};
use std::path::Path;
use tracing::info;

use sigmacatch_types::{Alert, Event};

use crate::config::SigmaFilterConfig;
use crate::sigma::engine::SigmaEngine;
use crate::sigma::loader::find_rules_dirs;
use crate::sigma::mapping::{build_logsource_to_channels, resolve_logsource};

/// Loads and filters Sigma rules into a configured SigmaEngine.
pub struct RuleLoader;

impl RuleLoader {
    /// Load all rules from the given repository path into a new SigmaEngine.
    /// Applies filter (status/level) and skip set during loading.
    pub fn load(
        sigma_repo_path: &Path,
        filter: &SigmaFilterConfig,
        skip_set: &HashSet<String>,
    ) -> Result<SigmaEngine> {
        let rules_dirs = find_rules_dirs(sigma_repo_path)?;
        let dir_refs: Vec<&Path> = rules_dirs.iter().map(|d| d.as_path()).collect();
        let mut engine = SigmaEngine::default();
        let count = engine.load_rules_from_dirs(&dir_refs, skip_set, filter)?;
        info!("RuleLoader: {} rules loaded into engine", count);
        Ok(engine)
    }

    /// Resolve the list of Windows Event Log channels needed by the loaded rules.
    pub fn resolve_channels(
        engine: &SigmaEngine,
        custom_map: &HashMap<String, String>,
    ) -> Vec<String> {
        let map = build_logsource_to_channels(custom_map);

        let mut channels_set: HashSet<String> = engine
            .active_services()
            .iter()
            .filter_map(|service| map.get(service.as_str()))
            .flat_map(|targets| targets.iter().map(|t| t.channel.to_string()))
            .collect();

        for category in engine.active_categories() {
            for service in engine.active_services() {
                let composite = format!("{}:{}", service, category);
                if let Some(targets) = map.get(composite.as_str()) {
                    for t in targets {
                        channels_set.insert(t.channel.to_string());
                    }
                }
            }
        }

        let mut channels: Vec<String> = channels_set.into_iter().collect();
        channels.sort();

        let mut active: Vec<&str> = engine
            .active_services()
            .iter()
            .map(|s| s.as_str())
            .collect();
        active.sort();
        info!("Active services: {:?}", active);

        let mut active_cats: Vec<&str> = engine
            .active_categories()
            .iter()
            .map(|s| s.as_str())
            .collect();
        active_cats.sort();
        info!("Active categories: {:?}", active_cats);

        let skipped: Vec<&str> = engine
            .all_services()
            .difference(engine.active_services())
            .map(|s| s.as_str())
            .collect();
        if !skipped.is_empty() {
            info!("Skipped services: {:?} (all rules skipped)", skipped);
        }

        let skipped_cats: Vec<&str> = engine
            .all_categories()
            .difference(engine.active_categories())
            .map(|s| s.as_str())
            .collect();
        if !skipped_cats.is_empty() {
            info!("Skipped categories: {:?} (all rules skipped)", skipped_cats);
        }

        if channels.is_empty() {
            info!("No channels resolved for active services/categories");
        } else {
            info!(
                "Resolved {} channel(s) from rules: {:?}",
                channels.len(),
                channels
            );
        }

        channels
    }
}

/// High-level detection engine: parses an Event, resolves logsource internally,
/// evaluates against loaded Sigma rules, and returns Alerts.
pub struct SigmaDetectionEngine<'a> {
    engine: &'a SigmaEngine,
    custom_map: &'a HashMap<String, String>,
}

impl<'a> SigmaDetectionEngine<'a> {
    pub fn new(engine: &'a SigmaEngine, custom_map: &'a HashMap<String, String>) -> Self {
        Self { engine, custom_map }
    }

    /// Number of rules loaded in the engine.
    pub fn rules_count(&self) -> usize {
        self.engine.rules_count()
    }

    /// Evaluate a single Event against all loaded rules.
    /// Extracts channel, provider, and event_id from event_json for logsource resolution.
    pub fn evaluate(&self, event: &Event) -> Vec<Alert> {
        let channel = extract_channel(&event.event_json).unwrap_or("");
        let provider = extract_provider(&event.event_json).unwrap_or("");
        let event_id = extract_event_id(&event.event_json);
        let logsource = resolve_logsource(channel, provider, event_id, self.custom_map);
        let results = self
            .engine
            .evaluate_event_with_logsource(&event.event_json, &logsource);

        results
            .into_iter()
            .map(|r| Alert::from_evaluation_result(r, event))
            .collect()
    }
}

fn extract_channel(json: &Value) -> Option<&str> {
    json.get("Event")?.get("System")?.get("Channel")?.as_str()
}

fn extract_provider(json: &Value) -> Option<&str> {
    json.get("Event")?
        .get("System")?
        .get("Provider")?
        .get("#attributes")?
        .get("Name")?
        .as_str()
}

fn extract_event_id(json: &Value) -> u32 {
    json.get("Event")
        .and_then(|v| v.get("System"))
        .and_then(|v| v.get("EventID"))
        .and_then(|v| v.as_u64())
        .unwrap_or(0) as u32
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn sample_event_json() -> Value {
        json!({
            "Event": {
                "System": {
                    "EventID": 1,
                    "Channel": "Microsoft-Windows-Sysmon/Operational",
                    "Provider": {
                        "#attributes": {
                            "Name": "Microsoft-Windows-Sysmon",
                            "Guid": "{5770385f-c22a-43e0-bf4c-06f5698ffbd9}"
                        }
                    }
                },
                "EventData": {}
            },
            "_source": "winevt"
        })
    }

    #[test]
    fn test_extract_channel() {
        let json = sample_event_json();
        assert_eq!(
            extract_channel(&json),
            Some("Microsoft-Windows-Sysmon/Operational")
        );
    }

    #[test]
    fn test_extract_provider() {
        let json = sample_event_json();
        assert_eq!(extract_provider(&json), Some("Microsoft-Windows-Sysmon"));
    }

    #[test]
    fn test_extract_event_id() {
        let json = sample_event_json();
        assert_eq!(extract_event_id(&json), 1);
    }

    #[test]
    fn test_extract_missing() {
        let empty = json!({});
        assert_eq!(extract_channel(&empty), None);
        assert_eq!(extract_provider(&empty), None);
        assert_eq!(extract_event_id(&empty), 0);
    }
}
