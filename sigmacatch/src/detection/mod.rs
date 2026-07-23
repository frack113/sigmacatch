use serde_json::Value;
use std::collections::HashMap;

use sigmacatch_types::{Alert, Event};

use crate::sigma::engine::SigmaEngine;
use crate::sigma::mapping::resolve_logsource;

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
