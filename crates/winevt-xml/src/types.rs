use serde_json::Value;

/// Captures a single Windows Event Log event: raw XML, parsed JSON, and
/// channel/event_id metadata extracted at collection time.
///
/// `event_json` is `Some(...)` when XML parsing succeeds, `None` when it
/// fails (the raw XML is preserved either way).
#[derive(Debug, Clone)]
pub struct WinevtEvent {
    pub channel: String,
    pub event_id: u32,
    pub raw_xml: String,
    pub event_json: Option<Value>,
}

impl WinevtEvent {
    pub fn from_json(json: Value, raw_xml: String) -> Self {
        let event_id = json
            .get("EventID_num")
            .and_then(|v| v.as_u64())
            .unwrap_or(0) as u32;
        let channel = json
            .get("Channel")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        Self {
            event_id,
            channel,
            raw_xml,
            event_json: Some(json),
        }
    }
}
