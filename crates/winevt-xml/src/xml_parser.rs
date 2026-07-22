// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 sigmacatch contributors

use roxmltree::Node;
use serde_json::{Map, Value};
use std::fmt;

/// Parse a Winevt XML string into nested JSON.
pub fn parse_winevt_xml(xml: &str) -> Result<Value, ParseError> {
    let doc = roxmltree::Document::parse(xml).map_err(|e| ParseError {
        message: format!("XML parse error: {}", e),
    })?;

    let root = doc.root();
    let event = root
        .descendants()
        .find(|n| n.tag_name().name() == "Event")
        .ok_or_else(|| ParseError {
            message: "no <Event> element found in XML".to_string(),
        })?;

    let mut event_map = Map::new();
    for child in event.children() {
        if child.is_element() {
            let name = child.tag_name().name().to_string();
            let value = node_to_value(child, true);
            event_map.insert(name, value);
        }
    }

    let mut result = Map::new();
    result.insert("Event".into(), Value::Object(event_map));
    result.insert("_source".into(), Value::String("winevt".to_string()));

    Ok(Value::Object(result))
}

fn node_to_value(node: Node, _is_root: bool) -> Value {
    let tag = node.tag_name().name();

    if tag == "EventData" {
        return handle_event_data(node);
    }

    let child_elements: Vec<Node> = node.children().filter(|c| c.is_element()).collect();
    let text = node
        .text()
        .map(|t| t.trim().to_string())
        .filter(|t| !t.is_empty());

    let attrs: Vec<_> = node.attributes().filter(|a| a.name() != "xmlns").collect();

    if child_elements.is_empty() && attrs.is_empty() {
        if let Some(t) = text {
            if let Ok(n) = t.parse::<u64>() {
                return Value::Number(n.into());
            }
            return Value::String(t);
        }
    }

    if child_elements.is_empty() && !attrs.is_empty() && text.is_none() {
        let mut attr_map = Map::new();
        for a in attrs {
            attr_map.insert(a.name().to_string(), Value::String(a.value().to_string()));
        }
        return Value::Object({
            let mut m = Map::new();
            m.insert("#attributes".into(), Value::Object(attr_map));
            m
        });
    }

    if child_elements.is_empty() && attrs.is_empty() && text.is_none() {
        return Value::Object(Map::new());
    }

    let mut map = Map::new();

    if !attrs.is_empty() {
        let mut attr_map = Map::new();
        for a in attrs {
            attr_map.insert(a.name().to_string(), Value::String(a.value().to_string()));
        }
        map.insert("#attributes".into(), Value::Object(attr_map));
    }

    for child in &child_elements {
        let child_name = child.tag_name().name().to_string();
        let child_value = node_to_value(*child, false);
        map.insert(child_name, child_value);
    }

    if let Some(t) = text {
        if !map.contains_key("#text") {
            map.insert("#text".into(), Value::String(t));
        }
    }

    Value::Object(map)
}

fn handle_event_data(node: Node) -> Value {
    let mut map = Map::new();
    for child in node.children() {
        if child.is_element() && child.tag_name().name() == "Data" {
            let name = child.attribute("Name").unwrap_or("");
            if !name.is_empty() {
                let value = child
                    .text()
                    .map(|t| t.trim().to_string())
                    .unwrap_or_default();
                map.insert(name.to_string(), Value::String(value));
            }
        }
    }
    Value::Object(map)
}

#[derive(Debug, Clone)]
pub struct ParseError {
    pub message: String,
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl std::error::Error for ParseError {}

/// Validate and coerce EventID to integer in a nested event JSON.
///
/// The evtx crate and some Winevt paths may produce `Event.System.EventID` as
/// a string (`"1"`) instead of a number (`1`). The `windows.yml` pipeline
/// injects integer conditions (`Event.System.EventID: 13`), so a string
/// value silently fails the match. This function coerces the field to a
/// number when possible, and returns the original value unchanged otherwise.
pub fn validate_event_id(event: &Value) -> Value {
    let Some(obj) = event.as_object() else {
        return event.clone();
    };

    let mut result = obj.clone();

    if let Some(Value::Object(event_inner)) = result.get("Event").cloned() {
        if let Some(Value::Object(system)) = event_inner.get("System").cloned() {
            if let Some(Value::String(s)) = system.get("EventID") {
                if let Ok(n) = s.parse::<u64>() {
                    let mut new_system = system;
                    new_system.insert("EventID".into(), Value::Number(n.into()));
                    let mut new_event_inner = event_inner;
                    new_event_inner.insert("System".into(), Value::Object(new_system));
                    result.insert("Event".into(), Value::Object(new_event_inner));
                }
            }
        }
    }

    Value::Object(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_sysmon_process() {
        let xml = r#"<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
            <System>
                <Provider Name="Microsoft-Windows-Sysmon" Guid="{guid}"/>
                <EventID>1</EventID>
                <TimeCreated SystemTime="2024-01-01T00:00:00.0000000Z"/>
                <Channel>Microsoft-Windows-Sysmon/Operational</Channel>
                <EventRecordID>1788</EventRecordID>
            </System>
            <EventData>
                <Data Name="Image">C:\\Windows\\System32\\cmd.exe</Data>
                <Data Name="CommandLine">cmd /c whoami</Data>
                <Data Name="User">DOMAIN\\user</Data>
            </EventData>
        </Event>"#;

        let result = parse_winevt_xml(xml).unwrap();
        let event = result.as_object().unwrap();

        assert_eq!(event["_source"].as_str().unwrap(), "winevt");
        assert!(!event.contains_key("_raw_xml"));

        let system = event["Event"]["System"].as_object().unwrap();
        assert_eq!(system["EventID"].as_u64().unwrap(), 1);

        let provider = system["Provider"].as_object().unwrap();
        let attrs = provider["#attributes"].as_object().unwrap();
        assert_eq!(attrs["Name"].as_str().unwrap(), "Microsoft-Windows-Sysmon");

        let event_data = event["Event"]["EventData"].as_object().unwrap();
        assert_eq!(event_data["CommandLine"].as_str().unwrap(), "cmd /c whoami");
        assert_eq!(
            event_data["Image"].as_str().unwrap(),
            r"C:\\Windows\\System32\\cmd.exe"
        );
    }

    #[test]
    fn test_parse_security_event() {
        let xml = r#"<Event Channel="Security">
            <System>
                <Provider Name="Microsoft-Windows-Security-Auditing"/>
                <EventID>4624</EventID>
                <Channel>Security</Channel>
            </System>
            <EventData>
                <Data Name="TargetUserName">admin</Data>
                <Data Name="TargetDomainName">WORKGROUP</Data>
            </EventData>
        </Event>"#;

        let result = parse_winevt_xml(xml).unwrap();
        let event_data = result["Event"]["EventData"].as_object().unwrap();
        assert_eq!(event_data["TargetUserName"].as_str().unwrap(), "admin");
    }

    #[test]
    fn test_validate_event_id_string_to_number() {
        let json = serde_json::json!({
            "Event": {
                "System": {
                    "EventID": "13",
                    "Channel": "Security"
                }
            },
            "_source": "winevt"
        });
        let result = validate_event_id(&json);
        assert_eq!(result["Event"]["System"]["EventID"].as_u64(), Some(13));
    }

    #[test]
    fn test_validate_event_id_already_number() {
        let json = serde_json::json!({
            "Event": {
                "System": {
                    "EventID": 13,
                    "Channel": "Security"
                }
            },
            "_source": "winevt"
        });
        let result = validate_event_id(&json);
        assert_eq!(result["Event"]["System"]["EventID"].as_u64(), Some(13));
    }
}
