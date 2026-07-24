// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 sigmacatch contributors

//! Parse EVTX files into [`Event`] objects for the detection engine.

use anyhow::Result;
use sigmacatch_types::{Event, InputSource};

/// Parse a single EVTX file into a vector of `Event` objects.
pub fn parse_evtx_file(path: &std::path::Path) -> Result<Vec<Event>> {
    let mut parser = evtx::EvtxParser::from_path(path)
        .map_err(|e| anyhow::anyhow!("Failed to open EVTX {}: {}", path.display(), e))?;

    let mut events = Vec::new();

    for record in parser.records() {
        let record = record
            .map_err(|e| anyhow::anyhow!("EVTX record error in {}: {}", path.display(), e))?;
        let event_json = parse_winevt_xml(record.data.as_bytes())?;
        let event_raw = record.data.as_bytes().to_vec();

        let channel = extract_channel(&event_json);

        events.push(Event {
            event_json,
            event_raw,
            input_source: InputSource::EvtxFile,
            channel: Some(channel),
        });
    }

    Ok(events)
}

fn parse_winevt_xml(data: &[u8]) -> Result<serde_json::Value> {
    let xml = std::str::from_utf8(data)
        .map_err(|e| anyhow::anyhow!("Invalid UTF-8 in EVTX record: {}", e))?;

    let doc =
        roxmltree::Document::parse(xml).map_err(|e| anyhow::anyhow!("XML parse error: {}", e))?;

    let root = doc.root();
    let event_node = root
        .descendants()
        .find(|n| n.tag_name().name() == "Event")
        .ok_or_else(|| anyhow::anyhow!("no <Event> element found in EVTX record"))?;

    let mut event_map = serde_json::Map::new();
    for child in event_node.children() {
        if child.is_element() {
            let name = child.tag_name().name().to_string();
            let value = node_to_value(child);
            event_map.insert(name, value);
        }
    }

    let mut result = serde_json::Map::new();
    result.insert("Event".into(), serde_json::Value::Object(event_map));
    result.insert(
        "_source".into(),
        serde_json::Value::String("winevt".to_string()),
    );

    Ok(serde_json::Value::Object(result))
}

fn node_to_value(node: roxmltree::Node) -> serde_json::Value {
    let tag = node.tag_name().name();

    if tag == "EventData" {
        return handle_event_data(node);
    }

    let child_elements: Vec<roxmltree::Node> = node.children().filter(|c| c.is_element()).collect();
    let text = node
        .text()
        .map(|t| t.trim().to_string())
        .filter(|t| !t.is_empty());

    let attrs: Vec<_> = node.attributes().filter(|a| a.name() != "xmlns").collect();

    if child_elements.is_empty() && attrs.is_empty() {
        if let Some(t) = text {
            if let Ok(n) = t.parse::<u64>() {
                return serde_json::Value::Number(n.into());
            }
            return serde_json::Value::String(t);
        }
    }

    if child_elements.is_empty() && !attrs.is_empty() && text.is_none() {
        let mut attr_map = serde_json::Map::new();
        for a in attrs {
            attr_map.insert(
                a.name().to_string(),
                serde_json::Value::String(a.value().to_string()),
            );
        }
        return serde_json::Value::Object({
            let mut m = serde_json::Map::new();
            m.insert("#attributes".into(), serde_json::Value::Object(attr_map));
            m
        });
    }

    if child_elements.is_empty() && attrs.is_empty() && text.is_none() {
        return serde_json::Value::Object(serde_json::Map::new());
    }

    let mut map = serde_json::Map::new();

    if !attrs.is_empty() {
        let mut attr_map = serde_json::Map::new();
        for a in attrs {
            attr_map.insert(
                a.name().to_string(),
                serde_json::Value::String(a.value().to_string()),
            );
        }
        map.insert("#attributes".into(), serde_json::Value::Object(attr_map));
    }

    for child in &child_elements {
        let child_name = child.tag_name().name().to_string();
        let child_value = node_to_value(*child);
        map.insert(child_name, child_value);
    }

    if let Some(t) = text {
        if !map.contains_key("#text") {
            map.insert("#text".into(), serde_json::Value::String(t));
        }
    }

    serde_json::Value::Object(map)
}

fn handle_event_data(node: roxmltree::Node) -> serde_json::Value {
    let mut map = serde_json::Map::new();
    for child in node.children() {
        if child.is_element() && child.tag_name().name() == "Data" {
            let name = child.attribute("Name").unwrap_or("");
            if !name.is_empty() {
                let value = child
                    .text()
                    .map(|t| t.trim().to_string())
                    .unwrap_or_default();
                map.insert(name.to_string(), serde_json::Value::String(value));
            }
        }
    }
    serde_json::Value::Object(map)
}

fn extract_channel(event_json: &serde_json::Value) -> String {
    event_json
        .get("Event")
        .and_then(|v| v.get("System"))
        .and_then(|v| v.get("Channel"))
        .and_then(|v| v.as_str())
        .or_else(|| event_json.get("Channel").and_then(|v| v.as_str()))
        .unwrap_or("")
        .to_string()
}
