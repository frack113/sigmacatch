// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 sigmacatch contributors

//! Linux auditd line parser used by the regression validator and shared with
//! the rest of the workspace.
//!
//! Converts raw `auditd` log lines (one event per line) into `Event` values
//! carrying the same fields and logsource injection as the live
//! `sigmacatch-input-auditd` collector.

use serde_json::{Map, Value as JsonValue};

use crate::types::Event;

/// Parse raw auditd lines and return the resulting events plus a dropped-line
/// count. Mirrors the encoding used by the live auditd tail collector so
/// regression data round-trips through the same pipeline.
pub fn parse_auditd_lines(raw: &[u8]) -> (Vec<Event>, usize) {
    use linux_audit_parser::Parser;

    let parser = Parser {
        enriched: true,
        split_msg: false,
    };

    let mut dropped = 0usize;
    let mut chunks: Vec<&[u8]> = Vec::new();
    let mut start = 0;
    for (i, &b) in raw.iter().enumerate() {
        if b == b'\n' {
            chunks.push(&raw[start..=i]);
            start = i + 1;
        }
    }
    if start < raw.len() {
        chunks.push(&raw[start..]);
    }
    let events: Vec<Event> = chunks
        .iter()
        .copied()
        .filter(|line| !line.is_empty())
        .filter_map(|line| {
            let message = match parser.parse(line) {
                Ok(m) => m,
                Err(_) => {
                    dropped += 1;
                    return None;
                }
            };
            let mut flat = Map::new();
            for (key, value) in &message.body {
                if let Some(json) = value_to_json(value) {
                    flat.insert(key.to_string(), json);
                }
            }
            let json_raw = serde_json::json!({
                "stamp": { "timestamp": message.id.timestamp, "sequence": message.id.sequence },
                "type": message.ty.to_string(),
                "fields": flat.clone(),
            });
            flat.insert("type".into(), JsonValue::String(message.ty.to_string()));
            flat.insert("provider".into(), JsonValue::String("auditd".into()));
            flat.insert("product".into(), JsonValue::String("linux".into()));
            flat.insert("service".into(), JsonValue::String("auditd".into()));
            let mut event = Event::new(json_raw, JsonValue::Object(flat), line.to_vec());
            event.inject_logsource_fields_for("linux", Some("auditd"));
            Some(event)
        })
        .collect();
    (events, dropped)
}

/// Convert a `linux-audit-parser` value into a JSON value, skipping types that
/// cannot be represented usefully.
pub fn value_to_json(value: &linux_audit_parser::Value<'_>) -> Option<JsonValue> {
    use linux_audit_parser::Value as AuditValue;
    match value {
        AuditValue::Empty => Some(JsonValue::String(String::new())),
        AuditValue::Str(bytes, _) => Some(JsonValue::String(
            String::from_utf8_lossy(bytes).into_owned(),
        )),
        AuditValue::Owned(bytes) => Some(JsonValue::String(
            String::from_utf8_lossy(bytes.as_slice()).into_owned(),
        )),
        AuditValue::Number(n) => Some(JsonValue::String(n.to_string())),
        AuditValue::List(items) | AuditValue::StringifiedList(items) => {
            let arr: Vec<JsonValue> = items.iter().filter_map(value_to_json).collect();
            if arr.is_empty() {
                None
            } else {
                Some(JsonValue::Array(arr))
            }
        }
        AuditValue::Map(pairs) => {
            let mut map = Map::new();
            for (k, v) in pairs {
                if let Some(json) = value_to_json(v) {
                    map.insert(k.to_string(), json);
                }
            }
            if map.is_empty() {
                None
            } else {
                Some(JsonValue::Object(map))
            }
        }
        AuditValue::Literal(s) => Some(JsonValue::String((*s).to_string())),
        AuditValue::Segments(_) | AuditValue::Skipped(_) => None,
    }
}
