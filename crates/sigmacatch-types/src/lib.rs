// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 sigmacatch contributors

//! Shared types for all sigmacatch crates and binaries.
//!
//! - [`Event`] — parsed event JSON + raw source bytes (input to the detection engine)
//! - [`Alert`] — a rule match produced by the detection engine (output)

use serde_json::Value;

/// A generic event for the detection engine: parsed JSON + raw source bytes.
/// Evolutive — the raw source can be XML, EVTX binary, etc.
#[derive(Debug, Clone)]
pub struct Event {
    pub event_json: Value,
    pub event_raw: Vec<u8>,
}

impl Event {
    pub fn new(event_json: Value, event_raw: Vec<u8>) -> Self {
        Self {
            event_json,
            event_raw,
        }
    }
}

/// An alert produced when an event matches a Sigma rule.
#[derive(Debug, Clone)]
pub struct Alert {
    pub rule_id: String,
    pub rule_title: String,
    pub severity: String,
    pub event_json: Value,
    pub event_raw: Vec<u8>,
}

impl Alert {
    pub fn new(rule_id: String, severity: String, event: &Event) -> Self {
        Self {
            rule_id: rule_id.clone(),
            rule_title: rule_id,
            severity,
            event_json: event.event_json.clone(),
            event_raw: event.event_raw.clone(),
        }
    }

    pub fn from_evaluation_result(r: rsigma_eval::EvaluationResult, event: &Event) -> Self {
        Self {
            rule_id: r
                .header
                .rule_id
                .clone()
                .unwrap_or_else(|| "unknown".to_string()),
            rule_title: r.header.rule_title.clone(),
            severity: r
                .header
                .level
                .as_ref()
                .map(|l| format!("{:?}", l))
                .unwrap_or_else(|| "unknown".to_string()),
            event_json: event.event_json.clone(),
            event_raw: event.event_raw.clone(),
        }
    }
}
