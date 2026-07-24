// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 sigmacatch contributors

//! Shared types for all sigmacatch crates and binaries.
//!
//! - [`Event`] — parsed event JSON + raw source bytes (input to the detection engine)
//! - [`Alert`] — a rule match produced by the detection engine (output)
//! - [`RegressionHeader`] — minimal rule metadata for regression data generation

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

    pub fn channel(&self) -> &str {
        self.event_json
            .get("Event")
            .and_then(|v| v.get("System"))
            .and_then(|v| v.get("Channel"))
            .and_then(|v| v.as_str())
            .or_else(|| self.event_json.get("Channel").and_then(|v| v.as_str()))
            .unwrap_or("")
    }

    pub fn record_id(&self) -> Option<u64> {
        self.event_json
            .get("EventRecordID_num")
            .and_then(|v| v.as_u64())
    }

    pub fn provider(&self) -> &str {
        self.event_json
            .get("Event")
            .and_then(|v| v.get("System"))
            .and_then(|v| v.get("Provider"))
            .and_then(|v| v.get("#attributes"))
            .and_then(|v| v.get("Name"))
            .and_then(|v| v.as_str())
            .unwrap_or("")
    }

    pub fn raw_xml(&self) -> &str {
        std::str::from_utf8(&self.event_raw).unwrap_or("")
    }
}

/// Minimal rule metadata required for regression data generation.
///
/// Decouples the regression data format from `rsigma_eval::result::RuleHeader`.
/// Evolutive — add fields here without touching rsigma internals.
#[derive(Debug, Clone)]
pub struct RegressionHeader {
    pub rule_id: String,
    pub rule_title: String,
}

impl RegressionHeader {
    pub fn new(rule_id: String, rule_title: String) -> Self {
        Self {
            rule_id,
            rule_title,
        }
    }
}

impl From<Alert> for RegressionHeader {
    fn from(a: Alert) -> Self {
        Self {
            rule_id: a.rule_id,
            rule_title: a.rule_title,
        }
    }
}

impl From<rsigma_eval::result::RuleHeader> for RegressionHeader {
    fn from(h: rsigma_eval::result::RuleHeader) -> Self {
        Self {
            rule_id: h.rule_id.unwrap_or_else(|| "unknown".to_string()),
            rule_title: h.rule_title,
        }
    }
}
