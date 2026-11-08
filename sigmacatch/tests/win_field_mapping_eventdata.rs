// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 sigmacatch contributors

//! Security `EventData` fields used by SigmaHQ rules resolve through the
//! Windows field-name pipeline.
//!
//! `2_win_field_name.yml` maps each flat Sigma field name onto its nested
//! `Event.EventData.*` path. A field missing from that list stays flat, so a
//! rule selecting on it can never match a Winevt event and nothing reports it.
//! `OperationType` (5136), `Entry` (4891) and `Attributes` (4886/4887) were
//! missing. Each test below fails without its mapping.

use std::fs;

use serde_json::{Value, json};
use sigmacatch::detection::DetectionEngine;
use sigmacatch::rule::SigmahqRules;
use sigmacatch::types::Event;

/// Build a one-rule engine for a `service: security` rule whose detection
/// block is `detection` (YAML, 4-space indented under `detection:`).
fn engine(detection: &str) -> DetectionEngine {
    let rule = format!(
        "title: Field Mapping Probe\n\
         id: bbbbbbbb-bbbb-4bbb-9bbb-bbbbbbbbbbbb\n\
         status: experimental\n\
         level: medium\n\
         author: Test\n\
         logsource:\n\
         \x20   product: windows\n\
         \x20   service: security\n\
         detection:\n{detection}"
    );
    let dir = tempfile::tempdir().unwrap();
    let rules_dir = dir.path().join("sigma").join("rules");
    fs::create_dir_all(&rules_dir).unwrap();
    fs::write(rules_dir.join("rule.yml"), rule).unwrap();
    let rules = SigmahqRules::new_from_path(&dir.path().join("sigma")).unwrap();
    assert_eq!(rules.rules().len(), 1);
    DetectionEngine::new(&rules).unwrap()
}

/// Count the alerts `detection` raises on a Security event.
fn alerts(detection: &str, event_id: u64, event_data: Value) -> usize {
    let mut event = Event::new(
        json!({}),
        json!({
            "Event": {
                "System": { "EventID": event_id, "Channel": "Security" },
                "EventData": event_data
            }
        }),
        Vec::new(),
    );
    event.inject_logsource_fields_for("windows", Some("security"));
    let mut engine = engine(detection);
    engine.put_events(vec![event]);
    engine.process_events();
    engine.get_alerts().len()
}

#[test]
fn operation_type_resolves() {
    let detection = "    selection:\n        EventID: 5136\n        OperationType: '%%14674'\n    condition: selection\n";
    let data = json!({
        "AttributeLDAPDisplayName": "altSecurityIdentities",
        "OperationType": "%%14674"
    });
    assert_eq!(alerts(detection, 5136, data), 1);
}

#[test]
fn entry_resolves() {
    let detection = "    selection:\n        EventID: 4891\n        Entry: 'Security'\n    condition: selection\n";
    assert_eq!(alerts(detection, 4891, json!({ "Entry": "Security" })), 1);
}

#[test]
fn attributes_resolves() {
    let detection = "    selection:\n        EventID: 4886\n        Attributes|contains: 'cdc:'\n    condition: selection\n";
    let data = json!({
        "RequestId": "2",
        "Attributes": "\ncdc:DC01.lab.local\nrmd:DC01.lab.local\n\nccm:DC01.lab.local"
    });
    assert_eq!(alerts(detection, 4886, data), 1);
}
