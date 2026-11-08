// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 sigmacatch contributors

//! `EventID` carrying a `Qualifiers` attribute still matches `EventID: <n>`.
//!
//! Classic providers (Service Control Manager, most Application sources)
//! render `<EventID Qualifiers="16384">7045</EventID>`. The detection view
//! used to keep that element as `{"#attributes": {...}, "#text": "7045"}`, so
//! `EventID: 7045` never matched and every `service: system` rule was dead.
//! The record below is a real System 7045 event (Windows Server 2025).

use std::fs;

use sigmacatch::detection::DetectionEngine;
use sigmacatch::rule::SigmahqRules;
use sigmacatch::types::Event;

const SERVICE_INSTALL_7045: &str = r#"<?xml version="1.0" encoding="utf-8"?>
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Service Control Manager" Guid="{555908d1-a6d7-4695-8e1e-26931d2012f4}" EventSourceName="Service Control Manager"/>
    <EventID Qualifiers="16384">7045</EventID>
    <Version>0</Version>
    <Level>4</Level>
    <Task>0</Task>
    <Opcode>0</Opcode>
    <Keywords>0x8080000000000000</Keywords>
    <TimeCreated SystemTime="2026-11-06T07:56:39.9532654Z"/>
    <EventRecordID>1207</EventRecordID>
    <Correlation/>
    <Execution ProcessID="744" ThreadID="5056"/>
    <Channel>System</Channel>
    <Computer>WSUS01.lab.local</Computer>
    <Security UserID="S-1-5-21-3499606684-2646096717-57156353-500"/>
  </System>
  <EventData>
    <Data Name="ServiceName">Sliver</Data>
    <Data Name="ImagePath">C:\lab\sim\x.exe</Data>
    <Data Name="ServiceType">user mode service</Data>
    <Data Name="StartType">demand start</Data>
    <Data Name="AccountName">LocalSystem</Data>
  </EventData>
</Event>"#;

/// Shape of `win_system_service_install_sliver.yml` (SigmaHQ).
const SERVICE_INSTALL_RULE: &str = r#"title: Service Installation Probe
id: cccccccc-cccc-4ccc-9ccc-cccccccccccc
status: experimental
level: high
author: Test
logsource:
    product: windows
    service: system
detection:
    selection_eid:
        Provider_Name: 'Service Control Manager'
        EventID: 7045
    selection_service:
        ServiceName: 'Sliver'
    condition: all of selection_*
"#;

#[test]
fn qualified_event_id_is_numeric_in_detection_view() {
    let event = Event::from_xml_injected(SERVICE_INSTALL_7045, "windows", None).unwrap();
    assert_eq!(
        event.event_json.pointer("/Event/System/EventID"),
        Some(&serde_json::json!(7045))
    );
    // The raw view (regression data) keeps the qualifier.
    assert_eq!(
        event
            .event_json_raw
            .pointer("/Event/System/EventID/#attributes/Qualifiers"),
        Some(&serde_json::json!(16384))
    );
}

#[test]
fn qualified_event_id_matches_rule() {
    let dir = tempfile::tempdir().unwrap();
    let rules_dir = dir.path().join("sigma").join("rules");
    fs::create_dir_all(&rules_dir).unwrap();
    fs::write(rules_dir.join("rule.yml"), SERVICE_INSTALL_RULE).unwrap();
    let rules = SigmahqRules::new_from_path(&dir.path().join("sigma")).unwrap();
    let mut engine = DetectionEngine::new(&rules).unwrap();

    let event = Event::from_xml_injected(SERVICE_INSTALL_7045, "windows", None).unwrap();
    engine.put_events(vec![event]);
    engine.process_events();
    assert_eq!(engine.get_alerts().len(), 1);
}
