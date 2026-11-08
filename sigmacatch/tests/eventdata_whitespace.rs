// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 sigmacatch contributors

//! EventData values reach the matcher verbatim, whitespace included.
//!
//! The detection view used to trim every `<Data>` value. A real
//! `CommandLine` ending with a space then matched `|endswith` rules that the
//! SigmaHQ checker (which reads the EVTX verbatim) does not match, so the
//! regression set sigmacatch wrote was rejected in CI. The record below is a
//! real Sysmon EID 1 event (Windows Server 2025), trailing space included.

use std::fs;

use sigmacatch::detection::DetectionEngine;
use sigmacatch::rule::SigmahqRules;
use sigmacatch::types::Event;

const PROCESS_CREATE_TRAILING_SPACE: &str = r#"<?xml version="1.0" encoding="utf-8"?>
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Sysmon" Guid="{5770385f-c22a-43e0-bf4c-06f5698ffbd9}"/>
    <EventID>1</EventID>
    <Version>5</Version>
    <Level>4</Level>
    <Task>1</Task>
    <Opcode>0</Opcode>
    <Keywords>0x8000000000000000</Keywords>
    <TimeCreated SystemTime="2026-11-06T07:53:23.6764905Z"/>
    <EventRecordID>114387</EventRecordID>
    <Correlation/>
    <Execution ProcessID="2828" ThreadID="3464"/>
    <Channel>Microsoft-Windows-Sysmon/Operational</Channel>
    <Computer>WSUS01.lab.local</Computer>
    <Security UserID="S-1-5-18"/>
  </System>
  <EventData>
    <Data Name="RuleName">-</Data>
    <Data Name="UtcTime">2026-11-06 07:53:23.653</Data>
    <Data Name="ProcessGuid">{6e0ebb69-8773-6aed-1901-000000000400}</Data>
    <Data Name="ProcessId">5772</Data>
    <Data Name="Image">C:\lab\sim\TeamViewer_Desktop.exe</Data>
    <Data Name="FileVersion">10.0.26100.1882 (WinBuild.160101.0800)</Data>
    <Data Name="Description">whoami - displays logged on user information</Data>
    <Data Name="Product">Microsoft® Windows® Operating System</Data>
    <Data Name="Company">Microsoft Corporation</Data>
    <Data Name="OriginalFileName">whoami.exe</Data>
    <Data Name="CommandLine">C:\lab\sim\TeamViewer_Desktop.exe  --IPCport 5939 --Module 1 </Data>
    <Data Name="CurrentDirectory">C:\Windows\System32\WindowsPowerShell\v1.0\</Data>
    <Data Name="User">WSUS01\Administrator</Data>
    <Data Name="LogonGuid">{6e0ebb69-8646-6aed-85b8-070100000000}</Data>
    <Data Name="LogonId">0x107b885</Data>
    <Data Name="TerminalSessionId">1</Data>
    <Data Name="IntegrityLevel">High</Data>
    <Data Name="Hashes">SHA256=23240EF9F8B0A9A324110B1C2331DE31DC1B0E08F5359CB707E51A939AF56CD3</Data>
    <Data Name="ParentProcessGuid">{6e0ebb69-8773-6aed-1701-000000000400}</Data>
    <Data Name="ParentProcessId">900</Data>
    <Data Name="ParentImage">C:\lab\sim\TeamViewer_Service.exe</Data>
    <Data Name="ParentCommandLine">"C:\lab\sim\TeamViewer_Service.exe" /c C:\lab\sim\TeamViewer_Desktop.exe --IPCport 5939 --Module 1 </Data>
    <Data Name="ParentUser">WSUS01\Administrator</Data>
  </EventData>
</Event>"#;

const COMMAND_LINE: &str = r"C:\lab\sim\TeamViewer_Desktop.exe  --IPCport 5939 --Module 1 ";

/// Shape of `proc_creation_win_remote_access_tools_teamviewer_incoming_connection.yml`.
const ENDSWITH_RULE: &str = r#"title: Endswith Probe
id: dddddddd-dddd-4ddd-9ddd-dddddddddddd
status: experimental
level: low
author: Test
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\TeamViewer_Desktop.exe'
        ParentImage|endswith: '\TeamViewer_Service.exe'
        CommandLine|endswith: ' --IPCport 5939 --Module 1'
    condition: selection
"#;

#[test]
fn eventdata_keeps_trailing_whitespace() {
    let event = Event::from_xml_injected(PROCESS_CREATE_TRAILING_SPACE, "windows", None).unwrap();
    let detection = event.event_json.pointer("/Event/EventData/CommandLine");
    assert_eq!(detection.and_then(|v| v.as_str()), Some(COMMAND_LINE));
    let raw = event.event_json_raw.pointer("/Event/EventData/CommandLine");
    assert_eq!(raw.and_then(|v| v.as_str()), Some(COMMAND_LINE));
}

#[test]
fn endswith_does_not_match_value_with_trailing_space() {
    let dir = tempfile::tempdir().unwrap();
    let rules_dir = dir.path().join("sigma").join("rules");
    fs::create_dir_all(&rules_dir).unwrap();
    fs::write(rules_dir.join("rule.yml"), ENDSWITH_RULE).unwrap();
    let rules = SigmahqRules::new_from_path(&dir.path().join("sigma")).unwrap();
    let mut engine = DetectionEngine::new(&rules).unwrap();

    let event = Event::from_xml_injected(PROCESS_CREATE_TRAILING_SPACE, "windows", None).unwrap();
    engine.put_events(vec![event]);
    engine.process_events();
    assert_eq!(engine.get_alerts().len(), 0);
}
