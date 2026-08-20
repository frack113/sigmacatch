// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 sigmacatch contributors

//! Assembles one audit record into an [`Event`].
//!
//! SigmaHQ auditd rules select records by their `type` (EXECVE, PATH, SYSCALL,
//! …) — each audit record is a distinct event for detection. Emitting one
//! [`Event`] per record (each with its own `type` and fields) is what makes the
//! rules matchable; this mirrors how pySigma/Elastic model auditd (one document
//! per record). The audit event ID (`stamp`) is preserved so multi-record
//! groups can be reconstructed later for `.log` regression generation.

use serde_json::{Map, Value};
use sigmacatch_types::Event;

use crate::parser::Record;

/// Build the `Event` for a single audit record of a grouped audit event:
/// - `event_json_raw`: structured `{stamp, type, node?, fields}` preserving
///   the record and its audit event ID;
/// - `event_json` (detection): flat `{type, node?, fields…}` with logsource
///   `product: linux` + `service: auditd` injected;
/// - `event_raw`: the complete original audit log lines of the event (all
///   records sharing its `timestamp:sequence`), newline-terminated.
pub fn record_to_event(lines: &[u8], record: &Record) -> Event {
    let json_raw = Value::Object({
        let mut root = Map::new();
        root.insert(
            "stamp".into(),
            Value::Object({
                let mut stamp = Map::new();
                stamp.insert("timestamp".into(), Value::from(record.id.timestamp));
                stamp.insert("sequence".into(), Value::from(record.id.sequence));
                stamp
            }),
        );
        root.insert("type".into(), Value::String(record.ty.clone()));
        if let Some(node) = &record.node {
            root.insert("node".into(), Value::String(node.clone()));
        }
        root.insert("fields".into(), Value::Object(record.fields.clone()));
        root
    });

    let mut flat = Map::new();
    flat.insert("type".into(), Value::String(record.ty.clone()));
    if let Some(node) = &record.node {
        flat.insert("node".into(), Value::String(node.clone()));
    }
    for (key, value) in &record.fields {
        flat.insert(key.clone(), value.clone());
    }

    flat.insert("provider".into(), Value::String("auditd".into()));
    let mut event = Event::new(json_raw, Value::Object(flat), lines.to_vec());
    event.inject_logsource_fields_for("linux", Some("auditd"));
    event
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser::parse_line;

    const SYSCALL: &[u8] = b"type=SYSCALL msg=audit(1717056137.482:90412): arch=c000003e syscall=257 success=yes exit=3 pid=20488 comm=\"cat\" exe=\"/usr/bin/cat\" key=\"identity\"\n";
    const PATH: &[u8] =
        b"type=PATH msg=audit(1717056137.482:90412): item=1 name=\"/etc/shadow\" nametype=NORMAL\n";
    const EXECVE: &[u8] =
        b"type=EXECVE msg=audit(1717056137.482:90412): argc=3 a0=\"cat\" a1=\"/etc/shadow\"\n";

    #[test]
    fn test_record_event_fields() {
        let record = parse_line(SYSCALL).unwrap();
        let event = record_to_event(SYSCALL, &record);

        assert_eq!(event.event_json["type"], "SYSCALL");
        assert_eq!(event.event_json["comm"], "cat");
        assert_eq!(event.event_json["exe"], "/usr/bin/cat");
        assert_eq!(event.event_json["key"], "identity");
        assert_eq!(event.event_json["product"], "linux");
        assert_eq!(event.event_json["service"], "auditd");
        assert_eq!(event.event_json["provider"], "auditd");
    }

    #[test]
    fn test_per_record_type_preserved() {
        // Two records of the SAME audit event become two distinct events, each
        // keeping its own `type` — required for type-selected Sigma rules.
        let path_record = parse_line(PATH).unwrap();
        let path_event = record_to_event(PATH, &path_record);
        assert_eq!(path_event.event_json["type"], "PATH");
        assert_eq!(path_event.event_json["name"], "/etc/shadow");

        let execve_record = parse_line(EXECVE).unwrap();
        let execve_event = record_to_event(EXECVE, &execve_record);
        assert_eq!(execve_event.event_json["type"], "EXECVE");
        assert_eq!(execve_event.event_json["a0"], "cat");
        assert_eq!(execve_event.event_json["a1"], "/etc/shadow");
    }

    #[test]
    fn test_raw_preserves_stamp_and_fields() {
        let record = parse_line(PATH).unwrap();
        let event = record_to_event(PATH, &record);

        let raw = &event.event_json_raw;
        assert_eq!(raw["stamp"]["timestamp"], 1717056137482u64);
        assert_eq!(raw["stamp"]["sequence"], 90412);
        assert_eq!(raw["type"], "PATH");
        assert_eq!(raw["fields"]["name"], "/etc/shadow");

        let raw_text = String::from_utf8_lossy(&event.event_raw);
        assert!(raw_text.starts_with("type=PATH msg=audit("));
        assert!(raw_text.ends_with("nametype=NORMAL\n"));
    }

    #[test]
    fn test_event_raw_carries_full_audit_event_lines() {
        // The `.log` regression data needs the complete original audit event,
        // not just the matched record: all records of the same sequence.
        let full = [SYSCALL, PATH, EXECVE].concat();
        let record = parse_line(SYSCALL).unwrap();
        let event = record_to_event(&full, &record);

        let raw_text = String::from_utf8_lossy(&event.event_raw);
        assert!(raw_text.starts_with("type=SYSCALL msg=audit("));
        assert!(raw_text.contains("type=PATH msg=audit("));
        assert!(raw_text.contains("type=EXECVE msg=audit("));
        assert_eq!(event.event_raw, full);
    }
}
