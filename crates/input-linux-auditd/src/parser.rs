// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 sigmacatch contributors

//! Adapter around [`linux_audit_parser`] for a single audit log line.

use linux_audit_parser::{Parser, Value};
use serde_json::{Map, Value as JsonValue};

/// A parsed audit record: one line of the audit log.
pub struct Record {
    /// Audit event identifier (timestamp ms + sequence).
    pub id: linux_audit_parser::EventID,
    /// Optional `node=` name.
    pub node: Option<String>,
    /// `type=` value (SYSCALL, EXECVE, PATH, PROCTITLE, …).
    pub ty: String,
    /// Parsed key/value fields, preserved as strings.
    pub fields: Map<String, JsonValue>,
}

/// Parse a single audit log line into a [`Record`].
///
/// `split_msg` is disabled so single-quoted `msg='…'` strings stay plain text
/// (they are not key/value maps), and enriched values are kept as-is.
/// Unparsable lines yield `None` (the caller logs/skips them).
pub fn parse_line(line: &[u8]) -> Option<Record> {
    let parser = Parser {
        enriched: true,
        split_msg: false,
    };
    let message = parser.parse(line).ok()?;
    let mut fields = Map::new();
    for (key, value) in &message.body {
        if let Some(json) = value_to_json(value) {
            fields.insert(key.to_string(), json);
        }
    }
    Some(Record {
        id: message.id,
        node: message
            .node
            .map(|n| String::from_utf8_lossy(&n).into_owned()),
        ty: message.ty.to_string(),
        fields,
    })
}

/// Serialize a `linux_audit_parser::Value` into a JSON value. Numbers and byte
/// strings become JSON strings (matching the string-typed fields of Winevt
/// events). Unrepresentable variants return `None` and the field is dropped.
fn value_to_json(value: &Value<'_>) -> Option<JsonValue> {
    match value {
        Value::Empty => Some(JsonValue::String(String::new())),
        Value::Str(bytes, _) => Some(JsonValue::String(
            String::from_utf8_lossy(bytes).into_owned(),
        )),
        Value::Owned(bytes) => Some(JsonValue::String(
            String::from_utf8_lossy(bytes.as_slice()).into_owned(),
        )),
        Value::Number(n) => Some(JsonValue::String(n.to_string())),
        Value::List(items) | Value::StringifiedList(items) => {
            let arr: Vec<JsonValue> = items.iter().filter_map(value_to_json).collect();
            if arr.is_empty() {
                None
            } else {
                Some(JsonValue::Array(arr))
            }
        }
        Value::Map(pairs) => {
            let mut map = Map::new();
            for (key, item) in pairs {
                if let Some(json) = value_to_json(item) {
                    map.insert(key.to_string(), json);
                }
            }
            if map.is_empty() {
                None
            } else {
                Some(JsonValue::Object(map))
            }
        }
        Value::Literal(s) => Some(JsonValue::String((*s).to_string())),
        Value::Segments(_) | Value::Skipped(_) => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SYSCALL: &[u8] = b"type=SYSCALL msg=audit(1717056137.482:90412): arch=c000003e syscall=257 success=yes exit=3 ppid=20471 pid=20488 comm=\"cat\" exe=\"/usr/bin/cat\" key=\"identity\"\n";
    const PATH: &[u8] =
        b"type=PATH msg=audit(1717056137.482:90412): item=1 name=\"/etc/shadow\" nametype=NORMAL\n";
    const EXECVE: &[u8] =
        b"type=EXECVE msg=audit(1717056137.482:90412): argc=3 a0=\"cat\" a1=\"/etc/shadow\"\n";
    const PROCTITLE: &[u8] = b"type=PROCTITLE msg=audit(1717056137.482:90412): proctitle=636174002F6574632F736861646F77\n";
    const NODE: &[u8] = b"node=hostname type=SYSCALL msg=audit(1717056137.482:90412): arch=c000003e syscall=257 success=yes exit=3\n";

    #[test]
    fn test_parse_syscall() {
        let record = parse_line(SYSCALL).expect("SYSCALL must parse");
        assert_eq!(record.ty, "SYSCALL");
        assert_eq!(record.id.timestamp, 1717056137482);
        assert_eq!(record.id.sequence, 90412);
        assert_eq!(
            record.fields.get("arch").and_then(|v| v.as_str()),
            Some("0xc000003e")
        );
        assert_eq!(
            record.fields.get("syscall").and_then(|v| v.as_str()),
            Some("257")
        );
        assert_eq!(
            record.fields.get("success").and_then(|v| v.as_str()),
            Some("yes")
        );
        assert_eq!(
            record.fields.get("exit").and_then(|v| v.as_str()),
            Some("3")
        );
        assert_eq!(
            record.fields.get("pid").and_then(|v| v.as_str()),
            Some("20488")
        );
        assert_eq!(
            record.fields.get("ppid").and_then(|v| v.as_str()),
            Some("20471")
        );
        assert_eq!(
            record.fields.get("comm").and_then(|v| v.as_str()),
            Some("cat")
        );
        assert_eq!(
            record.fields.get("exe").and_then(|v| v.as_str()),
            Some("/usr/bin/cat")
        );
        assert_eq!(
            record.fields.get("key").and_then(|v| v.as_str()),
            Some("identity")
        );
    }

    #[test]
    fn test_parse_path_and_execve_same_event() {
        let path = parse_line(PATH).expect("PATH must parse");
        assert_eq!(path.ty, "PATH");
        assert_eq!(path.id, parse_line(SYSCALL).unwrap().id);
        assert_eq!(path.fields.get("item").and_then(|v| v.as_str()), Some("1"));
        assert_eq!(
            path.fields.get("name").and_then(|v| v.as_str()),
            Some("/etc/shadow")
        );
        assert_eq!(
            path.fields.get("nametype").and_then(|v| v.as_str()),
            Some("NORMAL")
        );

        let execve = parse_line(EXECVE).expect("EXECVE must parse");
        assert_eq!(
            execve.fields.get("argc").and_then(|v| v.as_str()),
            Some("3")
        );
        assert_eq!(
            execve.fields.get("a0").and_then(|v| v.as_str()),
            Some("cat")
        );
        assert_eq!(
            execve.fields.get("a1").and_then(|v| v.as_str()),
            Some("/etc/shadow")
        );
    }

    #[test]
    fn test_parse_proctitle_hex_decoded() {
        let record = parse_line(PROCTITLE).expect("PROCTITLE must parse");
        // linux-audit-parser hex-decodes the value into Owned bytes.
        assert_eq!(
            record.fields.get("proctitle").and_then(|v| v.as_str()),
            Some("cat\x00/etc/shadow")
        );
    }

    #[test]
    fn test_parse_node_prefix() {
        let record = parse_line(NODE).expect("node-prefixed line must parse");
        assert_eq!(record.node.as_deref(), Some("hostname"));
        assert_eq!(
            record.fields.get("syscall").and_then(|v| v.as_str()),
            Some("257")
        );
    }

    #[test]
    fn test_parse_malformed_line() {
        assert!(parse_line(b"not an audit line").is_none());
        assert!(parse_line(b"").is_none());
    }

    #[test]
    fn test_key_display_for_args() {
        // Key Display follows the parser's Arg convention.
        let k = linux_audit_parser::Key::Arg(2, Some(0));
        assert_eq!(k.to_string(), "a2[0]");
        let k = linux_audit_parser::Key::ArgLen(0);
        assert_eq!(k.to_string(), "a0_len");
    }
}
