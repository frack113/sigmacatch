// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 sigmacatch contributors

//! Linux auditd event collector (tail of `/var/log/audit/audit.log`).
//!
//! # API
//! - `EventCollector::new()` → creates the collector (default path)
//! - `EventCollector::with_path(path)` → collector with a custom log path
//! - Implements `EventProducer` trait — calls `run(tx, stop)` to collect and send events
//!
//! On Linux, the collector tails the audit log: it reads appended lines, parses
//! them with [`linux_audit_parser`] and emits one [`Event`] per audit record.
//! Records sharing the same audit event id (`msg=audit(timestamp:sequence)`)
//! are grouped so each event carries the complete original audit event lines —
//! required for the `.log` regression data file. The blocking tail loop runs in
//! `spawn_blocking`; stopping is done via the `stop` watch or by dropping the
//! receiver. Log rotation (inode change) is detected and the file re-opened.
//! Non-Linux → silent stub.

use async_trait::async_trait;
use linux_audit_parser::{Parser, Value as AuditValue};
use serde_json::{Map, Value as JsonValue};
use sigmacatch_types::{Event, EventProducer, ProducerError};
use tokio::sync::{mpsc, watch};

/// Default path of the audit log.
pub const DEFAULT_LOG_PATH: &str = "/var/log/audit/audit.log";

/// Poll interval of the tail loop (how often new bytes are read from the file).
#[cfg(target_os = "linux")]
const TAIL_POLL_MS: u64 = 100;

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

fn value_to_json(value: &AuditValue<'_>) -> Option<JsonValue> {
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
        AuditValue::Literal(s) => Some(JsonValue::String((*s).to_string())),
        AuditValue::Segments(_) | AuditValue::Skipped(_) => None,
    }
}

/// Linux auditd event collector (implements `EventProducer` directly).
pub struct EventCollector {
    #[cfg(target_os = "linux")]
    path: String,
}

impl Default for EventCollector {
    fn default() -> Self {
        Self::new()
    }
}

impl EventCollector {
    /// Create a new collector on the default audit log path.
    pub fn new() -> Self {
        Self::with_path(DEFAULT_LOG_PATH.to_string())
    }

    /// Create a new collector on a custom audit log path.
    pub fn with_path(path: impl Into<String>) -> Self {
        #[cfg(target_os = "linux")]
        let path = path.into();
        #[cfg(not(target_os = "linux"))]
        let _ = &path;
        Self {
            #[cfg(target_os = "linux")]
            path,
        }
    }
}

#[async_trait]
impl EventProducer for EventCollector {
    async fn run(
        self: Box<Self>,
        tx: mpsc::Sender<Event>,
        stop: watch::Receiver<bool>,
    ) -> Result<(), ProducerError> {
        #[cfg(target_os = "linux")]
        {
            tail_loop(&self.path, tx, stop)
                .await
                .map_err(|e| ProducerError::Collector(e.into()))
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (tx, stop);
            Ok(())
        }
    }
}

/// Build the `Event` for a single audit record of a grouped audit event:
/// - `event_json_raw`: structured `{stamp, type, node?, fields}` preserving
///   the record and its audit event ID;
/// - `event_json` (detection): flat `{type, node?, fields…}` with logsource
///   `product: linux` + `service: auditd` injected;
/// - `event_raw`: the complete original audit log lines of the event.
pub fn record_to_event(lines: &[u8], record: &Record) -> Event {
    let json_raw = JsonValue::Object({
        let mut root = Map::new();
        root.insert(
            "stamp".into(),
            JsonValue::Object({
                let mut stamp = Map::new();
                stamp.insert("timestamp".into(), JsonValue::from(record.id.timestamp));
                stamp.insert("sequence".into(), JsonValue::from(record.id.sequence));
                stamp
            }),
        );
        root.insert("type".into(), JsonValue::String(record.ty.clone()));
        if let Some(node) = &record.node {
            root.insert("node".into(), JsonValue::String(node.clone()));
        }
        root.insert("fields".into(), JsonValue::Object(record.fields.clone()));
        root
    });

    let mut flat = Map::new();
    flat.insert("type".into(), JsonValue::String(record.ty.clone()));
    if let Some(node) = &record.node {
        flat.insert("node".into(), JsonValue::String(node.clone()));
    }
    for (key, value) in &record.fields {
        flat.insert(key.clone(), value.clone());
    }

    flat.insert("provider".into(), JsonValue::String("auditd".into()));
    let mut event = Event::new(json_raw, JsonValue::Object(flat), lines.to_vec());
    event.inject_logsource_fields_for("linux", Some("auditd"));
    event
}

/// Blocking tail loop: read appended lines from the audit log, parse and
/// reassemble them into events, send them through `tx`. Detects log rotation
/// (inode change) and re-opens the file. Exits when `stop` is set or the
/// receiver is dropped. Runs in `spawn_blocking`.
#[cfg(target_os = "linux")]
async fn tail_loop(
    path: &str,
    tx: mpsc::Sender<Event>,
    stop: watch::Receiver<bool>,
) -> anyhow::Result<()> {
    use tracing::info;

    info!("auditd collector starting (tail {path})");
    let path = path.to_string();

    let task = tokio::task::spawn_blocking(move || {
        use std::fs::OpenOptions;

        let file = OpenOptions::new()
            .read(true)
            .open(&path)
            .map_err(|e| anyhow::anyhow!("failed to open audit log {path}: {e}"))?;
        let mut state = TailState::new(file, path);
        loop {
            if *stop.borrow() || tx.is_closed() {
                break;
            }
            if let Err(e) = state.poll(&tx) {
                tracing::warn!("audit log tail error: {e}");
            }
            std::thread::sleep(std::time::Duration::from_millis(TAIL_POLL_MS));
        }
        Ok(())
    });

    match task.await {
        Ok(res) => res,
        Err(e) => Err(anyhow::anyhow!("audit tail task panicked: {e}")),
    }
}

/// Tracks the open log file, its identity (dev/ino) for rotation detection,
/// partial lines and the audit event currently being grouped.
#[cfg(target_os = "linux")]
struct TailState {
    file: std::fs::File,
    path: String,
    dev: u64,
    ino: u64,
    pending: Vec<u8>,
    group_seq: Option<linux_audit_parser::EventID>,
    group_lines: Vec<u8>,
    group_records: Vec<Record>,
}

#[cfg(target_os = "linux")]
impl TailState {
    fn new(file: std::fs::File, path: String) -> Self {
        use std::io::{Seek, SeekFrom};
        use std::os::unix::fs::MetadataExt;

        let (dev, ino) = match file.metadata() {
            Ok(m) => (m.dev(), m.ino()),
            Err(_) => (0, 0),
        };
        let _ = (&file).seek(SeekFrom::End(0));
        Self {
            file,
            path,
            dev,
            ino,
            pending: Vec::new(),
            group_seq: None,
            group_lines: Vec::new(),
            group_records: Vec::new(),
        }
    }

    fn poll(&mut self, tx: &mpsc::Sender<Event>) -> anyhow::Result<()> {
        use std::io::Read;

        if self.check_rotation()? {
            self.reopen()?;
        }

        let mut buf = [0u8; 8192];
        let n = self.file.read(&mut buf)?;
        if n == 0 {
            if self.pending.is_empty() {
                self.flush_group(tx)?;
            }
            return Ok(());
        }
        self.pending.extend_from_slice(&buf[..n]);
        self.drain_lines(tx)
    }

    fn check_rotation(&self) -> anyhow::Result<bool> {
        use std::os::unix::fs::MetadataExt;

        match std::fs::metadata(&self.path) {
            Ok(m) => Ok(m.dev() != self.dev || m.ino() != self.ino),
            Err(_) => Ok(false),
        }
    }

    fn reopen(&mut self) -> anyhow::Result<()> {
        use std::io::{Seek, SeekFrom};
        use std::os::unix::fs::MetadataExt;

        let file = std::fs::OpenOptions::new()
            .read(true)
            .open(&self.path)
            .map_err(|e| anyhow::anyhow!("failed to re-open audit log {}: {e}", self.path))?;
        let (dev, ino) = match file.metadata() {
            Ok(m) => (m.dev(), m.ino()),
            Err(_) => (0, 0),
        };
        self.file = file;
        self.dev = dev;
        self.ino = ino;
        self.pending.clear();
        self.group_seq = None;
        self.group_lines.clear();
        self.group_records.clear();
        let _ = (&self.file).seek(SeekFrom::Start(0));
        tracing::info!("audit log rotated — re-opened {}", self.path);
        Ok(())
    }

    fn drain_lines(&mut self, tx: &mpsc::Sender<Event>) -> anyhow::Result<()> {
        while let Some(pos) = self.pending.iter().position(|&b| b == b'\n') {
            let line: Vec<u8> = self.pending.drain(..=pos).collect();
            if let Some(record) = parse_line(&line) {
                if self.group_seq != Some(record.id) {
                    self.flush_group(tx)?;
                    self.group_seq = Some(record.id);
                }
                self.group_lines.extend_from_slice(&line);
                self.group_records.push(record);
            }
        }
        Ok(())
    }

    fn flush_group(&mut self, tx: &mpsc::Sender<Event>) -> anyhow::Result<()> {
        if self.group_records.is_empty() {
            self.group_seq = None;
            return Ok(());
        }
        let lines = std::mem::take(&mut self.group_lines);
        let records = std::mem::take(&mut self.group_records);
        self.group_seq = None;
        for record in records {
            if tx.blocking_send(record_to_event(&lines, &record)).is_err() {
                tracing::warn!("channel closed, dropping remaining records from group");
                break;
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_path() {
        #[cfg(target_os = "linux")]
        assert_eq!(EventCollector::new().path, "/var/log/audit/audit.log");
    }

    #[test]
    fn test_custom_path() {
        #[cfg(target_os = "linux")]
        assert_eq!(
            EventCollector::with_path("/tmp/audit.log").path,
            "/tmp/audit.log"
        );
    }

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
        let k = linux_audit_parser::Key::Arg(2, Some(0));
        assert_eq!(k.to_string(), "a2[0]");
        let k = linux_audit_parser::Key::ArgLen(0);
        assert_eq!(k.to_string(), "a0_len");
    }

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
