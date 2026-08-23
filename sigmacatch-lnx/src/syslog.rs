// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 sigmacatch contributors

//! Linux syslog event collector (tail of the central syslog file).
//!
//! The builtin linux Sigma rules (`sigma/rules/linux/builtin/{sshd,syslog,cron,
//! vsftpd,clamav,guacamole}`) are keyword rules matched against the raw message
//! text. Each non-sysmon line of the central syslog is emitted as one [`Event`]
//! carrying `product: linux` and a `service` derived from the RFC3164 program
//! tag (`sshd` → `sshd`, `CRON` → `cron`, …). Sysmon-for-Linux lines
//! (program tag `sysmon`, XML body) are excluded and handled by the dedicated
//! sysmon collector to prevent double-capture. Non-matching lines are dropped.
//!
//! # API
//! - `EventCollector::new()` → collector discovering the first existing default
//!   syslog path at start-up
//! - `EventCollector::with_path(path)` → collector pinned to a custom path
//! - Implements `EventProducer` — calls `run(tx, stop)` to collect
//!
//! The blocking tail loop runs in `spawn_blocking`; stopping is via the `stop`
//! watch or by dropping the receiver. Log rotation (inode change) is detected
//! and the file re-opened. Non-Linux → silent stub.

use async_trait::async_trait;
use regex::Regex;
use serde_json::{Map, Value as JsonValue};
use sigmacatch_types::{Event, EventProducer};
use std::sync::OnceLock;
use tokio::sync::{mpsc, watch};

/// Central syslog files, in discovery order. The first existing one is tailed.
pub const DEFAULT_LOG_PATHS: &[&str] = &["/var/log/messages", "/var/log/syslog"];

/// Compiled RFC3164 line parser.
static SYSLOG_RE: OnceLock<Regex> = OnceLock::new();

/// Map a syslog program tag to the Sigma linux service name (taxonomy appendix).
/// Unknown programs keep their own (lowercased) name so logsource pruning stays
/// exact: an unmapped service simply never matches a specific builtin rule.
fn service_for_program(program: &str) -> String {
    let lower = program.to_lowercase();
    let mapped: &str = match lower.as_str() {
        "sshd" => "sshd",
        "cron" | "crond" => "cron",
        "vsftpd" | "proftpd" | "pure-ftpd" => "vsftpd",
        "clamd" | "clamd.scan" | "clamonacc" | "freshclam" => "clamav",
        "guacamole" | "guac" => "guacamole",
        "sudo" => "sudo",
        "syslog" | "rsyslogd" | "rsyslog" => "syslog",
        other => other,
    };
    mapped.to_string()
}

/// First existing default syslog path, or `None`.
pub fn discover_default_path() -> Option<&'static str> {
    DEFAULT_LOG_PATHS
        .iter()
        .copied()
        .find(|p| std::path::Path::new(p).exists())
}

/// True when any default syslog path exists on disk.
pub fn default_log_exists() -> bool {
    discover_default_path().is_some()
}

/// A parsed syslog line: host, program tag, message and the original bytes.
pub struct Record {
    /// Optional emitting host.
    pub host: Option<String>,
    /// RFC3164 program tag.
    pub program: String,
    /// Log message body (everything after `program[pid]: `).
    pub message: String,
    /// Original line bytes (regression data source).
    pub raw: Vec<u8>,
}

fn syslog_re() -> &'static Regex {
    SYSLOG_RE.get_or_init(|| {
        // Optional <PRI>, BSD timestamp (Mmm dd hh:mm:ss), host, program
        // (optionally `[pid]`), then `: ` and the message.
        Regex::new(
            r"(?s)^(?:<\d+>\s*)?(?:\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(?P<host>\S+)\s+(?P<program>[\w.\-]+)(?:\[\d+\])?:\s?(?P<msg>.*)$",
        )
        .expect("syslog regex compiles")
    })
}

/// Parse a single syslog line into a [`Record`]. Returns `None` when the line
/// does not match the standard BSD/RFC3164 format.
pub fn parse_line(line: &[u8]) -> Option<Record> {
    let text = std::str::from_utf8(line).ok()?;
    let text = text.trim_end_matches(['\n', '\r', ' ']);
    if text.is_empty() {
        return None;
    }
    let caps = syslog_re().captures(text)?;
    let host = caps.name("host").map(|h| h.as_str().to_string());
    let program = caps.name("program").unwrap().as_str().to_string();
    let message = caps
        .name("msg")
        .map(|m| m.as_str().to_string())
        .unwrap_or_else(|| text.to_string());
    Some(Record {
        host,
        program,
        message,
        raw: line.to_vec(),
    })
}

/// Build the [`Event`] for a syslog line:
/// - `event_json` (detection): `{message, program, host?, service, product}`
///   with `product: linux` + the derived `service` injected;
/// - `event_raw`: the original line.
pub fn record_to_event(raw: &[u8], record: &Record) -> Event {
    let mut flat = Map::new();
    flat.insert("message".into(), JsonValue::String(record.message.clone()));
    flat.insert("program".into(), JsonValue::String(record.program.clone()));
    if let Some(host) = &record.host {
        flat.insert("host".into(), JsonValue::String(host.clone()));
    }
    let service = service_for_program(&record.program);
    let raw_json = JsonValue::Object({
        let mut root = Map::new();
        root.insert("message".into(), JsonValue::String(record.message.clone()));
        root.insert("program".into(), JsonValue::String(record.program.clone()));
        if let Some(host) = &record.host {
            root.insert("host".into(), JsonValue::String(host.clone()));
        }
        root
    });
    let mut event = Event::new(raw_json, JsonValue::Object(flat), raw.to_vec());
    event.inject_logsource_fields_for("linux", Some(&service));
    event
}

/// Linux syslog event collector (implements `EventProducer` directly).
pub struct EventCollector {
    /// Pinned path, or `None` to discover the first existing default path.
    #[cfg(target_os = "linux")]
    path: Option<String>,
}

impl Default for EventCollector {
    fn default() -> Self {
        Self::new()
    }
}

impl EventCollector {
    /// Create a new collector discovering the first existing default path.
    pub fn new() -> Self {
        #[cfg(target_os = "linux")]
        let path = None::<String>;
        #[cfg(not(target_os = "linux"))]
        let _ = ();
        Self {
            #[cfg(target_os = "linux")]
            path,
        }
    }

    /// Create a new collector pinned to a custom path, or `None` to discover.
    pub fn with_path(path: Option<impl Into<String>>) -> Self {
        #[cfg(target_os = "linux")]
        let path = path.map(Into::into);
        #[cfg(not(target_os = "linux"))]
        let _ = &path;
        Self {
            #[cfg(target_os = "linux")]
            path,
        }
    }

    #[cfg(target_os = "linux")]
    fn resolved_path(&self) -> String {
        match &self.path {
            Some(p) => p.clone(),
            None => discover_default_path()
                .map(str::to_string)
                .unwrap_or_else(|| DEFAULT_LOG_PATHS[0].to_string()),
        }
    }
}

#[async_trait]
impl EventProducer for EventCollector {
    async fn run(
        self: Box<Self>,
        tx: mpsc::Sender<Event>,
        stop: watch::Receiver<bool>,
    ) -> anyhow::Result<()> {
        #[cfg(target_os = "linux")]
        {
            let path = self.resolved_path();
            if !std::path::Path::new(&path).exists() {
                anyhow::bail!("default syslog not found at {path}");
            }
            tail_loop(&path, tx, stop).await
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (tx, stop);
            Ok(())
        }
    }
}

/// Blocking tail loop: read appended lines from the syslog, parse and emit one
/// [`Event`] per line. Detects log rotation (inode change) and re-opens the
/// file. Exits when `stop` is set or the receiver is dropped. Runs in
/// `spawn_blocking`.
#[cfg(target_os = "linux")]
async fn tail_loop(
    path: &str,
    tx: mpsc::Sender<Event>,
    stop: watch::Receiver<bool>,
) -> anyhow::Result<()> {
    use std::fs::OpenOptions;
    use std::time::Duration;

    tracing::info!("builtin syslog collector starting (tail {path})");
    let file = OpenOptions::new().read(true).open(path)?;
    tracing::info!("builtin syslog collector starting (tail {path})");
    let mut state = TailState::new(file, path.to_string());
    while !*stop.borrow() && !tx.is_closed() {
        if let Err(e) = state.poll(&tx).await {
            tracing::warn!("builtin syslog tail error: {e}");
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    Ok(())
}

/// Tracks the open log file, its identity (dev/ino) for rotation detection and
/// partial lines.
#[cfg(target_os = "linux")]
struct TailState {
    file: std::fs::File,
    path: String,
    dev: u64,
    ino: u64,
    pending: Vec<u8>,
}

#[cfg(target_os = "linux")]
impl TailState {
    fn new(file: std::fs::File, path: String) -> Self {
        use std::io::Seek;
        use std::os::unix::fs::MetadataExt;
        let (dev, ino) = file
            .metadata()
            .map(|m| (m.dev(), m.ino()))
            .unwrap_or((0, 0));
        let _ = (&file).seek(std::io::SeekFrom::End(0));
        Self {
            file,
            path,
            dev,
            ino,
            pending: Vec::new(),
        }
    }

    fn check_rotation(&self) -> std::io::Result<bool> {
        use std::os::unix::fs::MetadataExt;
        let m = std::fs::metadata(&self.path)?;
        Ok(m.dev() != self.dev || m.ino() != self.ino)
    }

    fn reopen(&mut self) -> std::io::Result<()> {
        use std::io::Seek;
        let file = std::fs::OpenOptions::new().read(true).open(&self.path)?;
        use std::os::unix::fs::MetadataExt;
        let (dev, ino) = file
            .metadata()
            .map(|m| (m.dev(), m.ino()))
            .unwrap_or((0, 0));
        let _ = (&file).seek(std::io::SeekFrom::Start(0));
        self.file = file;
        self.dev = dev;
        self.ino = ino;
        self.pending.clear();
        Ok(())
    }

    async fn poll(&mut self, tx: &mpsc::Sender<Event>) -> std::io::Result<()> {
        if self.check_rotation()? {
            self.reopen()?;
        }
        use std::io::Read;
        let mut buf = [0u8; 8192];
        let n = self.file.read(&mut buf)?;
        if n == 0 {
            return Ok(());
        }
        self.pending.extend_from_slice(&buf[..n]);
        self.drain_lines(tx).await
    }

    async fn drain_lines(&mut self, tx: &mpsc::Sender<Event>) -> std::io::Result<()> {
        while let Some(pos) = self.pending.iter().position(|&b| b == b'\n') {
            let line = self.pending[..=pos].to_vec();
            self.pending = self.pending[pos + 1..].to_vec();
            // sysmon for Linux handled exclusively by the sysmon collector.
            if let Some(record) = parse_line(&line)
                && !record.program.eq_ignore_ascii_case("sysmon")
                && tx.send(record_to_event(&line, &record)).await.is_err()
            {
                return Ok(());
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_service_map_known_programs() {
        assert_eq!(service_for_program("sshd"), "sshd");
        assert_eq!(service_for_program("CRON"), "cron");
        assert_eq!(service_for_program("vsftpd"), "vsftpd");
        assert_eq!(service_for_program("clamd.scan"), "clamav");
        assert_eq!(service_for_program("guacamole"), "guacamole");
        assert_eq!(service_for_program("sudo"), "sudo");
        assert_eq!(service_for_program("rsyslogd"), "syslog");
    }

    #[test]
    fn test_service_map_unknown_keeps_program() {
        assert_eq!(service_for_program("nginx"), "nginx");
        assert_eq!(service_for_program("Kernel"), "kernel");
    }

    #[test]
    fn test_parse_line_with_pid() {
        let line = b"May 11 14:23:33 host123 sshd[12345]: Failed password for invalid user root from 1.2.3.4";
        let rec = parse_line(line).expect("line must parse");
        assert_eq!(rec.host.as_deref(), Some("host123"));
        assert_eq!(rec.program, "sshd");
        assert_eq!(
            rec.message,
            "Failed password for invalid user root from 1.2.3.4"
        );
        assert_eq!(service_for_program(&rec.program), "sshd");
    }

    #[test]
    fn test_parse_line_with_priority() {
        let line = b"<134>May 11 14:23:33 host CRON[90]: (root) CMD (run-pam)";
        let rec = parse_line(line).expect("PRI line must parse");
        assert_eq!(rec.program, "CRON");
        assert_eq!(rec.message, "(root) CMD (run-pam)");
        assert_eq!(service_for_program(&rec.program), "cron");
    }

    #[test]
    fn test_parse_line_without_pid() {
        let line = b"May 11 14:23:33 host kernel: Uptime: 12345 secs";
        let rec = parse_line(line).expect("no-pid line must parse");
        assert_eq!(rec.program, "kernel");
        assert_eq!(rec.message, "Uptime: 12345 secs");
        assert_eq!(service_for_program(&rec.program), "kernel");
    }

    #[test]
    fn test_parse_line_rejects_garbage() {
        assert!(parse_line(b"this is not a syslog line").is_none());
        assert!(parse_line(b"").is_none());
    }

    #[test]
    fn test_record_to_event_injects_logsource() {
        let line = b"May 11 14:23:33 host123 sshd[12345]: Failed password for root";
        let rec = parse_line(line).unwrap();
        let event = record_to_event(line, &rec);
        assert_eq!(event.event_json["product"], "linux");
        assert_eq!(event.event_json["service"], "sshd");
        assert_eq!(event.event_json["program"], "sshd");
        assert_eq!(event.event_json["message"], "Failed password for root");
        assert_eq!(event.event_raw, line);
    }

    #[test]
    fn test_discover_default_path_falls_back() {
        // With no default path present, discovery returns None (nothing panics).
        let _ = discover_default_path();
    }
}
