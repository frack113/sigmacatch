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
use sigmacatch_types::{Event, EventProducer, ProducerError};
use std::sync::OnceLock;
use tokio::sync::{mpsc, watch};

/// Central syslog files, in discovery order (general messages + Sysmon-for-
/// Linux XML lines). The first existing one is tailed by the sysmon collector;
/// the builtin collector tails every existing default file.
pub const DEFAULT_LOG_PATHS: &[&str] = &["/var/log/messages", "/var/log/syslog"];

/// authpriv files: sshd, sudo, su, login, … Rsyslog routes the authpriv
/// facility here and EXCLUDES it from the central files (`/var/log/secure` on
/// RHEL families, `/var/log/auth.log` on Debian families).
pub const AUTH_LOG_PATHS: &[&str] = &["/var/log/secure", "/var/log/auth.log"];

/// cron files (`cron.*` facility, also excluded from the central files).
pub const CRON_LOG_PATHS: &[&str] = &["/var/log/cron", "/var/log/cron.log"];

/// Which default file group a tailed path belongs to. Drives the fallback
/// service injected for programs that carry no explicit mapping: an unknown
/// program writing to the authpriv file is Sigma service `auth`, one writing
/// to the cron file is `cron` (Sigma taxonomy appendix).
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum SourceKind {
    Central,
    Auth,
    Cron,
}

impl SourceKind {
    #[cfg(target_os = "linux")]
    fn paths(self) -> &'static [&'static str] {
        match self {
            Self::Central => DEFAULT_LOG_PATHS,
            Self::Auth => AUTH_LOG_PATHS,
            Self::Cron => CRON_LOG_PATHS,
        }
    }

    fn fallback_service(self) -> Option<&'static str> {
        match self {
            Self::Central => None,
            Self::Auth => Some("auth"),
            Self::Cron => Some("cron"),
        }
    }

    #[cfg(target_os = "linux")]
    fn all() -> [Self; 3] {
        [Self::Central, Self::Auth, Self::Cron]
    }
}

/// Compiled RFC3164 line parser.
static SYSLOG_RE: OnceLock<Regex> = OnceLock::new();

/// Map a syslog program tag to the Sigma linux service name (taxonomy appendix).
/// Unknown programs carry no mapping — the caller applies its source-file
/// fallback, else keeps the lowercased name so logsource pruning stays exact.
fn mapped_service(program: &str) -> Option<&'static str> {
    match program.to_lowercase().as_str() {
        "sshd" | "sshd-session" => Some("sshd"),
        "cron" | "crond" => Some("cron"),
        "vsftpd" | "proftpd" | "pure-ftpd" => Some("vsftpd"),
        "clamd" | "clamd.scan" | "clamonacc" | "freshclam" => Some("clamav"),
        "guacamole" | "guac" => Some("guacamole"),
        "sudo" => Some("sudo"),
        "syslog" | "rsyslogd" | "rsyslog" => Some("syslog"),
        _ => None,
    }
}

/// First existing default syslog path, or `None` (central files only — used
/// by the sysmon collector which pins to them).
pub fn discover_default_path() -> Option<&'static str> {
    DEFAULT_LOG_PATHS
        .iter()
        .copied()
        .find(|p| std::path::Path::new(p).exists())
}

/// Every existing default file across all groups (central + authpriv + cron).
#[cfg(target_os = "linux")]
fn discover_sources() -> Vec<(&'static str, SourceKind)> {
    SourceKind::all()
        .into_iter()
        .flat_map(|kind| {
            kind.paths()
                .iter()
                .filter(|p| std::path::Path::new(p).exists())
                .map(move |p| (*p, kind))
        })
        .collect()
}

/// True when any default syslog path exists on disk.
pub fn default_log_exists() -> bool {
    #[cfg(target_os = "linux")]
    return !discover_sources().is_empty();
    #[cfg(not(target_os = "linux"))]
    return discover_default_path().is_some();
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
    let program = caps
        .name("program")
        .expect("regex defines an unconditional 'program' group")
        .as_str()
        .to_string();
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
    build_event(SourceKind::Central, raw, record)
}

fn build_event(kind: SourceKind, raw: &[u8], record: &Record) -> Event {
    let mut flat = Map::new();
    flat.insert("message".into(), JsonValue::String(record.message.clone()));
    flat.insert("program".into(), JsonValue::String(record.program.clone()));
    if let Some(host) = &record.host {
        flat.insert("host".into(), JsonValue::String(host.clone()));
    }
    let service = mapped_service(&record.program)
        .or(kind.fallback_service())
        .map(str::to_string)
        .unwrap_or_else(|| record.program.to_lowercase());
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
    /// Create a new collector discovering every existing default file.
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

    /// Create a new collector pinned to a single custom path, or `None` to
    /// discover all defaults.
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
            let sources = match &self.path {
                Some(p) => vec![(p.clone(), SourceKind::Central)],
                None => discover_sources()
                    .into_iter()
                    .map(|(p, kind)| (p.to_string(), kind))
                    .collect(),
            };
            if sources.is_empty() {
                return Err(ProducerError::Message("no syslog source found".to_string()));
            }
            let mut tasks = Vec::with_capacity(sources.len());
            for (path, kind) in sources {
                let tx = tx.clone();
                let stop = stop.clone();
                tasks.push(tokio::task::spawn_blocking(move || {
                    blocking_tail(&path, kind, tx, stop)
                }));
            }
            drop(tx);
            let mut result: Result<(), ProducerError> = Ok(());
            for task in tasks {
                match task.await {
                    Ok(Ok(())) => {}
                    Ok(Err(e)) if result.is_ok() => {
                        result = Err(ProducerError::Collector(e.into()));
                    }
                    Ok(Err(_)) => {}
                    Err(e) if result.is_ok() => {
                        result = Err(ProducerError::Collector(
                            anyhow::anyhow!("syslog tail task panicked: {e}").into(),
                        ));
                    }
                    Err(_) => {}
                }
            }
            result
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (tx, stop);
            Ok(())
        }
    }
}

/// Blocking tail loop body for one file: read appended lines, parse and emit
/// one [`Event`] per line. Detects log rotation (inode change) and re-opens
/// the file. Exits when `stop` is set or the receiver is dropped.
#[cfg(target_os = "linux")]
fn blocking_tail(
    path: &str,
    kind: SourceKind,
    tx: mpsc::Sender<Event>,
    stop: watch::Receiver<bool>,
) -> anyhow::Result<()> {
    use std::fs::OpenOptions;
    use std::time::Duration;

    tracing::info!("builtin syslog collector starting (tail {path})");
    let file = OpenOptions::new().read(true).open(path)?;
    let mut state = TailState::new(file, path.to_string());
    while !*stop.borrow() && !tx.is_closed() {
        if let Err(e) = state.poll(kind, &tx) {
            tracing::warn!("builtin syslog tail error: {e}");
        }
        std::thread::sleep(Duration::from_millis(100));
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

    fn poll(&mut self, kind: SourceKind, tx: &mpsc::Sender<Event>) -> std::io::Result<()> {
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
        self.drain_lines(kind, tx)
    }

    fn drain_lines(&mut self, kind: SourceKind, tx: &mpsc::Sender<Event>) -> std::io::Result<()> {
        while let Some(pos) = self.pending.iter().position(|&b| b == b'\n') {
            let line = self.pending[..=pos].to_vec();
            self.pending = self.pending[pos + 1..].to_vec();
            // sysmon for Linux handled exclusively by the sysmon collector.
            if let Some(record) = parse_line(&line)
                && !record.program.eq_ignore_ascii_case("sysmon")
                && tx.blocking_send(build_event(kind, &line, &record)).is_err()
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
        assert_eq!(mapped_service("sshd"), Some("sshd"));
        assert_eq!(mapped_service("sshd-session"), Some("sshd"));
        assert_eq!(mapped_service("CRON"), Some("cron"));
        assert_eq!(mapped_service("vsftpd"), Some("vsftpd"));
        assert_eq!(mapped_service("clamd.scan"), Some("clamav"));
        assert_eq!(mapped_service("guacamole"), Some("guacamole"));
        assert_eq!(mapped_service("sudo"), Some("sudo"));
        assert_eq!(mapped_service("rsyslogd"), Some("syslog"));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_source_kind_fallback_service() {
        let su = b"Aug 23 10:00:00 sigmacatch-linux su[999]: pam_unix(su:session): session opened";
        let record = parse_line(su).unwrap();
        // Unknown program in the authpriv file → Sigma service `auth`.
        let event = build_event(SourceKind::Auth, su, &record);
        assert_eq!(event.event_json["service"], "auth");
        // Same line from a central file keeps its own (lowercased) name.
        let event = build_event(SourceKind::Central, su, &record);
        assert_eq!(event.event_json["service"], "su");

        let crond = b"Aug 23 10:01:01 sigmacatch-linux CROND[3805]: (root) CMD (run-parts /etc/cron.hourly)";
        let record = parse_line(crond).unwrap();
        // Explicit mapping wins over the file fallback.
        let event = build_event(SourceKind::Cron, crond, &record);
        assert_eq!(event.event_json["service"], "cron");
    }

    #[test]
    fn test_service_map_unknown_has_no_mapping() {
        assert_eq!(mapped_service("nginx"), None);
        assert_eq!(mapped_service("Kernel"), None);
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
        assert_eq!(mapped_service(&rec.program), Some("sshd"));
    }

    #[test]
    fn test_parse_line_with_priority() {
        let line = b"<134>May 11 14:23:33 host CRON[90]: (root) CMD (run-pam)";
        let rec = parse_line(line).expect("PRI line must parse");
        assert_eq!(rec.program, "CRON");
        assert_eq!(rec.message, "(root) CMD (run-pam)");
        assert_eq!(mapped_service(&rec.program), Some("cron"));
    }

    #[test]
    fn test_parse_line_without_pid() {
        let line = b"May 11 14:23:33 host kernel: Uptime: 12345 secs";
        let rec = parse_line(line).expect("no-pid line must parse");
        assert_eq!(rec.program, "kernel");
        assert_eq!(rec.message, "Uptime: 12345 secs");
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
