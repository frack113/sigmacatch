// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 sigmacatch contributors

//! macOS event collector (feature `macos`): read system log lines and emit them
//! as [`Event`]s for Sigma detection + regression data generation.
//!
//! # Design
//!
//! The collector reads lines from `/var/log/system.log` (or a custom path passed
//! via CLI `--macos-path` into `CliArgs.macos_path`), parses each line's `key=value`
//! body, and emits one [`Event`] per line.
//!
//! JSON view: parsed fields + `message` (the raw line) + `source: system.log`.
//! Raw view: the original log line bytes — written verbatim to `.log` regression data.
//!
//! # Mode
//!
//! One-shot: reads the file to EOF and closes the channel. No live tail, no
//! stop-file poller — use `max_runs`/external stop if you need bounded runs.
//!
//! # Note on permissions
//!
//! `/var/log/system.log` is world-readable on macOS but root access yields the
//! full fidelity (all processes/levels). Run as root for best results.

use crate::detection::DetectionEngine;
use crate::regression::DataFormat;
use crate::runner::CollectorKind;
use crate::types::{Event, EventProducer, ProducerError};
use anyhow::Result;
use async_trait::async_trait;
use serde_json::{Map, Value};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use tokio::fs::File;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::sync::{mpsc, watch};
use tracing::info;

/// Default path of the macOS system log.
pub const DEFAULT_LOG_PATH: &str = "/var/log/system.log";

/// A parsed system-log line: one event.
#[derive(Debug, Clone)]
pub struct Record {
    /// Raw event type hint (first token after the timestamp, when present).
    pub ty: Option<String>,
    /// Parsed key/value fields, preserved as strings.
    pub fields: Map<String, Value>,
    /// Original raw line bytes (kept verbatim for regression `.log` data).
    pub raw: Vec<u8>,
}

/// Parse a single system-log line into a [`Record`].
///
/// Lines look like: `Jul 20 10:30:00 macbook kernel[0] (...)`
/// Key=value pairs in the body are parsed into the `fields` map; the rest
/// (timestamp, process, pid) are stored verbatim in `raw`.
fn parse_line(line: &[u8]) -> Option<Record> {
    if line.is_empty() {
        return None;
    }

    // Split timestamp/process from the body: `Aug 23 10:00:03 host process[pid]: body`
    // The `): ` pattern marks the end of `audit(timestamp:sequence)`; syslog uses `: `.
    // Fall back to the first `:` when neither is present.
    let header_end: Option<usize> = line
        .windows(3)
        .position(|w| w == b"): ")
        .map(|pos| line.len() - (line.len() - pos));
    let header_end = header_end.unwrap_or_else(|| {
        line.iter()
            .position(|&b| b == b':')
            .map(|i| i + 2) // skip ": "
            .unwrap_or(line.len())
    });

    let body = &line[header_end..];
    let mut fields = Map::new();
    for field in body.split(|&b| b == b' ') {
        if field.is_empty() {
            continue;
        }
        let parts: Vec<&[u8]> = field.split(|&b| b == b'=').collect();
        if parts.len() != 2 {
            continue;
        }
        let (key, value) = (parts[0], parts[1]);
        let key_str = std::str::from_utf8(key).unwrap_or("").trim().to_string();
        let value_str = std::str::from_utf8(value).unwrap_or("").to_string();
        if !key_str.is_empty() {
            fields.insert(key_str, Value::String(value_str));
        }
    }

    let ty = fields
        .get("type")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());

    Some(Record {
        fields,
        ty,
        raw: line.to_vec(),
    })
}

/// MacOS collector: one-shot system-log reader.
#[derive(Debug, Clone, Default)]
pub struct MacosCollector {
    /// Log file path(s) to read.
    pub files: Vec<PathBuf>,
}

impl MacosCollector {
    /// Create a collector reading `DEFAULT_LOG_PATH`.
    pub fn new() -> Self {
        Self {
            files: vec![PathBuf::from(DEFAULT_LOG_PATH)],
        }
    }

    /// Create a collector reading a custom log path.
    pub fn with_path(path: PathBuf) -> Self {
        Self { files: vec![path] }
    }

    /// Parse and send all lines from a single file into `tx`, stopping when
    /// `stop` signals or the channel closes.
    async fn read_file(
        path: &Path,
        tx: &mpsc::Sender<Event>,
        stop: &watch::Receiver<bool>,
    ) -> Result<(), ProducerError> {
        let file = match File::open(path).await {
            Ok(f) => f,
            Err(e) => {
                return Err(ProducerError::Message(format!(
                    "failed to open {}: {}",
                    path.display(),
                    e
                )));
            }
        };
        let reader = BufReader::new(file);
        let mut lines = reader.lines();

        while !*stop.borrow() {
            let line = match lines.next_line().await {
                Ok(Some(l)) => l,
                Ok(None) => break, // EOF
                Err(e) => {
                    return Err(ProducerError::Message(format!(
                        "failed to read {}: {}",
                        path.display(),
                        e
                    )));
                }
            };

            let Some(record) = parse_line(line.as_bytes()) else {
                continue;
            };

            // Detection JSON: the parsed fields + `message` (raw line) + source.
            let mut event_json = record.fields.clone();
            if record.fields.get("message").is_none() {
                event_json.insert(
                    "message".to_string(),
                    Value::String(String::from_utf8_lossy(&record.raw).trim().to_string()),
                );
            }
            event_json.insert(
                "source".to_string(),
                Value::String("system.log".to_string()),
            );

            // Raw JSON: preserve the line verbatim as `data`.
            let event_json_raw = serde_json::json!({
                "data": String::from_utf8_lossy(&record.raw).trim(),
            });

            let event = Event::new(
                event_json_raw,
                serde_json::Value::Object(event_json),
                record.raw.clone(),
            );

            if tx.send(event).await.is_err() {
                // Receiver dropped — stop.
                return Ok(());
            }
        }
        Ok(())
    }
}

impl CollectorKind for MacosCollector {
    fn name(&self) -> &'static str {
        "macos"
    }

    fn mode(&self) -> String {
        "macOS system.log (one-shot)".to_string()
    }

    fn channels(
        &self,
        _engine: &DetectionEngine,
        _custom_map: &HashMap<String, String>,
    ) -> Option<Vec<String>> {
        // macOS collector does not use channel resolution.
        None
    }

    fn build(&self, _channels: &[String]) -> Box<dyn EventProducer> {
        Box::new(self.clone())
    }

    fn live_capture(&self) -> bool {
        false
    }

    fn regression_format(&self) -> DataFormat {
        DataFormat::Log
    }

    fn rule_product(&self) -> &'static str {
        "macos"
    }
}

#[async_trait]
impl EventProducer for MacosCollector {
    async fn run(
        self: Box<Self>,
        tx: mpsc::Sender<Event>,
        stop: watch::Receiver<bool>,
    ) -> Result<(), ProducerError> {
        let files: Vec<PathBuf> = self.files.clone();
        let mut total: u64 = 0;
        for path in files {
            Self::read_file(&path, &tx, &stop).await?;
            total += 1;
        }
        info!(count = total, "macOS collector finished reading log files");
        Ok(())
    }
}

/// Module-level entry point: create a `MacosCollector` and run it through the
/// shared runner pipeline. Selected by `main.rs` when `target_os = "macos"` +
/// `feature = "macos"`.
pub async fn run() -> Result<()> {
    let collector = MacosCollector::new();
    crate::runner::run(&collector).await
}

/// Entry point accepting a custom log path (used by `main.rs` when the
/// `--macos-path` flag is present).
pub async fn run_with_path(path: PathBuf) -> Result<()> {
    let collector = MacosCollector::with_path(path);
    crate::runner::run(&collector).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::ProducerError;
    use std::collections::HashMap;

    #[test]
    fn test_parse_line_with_kv_body() {
        let line = b"Jul 20 10:30:00 macbook kernel[0]: type=process pid=123 comm=launchd";
        let record = parse_line(line).expect("line must parse");
        assert_eq!(record.ty.as_deref(), Some("process"));
        assert_eq!(
            record.fields.get("pid").and_then(|v| v.as_str()),
            Some("123")
        );
        assert_eq!(
            record.fields.get("comm").and_then(|v| v.as_str()),
            Some("launchd")
        );
        assert!(!record.raw.is_empty());
    }

    #[test]
    fn test_parse_line_without_kv_body() {
        let line = b"Jul 20 10:30:00 macbook com.apple.xpc.launchd[1]: (com.apple.xpc)";
        let record = parse_line(line).expect("line must parse");
        assert_eq!(
            record.fields.get("message").and_then(|v| v.as_str()),
            Some("(com.apple.xpc)")
        );
        assert_eq!(record.raw, line);
    }

    #[test]
    fn test_parse_line_empty() {
        assert!(parse_line(b"").is_none());
    }

    #[test]
    fn test_collector_kind_defaults() {
        let engine = DetectionEngine::new(&crate::rule::SigmahqRules::default()).unwrap();
        let collector = MacosCollector::new();
        assert_eq!(collector.name(), "macos");
        assert!(collector.mode().contains("system.log"));
        assert!(collector.channels(&engine, &HashMap::new()).is_none());
        assert!(!collector.live_capture());
        assert!(matches!(collector.regression_format(), DataFormat::Log));
    }

    #[test]
    fn test_default_path() {
        assert_eq!(
            MacosCollector::new().files,
            vec![PathBuf::from(DEFAULT_LOG_PATH)]
        );
    }

    #[test]
    fn test_with_path() {
        let custom = PathBuf::from("/custom/log/system.log");
        let collector = MacosCollector::with_path(custom.clone());
        assert_eq!(collector.files, vec![custom]);
    }
}
