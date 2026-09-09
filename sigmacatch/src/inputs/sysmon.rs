// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 sigmacatch contributors

//! Sysmon for Linux event collector (tail of the central syslog file).
//!
//! Sysmon for Linux writes each event as a single RFC3164 line tagged `sysmon`
//! whose body is Windows-eventlog XML (`<Event><System>…</System>
//! <EventData>…</EventData></Event>`). The collector tails the same central
//! files as [`crate::inputs::syslog`], keeps only those lines and parses their XML via
//! the shared winevt parser: the schema matches Sysmon on Windows, so events
//! carry the full field set (`Image`, `CommandLine`, …) and the detection
//! engine pipelines work unchanged. Logsource is injected from the event
//! channel `Linux-Sysmon/Operational` → `product: linux` + `service: sysmon`.
//!
//! Lines tagged `sysmon` are excluded from [`crate::inputs::syslog`] — one line is
//! emitted exactly once, by this collector. Truncated XML (rsyslog size
//! limits) is skipped with a warning; collection continues.
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

use crate::inputs::syslog;
use crate::inputs::sysmon_parse::{parse_line, record_to_event};
use async_trait::async_trait;
use sigmacatch_types::{Event, EventProducer, ProducerError};
use tokio::sync::{mpsc, watch};

/// Sysmon for Linux event collector (implements `EventProducer` directly).
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
            None => syslog::discover_default_path()
                .map(str::to_string)
                .unwrap_or_else(|| syslog::DEFAULT_LOG_PATHS[0].to_string()),
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
            let path = self.resolved_path();
            if !std::path::Path::new(&path).exists() {
                return Err(ProducerError::Message(format!(
                    "default syslog not found at {path}"
                )));
            }
            tail_loop(&path, tx, stop)
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

/// Run the blocking tail on `path` in `spawn_blocking`.
#[cfg(target_os = "linux")]
async fn tail_loop(
    path: &str,
    tx: mpsc::Sender<Event>,
    stop: watch::Receiver<bool>,
) -> anyhow::Result<()> {
    tracing::info!("sysmon collector starting (tail {path})");
    let path = path.to_string();

    let task = tokio::task::spawn_blocking(move || {
        crate::inputs::tail::run(&path, SysmonHandler, tx, stop)
    });

    task.await
        .map_err(|e| anyhow::anyhow!("sysmon tail task panicked: {e}"))?
}

/// Keeps the `sysmon` RFC3164 lines and emits one [`Event`] per parsed XML
/// body. Truncated XML (rsyslog size limits) is skipped with a warning;
/// collection continues.
#[cfg(target_os = "linux")]
struct SysmonHandler;

#[cfg(target_os = "linux")]
impl crate::inputs::tail::LineHandler for SysmonHandler {
    fn on_line(&mut self, line: &[u8]) -> anyhow::Result<Vec<Event>> {
        let Some(record) = parse_line(line) else {
            return Ok(Vec::new());
        };
        let Some(event) = record_to_event(line, &record) else {
            tracing::warn!("invalid sysmon XML skipped");
            return Ok(Vec::new());
        };
        Ok(vec![event])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const PROCESS_CREATE: &[u8] = br#"<134>Aug 22 10:00:00 debian sysmon: <Event><System><Provider Name="Linux-Sysmon" Guid="{ff032593-a8d3-4f13-b0d6-01fc615a0f97}"/><EventID>1</EventID><Version>5</Version><Level>4</Level><TimeCreated SystemTime="2026-08-22T10:00:01.123456000Z"/><EventRecordID>42</EventRecordID><Channel>Linux-Sysmon/Operational</Channel><Computer>debian</Computer></System><EventData><Data Name="UtcTime">2026-08-22 10:00:01.123</Data><Data Name="ProcessId">28904</Data><Data Name="Image">/usr/bin/id</Data><Data Name="CommandLine">id</Data><Data Name="User">root</Data><Data Name="ParentImage">/usr/bin/bash</Data></EventData></Event>"#;
    const DNS_QUERY: &[u8] = br#"<134>Aug 22 10:00:05 debian sysmon: <Event><System><Provider Name="Linux-Sysmon"/><EventID>22</EventID><Channel>Linux-Sysmon/Operational</Channel></System><EventData><Data Name="QueryName">example.com</Data><Data Name="QueryResults">::1;</Data></EventData></Event>"#;
    const TRUNCATED: &[u8] =
        br#"<134>Aug 22 10:00:02 debian sysmon: <Event><System><Provider Name="Linux-Sysmon""#;
    const NOT_SYSMON: &[u8] = b"Aug 22 10:00:03 debian sshd[123]: Failed password for root";
    const NON_XML_BODY: &[u8] = b"Aug 22 10:00:04 debian sysmon: free text, no event";

    #[test]
    fn test_parse_keeps_sysmon_lines() {
        let record = parse_line(PROCESS_CREATE).expect("sysmon line must parse");
        assert_eq!(record.program, "sysmon");
        assert!(record.message.starts_with("<Event>"));
    }

    #[test]
    fn test_parse_rejects_other_lines() {
        assert!(parse_line(NOT_SYSMON).is_none());
        assert!(parse_line(NON_XML_BODY).is_none());
        assert!(parse_line(b"not a syslog line").is_none());
    }

    #[test]
    fn test_record_to_event_structure_and_logsource() {
        let record = parse_line(PROCESS_CREATE).unwrap();
        let event = record_to_event(PROCESS_CREATE, &record).expect("valid XML must build");

        assert_eq!(event.event_json["product"], "linux");
        assert_eq!(event.event_json["service"], "sysmon");
        assert_eq!(event.event_json["category"], "process_creation");
        assert_eq!(
            event.event_json["Event"]["EventData"]["Image"],
            "/usr/bin/id"
        );
        assert_eq!(event.event_json["Event"]["EventData"]["CommandLine"], "id");
        assert_eq!(
            event.event_json["Event"]["System"]["EventRecordID"], 42,
            "numeric XML text is converted to JSON numbers"
        );

        let raw_nested = &event.event_json_raw["Event"];
        assert_eq!(raw_nested["EventData"]["User"], "root");

        assert_eq!(event.event_raw, PROCESS_CREATE);
    }

    #[test]
    fn test_record_to_event_dns_category() {
        let record = parse_line(DNS_QUERY).unwrap();
        let event = record_to_event(DNS_QUERY, &record).expect("valid XML must build");
        assert_eq!(event.event_json["category"], "dns_query");
    }

    #[test]
    fn test_truncated_xml_is_skipped() {
        let record = parse_line(TRUNCATED).expect("tag still parses");
        assert!(
            record_to_event(TRUNCATED, &record).is_none(),
            "truncated XML must be rejected, not panic"
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_default_and_custom_path() {
        assert_eq!(EventCollector::new().path, None);
        assert_eq!(
            EventCollector::with_path(Some("/tmp/syslog")).path,
            Some("/tmp/syslog".to_string())
        );
    }

    #[cfg(all(test, target_os = "linux"))]
    mod tail {
        use super::*;
        use std::io::Write;

        #[tokio::test]
        async fn test_tail_emits_events_then_stops() {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("syslog");
            {
                let mut f = std::fs::File::create(&path).unwrap();
                writeln!(f, "{}", String::from_utf8_lossy(NOT_SYSMON)).unwrap();
            }

            let (tx, mut rx) = mpsc::channel::<Event>(16);
            let (_stop_tx, stop_rx) = watch::channel(false);
            let collector = EventCollector::with_path(Some(path.to_string_lossy()));

            let handle = tokio::spawn(Box::new(collector).run(tx, stop_rx));
            tokio::time::sleep(std::time::Duration::from_millis(300)).await;

            let mut file = std::fs::OpenOptions::new()
                .append(true)
                .open(&path)
                .unwrap();
            writeln!(file, "{}", String::from_utf8_lossy(PROCESS_CREATE)).unwrap();
            drop(file);

            let event = tokio::time::timeout(std::time::Duration::from_secs(5), rx.recv())
                .await
                .expect("sysmon event must arrive")
                .expect("channel open");
            assert_eq!(event.event_json["category"], "process_creation");

            // Non-sysmon lines already in the file are never emitted.
            assert!(rx.try_recv().is_err());

            drop(rx);
            handle.await.unwrap().expect("clean exit");
        }

        #[tokio::test]
        async fn test_tail_skips_truncated_xml_and_continues() {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("syslog");
            std::fs::File::create(&path).unwrap();

            let (tx, mut rx) = mpsc::channel::<Event>(16);
            let (stop_tx, stop_rx) = watch::channel(false);
            let collector = EventCollector::with_path(Some(path.to_string_lossy()));

            let handle = tokio::spawn(Box::new(collector).run(tx, stop_rx));
            tokio::time::sleep(std::time::Duration::from_millis(300)).await;

            let mut file = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(&path)
                .unwrap();
            writeln!(file, "{}", String::from_utf8_lossy(TRUNCATED)).unwrap();
            writeln!(file, "{}", String::from_utf8_lossy(DNS_QUERY)).unwrap();
            drop(file);

            let event = tokio::time::timeout(std::time::Duration::from_secs(5), rx.recv())
                .await
                .expect("dns event must arrive after truncated line")
                .expect("channel open");
            assert_eq!(event.event_json["category"], "dns_query");

            stop_tx.send(true).unwrap();
            handle.await.unwrap().expect("clean exit");
        }
    }
}
