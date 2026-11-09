// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 sigmacatch contributors

//! Parse EVTX files into [`Event`] objects for the detection engine.
//!
//! Pattern: producer → mpsc channel → detection engine

//! `EventCollector` — file-based EVTX collector with internal FIFO.
//!
//! Pattern: collector → convert → FIFO (Event)

use std::path::Path;
use std::sync::Arc;

use crate::types::{Event, EventProducer, ParseError, ProducerError};
use async_trait::async_trait;
use rayon::prelude::*;
use tracing::warn;

/// Errors produced while reading EVTX files.
#[derive(Debug, thiserror::Error)]
pub enum EvtxError {
    /// Filesystem failure.
    #[error("filesystem error: {0}")]
    Io(#[from] std::io::Error),
    /// The EVTX container or one of its records could not be decoded.
    #[error("EVTX parse error: {0}")]
    Parse(String),
    /// A record's XML violated the Winevt event schema.
    #[error("{0}")]
    InvalidEvent(#[from] ParseError),
}

/// Crate-local result alias over [`EvtxError`].
pub type Result<T> = std::result::Result<T, EvtxError>;
use tokio::sync::{mpsc, watch};

/// EVTX file producer.
///
/// Loads `.evtx` files and sends parsed events into an `mpsc` channel.
pub struct EventCollector {
    files: Vec<std::path::PathBuf>,
}

impl EventCollector {
    /// Create an empty producer.
    pub fn new() -> Self {
        Self { files: Vec::new() }
    }

    /// Add an EVTX file to be collected.
    pub fn add_file(&mut self, path: impl Into<std::path::PathBuf>) {
        self.files.push(path.into());
    }

    /// Load a single EVTX file into a buffer.
    ///
    /// Binary-XML rendering runs on all cores (`num_threads(0)`) and the
    /// XML -> [`Event`] conversion, the dominant cost, runs in parallel over
    /// bounded chunks of records. Both stages keep record order, so the events
    /// come out in exactly the order of the file.
    fn load_evtx(path: &Path) -> Result<Vec<Event>> {
        /// Records converted per parallel step: bounds the transient XML held
        /// in memory next to the events.
        const CHUNK: usize = 2048;

        let mut parser = evtx::EvtxParser::from_path(path)
            .map_err(|e| EvtxError::Parse(format!("Failed to open EVTX {}: {e}", path.display())))?
            .with_configuration(evtx::ParserSettings::default().num_threads(0));

        let mut events = Vec::new();
        let mut xml_chunk: Vec<String> = Vec::with_capacity(CHUNK);
        let mut records = parser.records();
        loop {
            xml_chunk.clear();
            for record in records.by_ref().take(CHUNK) {
                let record = record.map_err(|e| {
                    EvtxError::Parse(format!("EVTX record error in {}: {e}", path.display()))
                })?;
                xml_chunk.push(record.data);
            }
            if xml_chunk.is_empty() {
                break;
            }
            let converted: std::result::Result<Vec<Event>, ParseError> = xml_chunk
                .par_iter()
                .map(|xml| Event::from_xml_injected(xml, "windows", None))
                .collect();
            events.extend(converted?);
        }

        Ok(events)
    }
}

impl Default for EventCollector {
    fn default() -> Self {
        Self::new()
    }
}

/// Remove `Event.System.EventRecordID` from an event's JSON.
///
/// Events parsed from a static EVTX file are not present in the live Windows
/// Event Log.  Without this strip, `write_evtx` would re-export via
/// `EvtExportLog` (which queries the live log and finds nothing).  Stripping
/// the record id forces the pure-Rust EVTX writer path instead.
///
/// The event was just built, so its JSON `Arc` is unique and is edited in
/// place; `Arc::make_mut` only copies if the JSON were shared.
fn strip_record_id(event: &mut Event) {
    let has_record_id = event
        .event_json
        .get("Event")
        .and_then(|v| v.get("System"))
        .and_then(|v| v.as_object())
        .is_some_and(|system| system.contains_key("EventRecordID"));
    if !has_record_id {
        return;
    }
    if let Some(system) = Arc::make_mut(&mut event.event_json)
        .get_mut("Event")
        .and_then(|v| v.get_mut("System"))
        .and_then(|v| v.as_object_mut())
    {
        system.remove("EventRecordID");
    }
}

#[async_trait]
impl EventProducer for EventCollector {
    async fn run(
        self: Box<Self>,
        tx: mpsc::Sender<Event>,
        stop: watch::Receiver<bool>,
    ) -> std::result::Result<(), ProducerError> {
        for path in &self.files {
            if *stop.borrow() {
                break;
            }
            let events = match Self::load_evtx(path) {
                Ok(events) => events,
                Err(e) => {
                    warn!("Skipping EVTX {}: {e}", path.display());
                    continue;
                }
            };
            for mut event in events {
                if *stop.borrow() {
                    break;
                }
                strip_record_id(&mut event);
                tx.send(event).await.map_err(|_| {
                    ProducerError::Collector(Box::new(EvtxError::Parse(
                        "Channel send failed — receiver dropped".to_string(),
                    )))
                })?;
            }
        }
        Ok(())
    }
}

/// Parse a single EVTX file into a vector of `Event` objects.
///
/// Standalone function for backward compatibility.
pub fn parse_evtx_file(path: &Path) -> Result<Vec<Event>> {
    EventCollector::load_evtx(path)
}

/// Parse EVTX data from raw bytes into a vector of `Event` objects.
///
/// Useful for loading EVTX regression data from memory (e.g., regressiondata-check binary).
pub fn parse_evtx_bytes(data: &[u8]) -> Result<Vec<Event>> {
    let mut parser = evtx::EvtxParser::from_read_seek(std::io::Cursor::new(data)).map_err(|e| {
        EvtxError::Parse(format!("Failed to create EVTX parser from raw bytes: {e}"))
    })?;

    let mut events = Vec::new();

    for record in parser.records() {
        let record =
            record.map_err(|e| EvtxError::Parse(format!("EVTX record error in raw data: {e}")))?;
        let xml = std::str::from_utf8(record.data.as_bytes())
            .map_err(|_| EvtxError::Parse("Invalid UTF-8 in EVTX record".to_string()))?;
        let event = Event::from_xml_injected(xml, "windows", None)?;
        events.push(event);
    }

    Ok(events)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::tempdir;

    /// The parallel load yields exactly the events of a plain serial read, in
    /// the same order.
    #[test]
    fn test_parallel_load_keeps_record_order() {
        let fixture = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/sample.evtx");
        if !fixture.exists() {
            return; // fixture absent in some packaging contexts
        }
        let mut serial = evtx::EvtxParser::from_path(&fixture).unwrap();
        let expected: Vec<Vec<u8>> = serial
            .records()
            .map(|r| r.unwrap().data.into_bytes())
            .collect();

        let loaded = parse_evtx_file(&fixture).unwrap();
        let got: Vec<&[u8]> = loaded.iter().map(|e| e.event_raw.as_slice()).collect();
        assert!(!expected.is_empty());
        assert_eq!(got.len(), expected.len());
        for (g, e) in got.iter().zip(&expected) {
            assert_eq!(*g, e.as_slice());
        }
    }

    /// `strip_record_id` edits the unique JSON in place and keeps the rest.
    #[test]
    fn test_strip_record_id_removes_only_the_record_id() {
        let json = serde_json::json!({
            "Event": {"System": {"EventRecordID": 7, "EventID": 1}},
            "product": "windows"
        });
        let mut event = Event::new(json.clone(), json, Vec::new());
        strip_record_id(&mut event);
        assert!(
            event.event_json["Event"]["System"]
                .get("EventRecordID")
                .is_none()
        );
        assert_eq!(event.event_json["Event"]["System"]["EventID"], 1);
        assert_eq!(event.event_json["product"], "windows");
        // The raw view is a separate value and keeps the record id.
        assert_eq!(event.event_json_raw["Event"]["System"]["EventRecordID"], 7);
    }

    /// A corrupt file is skipped with a warning, the remaining files are still
    /// collected, and the producer completes successfully.
    #[tokio::test]
    async fn test_corrupt_file_is_skipped_others_still_collected() {
        let dir = tempdir().unwrap();
        let bad = dir.path().join("bad.evtx");
        let good = dir.path().join("good.evtx");
        let fixture = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/sample.evtx");
        if !fixture.exists() {
            return; // fixture absent in some packaging contexts
        }

        fs::write(&bad, b"this is not an evtx file").unwrap();
        fs::copy(&fixture, &good).unwrap();

        let expected = parse_evtx_file(&good).unwrap().len();
        assert!(expected > 0, "fixture should contain events");

        let mut collector = EventCollector::new();
        collector.add_file(bad);
        collector.add_file(good);

        let (tx, mut rx) = mpsc::channel::<Event>(256);
        let (_stop_tx, stop_rx) = watch::channel(false);

        Box::new(collector)
            .run(tx, stop_rx)
            .await
            .expect("collector should complete despite corrupt file");

        let mut got = 0usize;
        while rx.recv().await.is_some() {
            got += 1;
        }
        assert_eq!(got, expected);
    }
}
