// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 sigmacatch contributors

//! Parse EVTX files into [`Event`] objects for the detection engine.
//!
//! Pattern: producer → mpsc channel → detection engine

//! `EventCollector` — file-based EVTX collector with internal FIFO.
//!
//! Pattern: collector → convert → FIFO (Event)

use std::path::Path;

use async_trait::async_trait;
use sigmacatch_types::{Event, EventProducer, ParseError, ProducerError, parse_winevt_xml_raw};

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

/// Re-export of the Winevt XML parser shared by the sigmacatch-types crate.
pub use sigmacatch_types::parse_winevt_xml;

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
    fn load_evtx(path: &Path) -> Result<Vec<Event>> {
        let mut parser = evtx::EvtxParser::from_path(path).map_err(|e| {
            EvtxError::Parse(format!("Failed to open EVTX {}: {e}", path.display()))
        })?;

        let mut events = Vec::new();

        for record in parser.records() {
            let record = record.map_err(|e| {
                EvtxError::Parse(format!("EVTX record error in {}: {e}", path.display()))
            })?;
            let xml = std::str::from_utf8(record.data.as_bytes())
                .map_err(|_| EvtxError::Parse("Invalid UTF-8 in EVTX record".to_string()))?;
            let event_json_raw = parse_winevt_xml_raw(xml)?;
            let event_json = parse_winevt_xml(xml)?;
            let event_raw = record.data.as_bytes().to_vec();

            let mut event = Event {
                event_json_raw,
                event_json,
                event_raw,
                is_etw: false,
            };
            event.inject_logsource_fields();
            events.push(event);
        }

        Ok(events)
    }
}

impl Default for EventCollector {
    fn default() -> Self {
        Self::new()
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
            let events = Self::load_evtx(path).map_err(|e| {
                ProducerError::Collector(Box::new(EvtxError::Parse(format!(
                    "Failed to load EVTX {}: {e}",
                    path.display()
                ))))
            })?;
            for event in events {
                if *stop.borrow() {
                    break;
                }
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
/// Useful for loading EVTX regression data from memory (e.g., sigmacatch-check binary).
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
        let event_json_raw = parse_winevt_xml_raw(xml)?;
        let event_json = parse_winevt_xml(xml)?;
        let event_raw = record.data.as_bytes().to_vec();

        let mut event = Event {
            event_json_raw,
            event_json,
            event_raw,
            is_etw: false,
        };
        event.inject_logsource_fields();
        events.push(event);
    }

    Ok(events)
}
