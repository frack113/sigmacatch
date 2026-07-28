// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 sigmacatch contributors

//! `EventCollector` — file-based EVTX collector with internal FIFO.
//!
//! Pattern: collector → convert → FIFO (Event)

use std::path::Path;

use anyhow::{Context, Result};
use async_trait::async_trait;
use sigmacatch_types::{parse_winevt_xml, Event, EventProducer};
use tokio::sync::mpsc;

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
        let mut parser = evtx::EvtxParser::from_path(path)
            .with_context(|| format!("Failed to open EVTX {}", path.display()))?;

        let mut events = Vec::new();

        for record in parser.records() {
            let record =
                record.with_context(|| format!("EVTX record error in {}", path.display()))?;
            let xml = std::str::from_utf8(record.data.as_bytes())
                .context("Invalid UTF-8 in EVTX record")?;
            let event_json = parse_winevt_xml(xml)?;
            let event_raw = record.data.as_bytes().to_vec();

            let mut event = Event {
                event_json,
                event_raw,
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
    async fn run(self, tx: mpsc::Sender<Event>) -> anyhow::Result<()> {
        for path in &self.files {
            let events = Self::load_evtx(path)
                .with_context(|| format!("Failed to load EVTX {}", path.display()))?;
            for event in events {
                tx.send(event)
                    .await
                    .context("Channel send failed — receiver dropped")?;
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
/// Useful for loading EVTX regression data from memory (e.g., evtx_check binary).
pub fn parse_evtx_bytes(data: &[u8]) -> Result<Vec<Event>> {
    let mut parser = evtx::EvtxParser::from_read_seek(std::io::Cursor::new(data))
        .context("Failed to create EVTX parser from raw bytes")?;

    let mut events = Vec::new();

    for record in parser.records() {
        let record = record.with_context(|| "EVTX record error in raw data")?;
        let xml =
            std::str::from_utf8(record.data.as_bytes()).context("Invalid UTF-8 in EVTX record")?;
        let event_json = parse_winevt_xml(xml)?;
        let event_raw = record.data.as_bytes().to_vec();

        let mut event = Event {
            event_json,
            event_raw,
        };
        event.inject_logsource_fields();
        events.push(event);
    }

    Ok(events)
}
