// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 sigmacatch contributors

//! `EventCollector` — file-based EVTX collector with internal FIFO.
//!
//! Pattern: collector → convert → FIFO (Event)

use std::collections::VecDeque;
use std::path::Path;

use anyhow::{Context, Result};
use sigmacatch_types::{parse_winevt_xml, Event};

/// EVTX file collector.
///
/// Loads `.evtx` files via `load_evtx()`, converts records to `Event`,
/// and pushes them into an internal FIFO.
///
/// # Example
/// ```
/// use input_evtx::EventCollector;
///
/// let mut collector = EventCollector::new();
/// // collector.load_evtx(path).unwrap();
/// let events = collector.get_events();
/// ```
pub struct EventCollector {
    fifo: VecDeque<Event>,
}

impl EventCollector {
    /// Create an empty collector.
    pub fn new() -> Self {
        Self {
            fifo: VecDeque::new(),
        }
    }

    /// Load a single EVTX file into the FIFO.
    ///
    /// All events from the file are parsed first into a local buffer. Only on
    /// complete success are they moved into the FIFO — a partial failure never
    /// leaves the collector in a partially-loaded state.
    pub fn load_evtx(&mut self, path: &Path) -> Result<()> {
        let mut parser = evtx::EvtxParser::from_path(path)
            .with_context(|| format!("Failed to open EVTX {}", path.display()))?;

        let mut buffer = Vec::new();

        for record in parser.records() {
            let record =
                record.with_context(|| format!("EVTX record error in {}", path.display()))?;
            let xml = std::str::from_utf8(record.data.as_bytes())
                .context("Invalid UTF-8 in EVTX record")?;
            let event_json = parse_winevt_xml(xml)?;
            let event_raw = record.data.as_bytes().to_vec();

            buffer.push(Event {
                event_json,
                event_raw,
            });
        }

        self.fifo.extend(buffer);
        Ok(())
    }

    /// Drain all collected events from the FIFO.
    pub fn get_events(&mut self) -> Vec<Event> {
        self.fifo.drain(..).collect()
    }

    /// Load EVTX data from raw bytes into the FIFO.
    ///
    /// Parses binary EVTX records directly from the provided slice.
    /// All events are parsed first into a local buffer. Only on complete
    /// success are they moved into the FIFO — a partial failure never
    /// leaves the collector in a partially-loaded state.
    pub fn from_bytes(&mut self, data: &[u8]) -> Result<()> {
        let mut parser = evtx::EvtxParser::from_read_seek(std::io::Cursor::new(data))
            .context("Failed to create EVTX parser from raw bytes")?;

        let mut buffer = Vec::new();

        for record in parser.records() {
            let record = record.with_context(|| "EVTX record error in raw data")?;
            let xml = std::str::from_utf8(record.data.as_bytes())
                .context("Invalid UTF-8 in EVTX record")?;
            let event_json = parse_winevt_xml(xml)?;
            let event_raw = record.data.as_bytes().to_vec();

            buffer.push(Event {
                event_json,
                event_raw,
            });
        }

        self.fifo.extend(buffer);
        Ok(())
    }
}

impl Default for EventCollector {
    fn default() -> Self {
        Self::new()
    }
}

/// Parse a single EVTX file into a vector of `Event` objects.
///
/// Standalone function for backward compatibility. Prefer `EventCollector::load_evtx` for
/// batch or pipeline usage.
pub fn parse_evtx_file(path: &Path) -> Result<Vec<Event>> {
    let mut collector = EventCollector::new();
    collector.load_evtx(path)?;
    Ok(collector.get_events())
}
