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
//! them with [`linux_audit_parser`] (via [`parser`]) and emits one [`Event`]
//! per audit record (see [`event`]). Records sharing the same audit event id
//! (`msg=audit(timestamp:sequence)`) are grouped so each event carries the
//! complete original audit event lines — required for the `.log` regression
//! data file. The blocking tail loop runs in `spawn_blocking`; stopping is
//! done via the `stop` watch or by dropping the receiver. Log rotation (inode
//! change) is detected and the file re-opened. Non-Linux → silent stub.

pub mod event;
pub mod parser;

use async_trait::async_trait;
use sigmacatch_types::{Event, EventProducer};
use tokio::sync::{mpsc, watch};

/// Default path of the audit log.
pub const DEFAULT_LOG_PATH: &str = "/var/log/audit/audit.log";

/// Poll interval of the tail loop (how often new bytes are read from the file).
#[cfg(target_os = "linux")]
const TAIL_POLL_MS: u64 = 100;

/// Linux auditd event collector.
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
    ) -> anyhow::Result<()> {
        #[cfg(target_os = "linux")]
        {
            tail_loop(&self.path, tx, stop).await
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (tx, stop);
            Ok(())
        }
    }
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
    /// Audit event id (`timestamp:sequence`) of the group being collected.
    group_seq: Option<linux_audit_parser::EventID>,
    /// Original lines of the current group (each newline-terminated).
    group_lines: Vec<u8>,
    /// Parsed records of the current group, in log order.
    group_records: Vec<parser::Record>,
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
        // Tail semantics: start at the end of the existing file so only new
        // events are collected (historical audit events are not replayed).
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

    /// Read newly appended bytes, split them into lines and emit the parsed
    /// records as events through `tx`.
    fn poll(&mut self, tx: &mpsc::Sender<Event>) -> anyhow::Result<()> {
        use std::io::Read;

        if self.check_rotation()? {
            // The log was rotated: re-open the new file.
            self.reopen()?;
        }

        let mut buf = [0u8; 8192];
        let n = self.file.read(&mut buf)?;
        if n == 0 {
            // No new bytes: the current event group is complete once no
            // partial line is pending (auditd writes each event's records
            // contiguously). Flush it so alerts are not held until the next
            // event arrives.
            if self.pending.is_empty() {
                self.flush_group(tx)?;
            }
            return Ok(());
        }
        self.pending.extend_from_slice(&buf[..n]);
        self.drain_lines(tx)
    }

    /// Returns `true` when the log path now points to a different file
    /// (rotation). A transient metadata error (rename window) is ignored.
    fn check_rotation(&self) -> anyhow::Result<bool> {
        use std::os::unix::fs::MetadataExt;

        match std::fs::metadata(&self.path) {
            Ok(m) => Ok(m.dev() != self.dev || m.ino() != self.ino),
            Err(_) => Ok(false),
        }
    }

    /// Re-open the (new) log file and reset the read position to its start.
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
        // The old file is abandoned entirely: drop any half-collected group.
        self.group_seq = None;
        self.group_lines.clear();
        self.group_records.clear();
        // A fresh log file starts empty: read from the beginning.
        let _ = (&self.file).seek(SeekFrom::Start(0));
        tracing::info!("audit log rotated — re-opened {}", self.path);
        Ok(())
    }

    /// Process all complete lines in `pending`, keeping the trailing partial
    /// line for the next read. Records of the same audit event (same
    /// `timestamp:sequence`) are grouped; the group is flushed when the next
    /// event's first record arrives.
    fn drain_lines(&mut self, tx: &mpsc::Sender<Event>) -> anyhow::Result<()> {
        while let Some(pos) = self.pending.iter().position(|&b| b == b'\n') {
            // The line keeps its trailing newline: linux-audit-parser requires
            // the record to be newline-terminated.
            let line: Vec<u8> = self.pending.drain(..=pos).collect();
            if let Some(record) = parser::parse_line(&line) {
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

    /// Emit one [`Event`] per record of the current group. Every event of the
    /// group carries the group's complete original lines as `event_raw`.
    fn flush_group(&mut self, tx: &mpsc::Sender<Event>) -> anyhow::Result<()> {
        if self.group_records.is_empty() {
            self.group_seq = None;
            return Ok(());
        }
        let lines = std::mem::take(&mut self.group_lines);
        let records = std::mem::take(&mut self.group_records);
        self.group_seq = None;
        for record in records {
            if tx
                .blocking_send(event::record_to_event(&lines, &record))
                .is_err()
            {
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
}
