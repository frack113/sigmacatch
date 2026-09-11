// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 sigmacatch contributors

//! Shared tail driver for the Linux collectors (auditd, syslog, sysmon).
//!
//! Reads appended lines from a log file, detects log rotation (inode change)
//! and hands each complete line to a [`LineHandler`]. The handler is pure — it
//! turns whole lines into events and returns them — while this module owns the
//! channel, the file handle and the poll/rotation lifecycle. Runs in a blocking
//! task (callers use `spawn_blocking`).
//!
//! # Test contract (determinism by construction)
//!
//! - Tail starts at end-of-file: pre-existing content is never emitted.
//! - Rotation is detected by `(dev, ino)` identity change and re-opens the
//!   file at offset 0; the rotated file survives (smoke-checkable).
//! - Complete lines are emitted in order; a partial trailing line stays
//!   buffered until its newline arrives.
//! - `on_idle` fires on every poll where no new byte and no partial line is
//!   pending — this is the audited "record group complete" signal.
//! - Stop is honoured within one tick of `stop` being set or the receiver
//!   being dropped.
//! - The `LineHandler` is pure: it never touches the channel or the file.
//!
//! Tests therefore wait on the one-shot [`TailOptions::ready`] after open +
//! seek-to-EOF + first poll instead of a blind sleep (a write landing before
//! the tail is attached is lost silently), narrow the semantic idle window to
//! `with_poll_interval` when a record-group flush is under test, and wait on
//! `timeout(…, rx.recv())` everywhere else. A deadline paired with a
//! predicate is a bound; an unguarded `sleep` is a gamble.

use crate::types::Event;
use tokio::sync::{mpsc, oneshot, watch};

/// Poll interval of the tail loop (how often new bytes are read from the file).
const TAIL_POLL_MS: u64 = 100;

/// Process lines read by the shared tail driver.
///
/// Implementations are pure: they return the events to emit and never talk to
/// the channel themselves. `Event` return values are only sent when a full
/// line arrives (or, in auditd, when an idle poll closes a record group).
pub trait LineHandler {
    /// Called for every complete line (including the trailing newline).
    ///
    /// Normally yields zero or one event; grouped audit records may flush the
    /// previous group on a line boundary.
    fn on_line(&mut self, line: &[u8]) -> anyhow::Result<Vec<Event>>;

    /// Called when the file is idle (no new bytes and no partial line).
    /// Used by auditd to flush an in-progress record group.
    fn on_idle(&mut self) -> anyhow::Result<Vec<Event>> {
        Ok(Vec::new())
    }

    /// Called after a rotation was detected and the file re-opened.
    /// Used to drop in-flight grouping state.
    fn on_rotate(&mut self) {}
}

/// Tail-loop timing and test hook carried by [`run`].
///
/// [`Default`] is the historic production behaviour: a 100 ms poll/idle
/// period and no readiness signal. The tick is product semantics — auditd
/// flushes a record group on an idle poll — so it is a latency budget that
/// tests *inject*, never a value this module removes. Tests use the one-shot
/// barrier instead of sleeping blindly and narrow the idle window when the
/// flush itself is under test.
pub struct TailOptions {
    /// How often new bytes are read from the file and, when the file is
    /// idle, how long an aggregated record group waits before flush.
    pub poll_interval: std::time::Duration,
    /// One-shot fired once the file is open, seeked to end-of-file and the
    /// first poll completed. `None` disables the barrier (production).
    pub ready: Option<oneshot::Sender<()>>,
}

impl Default for TailOptions {
    fn default() -> Self {
        Self {
            poll_interval: std::time::Duration::from_millis(TAIL_POLL_MS),
            ready: None,
        }
    }
}

impl TailOptions {
    /// Set the poll/idle period (default 100 ms). Shortening it only changes
    /// the latency budget; it does not change what the semantics produce.
    pub fn with_poll_interval(mut self, poll_interval: std::time::Duration) -> Self {
        self.poll_interval = poll_interval;
        self
    }

    /// Arm the READY barrier: await this one-shot before appending to the
    /// file under test. After it fires the tail is attached (open + seek to
    /// EOF + first poll), so the append cannot be lost to the start-up race.
    pub fn with_ready(mut self, ready: oneshot::Sender<()>) -> Self {
        self.ready = Some(ready);
        self
    }
}

/// Tail `path` in a blocking loop, driving `handler` with every new line.
///
/// Starts at end-of-file, detects log rotation by (dev, ino) identity change,
/// re-opens rotated files from offset 0, and exits when `stop` is set or the
/// channel receiver is dropped. When [`TailOptions::ready`] is armed it is
/// fired after the first poll (see the module-level test contract).
pub fn run<H: LineHandler + Send>(
    path: &str,
    mut handler: H,
    tx: mpsc::Sender<Event>,
    stop: watch::Receiver<bool>,
    options: TailOptions,
) -> anyhow::Result<()> {
    use std::fs::OpenOptions;

    let TailOptions {
        poll_interval,
        ready,
    } = options;

    let file = OpenOptions::new()
        .read(true)
        .open(path)
        .map_err(|e| anyhow::anyhow!("failed to open {path}: {e}"))?;
    let mut state = TailState::new(file, path.to_string());

    // READY barrier: one poll after open+seek, then signal the test writer
    // that the tail is attached. Any append after this point is guaranteed to
    // be read, never lost to the start-up race.
    let _ = state.poll(&mut handler, &tx);
    if let Some(ready) = ready {
        tracing::info!("tail attached to {path}");
        let _ = ready.send(());
    }

    loop {
        if *stop.borrow() || tx.is_closed() {
            break;
        }
        if let Err(e) = state.poll(&mut handler, &tx) {
            tracing::warn!("tail {path} error: {e}");
        }
        std::thread::sleep(poll_interval);
    }
    Ok(())
}

/// Tracks the open log file, its identity (dev/ino) for rotation detection
/// and partial lines.
struct TailState {
    file: std::fs::File,
    path: String,
    dev: u64,
    ino: u64,
    pending: Vec<u8>,
}

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
        }
    }

    fn poll<H: LineHandler>(
        &mut self,
        handler: &mut H,
        tx: &mpsc::Sender<Event>,
    ) -> anyhow::Result<()> {
        use std::io::Read;

        if self.check_rotation() {
            self.reopen()?;
            handler.on_rotate();
        }

        let mut buf = [0u8; 8192];
        let n = self.file.read(&mut buf)?;
        if n == 0 {
            if self.pending.is_empty() {
                // Idle poll: no partial line waiting for more bytes. Handlers
                // (auditd) use this as the "record group complete" signal.
                self.send_all(handler.on_idle()?, tx);
            }
            return Ok(());
        }
        self.pending.extend_from_slice(&buf[..n]);
        self.drain_lines(handler, tx)
    }

    /// Send every complete line in `pending` through the handler.
    fn drain_lines<H: LineHandler>(
        &mut self,
        handler: &mut H,
        tx: &mpsc::Sender<Event>,
    ) -> anyhow::Result<()> {
        while let Some(pos) = self.pending.iter().position(|&b| b == b'\n') {
            let line: Vec<u8> = self.pending.drain(..=pos).collect();
            if !self.send_all(handler.on_line(&line)?, tx) {
                break; // channel closed — the main loop exits on the next poll
            }
        }
        Ok(())
    }

    /// A transient metadata error is treated as "no rotation" so the tail
    /// survives a temporary permission/gone moment on the path.
    fn check_rotation(&self) -> bool {
        use std::os::unix::fs::MetadataExt;
        match std::fs::metadata(&self.path) {
            Ok(m) => m.dev() != self.dev || m.ino() != self.ino,
            Err(_) => false,
        }
    }

    fn reopen(&mut self) -> anyhow::Result<()> {
        use std::io::{Seek, SeekFrom};
        use std::os::unix::fs::MetadataExt;

        let file = std::fs::OpenOptions::new()
            .read(true)
            .open(&self.path)
            .map_err(|e| anyhow::anyhow!("failed to re-open {}: {e}", self.path))?;
        let (dev, ino) = match file.metadata() {
            Ok(m) => (m.dev(), m.ino()),
            Err(_) => (0, 0),
        };
        self.file = file;
        self.dev = dev;
        self.ino = ino;
        self.pending.clear();
        let _ = (&self.file).seek(SeekFrom::Start(0));
        tracing::info!("{} rotated — re-opened", self.path);
        Ok(())
    }

    /// Send events through `tx`. Returns `false` when the receiver is gone.
    fn send_all(&self, events: Vec<Event>, tx: &mpsc::Sender<Event>) -> bool {
        for event in events {
            if tx.blocking_send(event).is_err() {
                return false;
            }
        }
        true
    }
}
