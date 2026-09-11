// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 sigmacatch contributors

//! Integration tests for the builtin syslog tail collector (Linux only).
//!
//! Deterministic by construction: every wait is a deadline paired with a
//! predicate (`await_ready` then `timeout(…, rx.recv())`) — never a blind
//! sleep. The READY barrier guarantees a write cannot land before the tail
//! is attached (open + seek-to-EOF + first poll), which would lose it.

#![cfg(all(target_os = "linux", feature = "builtin"))]

use sigmacatch::inputs::TailOptions;
use sigmacatch::inputs::syslog::EventCollector;
use sigmacatch::types::EventProducer;
use std::io::Write;
use std::time::Duration;
use tokio::sync::{mpsc, oneshot, watch};

const SSHD: &[u8] =
    b"May 11 14:23:33 host123 sshd[12345]: Failed password for invalid user root from 1.2.3.4\n";
const CRON: &[u8] = b"May 11 14:23:40 host123 CRON[90]: (root) CMD (run-pam)\n";
const KERNEL: &[u8] = b"May 11 14:23:41 host123 kernel: [123456.789] EXT4-fs(sda1)\n";

/// Spawn the collector on `path` and return the event side plus the READY
/// barrier the tail fires once attached. The test awaits the barrier before
/// appending any line.
async fn run_collector(
    path: &str,
    options: TailOptions,
) -> (
    mpsc::Receiver<sigmacatch::types::Event>,
    watch::Sender<bool>,
    oneshot::Receiver<()>,
) {
    let (ready_tx, ready_rx) = oneshot::channel();
    let (tx, rx) = mpsc::channel(100);
    let (stop_tx, stop_rx) = watch::channel(false);
    let collector = EventCollector::with_path(Some(path.to_string()))
        .tail_options(options.with_ready(ready_tx));
    tokio::spawn(async move {
        let _ = Box::new(collector).run(tx, stop_rx).await;
    });
    (rx, stop_tx, ready_rx)
}

async fn await_ready(ready: oneshot::Receiver<()>) {
    tokio::time::timeout(Duration::from_secs(5), ready)
        .await
        .expect("tail must signal READY within 5 s")
        .expect("READY sender dropped before firing");
}

#[tokio::test]
async fn test_collector_emits_per_valid_line() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("syslog");
    std::fs::File::create(&path).unwrap();

    let (mut rx, stop_tx, ready) =
        run_collector(path.to_str().unwrap(), TailOptions::default()).await;
    await_ready(ready).await;

    std::fs::OpenOptions::new()
        .append(true)
        .open(&path)
        .unwrap()
        .write_all(SSHD)
        .unwrap();
    std::fs::OpenOptions::new()
        .append(true)
        .open(&path)
        .unwrap()
        .write_all(CRON)
        .unwrap();
    std::fs::OpenOptions::new()
        .append(true)
        .open(&path)
        .unwrap()
        .write_all(KERNEL)
        .unwrap();

    let e1 = tokio::time::timeout(Duration::from_secs(2), rx.recv())
        .await
        .expect("sshd event must arrive")
        .expect("present");
    assert_eq!(e1.event_json["product"], "linux");
    assert_eq!(e1.event_json["service"], "sshd");
    assert_eq!(e1.event_json["program"], "sshd");
    assert_eq!(
        e1.event_json["message"],
        "Failed password for invalid user root from 1.2.3.4"
    );
    assert_eq!(e1.event_raw, SSHD);

    let e2 = tokio::time::timeout(Duration::from_secs(2), rx.recv())
        .await
        .expect("cron event must arrive")
        .expect("present");
    assert_eq!(e2.event_json["service"], "cron");
    assert_eq!(e2.event_json["program"], "CRON");
    assert_eq!(e2.event_raw, CRON);

    // The kernel tag is not in the taxonomy, so its service keeps the raw name.
    let e3 = tokio::time::timeout(Duration::from_secs(2), rx.recv())
        .await
        .expect("kernel event must arrive")
        .expect("present");
    assert_eq!(e3.event_json["service"], "kernel");
    assert_eq!(e3.event_json["program"], "kernel");

    stop_tx.send(true).unwrap();
}

#[tokio::test]
async fn test_collector_skips_non_matching_lines() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("syslog");
    std::fs::File::create(&path).unwrap();

    let (mut rx, stop_tx, ready) =
        run_collector(path.to_str().unwrap(), TailOptions::default()).await;
    await_ready(ready).await;

    std::fs::OpenOptions::new()
        .append(true)
        .open(&path)
        .unwrap()
        .write_all(b"this is not a syslog line\n")
        .unwrap();
    std::fs::OpenOptions::new()
        .append(true)
        .open(&path)
        .unwrap()
        .write_all(SSHD)
        .unwrap();

    // Only the valid syslog line is emitted.
    let e = tokio::time::timeout(Duration::from_secs(2), rx.recv())
        .await
        .expect("valid event must arrive")
        .expect("present");
    assert_eq!(e.event_json["service"], "sshd");

    // No spurious event follows (stop sent after: a closed channel would
    // return Ok(None) instead of timing out). Bounded absence wait.
    let extra = tokio::time::timeout(Duration::from_millis(300), rx.recv()).await;
    assert!(extra.is_err(), "non-matching lines must be dropped");
    stop_tx.send(true).unwrap();
}

#[tokio::test]
async fn test_collector_detects_rotation() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("syslog");
    // The original file is kept open (like rsyslog) but never written to.
    let _file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
        .unwrap();

    let (mut rx, stop_tx, ready) =
        run_collector(path.to_str().unwrap(), TailOptions::default()).await;
    await_ready(ready).await;

    // Simulate rsyslog rotation: rename + recreate the log.
    std::fs::rename(&path, dir.path().join("syslog.1")).unwrap();
    let mut new_file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
        .unwrap();
    new_file.write_all(SSHD).unwrap();
    new_file.flush().unwrap();

    let event = tokio::time::timeout(Duration::from_secs(2), rx.recv())
        .await
        .expect("event from rotated file must arrive")
        .expect("present");
    assert_eq!(event.event_json["service"], "sshd");
    assert!(dir.path().join("syslog.1").exists());

    stop_tx.send(true).unwrap();
}

#[tokio::test]
async fn test_stop_returns_promptly() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("syslog");
    std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
        .unwrap();

    let (mut rx, stop_tx, ready) =
        run_collector(path.to_str().unwrap(), TailOptions::default()).await;
    await_ready(ready).await;
    stop_tx.send(true).unwrap();

    // One tick after stop the tail exits and the channel closes.
    let end = tokio::time::timeout(Duration::from_secs(2), rx.recv())
        .await
        .expect("collector must exit within one tick of stop");
    assert!(end.is_none(), "channel must close when the tail stops");
}
