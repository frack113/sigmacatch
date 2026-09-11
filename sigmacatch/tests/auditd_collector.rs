// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 sigmacatch contributors

//! Integration tests for the auditd tail collector (Linux only).
//!
//! Deterministic by construction: every wait is a deadline paired with a
//! predicate — never a blind sleep. A record group only flushes on an idle
//! poll or on a different event id, so the 10 ms `poll_interval` injected
//! below is the *flush latency budget under test*, shortened but otherwise
//! identical in kind to the 100 ms production default.

#![cfg(all(target_os = "linux", feature = "auditd"))]

use sigmacatch::inputs::TailOptions;
use sigmacatch::inputs::auditd::EventCollector;
use sigmacatch::types::EventProducer;
use std::io::Write;
use std::time::Duration;
use tokio::sync::{mpsc, oneshot, watch};

const SYSCALL: &[u8] = b"type=SYSCALL msg=audit(1717056137.482:90412): arch=c000003e syscall=257 success=yes exit=3 ppid=20471 pid=20488 comm=\"cat\" exe=\"/usr/bin/cat\" key=\"identity\"\n";
const PATH: &[u8] =
    b"type=PATH msg=audit(1717056137.482:90412): item=1 name=\"/etc/shadow\" nametype=NORMAL\n";
const EXECVE: &[u8] =
    b"type=EXECVE msg=audit(1717056137.482:90412): argc=3 a0=\"cat\" a1=\"/etc/shadow\"\n";
const NEXT_SYSCALL: &[u8] = b"type=SYSCALL msg=audit(1717056140.100:90413): arch=c000003e syscall=59 success=yes exit=0 ppid=1 pid=500 comm=\"sh\" exe=\"/bin/sh\" key=\"exec\"\n";

/// 10 ms idle window: the auditd record group is flushed by an idle tail
/// poll, so the injected interval IS the flush budget under test.
const IDLE_WINDOW_MS: u64 = 10;

/// Spawn the collector on `path` and return the event side plus the READY
/// barrier the tail fires once attached (open + seek-to-EOF + first poll).
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
    let collector =
        EventCollector::with_path(path.to_string()).tail_options(options.with_ready(ready_tx));
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
async fn test_tail_emits_per_record_events() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("audit.log");
    std::fs::File::create(&path).unwrap();

    let (mut rx, stop_tx, ready) = run_collector(
        path.to_str().unwrap(),
        TailOptions::default().with_poll_interval(Duration::from_millis(IDLE_WINDOW_MS)),
    )
    .await;
    await_ready(ready).await;

    // One audit event, three records sharing the same EventID. The group
    // completes only at the next idle poll (IDLE_WINDOW_MS).
    let group = [SYSCALL, PATH, EXECVE].concat();
    std::fs::OpenOptions::new()
        .append(true)
        .open(&path)
        .unwrap()
        .write_all(&group)
        .unwrap();

    for expected in ["SYSCALL", "PATH", "EXECVE"] {
        let e = tokio::time::timeout(Duration::from_secs(2), rx.recv())
            .await
            .expect("event must arrive")
            .expect("present");
        assert_eq!(e.event_json["type"], expected);
        assert_eq!(e.event_json["service"], "auditd");
        // Every record of the group carries the full raw event lines.
        assert_eq!(e.event_raw, group);
    }

    stop_tx.send(true).unwrap();
}

#[tokio::test]
async fn test_tail_handles_next_event() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("audit.log");
    std::fs::File::create(&path).unwrap();

    let (mut rx, stop_tx, ready) = run_collector(
        path.to_str().unwrap(),
        TailOptions::default().with_poll_interval(Duration::from_millis(IDLE_WINDOW_MS)),
    )
    .await;
    await_ready(ready).await;

    std::fs::OpenOptions::new()
        .append(true)
        .open(&path)
        .unwrap()
        .write_all(SYSCALL)
        .unwrap();

    // A lone SYSCALL is a complete group once the idle poll flushes it.
    let first = tokio::time::timeout(Duration::from_secs(2), rx.recv())
        .await
        .expect("first event must arrive")
        .expect("present");
    assert_eq!(first.event_json_raw["stamp"]["sequence"], 90412);

    std::fs::OpenOptions::new()
        .append(true)
        .open(&path)
        .unwrap()
        .write_all(NEXT_SYSCALL)
        .unwrap();

    let second = tokio::time::timeout(Duration::from_secs(2), rx.recv())
        .await
        .expect("next event must arrive")
        .expect("present");
    assert_eq!(second.event_json_raw["stamp"]["sequence"], 90413);
    assert_ne!(first.event_raw, second.event_raw);

    stop_tx.send(true).unwrap();
}

#[tokio::test]
async fn test_tail_detects_rotation() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("audit.log");
    // The original file is kept open (like auditd) but never written to.
    let _file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
        .unwrap();

    let (mut rx, stop_tx, ready) = run_collector(
        path.to_str().unwrap(),
        TailOptions::default().with_poll_interval(Duration::from_millis(IDLE_WINDOW_MS)),
    )
    .await;
    await_ready(ready).await;

    // Simulate logrotate: rename + recreate the log.
    std::fs::rename(&path, dir.path().join("audit.log.1")).unwrap();
    let mut new_file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
        .unwrap();
    new_file.write_all(SYSCALL).unwrap();
    new_file.flush().unwrap();

    let e = tokio::time::timeout(Duration::from_secs(2), rx.recv())
        .await
        .expect("event from rotated file must arrive")
        .expect("present");
    assert_eq!(e.event_json["type"], "SYSCALL");
    assert!(dir.path().join("audit.log.1").exists());

    stop_tx.send(true).unwrap();
}

#[tokio::test]
async fn test_stop_returns_promptly() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("audit.log");
    std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
        .unwrap();

    let (mut rx, stop_tx, ready) = run_collector(
        path.to_str().unwrap(),
        TailOptions::default().with_poll_interval(Duration::from_millis(IDLE_WINDOW_MS)),
    )
    .await;
    await_ready(ready).await;
    stop_tx.send(true).unwrap();

    // One tick after stop the tail exits and the channel closes.
    let end = tokio::time::timeout(Duration::from_secs(2), rx.recv())
        .await
        .expect("collector must exit within one tick of stop");
    assert!(end.is_none(), "channel must close when the tail stops");
}
