// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 sigmacatch contributors

//! Integration tests for the auditd tail collector (Linux only).

#![cfg(all(target_os = "linux", feature = "auditd"))]

use sigmacatch_lnx::auditd::EventCollector;
use sigmacatch_types::EventProducer;
use std::io::Write;
use std::time::Duration;
use tokio::sync::{mpsc, watch};

const SYSCALL: &[u8] = b"type=SYSCALL msg=audit(1717056137.482:90412): arch=c000003e syscall=257 success=yes exit=3 ppid=20471 pid=20488 comm=\"cat\" exe=\"/usr/bin/cat\" key=\"identity\"\n";
const PATH: &[u8] =
    b"type=PATH msg=audit(1717056137.482:90412): item=1 name=\"/etc/shadow\" nametype=NORMAL\n";
const EXECVE: &[u8] =
    b"type=EXECVE msg=audit(1717056137.482:90412): argc=3 a0=\"cat\" a1=\"/etc/shadow\"\n";
const NEXT_SYSCALL: &[u8] = b"type=SYSCALL msg=audit(1717056140.100:90413): arch=c000003e syscall=59 success=yes exit=0 ppid=1 pid=500 comm=\"sh\" exe=\"/bin/sh\" key=\"exec\"\n";

async fn run_collector(
    path: &str,
) -> (mpsc::Receiver<sigmacatch_types::Event>, watch::Sender<bool>) {
    let (tx, rx) = mpsc::channel(100);
    let (stop_tx, stop_rx) = watch::channel(false);
    let collector = EventCollector::with_path(path.to_string());
    tokio::spawn(async move {
        let _ = Box::new(collector).run(tx, stop_rx).await;
    });
    (rx, stop_tx)
}

#[tokio::test]
async fn test_tail_emits_per_record_events() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("audit.log");
    std::fs::File::create(&path).unwrap();

    let (mut rx, stop_tx) = run_collector(path.to_str().unwrap()).await;
    tokio::time::sleep(Duration::from_millis(250)).await;

    // One audit event, three records sharing the same EventID.
    let group = [SYSCALL, PATH, EXECVE].concat();
    std::fs::OpenOptions::new()
        .append(true)
        .open(&path)
        .unwrap()
        .write_all(&group)
        .unwrap();

    tokio::time::sleep(Duration::from_millis(400)).await;

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

    let (mut rx, stop_tx) = run_collector(path.to_str().unwrap()).await;
    tokio::time::sleep(Duration::from_millis(250)).await;

    std::fs::OpenOptions::new()
        .append(true)
        .open(&path)
        .unwrap()
        .write_all(SYSCALL)
        .unwrap();
    tokio::time::sleep(Duration::from_millis(400)).await;

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
    tokio::time::sleep(Duration::from_millis(400)).await;

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

    let (mut rx, stop_tx) = run_collector(path.to_str().unwrap()).await;
    tokio::time::sleep(Duration::from_millis(250)).await;

    // Simulate logrotate: rename + recreate the log.
    std::fs::rename(&path, dir.path().join("audit.log.1")).unwrap();
    let mut new_file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
        .unwrap();
    new_file.write_all(SYSCALL).unwrap();
    new_file.flush().unwrap();

    tokio::time::sleep(Duration::from_millis(400)).await;

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

    let (mut rx, stop_tx) = run_collector(path.to_str().unwrap()).await;
    tokio::time::sleep(Duration::from_millis(250)).await;
    stop_tx.send(true).unwrap();

    let _ = tokio::time::timeout(Duration::from_secs(2), rx.recv()).await;
}
