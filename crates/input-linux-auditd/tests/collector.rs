// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 sigmacatch contributors

//! Integration tests for the auditd tail collector (Linux only).

#![cfg(target_os = "linux")]

use input_linux_auditd::EventCollector;
use sigmacatch_types::EventProducer;
use std::io::Write;
use std::time::Duration;
use tokio::sync::{mpsc, watch};

const SYSCALL: &[u8] = b"type=SYSCALL msg=audit(1717056137.482:90412): arch=c000003e syscall=257 success=yes exit=3 ppid=20471 pid=20488 comm=\"cat\" exe=\"/usr/bin/cat\" key=\"identity\"\n";
const PATH: &[u8] =
    b"type=PATH msg=audit(1717056137.482:90412): item=1 name=\"/etc/shadow\" nametype=NORMAL\n";
const EXECVE: &[u8] =
    b"type=EXECVE msg=audit(1717056137.482:90412): argc=3 a0=\"cat\" a1=\"/etc/shadow\"\n";

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
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
        .unwrap();
    // Pre-existing content is not replayed (tail starts at EOF).
    file.write_all(b"type=SYSCALL msg=audit(1717056100.000:90000): old=1\n")
        .unwrap();

    let (mut rx, stop_tx) = run_collector(path.to_str().unwrap()).await;
    tokio::time::sleep(Duration::from_millis(250)).await;

    file.write_all(SYSCALL).unwrap();
    file.write_all(PATH).unwrap();
    file.write_all(EXECVE).unwrap();
    file.flush().unwrap();

    tokio::time::sleep(Duration::from_millis(300)).await;
    stop_tx.send(true).unwrap();

    // One event per record — the three records of the same audit event arrive
    // as three distinct events, each keeping its own `type`.
    let e1 = tokio::time::timeout(Duration::from_secs(2), rx.recv())
        .await
        .expect("record 1 must arrive")
        .expect("present");
    assert_eq!(e1.event_json["type"], "SYSCALL");
    assert_eq!(e1.event_json["exe"], "/usr/bin/cat");
    assert_eq!(e1.event_json["product"], "linux");
    assert_eq!(e1.event_json["service"], "auditd");

    let e2 = tokio::time::timeout(Duration::from_secs(2), rx.recv())
        .await
        .expect("record 2 must arrive")
        .expect("present");
    assert_eq!(e2.event_json["type"], "PATH");
    assert_eq!(e2.event_json["name"], "/etc/shadow");

    let e3 = tokio::time::timeout(Duration::from_secs(2), rx.recv())
        .await
        .expect("record 3 must arrive")
        .expect("present");
    assert_eq!(e3.event_json["type"], "EXECVE");
    assert_eq!(e3.event_json["a0"], "cat");

    // The three records share the same audit event stamp.
    assert_eq!(e1.event_json_raw["stamp"], e2.event_json_raw["stamp"]);
    assert_eq!(e2.event_json_raw["stamp"], e3.event_json_raw["stamp"]);
    assert_eq!(e1.event_json_raw["stamp"]["sequence"], 90412);

    // Every record of the event carries the complete original audit event
    // lines (required for the `.log` regression data file).
    let full_group = [SYSCALL, PATH, EXECVE].concat();
    assert_eq!(e1.event_raw, full_group);
    assert_eq!(e3.event_raw, full_group);
}

#[tokio::test]
async fn test_tail_handles_next_event() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("audit.log");
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
        .unwrap();

    let (mut rx, stop_tx) = run_collector(path.to_str().unwrap()).await;
    tokio::time::sleep(Duration::from_millis(250)).await;

    file.write_all(SYSCALL).unwrap();
    let next = b"type=SYSCALL msg=audit(1717056138.100:90413): arch=c000003e syscall=59 success=yes exit=0 pid=20500 comm=\"id\"\n";
    file.write_all(next).unwrap();
    file.flush().unwrap();

    tokio::time::sleep(Duration::from_millis(300)).await;
    stop_tx.send(true).unwrap();

    let e1 = tokio::time::timeout(Duration::from_secs(2), rx.recv())
        .await
        .expect("first event")
        .expect("present");
    assert_eq!(e1.event_json["type"], "SYSCALL");
    assert_eq!(e1.event_json["comm"], "cat");
    assert_eq!(e1.event_json_raw["stamp"]["sequence"], 90412);

    let e2 = tokio::time::timeout(Duration::from_secs(2), rx.recv())
        .await
        .expect("second event")
        .expect("present");
    assert_eq!(e2.event_json["type"], "SYSCALL");
    assert_eq!(e2.event_json["comm"], "id");
    assert_eq!(e2.event_json_raw["stamp"]["sequence"], 90413);

    // Grouping boundaries: each event's `event_raw` only holds its own lines.
    assert_eq!(e1.event_raw, SYSCALL);
    assert_eq!(e2.event_raw, next);
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

    // Simulate auditd rotation: rename + recreate the log.
    std::fs::rename(&path, dir.path().join("audit.log.1")).unwrap();
    let mut new_file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
        .unwrap();
    new_file.write_all(SYSCALL).unwrap();
    new_file.flush().unwrap();

    tokio::time::sleep(Duration::from_millis(400)).await;
    stop_tx.send(true).unwrap();

    let event = tokio::time::timeout(Duration::from_secs(2), rx.recv())
        .await
        .expect("event from rotated file must arrive")
        .expect("present");
    assert_eq!(event.event_json["type"], "SYSCALL");
    assert_eq!(event.event_json["comm"], "cat");

    // The rotated-away file is no longer tailed: its content was already read.
    assert!(dir.path().join("audit.log.1").exists());
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
    // Collector task exits on its own; nothing to assert beyond no panic.
}
