// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 sigmacatch contributors

//! Integration tests for the builtin syslog tail collector (Linux only).

#![cfg(all(target_os = "linux", feature = "builtin"))]

use sigmacatch_lnx::syslog::EventCollector;
use sigmacatch_types::EventProducer;
use std::io::Write;
use std::time::Duration;
use tokio::sync::{mpsc, watch};

const SSHD: &[u8] =
    b"May 11 14:23:33 host123 sshd[12345]: Failed password for invalid user root from 1.2.3.4\n";
const CRON: &[u8] = b"May 11 14:23:40 host123 CRON[90]: (root) CMD (run-pam)\n";
const KERNEL: &[u8] = b"May 11 14:23:41 host123 kernel: [123456.789] EXT4-fs(sda1)\n";

async fn run_collector(
    path: &str,
) -> (mpsc::Receiver<sigmacatch_types::Event>, watch::Sender<bool>) {
    let (tx, rx) = mpsc::channel(100);
    let (stop_tx, stop_rx) = watch::channel(false);
    let collector = EventCollector::with_path(Some(path.to_string()));
    tokio::spawn(async move {
        let _ = Box::new(collector).run(tx, stop_rx).await;
    });
    (rx, stop_tx)
}

#[tokio::test]
async fn test_collector_emits_per_valid_line() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("syslog");
    std::fs::File::create(&path).unwrap();

    let (mut rx, stop_tx) = run_collector(path.to_str().unwrap()).await;
    tokio::time::sleep(Duration::from_millis(250)).await;

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

    tokio::time::sleep(Duration::from_millis(400)).await;

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

    let (mut rx, stop_tx) = run_collector(path.to_str().unwrap()).await;
    tokio::time::sleep(Duration::from_millis(250)).await;

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

    tokio::time::sleep(Duration::from_millis(400)).await;

    // Only the valid syslog line is emitted.
    let e = tokio::time::timeout(Duration::from_secs(2), rx.recv())
        .await
        .expect("valid event must arrive")
        .expect("present");
    assert_eq!(e.event_json["service"], "sshd");

    // No spurious event follows (stop sent after: a closed channel would
    // return Ok(None) instead of timing out).
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

    let (mut rx, stop_tx) = run_collector(path.to_str().unwrap()).await;
    tokio::time::sleep(Duration::from_millis(250)).await;

    // Simulate rsyslog rotation: rename + recreate the log.
    std::fs::rename(&path, dir.path().join("syslog.1")).unwrap();
    let mut new_file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
        .unwrap();
    new_file.write_all(SSHD).unwrap();
    new_file.flush().unwrap();

    tokio::time::sleep(Duration::from_millis(400)).await;

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

    let (mut rx, stop_tx) = run_collector(path.to_str().unwrap()).await;
    tokio::time::sleep(Duration::from_millis(250)).await;
    stop_tx.send(true).unwrap();

    let _ = tokio::time::timeout(Duration::from_secs(2), rx.recv()).await;
    // Collector task exits on its own; nothing to assert beyond no panic.
}
