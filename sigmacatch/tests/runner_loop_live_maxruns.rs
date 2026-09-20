// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 sigmacatch contributors

//! Live interval cycle (`runner::run_with_cli`, AD-6): a live collector sends
//! one matching event and returns (the main task's sender clone keeps the
//! channel open), so the live 30-second generation interval fires, generates
//! the batch, uploads it (offline: commit skipped) and the `--max-runs 1`
//! limit stops the loop — no stop file involved.
//!
//! This file is its own process (single test) because `logging::init` installs
//! a global tracing subscriber and the pipeline resolves `config.yaml`, `logs/`
//! and the stop-file against the process cwd (`set_current_dir`).

#![cfg(feature = "builtin")]

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::Duration;

use async_trait::async_trait;
use sigmacatch::config::CliArgs;
use sigmacatch::detection::DetectionEngine;
use sigmacatch::inputs::syslog;
use sigmacatch::regression::DataFormat;
use sigmacatch::runner::{CollectorKind, run_with_cli};
use sigmacatch::types::{Event, EventProducer, ProducerError};
use tokio::sync::{mpsc, watch};

const SSHD_RULE: &str = r#"title: Suspicious OpenSSH Daemon Error
id: e76b413a-83d0-4b94-8e4c-85db4a5b8bdc
status: test
description: Detects suspicious SSH / SSHD error messages that indicate a fatal or suspicious error that could be caused by exploiting attempts
references:
    - https://github.com/openssh/openssh-portable/blob/c483a5c0fb8e8b8915fad85c5f6113386a4341ca/ssherr.c
author: Florian Roth (Nextron Systems)
date: 2017-06-30
tags:
    - attack.initial-access
    - attack.t1190
logsource:
    product: linux
    service: sshd
detection:
    keywords:
        - 'Corrupted MAC on input'
        - 'bad client public DH value'
    condition: keywords
falsepositives:
    - Unknown
level: medium
"#;

const SSHD_LINE: &[u8] =
    b"Aug 23 10:00:03 sigmacatch-linux sshd[123]: fatal: Corrupted MAC on input from 192.168.122.1";

struct QuickProducer {
    event: Option<Event>,
}

#[async_trait]
impl EventProducer for QuickProducer {
    async fn run(
        mut self: Box<Self>,
        tx: mpsc::Sender<Event>,
        _stop: watch::Receiver<bool>,
    ) -> Result<(), ProducerError> {
        if let Some(event) = self.event.take() {
            tx.send(event).await.expect("channel stays open");
        }
        Ok(())
    }
}

struct QuickKind {
    event: Option<Event>,
}

impl CollectorKind for QuickKind {
    fn name(&self) -> &'static str {
        "live-maxruns"
    }
    fn mode(&self) -> String {
        "test".to_string()
    }
    fn channels(
        &self,
        _engine: &DetectionEngine,
        _custom_map: &HashMap<String, String>,
    ) -> Option<Vec<String>> {
        None
    }
    fn build(&self, _channels: &[String]) -> Box<dyn EventProducer> {
        Box::new(QuickProducer {
            event: self.event.clone(),
        })
    }
    fn regression_format(&self) -> DataFormat {
        DataFormat::Log
    }
}

fn find_file(dir: &Path, name: &str) -> Option<PathBuf> {
    let mut stack = vec![dir.to_path_buf()];
    while let Some(d) = stack.pop() {
        let entries = std::fs::read_dir(&d).ok()?;
        for entry in entries.flatten() {
            let p = entry.path();
            if p.is_dir() {
                stack.push(p);
            } else if entry.file_name() == name {
                return Some(p);
            }
        }
    }
    None
}

#[tokio::test]
async fn live_max_runs_interval_cycle_generates_uploads_and_exits() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let sigma = tmp.path().join("sigma");
    let rules_dir = sigma.join("rules");
    std::fs::create_dir_all(&rules_dir).expect("mkdir sigma/rules");
    std::fs::create_dir_all(sigma.join("regression_data")).expect("mkdir regression_data");
    std::fs::write(rules_dir.join("sshd.yml"), SSHD_RULE).expect("write rule");

    let config_yaml = format!(
        "git:\n  author: runner-test\n  email: runner-test@example.com\n  github_token: dummy\n  sigma_repo_path: {}\n  offline: true\nfilter:\n  product: linux\n",
        sigma.display()
    );
    std::fs::write(tmp.path().join("config.yaml"), config_yaml).expect("write config.yaml");

    let record = syslog::parse_line(SSHD_LINE).expect("fixture line must parse");
    let event = syslog::record_to_event(SSHD_LINE, &record);

    std::env::set_current_dir(tmp.path()).expect("chdir tempdir");

    let kind = QuickKind { event: Some(event) };
    let cli = CliArgs {
        max_runs: Some(1),
        ..CliArgs::default()
    };
    let config_path = PathBuf::from("config.yaml");
    let task = tokio::spawn(async move { run_with_cli(&kind, cli, config_path).await });

    // The live generation interval is 30 s, so the full run takes ~30 s.
    tokio::time::timeout(Duration::from_secs(60), task)
        .await
        .expect("live max-runs run must not hang")
        .expect("run task must complete")
        .expect("live max-runs pipeline must finish");

    // Keep the process alive one more stop-file poller tick so the background
    // poller observes the shutdown flag (set by the max-runs limit, not the
    // stop file) and exits through its own break path.
    tokio::time::sleep(Duration::from_millis(700)).await;

    let regression_root = tmp.path().join("sigma").join("regression_data");
    let info = find_file(&regression_root, "info.yml").expect("an info.yml must be written");
    let data = info
        .parent()
        .expect("info.yml parent")
        .join("e76b413a-83d0-4b94-8e4c-85db4a5b8bdc.log");
    assert!(
        data.exists(),
        "the .log data file must sit next to info.yml: {data:?}"
    );
}
