// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 sigmacatch contributors

//! Live shared-pipeline loop (`runner::run_with_cli`, AD-6): a live collector
//! sends one matching event and stays open (the main task keeps a sender
//! clone); a bloom of the configured stop-file triggers the graceful
//! shutdown → drain → final flush → offline upload. Live mode logs the final
//! flush errors instead of propagating them (`propagate_final_flush_error`).
//!
//! This file is its own process (single test) because `logging::init` installs
//! a global tracing subscriber and the pipeline resolves `config.yaml`, `logs/`
//! and the stop-file against the process cwd (`set_current_dir`).

#![cfg(feature = "builtin")]

use std::collections::HashMap;
use std::path::PathBuf;
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

struct LiveProducer {
    event: Option<Event>,
}

#[async_trait]
impl EventProducer for LiveProducer {
    async fn run(
        mut self: Box<Self>,
        tx: mpsc::Sender<Event>,
        _stop: watch::Receiver<bool>,
    ) -> Result<(), ProducerError> {
        if let Some(event) = self.event.take() {
            tx.send(event).await.expect("channel stays open");
        }
        // Live mode tolerates a collector error: it is logged by the runner and
        // the main loop keeps running until the stop file blooms.
        Err(ProducerError::Message(
            "collector finished with an error".to_string(),
        ))
    }
}

struct LiveKind {
    event: Option<Event>,
}

impl CollectorKind for LiveKind {
    fn name(&self) -> &'static str {
        "live-test"
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
        Box::new(LiveProducer {
            event: self.event.clone(),
        })
    }
    fn regression_format(&self) -> DataFormat {
        DataFormat::Log
    }
    fn live_capture(&self) -> bool {
        true
    }
}

/// Depth-first search for the first file named `name` under `dir`.
fn find_file(dir: &std::path::Path, name: &str) -> Option<std::path::PathBuf> {
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
async fn live_loop_stop_file_triggers_drain_flush_and_offline_upload() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let sigma = tmp.path().join("sigma");
    let rules_dir = sigma.join("rules");
    let regression_dir = sigma.join("regression_data");
    std::fs::create_dir_all(&rules_dir).expect("mkdir sigma/rules");
    std::fs::create_dir_all(&regression_dir).expect("mkdir regression_data");
    std::fs::write(rules_dir.join("sshd.yml"), SSHD_RULE).expect("write rule");

    let stop_file = tmp.path().join("stop");
    let config_yaml = format!(
        "git:\n  author: runner-test\n  email: runner-test@example.com\n  github_token: dummy\n  sigma_repo_path: {}\n  offline: true\n  working_branch: sigmacatch/live-test\nfilter:\n  product: linux\nstop_file: {}\n",
        sigma.display(),
        stop_file.display()
    );
    std::fs::write(tmp.path().join("config.yaml"), config_yaml).expect("write config.yaml");

    let record = syslog::parse_line(SSHD_LINE).expect("fixture line must parse");
    let event = syslog::record_to_event(SSHD_LINE, &record);

    std::env::set_current_dir(tmp.path()).expect("chdir tempdir");

    let kind = LiveKind { event: Some(event) };
    let config_path = PathBuf::from("config.yaml");
    let task = tokio::spawn(async move {
        let cli = CliArgs {
            max_runs: None,
            ..CliArgs::default()
        };
        run_with_cli(&kind, cli, config_path).await
    });

    // Let the pipeline spin up (collector task, stop-file poller), then bloom
    // the stop file. The poller runs every 500 ms, so shutdown lands quickly.
    tokio::time::sleep(Duration::from_millis(800)).await;
    std::fs::write(&stop_file, "stop").expect("write stop file");

    task.await
        .expect("run task must complete")
        .expect("live pipeline must finish");

    let info = find_file(&regression_dir, "info.yml").expect("an info.yml must be written");
    let data = info
        .parent()
        .expect("info.yml parent")
        .join("e76b413a-83d0-4b94-8e4c-85db4a5b8bdc.log");
    assert!(
        data.exists(),
        "the .log data file must sit next to info.yml: {data:?}"
    );
}
