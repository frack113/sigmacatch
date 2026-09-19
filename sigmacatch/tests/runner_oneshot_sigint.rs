// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 sigmacatch contributors

//! Ctrl-C shutdown (`runner::run_with_cli`): a one-shot collector holds its
//! channel open until the runner signals shutdown. The test sends SIGINT to
//! its own process: the spawned ctrl-C handler reacts (log + shutdown signal)
//! and the one-shot loop's shutdown arm breaks out; the final flush then
//! generates + uploads (offline: commit skipped) the buffered event.
//!
//! This file is its own process (single test) because `logging::init` installs
//! a global tracing subscriber, the pipeline resolves `config.yaml` and
//! `logs/` against the process cwd (`set_current_dir`), and the test signals
//! the process itself.

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

/// Sends its event, then holds the channel open until the runner signals
/// shutdown (the SIGINT's ctrl-C handler), so the loop's shutdown arm — not
/// the closed-channel arm — is what ends the one-shot run.
struct LongLivedProducer {
    event: Option<Event>,
}

#[async_trait]
impl EventProducer for LongLivedProducer {
    async fn run(
        mut self: Box<Self>,
        tx: mpsc::Sender<Event>,
        stop: watch::Receiver<bool>,
    ) -> Result<(), ProducerError> {
        if let Some(event) = self.event.take() {
            tx.send(event).await.expect("channel stays open");
        }
        while !*stop.borrow() {
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        Ok(())
    }
}

struct LongLivedKind {
    event: Option<Event>,
}

impl CollectorKind for LongLivedKind {
    fn name(&self) -> &'static str {
        "oneshot-sigint"
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
        Box::new(LongLivedProducer {
            event: self.event.clone(),
        })
    }
    fn regression_format(&self) -> DataFormat {
        DataFormat::Log
    }
    fn live_capture(&self) -> bool {
        false
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
async fn sigint_triggers_ctrl_c_handler_and_oneshot_shutdown_arm() {
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

    let cli = CliArgs {
        max_runs: None,
        ..CliArgs::default()
    };
    let run_task = tokio::spawn(async move {
        run_with_cli(
            &LongLivedKind { event: Some(event) },
            cli,
            PathBuf::from("config.yaml"),
        )
        .await
    });

    // Give the pipeline a moment to load the rules and arm its handlers,
    // then deliver SIGINT to this process: the spawned ctrl-C handler must
    // react and shut the one-shot loop down gracefully.
    tokio::time::sleep(Duration::from_millis(1000)).await;
    std::process::Command::new("sh")
        .args(["-c", &format!("kill -INT {}", std::process::id())])
        .status()
        .expect("kill -INT must be deliverable");

    tokio::time::timeout(Duration::from_secs(20), run_task)
        .await
        .expect("SIGINT shutdown must not hang")
        .expect("run task must complete")
        .expect("one-shot run must finish cleanly after SIGINT");

    let regression_root = tmp.path().join("sigma").join("regression_data");
    let info = find_file(&regression_root, "info.yml").expect("an info.yml must be written");
    let data = info
        .parent()
        .expect("info.yml parent")
        .join("e76b413a-83d0-4b94-8e4c-85db4a5b8bdc.log");
    assert!(
        data.exists(),
        "the final flush must write the .log data file: {data:?}"
    );
}
