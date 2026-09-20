// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 sigmacatch contributors

//! Channel resolution (`runner::run_with_cli`, AD-4): a kind whose
//! `channels()` returns `Some(non-empty)` exercises the resolved-channel
//! branch — the runner hands the resolved list to `build()` and the collector
//! collects those channels; the one-shot flow then generates and uploads
//! (offline: commit skipped) the regression data.
//!
//! This file is its own process (single test) because `logging::init` installs
//! a global tracing subscriber and the pipeline resolves `config.yaml` and
//! `logs/` against the process cwd (`set_current_dir`).

#![cfg(feature = "builtin")]

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

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

struct ResolvingProducer {
    event: Option<Event>,
}

#[async_trait]
impl EventProducer for ResolvingProducer {
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

struct ResolvingKind {
    event: Option<Event>,
    received: Arc<Mutex<Option<Vec<String>>>>,
}

impl CollectorKind for ResolvingKind {
    fn name(&self) -> &'static str {
        "oneshot-channels"
    }
    fn mode(&self) -> String {
        "test".to_string()
    }
    fn channels(
        &self,
        _engine: &DetectionEngine,
        _custom_map: &HashMap<String, String>,
    ) -> Option<Vec<String>> {
        // Non-empty resolved channel list (AD-4): the runner must pass it to
        // build() as the collection target.
        Some(vec!["sshd".to_string()])
    }
    fn build(&self, channels: &[String]) -> Box<dyn EventProducer> {
        *self.received.lock().expect("channels mutex") = Some(channels.to_vec());
        Box::new(ResolvingProducer {
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
async fn resolved_channels_reach_the_collector_and_data_is_written() {
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

    let received = Arc::new(Mutex::new(None));
    let kind = ResolvingKind {
        event: Some(event),
        received: Arc::clone(&received),
    };
    let cli = CliArgs {
        max_runs: None,
        ..CliArgs::default()
    };
    run_with_cli(&kind, cli, PathBuf::from("config.yaml"))
        .await
        .expect("one-shot pipeline with resolved channels must run");

    let channels = received.lock().expect("channels mutex").take();
    assert_eq!(
        channels.as_deref(),
        Some(vec!["sshd".to_string()].as_slice()),
        "build() must receive the channels resolved by channels()"
    );

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
