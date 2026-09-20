// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 sigmacatch contributors

//! One-shot shared-pipeline loop (`runner::run_with_cli`, AD-6): a collector
//! emits a matching event and drops its sender → the channel closes → the loop
//! drains, generates the regression batch in the final flush and uploads it
//! (offline: commit skipped, files left on disk).
//!
//! This file is its own process (single test) because `logging::init` installs
//! a global tracing subscriber and the pipeline resolves `config.yaml`, `logs/`
//! and `custom_channels.yaml` against the process cwd (`set_current_dir`).

#![cfg(feature = "builtin")]

use std::collections::HashMap;
use std::path::PathBuf;

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

struct OneShotProducer {
    event: Option<Event>,
}

#[async_trait]
impl EventProducer for OneShotProducer {
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

struct OneShotKind {
    event: Option<Event>,
}

impl CollectorKind for OneShotKind {
    fn name(&self) -> &'static str {
        "oneshot-test"
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
        Box::new(OneShotProducer {
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

fn setup() -> (tempfile::TempDir, Event) {
    let tmp = tempfile::tempdir().expect("tempdir");
    let sigma = tmp.path().join("sigma");
    let rules_dir = sigma.join("rules");
    std::fs::create_dir_all(&rules_dir).expect("mkdir sigma/rules");
    std::fs::create_dir_all(sigma.join("regression_data")).expect("mkdir regression_data");
    std::fs::write(rules_dir.join("sshd.yml"), SSHD_RULE).expect("write rule");
    let ssh_key = tmp.path().join("id_ed25519");
    std::fs::write(&ssh_key, "dummy").expect("write dummy ssh key");

    // SSH transport with a signing key and no working branch: exercises the
    // ssh bootstrap branch and the default `sigmacatch/<YYYYMMDD>` branch name.
    let config_yaml = format!(
        "git:\n  author: runner-test\n  email: runner-test@example.com\n  github_token: dummy\n  transport: ssh\n  ssh_key_path: {}\n  sigma_repo_path: {}\n  offline: true\nfilter:\n  product: linux\n",
        ssh_key.display(),
        sigma.display()
    );
    std::fs::write(tmp.path().join("config.yaml"), config_yaml).expect("write config.yaml");

    let record = syslog::parse_line(SSHD_LINE).expect("fixture line must parse");
    let event = syslog::record_to_event(SSHD_LINE, &record);
    (tmp, event)
}

#[tokio::test]
async fn oneshot_loop_offline_generates_and_uploads_batch() {
    let (tmp, event) = setup();

    std::env::set_current_dir(tmp.path()).expect("chdir tempdir");

    let cli = CliArgs {
        all_rules: true,
        ..CliArgs::default()
    };
    run_with_cli(
        &OneShotKind { event: Some(event) },
        cli,
        PathBuf::from("config.yaml"),
    )
    .await
    .expect("one-shot pipeline must run end to end offline");

    let regression_root = tmp.path().join("sigma").join("regression_data");
    assert!(
        regression_root.exists(),
        "regression_data must exist after the run"
    );
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
