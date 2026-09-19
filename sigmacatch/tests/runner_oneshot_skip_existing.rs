// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 sigmacatch contributors

//! Existing-regression skip (`runner::run_with_cli`, AD-5): when every loaded
//! rule already has regression data (parseable `info.yml` + non-empty data
//! file) and `--all-rules` is not set, the rule list empties out and the
//! pipeline bails with "0 rules loaded" before any collection starts.
//!
//! This file is its own process (single test) because `logging::init` installs
//! a global tracing subscriber and the pipeline resolves `config.yaml` and
//! `logs/` against the process cwd (`set_current_dir`).

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

const RULE_ID: &str = "e76b413a-83d0-4b94-8e4c-85db4a5b8bdc";

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

struct OneShotKind {
    event: Option<Event>,
}

impl CollectorKind for OneShotKind {
    fn name(&self) -> &'static str {
        "oneshot"
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

#[tokio::test]
async fn all_rules_have_existing_regression_data_bails_without_collecting() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let sigma = tmp.path().join("sigma");
    let rules_dir = sigma.join("rules");
    std::fs::create_dir_all(&rules_dir).expect("mkdir sigma/rules");
    std::fs::write(rules_dir.join("sshd.yml"), SSHD_RULE).expect("write rule");

    // Pre-existing regression data for the only rule: a parseable info.yml
    // (rule_metadata[0].id = the rule id) plus a non-empty data file. The
    // directory mirrors the rule's relative path (rules/sshd), matching the
    // layout the runner itself writes.
    let data_dir = sigma.join("regression_data").join("rules").join("sshd");
    std::fs::create_dir_all(&data_dir).expect("mkdir regression_data/rules/sshd");
    std::fs::write(
        data_dir.join("info.yml"),
        format!(
            "id: 00000000-1111-4222-8333-444455556666\ndescription: pre-existing fixture\ndate: \"2026-09-19\"\nauthor: runner-test\nrule_metadata:\n  - id: {RULE_ID}\n    title: Suspicious OpenSSH Daemon Error\n"
        ),
    )
    .expect("write info.yml");
    std::fs::write(
        data_dir.join(format!("{RULE_ID}.log")),
        "Aug 23 10:00:03 fixture sshd[1]: existing\n",
    )
    .expect("write existing data file");

    let config_yaml = format!(
        "git:\n  author: runner-test\n  email: runner-test@example.com\n  github_token: dummy\n  sigma_repo_path: {}\n  offline: true\nfilter:\n  product: linux\n",
        sigma.display()
    );
    std::fs::write(tmp.path().join("config.yaml"), config_yaml).expect("write config.yaml");

    let record = syslog::parse_line(
        b"Aug 23 10:00:03 sigmacatch-linux sshd[123]: fatal: Corrupted MAC on input from 192.168.122.1",
    )
    .expect("fixture line must parse");
    let event = syslog::record_to_event(
        b"Aug 23 10:00:03 sigmacatch-linux sshd[123]: fatal: Corrupted MAC on input from 192.168.122.1",
        &record,
    );

    std::env::set_current_dir(tmp.path()).expect("chdir tempdir");

    // No --all-rules: the existing regression data must exclude the rule.
    let cli = CliArgs {
        max_runs: None,
        ..CliArgs::default()
    };
    let error = run_with_cli(
        &OneShotKind { event: Some(event) },
        cli,
        PathBuf::from("config.yaml"),
    )
    .await
    .expect_err("pipeline must bail when every rule already has regression data");
    let message = error.to_string();
    assert!(
        message.contains("0 rules loaded"),
        "expected the 0-rules bail, got: {message}"
    );

    // The run must not have appended fresh data next to the fixture.
    let data_file = data_dir.join(format!("{RULE_ID}.log"));
    let content = std::fs::read_to_string(&data_file).expect("read data file");
    assert_eq!(
        content, "Aug 23 10:00:03 fixture sshd[1]: existing\n",
        "pre-existing data file must stay untouched"
    );
}
