// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 sigmacatch contributors

//! Dry-run via the API (`runner::run_with_cli` + `CliArgs.dry_run`): the
//! rules are loaded and the engine is built, but no regression data is
//! written and no git operation is performed (`--dry-run` semantics).
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

/// Dry-run never builds a collector: a minimal kind whose producer is never
/// started.
struct NoCollectorKind;

impl CollectorKind for NoCollectorKind {
    fn name(&self) -> &'static str {
        "dry-run"
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
        Box::new(NoopProducer)
    }
    fn regression_format(&self) -> DataFormat {
        DataFormat::Log
    }
}

struct NoopProducer;

#[async_trait]
impl EventProducer for NoopProducer {
    async fn run(
        self: Box<Self>,
        _tx: mpsc::Sender<Event>,
        _stop: watch::Receiver<bool>,
    ) -> Result<(), ProducerError> {
        Ok(())
    }
}

#[tokio::test]
async fn dry_run_loads_rules_and_writes_nothing() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let sigma = tmp.path().join("sigma");
    let rules_dir = sigma.join("rules");
    std::fs::create_dir_all(&rules_dir).expect("mkdir sigma/rules");
    std::fs::write(rules_dir.join("sshd.yml"), SSHD_RULE).expect("write rule");

    // No `regression_data` dir on purpose: dry-run must not create it.
    let config_yaml = format!(
        "git:\n  author: runner-test\n  email: runner-test@example.com\n  github_token: dummy\n  sigma_repo_path: {}\n  offline: true\nfilter:\n  product: linux\n",
        sigma.display()
    );
    std::fs::write(tmp.path().join("config.yaml"), config_yaml).expect("write config.yaml");

    // Fixture: parse one syslog line only to exercise the fixture pipeline
    // import; the event is never sent in dry-run mode.
    let _ = syslog::parse_line(
        b"Aug 23 10:00:03 sigmacatch-linux sshd[123]: fatal: Corrupted MAC on input from 192.168.122.1",
    )
    .expect("fixture line must parse");

    std::env::set_current_dir(tmp.path()).expect("chdir tempdir");

    let cli = CliArgs {
        dry_run: true,
        ..CliArgs::default()
    };
    run_with_cli(&NoCollectorKind, cli, PathBuf::from("config.yaml"))
        .await
        .expect("dry-run must succeed");

    let regression_root = tmp.path().join("sigma").join("regression_data");
    assert!(
        !regression_root.exists(),
        "dry-run must not create regression_data: {regression_root:?}"
    );
}
