// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 sigmacatch contributors

//! Empty channel resolution (`runner::run_with_cli`, AD-4): a kind whose
//! `channels()` returns `Some` of an *empty* list takes the early-return
//! branch — the runner warns "0 channels resolved" and finishes without
//! building a collector or writing any regression data.
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

/// A kind that resolves to zero channels: the runner must stop right after
/// the warning — `build` must never be called.
struct EmptyChannelsKind {
    built: std::sync::Arc<std::sync::atomic::AtomicBool>,
}

impl CollectorKind for EmptyChannelsKind {
    fn name(&self) -> &'static str {
        "oneshot-empty-channels"
    }
    fn mode(&self) -> String {
        "test".to_string()
    }
    fn channels(
        &self,
        _engine: &DetectionEngine,
        _custom_map: &HashMap<String, String>,
    ) -> Option<Vec<String>> {
        Some(Vec::new())
    }
    fn build(&self, _channels: &[String]) -> Box<dyn EventProducer> {
        self.built.store(true, std::sync::atomic::Ordering::SeqCst);
        Box::new(NoopProducer)
    }
    fn regression_format(&self) -> DataFormat {
        DataFormat::Log
    }
    fn live_capture(&self) -> bool {
        false
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
async fn empty_resolved_channels_stop_the_run_before_building_a_collector() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let sigma = tmp.path().join("sigma");
    let rules_dir = sigma.join("rules");
    std::fs::create_dir_all(&rules_dir).expect("mkdir sigma/rules");
    std::fs::write(rules_dir.join("sshd.yml"), SSHD_RULE).expect("write rule");

    let config_yaml = format!(
        "git:\n  author: runner-test\n  email: runner-test@example.com\n  github_token: dummy\n  sigma_repo_path: {}\n  offline: true\nfilter:\n  product: linux\n",
        sigma.display()
    );
    std::fs::write(tmp.path().join("config.yaml"), config_yaml).expect("write config.yaml");

    // Fixture: parse one syslog line to exercise the fixture import; the
    // event is never sent because the run stops at channel resolution.
    let _ = syslog::parse_line(
        b"Aug 23 10:00:03 sigmacatch-linux sshd[123]: fatal: Corrupted MAC on input from 192.168.122.1",
    )
    .expect("fixture line must parse");

    std::env::set_current_dir(tmp.path()).expect("chdir tempdir");

    let built = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let kind = EmptyChannelsKind {
        built: std::sync::Arc::clone(&built),
    };
    let cli = CliArgs {
        max_runs: None,
        ..CliArgs::default()
    };
    run_with_cli(&kind, cli, PathBuf::from("config.yaml"))
        .await
        .expect("empty resolved channels must end the run with Ok(())");

    assert!(
        !built.load(std::sync::atomic::Ordering::SeqCst),
        "build() must not be called when channels() resolves to an empty list"
    );
    let regression_root = tmp.path().join("sigma").join("regression_data");
    assert!(
        !regression_root.exists(),
        "no regression data must be written: {regression_root:?}"
    );
}
