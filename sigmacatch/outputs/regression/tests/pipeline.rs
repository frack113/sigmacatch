// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 sigmacatch contributors

//! Full-cycle integration tests: the real writer behind the shared runner.

use sigmacatch_core::detection_engine::DetectionEngine;
use sigmacatch_core::regression::{DataFormat, RegressionSink};
use sigmacatch_core::rule::SigmahqRules;
use sigmacatch_core::runner::{Pipeline, process_and_generate};
use sigmacatch_core::types::Event;
use sigmacatch_output_regression::SigmahqRegression;
use std::path::PathBuf;

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

fn make_rule_dir() -> (tempfile::TempDir, PathBuf) {
    let tmp = tempfile::tempdir().unwrap();
    let sigma = tmp.path().join("sigma");
    let rules_dir = sigma.join("rules");
    std::fs::create_dir_all(&rules_dir).unwrap();
    std::fs::write(rules_dir.join("rule.yml"), SSHD_RULE).unwrap();
    (tmp, sigma)
}

#[test]
fn process_and_generate_writes_batch_for_matching_event() {
    let (_tmp, sigma) = make_rule_dir();
    std::fs::create_dir_all(sigma.join("regression_data")).unwrap();

    let rules = SigmahqRules::new_from_path(&sigma).unwrap();
    assert_eq!(rules.len(), 1);

    let mut engine = DetectionEngine::new(&rules).unwrap();
    let message = "fatal: Corrupted MAC on input from 192.168.122.1";
    let event = Event::new_injected(
        serde_json::json!({ "message": message, "program": "sshd" }),
        serde_json::json!({ "message": message, "program": "sshd" }),
        SSHD_LINE.to_vec(),
        "linux",
        Some("sshd"),
    );
    assert_eq!(event.event_json["service"], "sshd");
    engine.put_events(vec![event]);
    engine.process_events();
    assert_eq!(
        engine.stats().events_processed,
        1,
        "the fixture line must be processed by the engine"
    );

    let mut regression: Box<dyn RegressionSink> =
        Box::new(SigmahqRegression::new_from_path(&sigma.join("regression_data")).unwrap());
    regression.set_format(DataFormat::Log);
    regression.set_author("runner-test".to_string());

    let pipeline = Pipeline {
        engine,
        rules,
        regression,
    };
    let (returned, batches) = process_and_generate(pipeline);

    assert_eq!(batches.len(), 1, "one matching rule -> one batch");
    let (rule_id, files) = &batches[0];
    assert_eq!(files.len(), 3, "data file + info.yml + rule yaml");
    for f in files {
        assert!(sigma.join(f).exists(), "generated file {f} must exist");
    }
    assert!(
        returned.rules.get_rule_path(rule_id).is_none(),
        "rule must be retired from the returned pipeline"
    );

    let (_returned2, batches2) = process_and_generate(returned);
    assert!(
        batches2.is_empty(),
        "no further alerts -> no further batches"
    );
}

#[test]
fn process_and_generate_without_alerts_returns_no_batches() {
    let (_tmp, sigma) = make_rule_dir();
    std::fs::create_dir_all(sigma.join("regression_data")).unwrap();

    let rules = SigmahqRules::new_from_path(&sigma).unwrap();
    let mut engine = DetectionEngine::new(&rules).unwrap();

    let message = "(root) CMD (run-parts /etc/cron.daily)";
    let event = Event::new_injected(
        serde_json::json!({ "message": message, "program": "cron" }),
        serde_json::json!({ "message": message, "program": "cron" }),
        b"Aug 23 10:00:03 sigmacatch-linux cron[999]: (root) CMD (run-parts /etc/cron.daily)"
            .to_vec(),
        "linux",
        Some("cron"),
    );
    engine.put_events(vec![event]);
    engine.process_events();
    assert!(
        engine.get_alerts().is_empty(),
        "benign event must not match"
    );

    let regression: Box<dyn RegressionSink> =
        Box::new(SigmahqRegression::new_from_path(&sigma.join("regression_data")).unwrap());
    let pipeline = Pipeline {
        engine,
        rules,
        regression,
    };
    let (_returned, batches) = process_and_generate(pipeline);
    assert!(batches.is_empty());
}
