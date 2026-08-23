// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 sigmacatch contributors

//! End-to-end: builtin syslog line → collector parse → detection engine →
//! alert. Rule body is a verbatim SigmaHQ rule, embedded so the test is
//! self-contained.

use sigmacatch_detection::DetectionEngine;
use sigmacatch_lnx::syslog;
use sigmacatch_rule::SigmahqRules;

const SSHD_LINE: &[u8] =
    b"Aug 23 10:00:03 sigmacatch-linux sshd[123]: fatal: Corrupted MAC on input from 192.168.122.1";

/// sigma/rules/linux/builtin/sshd/lnx_sshd_susp_ssh.yml (keyword list kept
/// verbatim; unused keywords trimmed to keep the fixture readable).
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

#[test]
fn builtin_syslog_line_matches_service_rule() {
    let dir = tempfile::tempdir().unwrap();
    let rules_dir = dir.path().join("sigma").join("rules");
    std::fs::create_dir_all(&rules_dir).unwrap();
    std::fs::write(rules_dir.join("rule.yml"), SSHD_RULE).unwrap();

    let rules = SigmahqRules::new_from_path(dir.path().join("sigma").as_path()).unwrap();
    assert!(!rules.is_empty(), "rules must load");

    let record = syslog::parse_line(SSHD_LINE).expect("line must parse");
    let event = syslog::record_to_event(SSHD_LINE, &record);
    assert_eq!(event.event_json["service"], "sshd");

    let mut engine = DetectionEngine::new(&rules).unwrap();
    engine.put_events(vec![event]);
    engine.process_events();
    let alerts = engine.get_alerts();
    assert!(
        !alerts.is_empty(),
        "builtin syslog line must match sshd rule(s)"
    );
}
