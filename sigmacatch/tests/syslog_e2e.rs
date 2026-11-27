// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 sigmacatch contributors

//! End-to-end: builtin syslog line → collector parse → detection engine →
//! alert. Rule body is a verbatim SigmaHQ rule, embedded so the test is
//! self-contained.

mod common;
use common::{SSHD_LINE, SSHD_RULE};

use sigmacatch::detection::DetectionEngine;
use sigmacatch::orchestrators::syslog;
use sigmacatch::rule::SigmahqRules;

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
