// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 sigmacatch contributors

//! End-to-end: builtin syslog line → collector parse → detection engine →
//! alert. Uses a real SigmaHQ syslog rule.

use sigmacatch_detection::DetectionEngine;
use sigmacatch_lnx::syslog;
use sigmacatch_rule::SigmahqRules;

const SSHD_LINE: &[u8] =
    b"Aug 23 10:00:03 sigmacatch-linux sshd[123]: fatal: Corrupted MAC on input from 192.168.122.1";

#[test]
fn builtin_syslog_line_matches_service_rule() {
    let dir = tempfile::tempdir().unwrap();
    let rules_dir = dir.path().join("sigma").join("rules");
    std::fs::create_dir_all(&rules_dir).unwrap();
    std::fs::copy(
        "../sigma/rules/linux/builtin/sshd/lnx_sshd_susp_ssh.yml",
        rules_dir.join("lnx_sshd_susp_ssh.yml"),
    )
    .unwrap();

    let rules = SigmahqRules::new_from_path(dir.path().join("sigma").as_path()).unwrap();
    assert!(!rules.is_empty(), "rules must load");

    let record = syslog::parse_line(SSHD_LINE).expect("line must parse");
    let event = syslog::record_to_event(SSHD_LINE, &record);
    println!("event_json: {}", event.event_json);

    let mut engine = DetectionEngine::new(&rules).unwrap();
    engine.put_events(vec![event]);
    engine.process_events();
    let alerts = engine.get_alerts();
    println!("alerts: {}", alerts.len());
    for a in &alerts {
        println!("matched rule: {} ({})", a.rule_title, a.rule_id);
    }
    assert!(
        !alerts.is_empty(),
        "builtin syslog line must match sshd rule(s)"
    );
}
