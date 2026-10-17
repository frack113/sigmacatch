// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 sigmacatch contributors

//! A `fieldref` target is rewritten by the field-name pipeline.
//!
//! Sigma events are nested JSON (`Event.EventData.*`) and sigmacatch's
//! `2_win_field_name.yml` maps the flat Sigma field names onto those paths.
//! Before rsigma 0.24 only the *left* side of a field reference went through
//! that mapping, so `SubjectUserName|fieldref: TargetUserName` compared
//! against a flat `TargetUserName` that no Winevt event ever carries. The
//! comparison silently failed, the filter never excluded anything, and the
//! rule alerted on the very case it was written to filter out.
//!
//! 0.24 rewrites the reference target as well
//! (`transform_field_reference_values` in rsigma-eval), so the filter now
//! resolves `Event.EventData.TargetUserName` and excludes the same-user
//! logon. The rule shape below mirrors
//! `rules/windows/builtin/security/win_security_explicit_credential_local_logon.yml`.

use std::fs;

use serde_json::json;
use sigmacatch::detection::DetectionEngine;
use sigmacatch::rule::SigmahqRules;
use sigmacatch::types::Event;

const FIELDREF_FILTER_RULE: &str = r#"title: Explicit Credential Same User Filter
id: aaaaaaaa-aaaa-4aaa-9aaa-aaaaaaaaaaaa
status: experimental
level: medium
author: Test
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4648
  filter_same_user:
    SubjectUserName|fieldref: TargetUserName
  condition: selection and not filter_same_user
"#;

/// A 4648 event where the logon subject and target user are identical, which
/// the rule is supposed to filter out.
fn same_user_event() -> Event {
    let mut event = Event::new(
        json!({}),
        json!({
            "Event": {
                "System": { "EventID": "4648" },
                "EventData": {
                    "SubjectUserName": "CONTOSO\\alice",
                    "TargetUserName": "CONTOSO\\alice"
                }
            }
        }),
        Vec::new(),
    );
    event.inject_logsource_fields_for("windows", Some("security"));
    event
}

/// The same event with a different target user, which must still alert.
fn different_user_event() -> Event {
    let mut event = Event::new(
        json!({}),
        json!({
            "Event": {
                "System": { "EventID": "4648" },
                "EventData": {
                    "SubjectUserName": "CONTOSO\\alice",
                    "TargetUserName": "CONTOSO\\administrator"
                }
            }
        }),
        Vec::new(),
    );
    event.inject_logsource_fields_for("windows", Some("security"));
    event
}

fn engine() -> DetectionEngine {
    let dir = tempfile::tempdir().unwrap();
    let rules_dir = dir.path().join("sigma").join("rules");
    fs::create_dir_all(&rules_dir).unwrap();
    fs::write(rules_dir.join("rule.yml"), FIELDREF_FILTER_RULE).unwrap();
    let rules = SigmahqRules::new_from_path(&dir.path().join("sigma")).unwrap();
    assert_eq!(rules.rules().len(), 1);
    DetectionEngine::new(&rules).unwrap()
}

#[test]
fn fieldref_filter_excludes_same_user() {
    let mut engine = engine();
    engine.put_events(vec![same_user_event()]);
    engine.process_events();
    assert_eq!(
        engine.get_alerts().len(),
        0,
        "SubjectUserName|fieldref: TargetUserName must resolve through the field \
         mapping and filter the same-user logon out"
    );
}

#[test]
fn fieldref_filter_keeps_different_user() {
    let mut engine = engine();
    engine.put_events(vec![different_user_event()]);
    engine.process_events();
    assert_eq!(
        engine.get_alerts().len(),
        1,
        "a different target user must still alert"
    );
}
