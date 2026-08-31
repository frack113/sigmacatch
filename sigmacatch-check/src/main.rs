// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 sigmacatch contributors

//! Cross-platform regression validation tool.
//!
//! Loads Sigma rules and regression data, replays each stored event through
//! the detection engine, and reports whether the expected rule still matches.
//! Works on both Linux and Windows — no platform-specific collectors required.

use std::collections::HashSet;
use std::path::Path;

use serde::Serialize;
use serde_json::{Map, Value as JsonValue};
use sigmacatch_detection::DetectionEngine;
use sigmacatch_regression::SigmahqRegression;
use sigmacatch_rule::SigmahqRules;
use sigmacatch_types::Event;
use uuid::Uuid;

#[derive(Serialize)]
struct CheckFail {
    rule_name: String,
    error: String,
}

fn main() -> anyhow::Result<()> {
    let args: Vec<String> = std::env::args().collect();

    let mut json_output = false;
    let mut ignore_invalid = false;
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--json" => json_output = true,
            "--ignore" => ignore_invalid = true,
            "--help" | "-h" => {
                println!(
                    "sigmacatch-check — validate regression data against loaded rules\n\n\
                    Usage: sigmacatch-check [OPTIONS]\n\n\
                    Options:\n\
                      --json      Output results as JSON\n\
                      --ignore    Skip invalid entries without counting them\n\
                      --help, -h  Print this help and exit"
                );
                return Ok(());
            }
            other => {
                eprintln!("Unknown argument: {other}");
                return Ok(());
            }
        }
        i += 1;
    }

    let rules = SigmahqRules::new()?;

    let regression = SigmahqRegression::new()?;
    if regression.is_empty() {
        eprintln!("No regression entries found — nothing to validate");
        std::process::exit(1);
    }

    // Bidirectional regression_tests_path validation.
    // Direction 1: each entry → rule must exist and declare a matching path.
    // Direction 2: each rule with regression_tests_path → entry must exist.
    let path_validation = validate_regression_paths(&rules, &regression);
    let missing_path = path_validation.missing_path;
    let mismatched_path = path_validation.mismatched_path;

    if missing_path > 0 && !json_output {
        eprintln!("[FAIL] {} missing regression_tests_path(s)", missing_path);
    }
    if mismatched_path > 0 && !json_output {
        eprintln!("[FAIL] {} mismatched regression_tests_path(s)", mismatched_path);
    }

    let mut engine = DetectionEngine::new(&rules)?;

    let mut total = 0usize;
    let mut passed = 0usize;
    let mut skipped = 0usize;
    let mut failed: Vec<CheckFail> = Vec::new();
    let mut dropped_audit_lines = 0usize;
    let mut ignored = 0usize;

    for idx in 0..regression.len() {
        let entry = match regression.get_entry(idx) {
            Some(e) => e,
            None => {
                if ignore_invalid {
                    ignored += 1;
                    if !json_output {
                        println!("[IGNORE] No entry");
                    }
                } else {
                    total += 1;
                    if !json_output {
                        println!("[FAIL] No entry");
                    }
                }
                continue;
            }
        };

        let raw = match regression.get_raw_data(idx) {
            Some(r) => r,
            None => {
                if ignore_invalid {
                    ignored += 1;
                    if !json_output {
                        println!("[IGNORE] No raw data");
                    }
                } else {
                    total += 1;
                    failed.push(CheckFail {
                        rule_name: entry.rule_name.clone(),
                        error: "No raw data".to_string(),
                    });
                    if !json_output {
                        println!("[FAIL] No raw data");
                    }
                }
                continue;
            }
        };

        let events: Vec<Event> = match entry.logtype {
            sigmacatch_regression::logtype::LogType::Evtx => {
                match input_windows_evtx::parse_evtx_bytes(&raw) {
                    Ok(evts) => evts,
                    Err(e) => {
                        total += 1;
                        failed.push(CheckFail {
                            rule_name: entry.rule_name.clone(),
                            error: format!("EVTX parse error: {e}"),
                        });
                        if !json_output {
                            println!("[FAIL] EVTX parse error: {e}");
                        }
                        continue;
                    }
                }
            }
            sigmacatch_regression::logtype::LogType::Log => {
                let (events, dropped) = parse_auditd_lines(&raw);
                dropped_audit_lines += dropped;
                events
            }
            sigmacatch_regression::logtype::LogType::Json => parse_json_lines(&raw),
            sigmacatch_regression::logtype::LogType::Raw => {
                skipped += 1;
                if !json_output {
                    println!("[SKIP] Raw logtype — skipped");
                }
                total += 1;
                continue;
            }
        };

        if events.is_empty() {
            if ignore_invalid {
                ignored += 1;
                if !json_output {
                    println!("[IGNORE] No events produced from raw data");
                }
            } else {
                total += 1;
                failed.push(CheckFail {
                    rule_name: entry.rule_name.clone(),
                    error: "EMPTY — no events produced from raw data".to_string(),
                });
                if !json_output {
                    println!("[FAIL] EMPTY — no events produced from raw data");
                }
            }
            continue;
        }

        engine.put_events(events);
        engine.process_events();
        let alerts = engine.get_alerts();
        let matched_ids: HashSet<Uuid> = alerts.iter().map(|a| a.rule_id).collect();

        if !matched_ids.contains(&entry.rule_id) {
            let matched: Vec<String> = matched_ids.iter().map(|s| s.to_string()).collect();
            total += 1;
            failed.push(CheckFail {
                rule_name: entry.rule_name.clone(),
                error: format!(
                    "RULE NOT MATCHED — expected '{}' ({} alert(s), matched: {})",
                    entry.rule_id,
                    alerts.len(),
                    matched.join(", ")
                ),
            });
            if !json_output {
                println!(
                    "[FAIL] RULE NOT MATCHED — expected '{}' ({} alert(s), matched: {})",
                    entry.rule_id,
                    alerts.len(),
                    matched.join(", ")
                );
            }
            continue;
        }

        let rule_alert_count = alerts.iter().filter(|a| a.rule_id == entry.rule_id).count();
        if rule_alert_count < 1 {
            total += 1;
            failed.push(CheckFail {
                rule_name: entry.rule_name.clone(),
                error: "MATCH COUNT MISMATCH — expected >= 1 (got 0)".to_string(),
            });
            if !json_output {
                println!("[FAIL] MATCH COUNT MISMATCH — expected >= 1 (got 0)");
            }
            continue;
        }

        // Validate the declared match_count against the actual hit count when a
        // JSON auxiliary file is present alongside the data. The JSON mirrors
        // the raw event, so its hit count must equal info.yml's match_count.
        let expected = regression
            .get_info(idx)
            .and_then(|info| info.regression_tests_info.first())
            .map(|t| t.match_count)
            .unwrap_or(0);
        let json_present = regression.get_json_data(idx).is_some();
        if json_present && expected > 0 && rule_alert_count != expected {
            total += 1;
            let msg = format!(
                "MATCH COUNT MISMATCH — expected {} hit(s), got {}",
                expected, rule_alert_count
            );
            failed.push(CheckFail {
                rule_name: entry.rule_name.clone(),
                error: msg,
            });
            if !json_output {
                println!(
                    "[FAIL] {}",
                    failed.last().expect("failed entry just pushed").error
                );
            }
            continue;
        }

        total += 1;
        passed += 1;
        if !json_output {
            println!("[PASS] {} alert(s), rule matched", rule_alert_count);
        }
    }

    let pass_rate = if total > 0 {
        (passed as f64 / (total + skipped) as f64) * 100.0
    } else {
        0.0
    };

    let path_failures = missing_path + mismatched_path;
    if json_output {
        let output = serde_json::json!({
            "total": total,
            "passed": passed,
            "skipped": skipped,
            "ignored": ignored,
            "missing_path": missing_path,
            "mismatched_path": mismatched_path,
            "failed_count": failed.len(),
            "pass_rate": pass_rate,
            "failed": failed,
        });
        println!(
            "{}",
            serde_json::to_string_pretty(&output)
                .expect("serde_json Value serialization is infallible")
        );
    } else {
        println!("\n{}", "=".repeat(60));
        println!("  VALIDATION SUMMARY");
        println!("{}", "=".repeat(60));
        println!("  Total entries:   {}", total);
        println!("  Passed:          {}", passed);
        println!("  Failed:          {}", failed.len());
        if missing_path > 0 {
            println!("  Missing paths:   {}", missing_path);
        }
        if mismatched_path > 0 {
            println!("  Mismatched:      {}", mismatched_path);
        }
        if ignored > 0 {
            println!("  Ignored:         {}", ignored);
        }
        if skipped > 0 {
            println!("  Skipped:         {}", skipped);
        }
        if dropped_audit_lines > 0 {
            println!("  Dropped lines:   {}", dropped_audit_lines);
        }
        println!("  Pass rate:       {:.1}%", pass_rate);
        println!("{}", "=".repeat(60));
        if missing_path > 0 || mismatched_path > 0 {
            println!("\nRegression path issues:");
            println!("  Missing paths:   {}", missing_path);
            println!("  Mismatched:      {}", mismatched_path);
        }
        if !failed.is_empty() {
            println!("\nFailed rules:");
            for f in &failed {
                println!("  FAIL {} — {}", f.rule_name, f.error);
            }
        }
    }

    if path_failures > 0 || !failed.is_empty() {
        std::process::exit(1);
    }

    Ok(())
}

struct PathValidation {
    missing_path: usize,
    mismatched_path: usize,
}

/// Bidirectional validation of `regression_tests_path` between rules and
/// regression entries. Returns counts of missing and mismatched paths.
fn validate_regression_paths(rules: &SigmahqRules, regression: &SigmahqRegression) -> PathValidation {
    let sigma_root = regression.path().parent().unwrap_or(Path::new("./sigma"));
    let mut missing_path = 0usize;
    let mut mismatched_path = 0usize;

    for (info_path, _info, entry) in regression.iter_entries() {
        let Some(rule) = rules.get(&entry.rule_id) else {
            missing_path += 1;
            continue;
        };
        let Some(rtp) = rule
            .custom_attributes
            .get("regression_tests_path")
            .and_then(|v| v.as_str())
        else {
            missing_path += 1;
            continue;
        };
        let expected = sigma_root.join(rtp);
        if *info_path != expected {
            mismatched_path += 1;
        }
    }

    let entry_paths: HashSet<&Path> = regression
        .iter_entries()
        .map(|(p, _, _)| p.as_path())
        .collect();
    for rule in rules.iter() {
        let Some(v) = rule.custom_attributes.get("regression_tests_path") else {
            continue;
        };
        let Some(rtp) = v.as_str() else {
            continue;
        };
        let full = sigma_root.join(rtp);
        if !full.exists() {
            mismatched_path += 1;
        } else if !entry_paths.contains(full.as_path()) {
            missing_path += 1;
        }
    }

    PathValidation {
        missing_path,
        mismatched_path,
    }
}

fn parse_auditd_lines(raw: &[u8]) -> (Vec<Event>, usize) {
    use linux_audit_parser::Parser;

    let parser = Parser {
        enriched: true,
        split_msg: false,
    };

    let mut dropped = 0usize;
    let events: Vec<Event> = raw
        .split(|b| *b == b'\n')
        .filter(|line| !line.is_empty())
        .filter_map(|line| {
            let message = match parser.parse(line) {
                Ok(m) => m,
                Err(_) => {
                    dropped += 1;
                    return None;
                }
            };
            let mut fields = Map::new();
            for (key, value) in &message.body {
                if let Some(json) = value_to_json(value) {
                    fields.insert(key.to_string(), json);
                }
            }
            let json_raw = serde_json::json!({
                "stamp": { "timestamp": message.id.timestamp, "sequence": message.id.sequence },
                "type": message.ty.to_string(),
                "fields": fields,
            });
            let mut flat = Map::new();
            for (key, value) in &fields {
                flat.insert(key.clone(), value.clone());
            }
            flat.insert("type".into(), JsonValue::String(message.ty.to_string()));
            flat.insert("provider".into(), JsonValue::String("auditd".into()));
            flat.insert("product".into(), JsonValue::String("linux".into()));
            flat.insert("service".into(), JsonValue::String("auditd".into()));
            let mut event = Event::new(json_raw, JsonValue::Object(flat), line.to_vec());
            event.inject_logsource_fields_for("linux", Some("auditd"));
            Some(event)
        })
        .collect();
    (events, dropped)
}

fn value_to_json(value: &linux_audit_parser::Value<'_>) -> Option<JsonValue> {
    use linux_audit_parser::Value as AuditValue;
    match value {
        AuditValue::Empty => Some(JsonValue::String(String::new())),
        AuditValue::Str(bytes, _) => Some(JsonValue::String(
            String::from_utf8_lossy(bytes).into_owned(),
        )),
        AuditValue::Owned(bytes) => Some(JsonValue::String(
            String::from_utf8_lossy(bytes.as_slice()).into_owned(),
        )),
        AuditValue::Number(n) => Some(JsonValue::String(n.to_string())),
        AuditValue::List(items) | AuditValue::StringifiedList(items) => {
            let arr: Vec<JsonValue> = items.iter().filter_map(value_to_json).collect();
            if arr.is_empty() {
                None
            } else {
                Some(JsonValue::Array(arr))
            }
        }
        AuditValue::Map(pairs) => {
            let mut map = Map::new();
            for (k, v) in pairs {
                if let Some(json) = value_to_json(v) {
                    map.insert(k.to_string(), json);
                }
            }
            if map.is_empty() {
                None
            } else {
                Some(JsonValue::Object(map))
            }
        }
        AuditValue::Literal(s) => Some(JsonValue::String((*s).to_string())),
        AuditValue::Segments(_) | AuditValue::Skipped(_) => None,
    }
}

fn parse_json_lines(raw: &[u8]) -> Vec<Event> {
    raw.split(|b| *b == b'\n')
        .filter(|line| !line.is_empty())
        .filter_map(|line| {
            let value: JsonValue = serde_json::from_slice(line).ok()?;
            let mut event = Event::new(value.clone(), value, line.to_vec());
            event.inject_logsource_fields();
            Some(event)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use sigmacatch_regression::SigmahqRegression;
    use sigmacatch_rule::SigmahqRules;
    use std::fs;

    fn write_file(path: &Path, content: &str) {
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, content).unwrap();
    }

    fn write_evtx(dir: &Path, rule_id: &str) {
        let path = dir.join(format!("{rule_id}.evtx"));
        fs::create_dir_all(dir).unwrap();
        // EVTX files must be non-empty for data_file_exists to return true.
        fs::write(path, vec![0u8; 4096]).unwrap();
    }

    const RULE_YML: &str = "title: Test Rule\nid: aaaaaaaa-aaaa-4aaa-9aaa-aaaaaaaaaaaa\nstatus: test\nlevel: low\nlogsource:\n  product: windows\n  service: sysmon\ndetection:\n  selection:\n    EventID: 1\n  condition: selection\n";
    const RULE_WITH_PATH_YML: &str = "title: Test Rule\nid: aaaaaaaa-aaaa-4aaa-9aaa-aaaaaaaaaaaa\nstatus: test\nlevel: low\nlogsource:\n  product: windows\n  service: sysmon\nregression_tests_path: regression_data/rules/wrong_location/info.yml\ndetection:\n  selection:\n    EventID: 1\n  condition: selection\n";
    const RULE_WITH_CORRECT_PATH_YML: &str = "title: Test Rule\nid: aaaaaaaa-aaaa-4aaa-9aaa-aaaaaaaaaaaa\nstatus: test\nlevel: low\nlogsource:\n  product: windows\n  service: sysmon\nregression_tests_path: regression_data/rules/test/info.yml\ndetection:\n  selection:\n    EventID: 1\n  condition: selection\n";
    const INFO_YML_DIFF_ID: &str = "id: bbbbbbbb-bbbb-4bbb-9bbb-bbbbbbbbbbbb\ndescription: test\ndate: 2026-01-01\nauthor: test\nrule_metadata:\n  - id: cccccccc-cccc-4ccc-9ccc-cccccccccccc\n    title: Other Rule\nregression_tests_info:\n  - name: test\n    type: evtx\n    path: dummy.evtx\n";
    const INFO_YML_SAME_ID: &str = "id: aaaaaaaa-aaaa-4aaa-9aaa-aaaaaaaaaaaa\ndescription: test\ndate: 2026-01-01\nauthor: test\nrule_metadata:\n  - id: aaaaaaaa-aaaa-4aaa-9aaa-aaaaaaaaaaaa\n    title: Test Rule\nregression_tests_info:\n  - name: test\n    type: evtx\n    path: dummy.evtx\n";
    const INFO_YML_DIFF_RULE: &str = "id: bbbbbbbb-bbbb-4bbb-9bbb-bbbbbbbbbbbb\ndescription: test\ndate: 2026-01-01\nauthor: test\nrule_metadata:\n  - id: bbbbbbbb-bbbb-4bbb-9bbb-bbbbbbbbbbbb\n    title: Different Rule\nregression_tests_info:\n  - name: test\n    type: evtx\n    path: dummy.evtx\n";

    #[test]
    fn validates_missing_regression_tests_path() {
        let tmp = std::env::temp_dir().join("sigmacatch-check-test-missing-path");
        let _ = fs::remove_dir_all(&tmp);

        let rules_dir = tmp.join("sigma").join("rules");
        let reg_dir = tmp.join("sigma").join("regression_data");

        write_file(&rules_dir.join("test_rule.yml"), RULE_YML);

        let info_dir = reg_dir.join("rules").join("test");
        write_file(&info_dir.join("info.yml"), INFO_YML_DIFF_ID);
        write_evtx(&info_dir, "cccccccc-cccc-4ccc-9ccc-cccccccccccc");

        let rules = SigmahqRules::new_from_path(&tmp.join("sigma")).unwrap();
        let regression = SigmahqRegression::new_from_path(&reg_dir).unwrap();

        let pv = validate_regression_paths(&rules, &regression);
        // Entry's rule_id (cccc...) has no matching rule in SigmahqRules → missing_path=1.
        assert_eq!(pv.missing_path, 1, "expected 1 missing path");
        assert_eq!(pv.mismatched_path, 0, "expected 0 mismatched paths");

        fs::remove_dir_all(&tmp).unwrap();
    }

    #[test]
    fn validates_mismatched_regression_tests_path() {
        let tmp = std::env::temp_dir().join("sigmacatch-check-test-mismatch");
        let _ = fs::remove_dir_all(&tmp);

        let rules_dir = tmp.join("sigma").join("rules");
        let reg_dir = tmp.join("sigma").join("regression_data");

        // Rule points to wrong location
        write_file(&rules_dir.join("test_rule.yml"), RULE_WITH_PATH_YML);

        let info_dir = reg_dir.join("rules").join("test");
        write_file(&info_dir.join("info.yml"), INFO_YML_SAME_ID);
        write_evtx(&info_dir, "aaaaaaaa-aaaa-4aaa-9aaa-aaaaaaaaaaaa");

        let rules = SigmahqRules::new_from_path(&tmp.join("sigma")).unwrap();
        let regression = SigmahqRegression::new_from_path(&reg_dir).unwrap();

        let pv = validate_regression_paths(&rules, &regression);
        // Direction 1: rule matches entry, but rtp (wrong_location) ≠ info_path (test) → mismatch.
        // Direction 2: rule rtp (wrong_location) file doesn't exist → mismatch.
        // Both directions legitimately flag the issue: mismatched_path=2.
        assert_eq!(pv.missing_path, 0, "expected 0 missing paths");
        assert_eq!(
            pv.mismatched_path, 2,
            "expected 2 mismatched paths (rule points to wrong location)"
        );

        fs::remove_dir_all(&tmp).unwrap();
    }

    #[test]
    fn validates_orphaned_rule_regression_tests_path() {
        let tmp = std::env::temp_dir().join("sigmacatch-check-test-orphan");
        let _ = fs::remove_dir_all(&tmp);

        let rules_dir = tmp.join("sigma").join("rules");
        let reg_dir = tmp.join("sigma").join("regression_data");

        write_file(&rules_dir.join("test_rule.yml"), RULE_WITH_CORRECT_PATH_YML);

        let info_dir = reg_dir.join("rules").join("test");
        write_file(&info_dir.join("info.yml"), INFO_YML_DIFF_RULE);
        write_evtx(&info_dir, "bbbbbbbb-bbbb-4bbb-9bbb-bbbbbbbbbbbb");

        let rules = SigmahqRules::new_from_path(&tmp.join("sigma")).unwrap();
        let regression = SigmahqRegression::new_from_path(&reg_dir).unwrap();

        let pv = validate_regression_paths(&rules, &regression);
        // Direction 1: entry rule_id (bbbb...) doesn't match any loaded rule → missing_path=1.
        // Direction 2: rule points to info.yml, file exists, but entry_paths has bbb's path
        //              while the rule expects the same path → entry_paths.contains=true, so no
        //              additional missing_path. But the entry's rule_id is bbbb, not aaaa, so
        //              direction 1 already counted it. Direction 2 checks if the file exists
        //              (yes) and if entry_paths contains it (yes, bbb's path is there) → 0.
        // Total: missing_path=1.
        assert_eq!(pv.missing_path, 1, "expected 1 missing path");
        assert_eq!(pv.mismatched_path, 0, "expected 0 mismatched paths");

        fs::remove_dir_all(&tmp).unwrap();
    }

    const RULE_MATCH_YML: &str = "title: Test Rule\nid: aaaaaaaa-aaaa-4aaa-9aaa-aaaaaaaaaaaa\nstatus: test\nlevel: low\nlogsource:\n  product: windows\nregression_tests_path: regression_data/rules/test/info.yml\ndetection:\n  selection:\n    event_id: 1\n  condition: selection\n";

    /// Build a one-rule / one-entry scenario where the JSON data (and its
    /// auxiliary `.json`) holds a single event that matches the rule. `match_count`
    /// in `info.yml` controls whether the validation should pass or fail.
    fn setup_match_count(tmp: &Path, match_count: usize) -> (SigmahqRules, SigmahqRegression) {
        let rules_dir = tmp.join("sigma").join("rules");
        let reg_dir = tmp.join("sigma").join("regression_data");
        let info_dir = reg_dir.join("rules").join("test");
        fs::create_dir_all(&rules_dir).unwrap();
        fs::create_dir_all(&info_dir).unwrap();

        write_file(&rules_dir.join("test_rule.yml"), RULE_MATCH_YML);

        let info = format!(
            "id: aaaaaaaa-aaaa-4aaa-9aaa-aaaaaaaaaaaa\n\
             description: test\ndate: 2026-01-01\nauthor: test\n\
             rule_metadata:\n  - id: aaaaaaaa-aaaa-4aaa-9aaa-aaaaaaaaaaaa\n    title: Test Rule\n\
             regression_tests_info:\n  - name: test\n    type: json\n    match_count: {}\n    path: dummy.json\n",
            match_count
        );
        write_file(&info_dir.join("info.yml"), &info);
        // The data file doubles as the JSON auxiliary read by get_json_data.
        write_file(
            &info_dir.join("aaaaaaaa-aaaa-4aaa-9aaa-aaaaaaaaaaaa.json"),
            "{\"event_id\": 1}\n",
        );

        let rules = SigmahqRules::new_from_path(&tmp.join("sigma")).unwrap();
        let regression = SigmahqRegression::new_from_path(&reg_dir).unwrap();
        (rules, regression)
    }

    /// Run the detection pipeline for entry 0 and return its hit count.
    fn detect_hits(rules: &SigmahqRules, regression: &SigmahqRegression) -> usize {
        let idx = 0;
        let raw = regression.get_raw_data(idx).expect("raw data present");
        let events = parse_json_lines(&raw);
        let mut engine = DetectionEngine::new(rules).expect("engine builds");
        engine.put_events(events);
        engine.process_events();
        let alerts = engine.get_alerts();
        let entry = regression.get_entry(idx).expect("entry present");
        alerts.iter().filter(|a| a.rule_id == entry.rule_id).count()
    }

    #[test]
    fn validates_match_count_ok_when_json_present() {
        let tmp = std::env::temp_dir().join("sigmacatch-check-test-mc-ok");
        let _ = fs::remove_dir_all(&tmp);

        let (rules, regression) = setup_match_count(&tmp, 1);
        let hits = detect_hits(&rules, &regression);
        assert_eq!(hits, 1, "rule should produce exactly 1 hit");

        // Inline the match_count check logic (mirrors main()).
        let expected = regression
            .get_info(0)
            .and_then(|info| info.regression_tests_info.first())
            .map(|t| t.match_count)
            .unwrap_or(0);
        let json_present = regression.get_json_data(0).is_some();
        let verdict = if json_present && expected > 0 && hits != expected {
            Some(format!(
                "MATCH COUNT MISMATCH — expected {} hit(s), got {}",
                expected, hits
            ))
        } else {
            None
        };
        assert!(
            verdict.is_none(),
            "match_count 1 vs 1 hit should pass, got: {:?}",
            verdict
        );

        fs::remove_dir_all(&tmp).unwrap();
    }

    #[test]
    fn validates_match_count_mismatch_detected() {
        let tmp = std::env::temp_dir().join("sigmacatch-check-test-mc-mismatch");
        let _ = fs::remove_dir_all(&tmp);

        let (rules, regression) = setup_match_count(&tmp, 2);
        let hits = detect_hits(&rules, &regression);
        assert_eq!(hits, 1, "rule should produce exactly 1 hit");

        let expected = regression
            .get_info(0)
            .and_then(|info| info.regression_tests_info.first())
            .map(|t| t.match_count)
            .unwrap_or(0);
        let json_present = regression.get_json_data(0).is_some();
        let verdict = if json_present && expected > 0 && hits != expected {
            Some(format!(
                "MATCH COUNT MISMATCH — expected {} hit(s), got {}",
                expected, hits
            ))
        } else {
            None
        };
        assert!(verdict.is_some(), "match_count 2 vs 1 hit should fail");
        assert!(
            verdict.unwrap().contains("MATCH COUNT MISMATCH"),
            "error should report match count mismatch"
        );

        fs::remove_dir_all(&tmp).unwrap();
    }

    #[test]
    fn validates_match_count_skipped_when_json_absent() {
        let tmp = std::env::temp_dir().join("sigmacatch-check-test-mc-nojson");
        let _ = fs::remove_dir_all(&tmp);

        let (rules, regression) = setup_match_count(&tmp, 2);
        let hits = detect_hits(&rules, &regression);
        assert_eq!(hits, 1, "rule should produce exactly 1 hit");

        // Remove the auxiliary .json so get_json_data returns None.
        let json_path = tmp
            .join("sigma")
            .join("regression_data")
            .join("rules")
            .join("test")
            .join("aaaaaaaa-aaaa-4aaa-9aaa-aaaaaaaaaaaa.json");
        fs::remove_file(&json_path).unwrap();

        let expected = regression
            .get_info(0)
            .and_then(|info| info.regression_tests_info.first())
            .map(|t| t.match_count)
            .unwrap_or(0);
        let json_present = regression.get_json_data(0).is_some();
        let verdict = if json_present && expected > 0 && hits != expected {
            Some(format!(
                "MATCH COUNT MISMATCH — expected {} hit(s), got {}",
                expected, hits
            ))
        } else {
            None
        };
        assert!(
            verdict.is_none(),
            "without a .json auxiliary the match_count check must be skipped, got: {:?}",
            verdict
        );

        fs::remove_dir_all(&tmp).unwrap();
    }
}
