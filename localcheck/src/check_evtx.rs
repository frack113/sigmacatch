// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 sigmacatch contributors

//! check_evtx: validate SigmaHQ regression data against the detection engine.
//!
//! Pipeline:
//!   1. Load all Sigma rules from `./sigma` into a single DetectionEngine
//!   2. Scan `./sigma/regression_data` for info.yml entries
//!   3. For each entry: load evtx, evaluate, check alerts
//!   4. When a committed `<rule_id>.json` exists, verify that our
//!      `parse_winevt_xml_raw` output reproduces it (SigmaHQ format conformance)
//!   5. Report per-rule pass/fail + summary
//!
//! Usage:
//!   cargo run --release --bin check_evtx

use input_evtx::parse_evtx_bytes;
use sigmacatch_detection::DetectionEngine;
use sigmacatch_regression::logtype::LogType;
use sigmacatch_regression::SigmahqRegression;
use sigmacatch_rule::{SigmaFilterConfig, SigmahqRules};
use std::collections::HashSet;
use std::process;
use uuid::Uuid;

// ─── Stats ────────────────────────────────────────────────────────────────────

struct ValidationStats {
    total: usize,
    passed: usize,
    skipped: usize,
    failed: Vec<(String, String)>,
    json_checked: usize,
    json_ok: usize,
    json_mismatch: Vec<(String, String)>,
}

impl ValidationStats {
    fn new() -> Self {
        Self {
            total: 0,
            passed: 0,
            skipped: 0,
            failed: Vec::new(),
            json_checked: 0,
            json_ok: 0,
            json_mismatch: Vec::new(),
        }
    }

    fn add_pass(&mut self) {
        self.passed += 1;
    }

    fn add_skip(&mut self) {
        self.skipped += 1;
    }

    fn add_fail(&mut self, rule_name: String, error: String) {
        self.failed.push((rule_name, error));
    }

    fn add_json_ok(&mut self) {
        self.json_checked += 1;
        self.json_ok += 1;
    }

    fn add_json_mismatch(&mut self, rule_name: String, error: String) {
        self.json_checked += 1;
        self.json_mismatch.push((rule_name, error));
    }

    fn print_summary(&self) {
        println!("\n{}", "=".repeat(60));
        println!("  VALIDATION SUMMARY");
        println!("{}", "=".repeat(60));
        println!("  Total entries:   {}", self.total);
        println!("  Passed:          {}", self.passed);
        println!("  Skipped:         {}", self.skipped);
        println!("  Failed:          {}", self.failed.len());
        let evaluated = self.passed + self.failed.len();
        println!(
            "  Pass rate:       {:.1}%",
            if evaluated > 0 {
                (self.passed as f64 / evaluated as f64) * 100.0
            } else {
                0.0
            }
        );

        if self.json_checked > 0 {
            println!();
            println!("  JSON FORMAT CHECKS (parse_winevt_xml_raw vs committed JSON):");
            println!("  Checked:         {}", self.json_checked);
            println!("  Matched:         {}", self.json_ok);
            println!("  Mismatch:        {}", self.json_mismatch.len());
        }

        println!("{}", "=".repeat(60));

        if !self.failed.is_empty() {
            println!("\nFailed rules:");
            for (name, error) in &self.failed {
                println!("  FAIL {} — {}", name, error);
            }
        }

        if !self.json_mismatch.is_empty() {
            println!("\nJSON format mismatches:");
            for (name, error) in &self.json_mismatch {
                println!("  MISMATCH {} — {}", name, error);
            }
        }
    }
}

/// First differing path between two JSON values (for actionable mismatch reports).
fn first_diff_path(a: &serde_json::Value, b: &serde_json::Value) -> Option<String> {
    if a == b {
        return None;
    }
    Some(match (a, b) {
        (serde_json::Value::Object(ao), serde_json::Value::Object(bo)) => {
            for key in ao.keys().chain(bo.keys()) {
                let av = ao.get(key);
                let bv = bo.get(key);
                if av != bv {
                    let sub = match (av, bv) {
                        (Some(x), Some(y)) => first_diff_path(x, y).unwrap_or_default(),
                        _ => "<missing>".to_string(),
                    };
                    return Some(if sub.is_empty() {
                        key.clone()
                    } else {
                        format!("{key}.{sub}")
                    });
                }
            }
            "object".to_string()
        }
        (serde_json::Value::Array(aa), serde_json::Value::Array(ba)) => {
            for (i, (xv, yv)) in aa.iter().zip(ba.iter()).enumerate() {
                if xv != yv {
                    let sub = first_diff_path(xv, yv).unwrap_or_default();
                    return Some(if sub.is_empty() {
                        format!("[{i}]")
                    } else {
                        format!("[{i}].{sub}")
                    });
                }
            }
            "array".to_string()
        }
        (x, y) => format!("{:?} != {:?}", x, y),
    })
}

// ─── Main ─────────────────────────────────────────────────────────────────────

fn main() {
    let rules = match SigmahqRules::new() {
        Ok(r) => r,
        Err(e) => {
            eprintln!("Failed to load rules: {}", e);
            process::exit(1);
        }
    };
    println!("Found {} total rules", rules.len());

    let rules = rules.filter(SigmaFilterConfig {
        product: "windows".to_string(),
        ..Default::default()
    });
    println!("  → {} windows rules after filtering", rules.len());
    println!();

    let regression = match SigmahqRegression::new() {
        Ok(r) => r,
        Err(e) => {
            eprintln!("Failed to load regression data: {}", e);
            process::exit(1);
        }
    };
    if regression.is_empty() {
        eprintln!("No regression entries found — nothing to validate");
        process::exit(1);
    }
    println!("Found {} regression entry(ies)", regression.len());
    println!();

    let mut engine = match DetectionEngine::new(&rules) {
        Ok(e) => e,
        Err(e) => {
            eprintln!("Failed to build engine: {}", e);
            process::exit(1);
        }
    };
    println!("Engine ready — {} rule(s) loaded.\n", engine.rule_count());

    println!("Running validation...");
    println!();

    let mut stats = ValidationStats::new();

    for i in 0..regression.len() {
        let entry = match regression.get_entry(i) {
            Some(e) => e,
            None => {
                stats.total += 1;
                println!("[FAIL] No entry");
                continue;
            }
        };

        print!(
            "  [{:>4}/{:<4}] {:<50} ... ",
            i + 1,
            regression.len(),
            entry.rule_name
        );

        let raw = match regression.get_raw_data(i) {
            Some(r) => r,
            None => {
                stats.total += 1;
                stats.add_fail(entry.rule_name.clone(), "No raw data".to_string());
                println!("[FAIL] No raw data");
                continue;
            }
        };

        let events = match entry.logtype {
            LogType::Evtx => match parse_evtx_bytes(&raw) {
                Ok(events) => events,
                Err(e) => {
                    stats.total += 1;
                    stats.add_fail(
                        entry.rule_name.clone(),
                        format!("Failed to load EVTX: {}", e),
                    );
                    println!("[FAIL] Failed to load EVTX: {}", e);
                    continue;
                }
            },
            _ => {
                stats.total += 1;
                stats.add_skip();
                println!("[SKIP] {} (EVTX check only)", entry.logtype.as_str());
                continue;
            }
        };

        if events.is_empty() {
            stats.total += 1;
            stats.add_fail(
                entry.rule_name.clone(),
                "EMPTY — evtx produced no events".to_string(),
            );
            println!("[FAIL] EMPTY — evtx produced no events");
            continue;
        }

        // Clone events for debug output before they're consumed
        let events_for_debug = events.clone();

        // JSON format check: when a committed <rule_id>.json exists, verify our
        // parse_winevt_xml_raw output (event.event_json_raw) reproduces it.
        if let Some(expected) = regression.get_json_data(i) {
            let reproduced = events_for_debug
                .iter()
                .any(|e| e.event_json_raw == expected);
            if reproduced {
                stats.add_json_ok();
                println!("    [JSON OK] parse_winevt_xml_raw reproduces committed JSON");
            } else {
                let diff = events_for_debug
                    .iter()
                    .find_map(|e| first_diff_path(&e.event_json_raw, &expected));
                let detail = diff
                    .map(|p| format!(" first diff: {p}"))
                    .unwrap_or_default();
                stats.add_json_mismatch(
                    entry.rule_name.clone(),
                    format!("no EVTX record reproduces committed JSON{detail}"),
                );
                println!("    [JSON MISMATCH] no EVTX record reproduces committed JSON{detail}");
            }
        }

        engine.put_events(events);
        engine.process_events();
        let alerts = engine.get_alerts();

        let matched_ids: HashSet<Uuid> = alerts.iter().map(|a| a.rule_id).collect();

        if !matched_ids.contains(&entry.rule_id) {
            let matched: Vec<String> = matched_ids.iter().map(|s| s.to_string()).collect();
            stats.total += 1;
            stats.add_fail(
                entry.rule_name.clone(),
                format!(
                    "RULE NOT MATCHED — expected '{}' ({} alert(s), matched: {})",
                    entry.rule_id,
                    alerts.len(),
                    matched.join(", ")
                ),
            );
            println!(
                "[FAIL] RULE NOT MATCHED — expected '{}' ({} alert(s), matched: {})",
                entry.rule_id,
                alerts.len(),
                matched.join(", ")
            );

            // Debug: explain rule against each event
            for event in &events_for_debug {
                if let Some(explanation) = engine.explain_rule(&entry.rule_id, event) {
                    println!("  --- explain_rule trace ---");
                    if let Ok(json) = serde_json::to_string_pretty(&explanation) {
                        println!("  {}", json.replace('\n', "\n  "));
                    }
                }
                println!("  --- event JSON ---");
                if let Ok(json) = serde_json::to_string_pretty(&event.event_json) {
                    println!("  {}", json.replace('\n', "\n  "));
                }
                println!();
            }
            continue;
        }

        let rule_alert_count: u64 =
            alerts.iter().filter(|a| a.rule_id == entry.rule_id).count() as u64;
        if rule_alert_count < 1 {
            stats.total += 1;
            stats.add_fail(
                entry.rule_name.clone(),
                "MATCH COUNT MISMATCH — expected >= 1 (got 0)".to_string(),
            );
            println!("[FAIL] MATCH COUNT MISMATCH — expected >= 1 (got 0)");
            continue;
        }

        stats.total += 1;
        stats.add_pass();
        println!("[PASS] {} alert(s), rule matched", rule_alert_count);
    }

    stats.print_summary();

    if !stats.failed.is_empty() || !stats.json_mismatch.is_empty() {
        process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validation_stats_print() {
        let mut stats = ValidationStats::new();
        stats.add_pass();
        stats.add_pass();
        stats.add_skip();
        stats.add_fail("test-rule".to_string(), "some error".to_string());
        stats.total = 4;
        stats.print_summary();
    }

    #[test]
    fn test_first_diff_path_equal() {
        let a = serde_json::json!({"Event": {"EventID": 1}});
        let b = serde_json::json!({"Event": {"EventID": 1}});
        assert_eq!(first_diff_path(&a, &b), None);
    }

    #[test]
    fn test_first_diff_path_number_vs_string() {
        let a = serde_json::json!({"Event": {"System": {"EventID": 1}, "EventData": {"ProcessId": "5112"}}});
        let b = serde_json::json!({"Event": {"System": {"EventID": 1}, "EventData": {"ProcessId": 5112}}});
        let diff = first_diff_path(&a, &b).unwrap();
        assert!(
            diff.contains("EventData"),
            "diff should point at EventData: {diff}"
        );
        assert!(
            diff.contains("ProcessId"),
            "diff should name ProcessId: {diff}"
        );
    }

    #[test]
    fn test_first_diff_path_missing_key() {
        let a = serde_json::json!({"Event": {"EventID": 1}});
        let b = serde_json::json!({"Event": {"EventID": 1, "_source": "winevt"}});
        let diff = first_diff_path(&a, &b).unwrap();
        assert!(diff.contains("_source"), "diff should name _source: {diff}");
    }
}
