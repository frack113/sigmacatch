// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 sigmacatch contributors

//! evtx_check: validate SigmaHQ regression data against the detection engine.
//!
//! Pipeline:
//!   1. Load all Sigma rules from `./sigma` into a single DetectionEngine
//!   2. Scan `./sigma/regression_data` for info.yml entries
//!   3. For each entry: load evtx, evaluate, check alerts
//!   4. Report per-rule pass/fail + summary
//!
//! Usage:
//!   cargo run --release --bin evtx_check

use input_evtx::parse_evtx_bytes;
use sigmacatch_detection::DetectionEngine;
use sigmacatch_regression::logtype::LogType;
use sigmacatch_regression::SigmahqRegression;
use sigmacatch_rule::SigmahqRules;
use std::collections::HashSet;
use std::process;
use uuid::Uuid;

// ─── Stats ────────────────────────────────────────────────────────────────────

struct ValidationStats {
    total: usize,
    passed: usize,
    skipped: usize,
    failed: Vec<(String, String)>,
}

impl ValidationStats {
    fn new() -> Self {
        Self {
            total: 0,
            passed: 0,
            skipped: 0,
            failed: Vec::new(),
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
        println!("{}", "=".repeat(60));

        if !self.failed.is_empty() {
            println!("\nFailed rules:");
            for (name, error) in &self.failed {
                println!("  FAIL {} — {}", name, error);
            }
        }
    }
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

    let rules = rules.filter(Some("windows"), None, None);
    println!("  → {} windows rules after filtering", rules.len());
    println!();

    // Load regression entries
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

    // Build engine once
    let mut engine = match DetectionEngine::new(&rules) {
        Ok(e) => e,
        Err(e) => {
            eprintln!("Failed to build engine: {}", e);
            process::exit(1);
        }
    };
    println!("Engine ready — {} rule(s) loaded.\n", engine.rule_count());

    // Validate each entry
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

    if !stats.failed.is_empty() {
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
}
