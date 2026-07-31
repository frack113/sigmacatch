// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 sigmacatch contributors

//! evtx_check: validate SigmaHQ regression data against the detection engine.
//!
//! Pipeline:
//!   1. Scan `./sigma/regression_data` for info.yml entries via list_all()
//!   2. Load all Sigma rules from `./sigma` into a single DetectionEngine
//!   3. For each entry: load its evtx data, push events into the engine, check alerts
//!   4. Report per-rule pass/fail + summary
//!
//! Usage:
//!   cargo run --release --bin evtx_check

use input_evtx::parse_evtx_bytes;
use sigmacatch_detection::DetectionEngine;
use sigmacatch_regression::logtype::LogType;
use sigmacatch_regression::{list_all, RegressionData};
use sigmacatch_rule::SigmahqRules;
use std::collections::HashSet;
use std::path::PathBuf;

// ─── Stats ────────────────────────────────────────────────────────────────────

struct ValidationStats {
    total: usize,
    passed: usize,
    failed: Vec<(String, String)>,
}

impl ValidationStats {
    fn new() -> Self {
        Self {
            total: 0,
            passed: 0,
            failed: Vec::new(),
        }
    }

    fn add_pass(&mut self) {
        self.passed += 1;
    }

    fn add_fail(&mut self, rule_name: String, error: String) {
        self.failed.push((rule_name, error));
    }

    fn print_summary(&self) {
        println!("\n{}", "=".repeat(60));
        println!("  VALIDATION SUMMARY");
        println!("{}", "=".repeat(60));
        println!("  Total rules:     {}", self.total);
        println!("  Passed:          {}", self.passed);
        println!("  Failed:          {}", self.failed.len());
        println!(
            "  Pass rate:       {:.1}%",
            if self.total > 0 {
                (self.passed as f64 / self.total as f64) * 100.0
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
    let sigma_dir = PathBuf::from("./sigma");
    if !sigma_dir.exists() {
        eprintln!("sigma/ directory not found — run sigmacatch first");
        std::process::exit(1);
    }

    let regression_dir = sigma_dir.join("regression_data");
    if !regression_dir.exists() {
        eprintln!("sigma/regression_data directory not found — run sigmacatch first");
        std::process::exit(1);
    }

    println!("Loading Sigma rules into engine...");
    let rules = match SigmahqRules::new(&sigma_dir) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("Failed to load rules: {}", e);
            std::process::exit(1);
        }
    };
    println!("Found {} sigmahq rules", rules.len());
    let rules = rules.filter(Some("windows"), None, None);
    println!("Found {} windows rules", rules.len());
    println!();

    println!("Scanning regression data: {}", regression_dir.display());
    println!();

    let info_paths = list_all(&regression_dir);

    if info_paths.is_empty() {
        eprintln!(
            "No regression entries found in {}",
            regression_dir.display()
        );
        std::process::exit(1);
    }

    println!("Found {} regression entry(ies)", info_paths.len());
    println!();

    println!("Loading Sigma rules into engine...");
    let rules = match SigmahqRules::new(&sigma_dir) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("Failed to load rules: {}", e);
            std::process::exit(1);
        }
    };
    let mut engine = match DetectionEngine::new(&rules) {
        Ok(e) => e,
        Err(e) => {
            eprintln!("Failed to build engine: {}", e);
            std::process::exit(1);
        }
    };
    println!("Engine ready — {} rule(s) loaded.\n", engine.rule_count());

    println!("Running validation...");
    println!();

    let mut stats = ValidationStats::new();

    for info_path in &info_paths {
        stats.total += 1;
        let name = info_path
            .parent()
            .and_then(|p| p.file_name())
            .and_then(|n| n.to_str())
            .unwrap_or("unknown")
            .to_string();

        print!(
            "  [{:>4}/{:<4}] {:<50} ... ",
            stats.passed + stats.failed.len(),
            stats.total,
            name
        );

        let data = match RegressionData::from_info(info_path) {
            Ok(d) => d,
            Err(e) => {
                stats.total -= 1; // don't count as a real entry
                stats.add_fail(name, format!("Failed to load: {}", e));
                println!("[FAIL] {}", e);
                continue;
            }
        };

        let rule_id = data.rule_id();

        let raw = match data.get_raw_data() {
            Some(r) => r,
            None => {
                stats.add_fail(name.clone(), "No raw data".to_string());
                println!("[FAIL] No raw data");
                continue;
            }
        };
        let logtype = data.get_logtype();

        let events = match logtype {
            LogType::Evtx => match parse_evtx_bytes(raw) {
                Ok(events) => events,
                Err(e) => {
                    stats.add_fail(name.clone(), format!("Failed to load EVTX: {}", e));
                    println!("[FAIL] Failed to load EVTX: {}", e);
                    continue;
                }
            },
            _ => {
                stats.add_fail(
                    name.clone(),
                    format!("Skipped ({} — EVTX check only)", logtype.as_str()),
                );
                println!("[SKIP] {} (EVTX check only)", logtype.as_str());
                continue;
            }
        };

        if events.is_empty() {
            stats.add_fail(name.clone(), "EMPTY — evtx produced no events".to_string());
            println!("[FAIL] EMPTY — evtx produced no events");
            continue;
        }

        let events_for_debug = events.clone();
        engine.put_events(events);
        engine.process_events();
        let alerts = engine.get_alerts();

        let matched_ids: HashSet<&str> = alerts.iter().map(|a| a.rule_id.as_str()).collect();

        if !matched_ids.contains(rule_id) {
            let matched: Vec<String> = matched_ids.iter().map(|s| s.to_string()).collect();
            stats.add_fail(
                name.clone(),
                format!(
                    "RULE NOT MATCHED — expected '{}' ({} alert(s), matched: {})",
                    rule_id,
                    alerts.len(),
                    matched.join(", ")
                ),
            );
            println!(
                "[FAIL] RULE NOT MATCHED — expected '{}' ({} alert(s), matched: {})",
                rule_id,
                alerts.len(),
                matched.join(", ")
            );

            // Debug: explain rule against each event
            for event in &events_for_debug {
                if let Some(explanation) = engine.explain_rule(rule_id, event) {
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

        let rule_alert_count: u64 = alerts.iter().filter(|a| a.rule_id == rule_id).count() as u64;
        if rule_alert_count < 1 {
            stats.add_fail(
                name.clone(),
                "MATCH COUNT MISMATCH — expected >= 1 (got 0)".to_string(),
            );
            println!("[FAIL] MATCH COUNT MISMATCH — expected >= 1 (got 0)");
            continue;
        }

        stats.add_pass();
        println!("[PASS] {} alert(s), rule matched", rule_alert_count);
    }

    stats.print_summary();

    if !stats.failed.is_empty() {
        std::process::exit(1);
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
        stats.add_fail("test-rule".to_string(), "some error".to_string());
        stats.total = 3;
        stats.print_summary();
    }
}
