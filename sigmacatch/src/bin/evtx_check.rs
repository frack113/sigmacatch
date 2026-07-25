// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 sigmacatch contributors

//! evtx_check: batch validation of the Sigma detection engine against SigmaHQ regression data.
//!
//! Pipeline:
//!   1. Scan <sigmahq_dir>/regression_data for info.yml entries via load_all()
//!   2. Load all Sigma rules from the sigma dir into a single engine
//!   3. For each regression entry: parse data file, evaluate against the engine
//!   4. Validate: expected rule matches + hit count matches
//!   5. Report per-rule pass/fail + summary
//!
//! Usage:
//!   cargo run --release --bin evtx_check <sigmahq_dir>

use anyhow::{anyhow, Result};
use detection_engine::find_rules_dirs;
use detection_engine::DetectionEngine;
use input_evtx::EventCollector;
use sigma_mapping::mapping::resolve_logsource;
use sigma_regression::{load_all, RegressionInfo};
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

// ─── Validation ───────────────────────────────────────────────────────────────

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

fn validate_regression(
    regression: &RegressionInfo,
    engine: &DetectionEngine,
) -> Result<(String, bool, String)> {
    let rule_name = regression
        .info_path
        .parent()
        .and_then(|p| p.file_name())
        .and_then(|n| n.to_str())
        .unwrap_or("unknown")
        .to_string();

    let rule_title = regression
        .info
        .rule_metadata
        .first()
        .map(|r| r.title.clone())
        .unwrap_or_else(|| "<no title>".to_string());

    let data_path = regression
        .data_path
        .as_ref()
        .ok_or_else(|| anyhow!("No data file for rule '{}'", regression.rule_id))?;

    let mut collector = EventCollector::new();
    collector.load_evtx(data_path)?;
    let events = collector.get_events();

    if events.is_empty() {
        return Err(anyhow!("EMPTY — evtx produced no events"));
    }

    let event = events.first().unwrap();
    let channel = event.channel().to_string();
    let provider = event.provider().to_string();
    let event_id = event.event_id();
    let logsource = resolve_logsource(&channel, &provider, event_id, &HashMap::new());
    let matches = engine.evaluate(&event.event_json, &logsource);

    let matched_rule_ids: HashSet<&str> = matches
        .iter()
        .filter_map(|m| m.header.rule_id.as_deref())
        .collect();

    if !matched_rule_ids.contains(&regression.rule_id.as_str()) {
        return Err(anyhow!(
            "RULE NOT MATCHED — expected '{}' ({} matches)",
            regression.rule_id,
            matches.len()
        ));
    }

    Ok((
        format!("{} ({})", rule_name, rule_title),
        true,
        format!("{} match(es), rule matched", matches.len()),
    ))
}

// ─── Main ─────────────────────────────────────────────────────────────────────

fn main() {
    let args: Vec<String> = std::env::args().collect();

    if args.len() < 2 {
        eprintln!("Usage: evtx_check <sigmahq_dir>");
        eprintln!();
        eprintln!("Scans <sigmahq_dir>/regression_data/ for info.yml entries,");
        eprintln!("evaluates each data file against all loaded Sigma rules, and");
        eprintln!("validates that expected rules match with correct hit counts.");
        eprintln!();
        eprintln!("Example:");
        eprintln!("  cargo run --release --bin evtx_check ./sigma");
        std::process::exit(1);
    }

    let sigma_dir = PathBuf::from(&args[1]);
    let regression_dir = sigma_dir.join("regression_data");

    println!("SigmaHQ directory: {}", sigma_dir.display());
    println!("Scanning regression data: {}", regression_dir.display());
    println!();

    let regressions = match load_all(&regression_dir) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("Failed to scan regression data: {}", e);
            std::process::exit(1);
        }
    };

    if regressions.is_empty() {
        eprintln!(
            "No regression entries found in {}",
            regression_dir.display()
        );
        std::process::exit(1);
    }

    println!("Found {} regression entry(ies)", regressions.len());
    println!();

    println!("Loading Sigma rules into engine...");
    let dirs = match find_rules_dirs(&sigma_dir) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("Failed to find rule directories: {}", e);
            std::process::exit(1);
        }
    };
    let refs: Vec<&Path> = dirs.iter().map(|d| d.as_path()).collect();
    let engine = match DetectionEngine::from_rules_dirs(&refs) {
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
    let mut skipped: Vec<(String, String)> = Vec::new();

    for regression in &regressions {
        stats.total += 1;
        let name = regression
            .info_path
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

        if regression.data_path.is_none() {
            skipped.push((name.clone(), "no data file found".to_string()));
            println!("[SKIP] no data file found");
            continue;
        }

        match validate_regression(regression, &engine) {
            Ok((display_name, is_pass, detail)) => {
                if is_pass {
                    stats.add_pass();
                    println!("[PASS] {}", detail);
                } else {
                    let msg = detail.clone();
                    stats.add_fail(display_name.clone(), msg);
                    println!("[FAIL] {}", detail);
                }
            }
            Err(e) => {
                let msg = e.to_string();
                stats.add_fail(name.clone(), msg.clone());
                println!("[FAIL] {}", e);
            }
        }
    }

    if !skipped.is_empty() {
        println!("\n[SKIPPED] {} entry(ies) (missing data):", skipped.len());
        for (name, reason) in &skipped {
            println!("  - {} — {}", name, reason);
        }
    }

    stats.print_summary();

    if !stats.failed.is_empty() {
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sigma_regression::load_all;
    use std::fs;

    fn valid_info_yml(rule_id: &str, test_type: &str) -> String {
        format!(
            "id: 00000000-0000-0000-0000-000000000000\n\
             description: N/A\n\
             date: 2024-01-01\n\
             author: test\n\
             rule_metadata:\n\
             \x20 - id: {}\n\
             \x20   title: Test Rule\n\
             regression_tests_info:\n\
             \x20 - name: test\n\
             \x20   type: {}\n\
             \x20   provider: test\n\
             \x20   match_count: 1\n\
             \x20   path: test.evtx\n",
            rule_id, test_type
        )
    }

    #[test]
    fn test_validate_regression_no_data_file() {
        let tmp = tempfile::tempdir().unwrap();
        let rule_dir = tmp.path().join("bare-rule");
        fs::create_dir(&rule_dir).unwrap();
        fs::write(
            rule_dir.join("info.yml"),
            valid_info_yml("bare-rule", "evtx"),
        )
        .unwrap();

        let regressions = load_all(tmp.path()).unwrap();
        assert_eq!(regressions.len(), 1);

        let entry = &regressions[0];
        let result = validate_regression(entry, &DetectionEngine::default());
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("No data file for rule"));
    }

    #[test]
    fn test_validation_stats_print() {
        let mut stats = ValidationStats::new();
        stats.add_pass();
        stats.add_pass();
        stats.add_fail("test-rule".to_string(), "some error".to_string());
        stats.total = 3;
        // Just verify it doesn't panic
        stats.print_summary();
    }
}
