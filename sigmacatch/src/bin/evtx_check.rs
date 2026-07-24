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
use detection_engine::DetectionEngine;
use input_evtx::parse_evtx_file;
use sigma_mapping::mapping::resolve_logsource;
use sigmacatch::regression::loader::{load_all, RegressionInfo};
use sigmacatch::sigma::loader::find_rules_dirs;
use std::collections::HashMap;
use std::fs;
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
    expected_match_count: usize,
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

    if regression.logtype != "evtx" {
        return Err(anyhow!(
            "Unsupported logtype '{}' for rule '{}'",
            regression.logtype,
            regression.rule_id
        ));
    }

    // Parse EVTX → Event (uses sigmacatch_types::Event)
    let events = parse_evtx_file(data_path).map_err(|e| anyhow!("EVTX parse error: {}", e))?;
    let event = events
        .first()
        .ok_or_else(|| anyhow!("No records in EVTX: {}", data_path.display()))?
        .clone();

    let channel = event.channel().to_string();
    let provider = event.provider().to_string();
    let event_id = event.event_id();

    let logsource = resolve_logsource(&channel, &provider, event_id, &HashMap::new());

    let matches = engine.evaluate(&event.event_json, &logsource);

    // Check that the expected rule is in the matched rules
    let matched_rule_ids: Vec<&str> = matches
        .iter()
        .filter_map(|m| m.header.rule_id.as_deref())
        .collect();

    let rule_matched = matched_rule_ids.contains(&regression.rule_id.as_str());
    let actual_match_count = matches.len();

    if !rule_matched && expected_match_count > 0 {
        Err(anyhow!(
            "FALSE NEGATIVE — expected rule '{}' not matched (EventID={}, Channel={}, provider={}) — got {} match(es)",
            regression.rule_id,
            event_id,
            channel,
            provider,
            actual_match_count
        ))
    } else if expected_match_count > 0 && actual_match_count != expected_match_count {
        Err(anyhow!(
            "HIT MISMATCH — expected {} hit(s), got {} (rule '{}')",
            expected_match_count,
            actual_match_count,
            regression.rule_id
        ))
    } else if !rule_matched {
        Err(anyhow!(
            "RULE NOT MATCHED — expected rule '{}' not in results ({} match(es), no match_count in info.yml)",
            regression.rule_id, actual_match_count
        ))
    } else {
        Ok((
            format!("{} ({})", rule_name, rule_title),
            true,
            format!("{} match(es), rule matched", actual_match_count),
        ))
    }
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

        let data_size = regression
            .data_path
            .as_ref()
            .and_then(|p| fs::metadata(p).ok())
            .map(|m| m.len())
            .unwrap_or(0);

        let expected_match_count = regression
            .info
            .regression_tests_info
            .first()
            .map(|t| t.match_count)
            .unwrap_or(0);

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

        if data_size < 0x1000 {
            skipped.push((
                name.clone(),
                format!("data file too small ({} bytes)", data_size),
            ));
            println!("[SKIP] data file too small ({} bytes)", data_size);
            continue;
        }

        match validate_regression(regression, &engine, expected_match_count) {
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
