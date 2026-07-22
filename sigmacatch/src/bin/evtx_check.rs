// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 sigmacatch contributors

//! evtx_check: batch validation of the Sigma detection engine against SigmaHQ regression data.
//!
//! Pipeline:
//!   1. Scan <sigmahq_dir>/regression_data for info.yml files
//!   2. Load all Sigma rules from the sigma dir into a single engine
//!   3. For each info.yml triplet: parse EVTX, evaluate against the engine
//!   4. Validate: expected rule matches + hit count matches
//!   5. Report per-rule pass/fail + summary
//!
//! Usage:
//!   cargo run --release --bin evtx_check <sigmahq_dir>

use anyhow::{anyhow, Result};
use evtx::EvtxParser;
use rsigma_eval::event::JsonEvent;
use rsigma_eval::pipeline::parse_pipeline;
use rsigma_eval::Engine;
use serde_json::Value;
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

use rsigma_parser::parse_sigma_yaml;
use sigma_core::mapping::resolve_logsource;
use win_evt_core::xml_parser::validate_event_id;

// ─── Regression Data Scanner ──────────────────────────────────────────────────

#[derive(Debug)]
struct RegressionTriplet {
    evtx_path: PathBuf,
    info_path: PathBuf,
}

fn scan_regression_data(base: &Path) -> Result<Vec<RegressionTriplet>> {
    let mut triplets = Vec::new();

    if !base.exists() {
        return Err(anyhow!("Directory does not exist: {}", base.display()));
    }

    let walk = fs::read_dir(base)?;
    for entry in walk.flatten() {
        let sub = entry.path();
        if !sub.is_dir() {
            continue;
        }
        scan_dir_recursive(&sub, base, &mut triplets)?;
    }

    triplets.sort_by(|a, b| a.info_path.cmp(&b.info_path));
    Ok(triplets)
}

#[allow(clippy::only_used_in_recursion)]
fn scan_dir_recursive(
    dir: &Path,
    base: &Path,
    triplets: &mut Vec<RegressionTriplet>,
) -> Result<()> {
    let entries = match fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return Ok(()),
    };

    let mut has_info = false;
    let mut has_evtx = false;
    let mut info_path = None;
    let mut evtx_path = None;

    for entry in entries.flatten() {
        let ep = entry.path();
        if ep.is_file() {
            match ep.extension().and_then(|e| e.to_str()) {
                Some("yml") | Some("yaml") => {
                    if ep.file_name().map(|n| n == "info.yml").unwrap_or(false) {
                        has_info = true;
                        info_path = Some(ep);
                    }
                }
                Some("evtx") => {
                    has_evtx = true;
                    evtx_path = Some(ep);
                }
                _ => {}
            }
        } else if ep.is_dir() {
            scan_dir_recursive(&ep, base, triplets)?;
        }
    }

    if has_info && has_evtx {
        if let (Some(info), Some(evtx)) = (info_path, evtx_path) {
            triplets.push(RegressionTriplet {
                evtx_path: evtx,
                info_path: info,
            });
        }
    }

    Ok(())
}

// ─── Rule Resolution ──────────────────────────────────────────────────────────

#[allow(dead_code)]
fn find_rule_file(info_path: &Path, sigma_dir: &Path) -> Result<PathBuf> {
    let info: InfoYml = InfoYml::load(info_path)?;
    let rule_id = info
        .rule_metadata
        .first()
        .ok_or_else(|| anyhow!("No rule_metadata in info.yml"))?
        .id
        .clone();

    for rules_subdir in [
        "rules",
        "rules-dfir",
        "rules-emerging-threats",
        "rules-threat-hunting",
    ] {
        let rules_dir = sigma_dir.join(rules_subdir);
        if !rules_dir.exists() {
            continue;
        }
        if let Ok(found) = find_rule_by_id(&rules_dir, &rule_id) {
            return Ok(found);
        }
    }

    Err(anyhow!(
        "Rule file not found for ID {} in {}",
        rule_id,
        sigma_dir.display()
    ))
}

#[allow(dead_code)]
fn find_rule_by_id(dir: &Path, rule_id: &str) -> Result<PathBuf> {
    let entries = fs::read_dir(dir)?;
    for entry in entries.flatten() {
        let ep = entry.path();
        if ep.is_file() {
            if let Some(name) = ep.file_name().and_then(|n| n.to_str()) {
                if name == "index.yml" {
                    continue;
                }
                if let Ok(content) = fs::read_to_string(&ep) {
                    for line in content.lines() {
                        if line.trim() == format!("id: {}", rule_id) {
                            return Ok(ep);
                        }
                    }
                }
            }
        } else if ep.is_dir() {
            if let Ok(found) = find_rule_by_id(&ep, rule_id) {
                return Ok(found);
            }
        }
    }
    Err(anyhow!("Not found"))
}

// ─── info.yml ────────────────────────────────────────────────────────────────

use sigmacatch::regression::info::InfoYml;

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

fn build_engine(sigma_dir: &Path) -> Result<Engine> {
    let mut engine = Engine::new();

    let flatten_yaml = include_str!("../pipelines/flatten_winevt.yml");
    let flatten_pipeline =
        parse_pipeline(flatten_yaml).expect("flatten_winevt pipeline YAML is valid");
    engine.add_pipeline(flatten_pipeline);

    let windows_yaml = include_str!("../pipelines/windows.yml");
    let windows_pipeline = parse_pipeline(windows_yaml).expect("windows pipeline YAML is valid");
    engine.add_pipeline(windows_pipeline);

    let rules_dirs = [
        sigma_dir.join("rules"),
        sigma_dir.join("rules-dfir"),
        sigma_dir.join("rules-emerging-threats"),
        sigma_dir.join("rules-threat-hunting"),
    ];

    for rules_dir in &rules_dirs {
        if !rules_dir.exists() {
            continue;
        }
        for entry in
            fs::read_dir(rules_dir).map_err(|e| anyhow!("Cannot read {:?}: {}", rules_dir, e))?
        {
            let entry = entry.map_err(|e| anyhow!("Read error: {}", e))?;
            let path = entry.path();
            if !path.is_dir() {
                continue;
            }
            collect_rules_recursive(&path, &mut engine)
                .map_err(|e| anyhow!("Failed to collect rules from {:?}: {}", path, e))?;
        }
    }

    Ok(engine)
}

fn collect_rules_recursive(dir: &Path, engine: &mut Engine) -> Result<()> {
    let entries = match fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return Ok(()),
    };

    for entry in entries.flatten() {
        let ep = entry.path();
        if ep.is_file() {
            if let Some(ext) = ep.extension().and_then(|e| e.to_str()) {
                if ext == "yml" || ext == "yaml" {
                    if let Some(name) = ep.file_name().and_then(|n| n.to_str()) {
                        if name == "index.yml" {
                            continue;
                        }
                    }
                    let content = fs::read_to_string(&ep)
                        .map_err(|e| anyhow!("Failed to read {:?}: {}", ep, e))?;
                    let collection = parse_sigma_yaml(&content)
                        .map_err(|e| anyhow!("Failed to parse {:?}: {}", ep, e))?;
                    if !collection.rules.is_empty() {
                        engine.add_collection(&collection).map_err(|e| {
                            anyhow!("Engine add_collection failed for {:?}: {}", ep, e)
                        })?;
                    }
                }
            }
        } else if ep.is_dir() {
            collect_rules_recursive(&ep, engine)?;
        }
    }

    Ok(())
}

fn validate_triplet(
    triplet: &RegressionTriplet,
    engine: &Engine,
    expected_rule_id: &str,
    expected_match_count: usize,
) -> Result<(String, bool, String)> {
    let info = InfoYml::load(&triplet.info_path)?;
    let rule_name = triplet
        .info_path
        .parent()
        .and_then(|p| p.file_name())
        .and_then(|n| n.to_str())
        .unwrap_or("unknown")
        .to_string();

    let rule_title = info
        .rule_metadata
        .first()
        .map(|r| r.title.clone())
        .unwrap_or_default();

    // Parse EVTX
    let mut parser = EvtxParser::from_path(&triplet.evtx_path)
        .map_err(|e| anyhow!("Failed to open EVTX file: {}", e))?;

    let events: Vec<Value> = parser
        .records_json_value()
        .flatten()
        .map(|r| r.data)
        .collect();

    if events.is_empty() {
        return Err(anyhow!(
            "No events extracted from EVTX: {}",
            triplet.evtx_path.display()
        ));
    }

    let first_event = validate_event_id(&events[0]);

    // Derive logsource from nested JSON paths
    let event_obj = first_event
        .get("Event")
        .and_then(|v| v.as_object())
        .ok_or_else(|| anyhow!("EVTX event missing Event key"))?;
    let system = event_obj
        .get("System")
        .and_then(|v| v.as_object())
        .ok_or_else(|| anyhow!("EVTX event missing Event.System"))?;

    let channel = system.get("Channel").and_then(|v| v.as_str()).unwrap_or("");
    let provider = system
        .get("Provider")
        .and_then(|v| v.get("#attributes"))
        .and_then(|a| a.get("Name"))
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let event_id: u32 = system.get("EventID").and_then(|v| v.as_u64()).unwrap_or(0) as u32;

    let event_logsource = resolve_logsource(channel, provider, event_id, &HashMap::new());

    let json_event = JsonEvent::borrow(&first_event);
    let matches = engine.evaluate_with_logsource(&json_event, &event_logsource);

    // Check that the expected rule is in the matched rules
    let matched_rule_ids: Vec<&str> = matches
        .iter()
        .filter_map(|m| m.header.rule_id.as_deref())
        .collect();

    let rule_matched = matched_rule_ids.contains(&expected_rule_id);
    let actual_match_count = matches.len();

    if !rule_matched && expected_match_count > 0 {
        Err(anyhow!(
            "FALSE NEGATIVE — expected rule '{}' not matched (EventID={}, Channel={:?}, provider={:?}) — got {} match(es)",
            expected_rule_id,
            system.get("EventID").and_then(|v| v.as_u64()).unwrap_or(0),
            system.get("Channel").and_then(|v| v.as_str()),
            system
                .get("Provider")
                .and_then(|v| v.get("#attributes"))
                .and_then(|a| a.get("Name"))
                .and_then(|v| v.as_str()),
            actual_match_count
        ))
    } else if expected_match_count > 0 && actual_match_count != expected_match_count {
        Err(anyhow!(
            "HIT MISMATCH — expected {} hit(s), got {} (rule '{}')",
            expected_match_count,
            actual_match_count,
            expected_rule_id
        ))
    } else if !rule_matched {
        Err(anyhow!(
            "RULE NOT MATCHED — expected rule '{}' not in results ({} match(es), no match_count in info.yml)",
            expected_rule_id, actual_match_count
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
        eprintln!("Scans <sigmahq_dir>/regression_data/ for info.yml triplets");
        eprintln!("evaluates each EVTX against all loaded Sigma rules, and");
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

    let triplets = match scan_regression_data(&regression_dir) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("Failed to scan regression data: {}", e);
            std::process::exit(1);
        }
    };

    if triplets.is_empty() {
        eprintln!(
            "No regression triplets found in {}",
            regression_dir.display()
        );
        std::process::exit(1);
    }

    println!("Found {} regression triplet(s)", triplets.len());
    println!();

    println!("Loading Sigma rules into engine...");
    let engine = match build_engine(&sigma_dir) {
        Ok(e) => e,
        Err(e) => {
            eprintln!("Failed to build engine: {}", e);
            std::process::exit(1);
        }
    };
    println!("Engine ready.\n");

    println!("Running validation...");
    println!();

    let mut stats = ValidationStats::new();
    let mut skipped: Vec<(String, String)> = Vec::new();

    for triplet in &triplets {
        stats.total += 1;
        let name = triplet
            .info_path
            .parent()
            .and_then(|p| p.file_name())
            .and_then(|n| n.to_str())
            .unwrap_or("unknown")
            .to_string();

        let evtx_exists = triplet.evtx_path.exists();
        let evtx_size = if evtx_exists {
            fs::metadata(&triplet.evtx_path)
                .map(|m| m.len())
                .unwrap_or(0)
        } else {
            0
        };

        print!(
            "  [{:>4}/{:<4}] {:<50} ... ",
            stats.passed + stats.failed.len(),
            stats.total,
            name
        );

        if !evtx_exists {
            skipped.push((name.clone(), "evtx file missing".to_string()));
            println!("[SKIP] evtx file missing");
            continue;
        }

        if evtx_size < 0x1000 {
            skipped.push((
                name.clone(),
                format!("evtx too small ({} bytes)", evtx_size),
            ));
            println!("[SKIP] evtx too small ({} bytes)", evtx_size);
            continue;
        }

        let info = match InfoYml::load(&triplet.info_path) {
            Ok(i) => i,
            Err(e) => {
                let msg = e.to_string();
                stats.total += 0; // already counted
                stats.add_fail(name.clone(), msg.clone());
                println!("[SKIP] {}", e);
                continue;
            }
        };

        let expected_rule_id = info
            .rule_metadata
            .first()
            .map(|r| r.id.as_str())
            .unwrap_or("unknown");
        let expected_match_count = info
            .regression_tests_info
            .first()
            .map(|t| t.match_count)
            .unwrap_or(0);

        match validate_triplet(triplet, &engine, expected_rule_id, expected_match_count) {
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
        println!("\n[SKIPPED] {} triplet(s) (missing data):", skipped.len());
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
    use std::fs;

    #[test]
    fn test_find_rule_by_id() {
        let dir = tempfile::tempdir().unwrap();
        let yml_path = dir.path().join("test_rule.yml");
        fs::write(&yml_path, "id: abc123\ntitle: Test\n").unwrap();

        let found = find_rule_by_id(dir.path(), "abc123");
        assert!(found.is_ok());
        assert_eq!(found.unwrap(), yml_path);
    }

    #[test]
    fn test_find_rule_by_id_not_found() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("other.yml"), "id: xyz789\n").unwrap();

        let found = find_rule_by_id(dir.path(), "abc123");
        assert!(found.is_err());
    }
}
