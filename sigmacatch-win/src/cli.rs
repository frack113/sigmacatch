// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 sigmacatch contributors

//! CLI subcommands for the main `sigmacatch-channel` binary.
//!
//! Gated behind the `tools` feature. Dispatched from `main_winevt.rs` before
//! `runner::run()` is entered.

use std::collections::{BTreeSet, HashSet};
use std::path::{Path, PathBuf};

use sigmacatch_config::{self, Config, load_custom_channel_mapping};
use sigmacatch_detection::DetectionEngine;
use sigmacatch_regression::SigmahqRegression;
use sigmacatch_repo::SigmaRepo;
use sigmacatch_rule::{
    Level, MinLevel, MinStatus, SigmaFilterConfig, SigmaRuleExt, SigmahqRules, Status,
};
use uuid::Uuid;

#[cfg(feature = "winevt")]
use input_windows_evtx::parse_evtx_bytes;

// ─── Dispatch ─────────────────────────────────────────────────────────────────

/// Dispatch on argv[1]. `None` = no/unknown subcommand → caller runs the
/// normal collection loop; `Some(code)` = subcommand handled → exit with code.
pub fn dispatch() -> Option<i32> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        return None; // no subcommand → fall through to normal loop
    }
    match args[1].as_str() {
        "check" => Some(cmd_check(&args[1..])),
        "check-filter" => Some(cmd_check_filter(&args[1..])),
        "check-channels" => Some(cmd_check_channels(&args[1..])),
        "list-rules" => Some(cmd_list_rules(&args[1..])),
        "get-atomic" => Some(cmd_get_atomic(&args[1..])),
        _ => None, // unknown subcommand → normal loop
    }
}

// ─── check ────────────────────────────────────────────────────────────────────

#[derive(serde::Serialize)]
struct CheckFail {
    rule_name: String,
    error: String,
}

fn cmd_check(args: &[String]) -> i32 {
    let mut json_output = false;
    for arg in args {
        match arg.as_str() {
            "--json" => json_output = true,
            other => {
                eprintln!("Unknown argument: {other}");
                return 1;
            }
        }
    }

    let rules = match SigmahqRules::new() {
        Ok(r) => r,
        Err(e) => {
            eprintln!("Failed to load rules: {e}");
            return 1;
        }
    };
    let rules = rules.filter(SigmaFilterConfig {
        product: "windows".to_string(),
        ..Default::default()
    });

    let regression = match SigmahqRegression::new() {
        Ok(r) => r,
        Err(e) => {
            eprintln!("Failed to load regression data: {e}");
            return 1;
        }
    };
    if regression.is_empty() {
        eprintln!("No regression entries found — nothing to validate");
        return 1;
    }

    let mut engine = match DetectionEngine::new(&rules) {
        Ok(e) => e,
        Err(e) => {
            eprintln!("Failed to build engine: {e}");
            return 1;
        }
    };

    let mut total = 0usize;
    let mut passed = 0usize;
    let mut skipped = 0usize;
    let mut failed: Vec<CheckFail> = Vec::new();

    for i in 0..regression.len() {
        let entry = match regression.get_entry(i) {
            Some(e) => e,
            None => {
                total += 1;
                if !json_output {
                    println!("[FAIL] No entry");
                }
                continue;
            }
        };

        let raw = match regression.get_raw_data(i) {
            Some(r) => r,
            None => {
                total += 1;
                failed.push(CheckFail {
                    rule_name: entry.rule_name.clone(),
                    error: "No raw data".to_string(),
                });
                if !json_output {
                    println!("[FAIL] No raw data");
                }
                continue;
            }
        };

        if entry.logtype == sigmacatch_regression::logtype::LogType::Evtx {
            #[cfg(feature = "winevt")]
            {
                let events = match parse_evtx_bytes(&raw) {
                    Ok(ev) => ev,
                    Err(e) => {
                        total += 1;
                        failed.push(CheckFail {
                            rule_name: entry.rule_name.clone(),
                            error: format!("Failed to load EVTX: {e}"),
                        });
                        if !json_output {
                            println!("[FAIL] Failed to load EVTX: {e}");
                        }
                        continue;
                    }
                };
                if events.is_empty() {
                    total += 1;
                    failed.push(CheckFail {
                        rule_name: entry.rule_name.clone(),
                        error: "EMPTY — evtx produced no events".to_string(),
                    });
                    if !json_output {
                        println!("[FAIL] EMPTY — evtx produced no events");
                    }
                    continue;
                }
                engine.put_events(events);
            }
            #[cfg(not(feature = "winevt"))]
            {
                total += 1;
                skipped += 1;
                if !json_output {
                    println!(
                        "[SKIP] {name} (EVTX not available in this build)",
                        name = entry.rule_name
                    );
                }
                continue;
            }
        } else {
            // The Windows binaries have no auditd/syslog collector: `.log`
            // entries belong to `sigmacatch-linux check`.
            total += 1;
            skipped += 1;
            if !json_output {
                println!(
                    "[SKIP] {} (.log data requires sigmacatch-linux)",
                    entry.rule_name
                );
            }
            continue;
        }

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

        total += 1;
        passed += 1;
        if !json_output {
            println!("[PASS] {} alert(s), rule matched", rule_alert_count);
        }
    }

    let pass_rate = if total > 0 {
        (passed as f64 / total as f64) * 100.0
    } else {
        0.0
    };

    if json_output {
        let output = serde_json::json!({
            "total": total,
            "passed": passed,
            "skipped": skipped,
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
        println!("  Skipped:         {}", skipped);
        println!("  Failed:          {}", failed.len());
        println!("  Pass rate:       {:.1}%", pass_rate);
        println!("{}", "=".repeat(60));
        if !failed.is_empty() {
            println!("\nFailed rules:");
            for f in &failed {
                println!("  FAIL {} — {}", f.rule_name, f.error);
            }
        }
    }

    if !failed.is_empty() { 1 } else { 0 }
}

// ─── check-filter ─────────────────────────────────────────────────────────────

#[derive(serde::Serialize)]
struct FilterTestResult {
    name: String,
    passed: bool,
    filter_results: Vec<FilterResult>,
}

#[derive(serde::Serialize)]
struct FilterResult {
    product: String,
    min_status: Option<String>,
    min_level: Option<String>,
    author: Option<String>,
    rules_loaded: u64,
    rules_total_candidate: u64,
    rules_filtered_product: u64,
    rules_filtered_status: u64,
    rules_filtered_level: u64,
    rules_filtered_author: u64,
    ground_truth: GroundTruth,
    mismatch: Option<String>,
}

#[derive(serde::Serialize)]
struct GroundTruth {
    loaded: u64,
    product_filtered: u64,
    status_filtered: u64,
    level_filtered: u64,
    author_filtered: u64,
    total: u64,
}

struct FilterTest {
    name: &'static str,
    filters: Vec<SigmaFilterConfig>,
}

fn count_ground_truth(
    rules: &[sigmacatch_rule::SigmaRule],
    filters: &SigmaFilterConfig,
) -> (u64, u64, u64, u64, u64) {
    let mut gt_product = 0u64;
    let mut gt_status = 0u64;
    let mut gt_level = 0u64;
    let mut gt_author = 0u64;
    let mut gt_loaded = 0u64;

    for rule in rules {
        let product_match = rule
            .logsource
            .product
            .as_deref()
            .is_some_and(|p| p == filters.product);
        if !product_match {
            gt_product += 1;
            continue;
        }
        let status_match = match (&filters.min_status, &rule.status) {
            (Some(threshold), Some(s)) => threshold.accepts(s),
            _ => true,
        };
        if !status_match {
            gt_status += 1;
            continue;
        }
        let level_match = match (&filters.min_level, &rule.level) {
            (Some(threshold), Some(l)) => threshold.accepts(l),
            _ => true,
        };
        if !level_match {
            gt_level += 1;
            continue;
        }
        let author_match = match (&filters.author, &rule.author) {
            (Some(filter_author), Some(rule_author)) => {
                let filter_lower = filter_author.trim().to_lowercase();
                rule_author
                    .to_lowercase()
                    .split(',')
                    .any(|a| a.trim() == filter_lower)
            }
            (Some(_), None) => false,
            _ => true,
        };
        if !author_match {
            gt_author += 1;
            continue;
        }
        gt_loaded += 1;
    }
    (gt_loaded, gt_product, gt_status, gt_level, gt_author)
}

fn run_filter_tests(tests: &[FilterTest], json_output: bool) -> bool {
    let all_rules = match SigmahqRules::new() {
        Ok(r) => r,
        Err(e) => {
            eprintln!("Failed to load rules from ./sigma: {e}");
            return false;
        }
    };

    let mut results: Vec<FilterTestResult> = Vec::new();
    let mut total_passed = 0;
    let mut total_failed = 0;

    for test in tests {
        let mut test_passed = true;
        let mut filter_results: Vec<FilterResult> = Vec::new();

        for filters in &test.filters {
            let filtered = all_rules.clone().filter(filters.clone());
            let stats = filtered.stats();

            let (gt_loaded, gt_product, gt_status, gt_level, gt_author) =
                count_ground_truth(all_rules.rules(), filters);
            let total = gt_loaded + gt_product + gt_status + gt_level + gt_author;

            let loaded_ok = stats.rules_loaded == gt_loaded;
            let product_ok = stats.rules_filtered_product == gt_product;
            let status_ok = stats.rules_filtered_status == gt_status;
            let level_ok = stats.rules_filtered_level == gt_level;
            let author_ok = stats.rules_filtered_author == gt_author;
            let total_ok = stats.rules_total_candidate == total;
            let all_ok = loaded_ok && product_ok && status_ok && level_ok && author_ok && total_ok;

            let mismatch = if all_ok {
                None
            } else {
                let mut parts = Vec::new();
                if !loaded_ok {
                    parts.push(format!("loaded: {}!={}", stats.rules_loaded, gt_loaded));
                }
                if !product_ok {
                    parts.push(format!(
                        "product: {}!={}",
                        stats.rules_filtered_product, gt_product
                    ));
                }
                if !status_ok {
                    parts.push(format!(
                        "status: {}!={}",
                        stats.rules_filtered_status, gt_status
                    ));
                }
                if !level_ok {
                    parts.push(format!(
                        "level: {}!={}",
                        stats.rules_filtered_level, gt_level
                    ));
                }
                if !author_ok {
                    parts.push(format!(
                        "author: {}!={}",
                        stats.rules_filtered_author, gt_author
                    ));
                }
                if !total_ok {
                    parts.push(format!("total: {}!={}", stats.rules_total_candidate, total));
                }
                Some(parts.join(", "))
            };

            if !all_ok {
                test_passed = false;
            }

            filter_results.push(FilterResult {
                product: filters.product.clone(),
                min_status: filters.min_status.map(|s| format!("{:?}", s)),
                min_level: filters.min_level.map(|l| format!("{:?}", l)),
                author: filters.author.clone(),
                rules_loaded: stats.rules_loaded,
                rules_total_candidate: stats.rules_total_candidate,
                rules_filtered_product: stats.rules_filtered_product,
                rules_filtered_status: stats.rules_filtered_status,
                rules_filtered_level: stats.rules_filtered_level,
                rules_filtered_author: stats.rules_filtered_author,
                ground_truth: GroundTruth {
                    loaded: gt_loaded,
                    product_filtered: gt_product,
                    status_filtered: gt_status,
                    level_filtered: gt_level,
                    author_filtered: gt_author,
                    total,
                },
                mismatch: mismatch.clone(),
            });

            if !json_output {
                println!(
                    "  product={} status={:?} level={:?} author={:?}  →  {} loaded / {} total",
                    filters.product,
                    filters.min_status,
                    filters.min_level,
                    filters.author,
                    stats.rules_loaded,
                    stats.rules_total_candidate,
                );
                println!(
                    "    GT: loaded={} prod={} stat={} lvl={} auth={} total={}",
                    gt_loaded, gt_product, gt_status, gt_level, gt_author, total
                );
                println!(
                    "    filter: loaded={} prod={} stat={} lvl={} auth={} total={}",
                    stats.rules_loaded,
                    stats.rules_filtered_product,
                    stats.rules_filtered_status,
                    stats.rules_filtered_level,
                    stats.rules_filtered_author,
                    stats.rules_total_candidate,
                );
                if let Some(mismatch) = mismatch.as_ref() {
                    println!("    ❌ MISMATCH: {mismatch}");
                } else {
                    println!("    ✅ all dimensions match ground truth");
                }
            }

            if stats.rules_loaded == 0 && test.name != "empty_filter" && !json_output {
                println!("    WARN: 0 rules loaded with this filter combination");
            }
        }

        if test_passed {
            total_passed += 1;
            if !json_output {
                println!("  ✅ PASS\n");
            }
        } else {
            total_failed += 1;
            if !json_output {
                println!("  ❌ FAIL\n");
            }
        }

        results.push(FilterTestResult {
            name: test.name.to_string(),
            passed: test_passed,
            filter_results,
        });
    }

    if json_output {
        let output = serde_json::json!({
            "total_passed": total_passed,
            "total_failed": total_failed,
            "tests": results,
        });
        println!(
            "{}",
            serde_json::to_string_pretty(&output)
                .expect("serde_json Value serialization is infallible")
        );
    } else {
        println!("{}", "=".repeat(60));
        println!("  SUMMARY");
        println!("{}", "=".repeat(60));
        println!("  Passed: {}", total_passed);
        println!("  Failed: {}", total_failed);
        println!("{}", "=".repeat(60));
    }

    total_failed == 0
}

fn cmd_check_filter(args: &[String]) -> i32 {
    let mut json_output = false;
    for arg in args {
        match arg.as_str() {
            "--json" => json_output = true,
            other => {
                eprintln!("Unknown argument: {other}");
                return 1;
            }
        }
    }

    if !json_output {
        match SigmahqRules::new() {
            Ok(r) => println!("Loaded {} total rules from ./sigma", r.len()),
            Err(e) => {
                eprintln!("Failed to load rules: {e}");
                return 1;
            }
        }
        println!();
    }

    let tests = vec![
        FilterTest {
            name: "empty filter (no filtering)",
            filters: vec![SigmaFilterConfig::new()],
        },
        FilterTest {
            name: "product filter",
            filters: vec![
                SigmaFilterConfig {
                    product: "windows".to_string(),
                    ..Default::default()
                },
                SigmaFilterConfig {
                    product: "linux".to_string(),
                    ..Default::default()
                },
                SigmaFilterConfig {
                    product: "macos".to_string(),
                    ..Default::default()
                },
            ],
        },
        FilterTest {
            name: "status filter",
            filters: vec![
                SigmaFilterConfig {
                    min_status: None,
                    ..Default::default()
                },
                SigmaFilterConfig {
                    min_status: Some(MinStatus(Status::Stable)),
                    ..Default::default()
                },
                SigmaFilterConfig {
                    min_status: Some(MinStatus(Status::Test)),
                    ..Default::default()
                },
                SigmaFilterConfig {
                    min_status: Some(MinStatus(Status::Experimental)),
                    ..Default::default()
                },
                SigmaFilterConfig {
                    min_status: Some(MinStatus(Status::Deprecated)),
                    ..Default::default()
                },
                SigmaFilterConfig {
                    min_status: Some(MinStatus(Status::Unsupported)),
                    ..Default::default()
                },
            ],
        },
        FilterTest {
            name: "level filter",
            filters: vec![
                SigmaFilterConfig {
                    min_level: None,
                    ..Default::default()
                },
                SigmaFilterConfig {
                    min_level: Some(MinLevel(Level::Critical)),
                    ..Default::default()
                },
                SigmaFilterConfig {
                    min_level: Some(MinLevel(Level::High)),
                    ..Default::default()
                },
                SigmaFilterConfig {
                    min_level: Some(MinLevel(Level::Medium)),
                    ..Default::default()
                },
                SigmaFilterConfig {
                    min_level: Some(MinLevel(Level::Low)),
                    ..Default::default()
                },
                SigmaFilterConfig {
                    min_level: Some(MinLevel(Level::Informational)),
                    ..Default::default()
                },
            ],
        },
        FilterTest {
            name: "author filter",
            filters: vec![
                SigmaFilterConfig {
                    author: None,
                    ..Default::default()
                },
                SigmaFilterConfig {
                    author: Some("frack113".to_string()),
                    ..Default::default()
                },
                SigmaFilterConfig {
                    author: Some("Elastic".to_string()),
                    ..Default::default()
                },
                SigmaFilterConfig {
                    author: Some("NonExistentAuthor12345".to_string()),
                    ..Default::default()
                },
                SigmaFilterConfig {
                    author: Some(" frack113 ".to_string()),
                    ..Default::default()
                },
                SigmaFilterConfig {
                    author: Some("FRACK113".to_string()),
                    ..Default::default()
                },
            ],
        },
        FilterTest {
            name: "combined: product + status + level",
            filters: vec![
                SigmaFilterConfig {
                    product: "windows".to_string(),
                    min_status: Some(MinStatus(Status::Stable)),
                    min_level: Some(MinLevel(Level::Critical)),
                    ..Default::default()
                },
                SigmaFilterConfig {
                    product: "linux".to_string(),
                    min_status: Some(MinStatus(Status::Test)),
                    min_level: Some(MinLevel(Level::High)),
                    ..Default::default()
                },
            ],
        },
        FilterTest {
            name: "combined: with author",
            filters: vec![
                SigmaFilterConfig {
                    product: "windows".to_string(),
                    min_status: Some(MinStatus(Status::Stable)),
                    min_level: Some(MinLevel(Level::Critical)),
                    author: Some("frack113".to_string()),
                    ..Default::default()
                },
                SigmaFilterConfig {
                    product: "windows".to_string(),
                    author: Some("Elastic".to_string()),
                    ..Default::default()
                },
            ],
        },
    ];

    let ok = run_filter_tests(&tests, json_output);
    if !ok { 1 } else { 0 }
}

// ─── check-channels ───────────────────────────────────────────────────────────

fn cmd_check_channels(args: &[String]) -> i32 {
    let mut json_output = false;
    for arg in args {
        match arg.as_str() {
            "--json" => json_output = true,
            other => {
                eprintln!("Unknown argument: {other}");
                return 1;
            }
        }
    }

    let config = match Config::load(&PathBuf::from("config.yaml")) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Failed to load config.yaml: {e}");
            return 1;
        }
    };

    let rules = match SigmahqRules::new() {
        Ok(r) => r,
        Err(e) => {
            eprintln!("Failed to load rules from ./sigma: {e}");
            return 1;
        }
    };
    let rules = rules.filter(config.filter.clone());

    if rules.is_empty() {
        eprintln!("0 rules loaded — adjust filter.* in config.yaml");
        return 1;
    }

    let engine = match DetectionEngine::new(&rules) {
        Ok(e) => e,
        Err(e) => {
            eprintln!("Failed to build engine: {e}");
            return 1;
        }
    };

    let custom_map = load_custom_channel_mapping(PathBuf::from("custom_channels.yaml").as_path());
    let cycle_channels = engine.resolve_channels(&custom_map);

    if cycle_channels.is_empty() {
        if json_output {
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "total_rules": rules.len(),
                    "channel_count": 0,
                    "channels": Vec::<String>::new(),
                }))
                .expect("serde_json Value serialization is infallible")
            );
        } else {
            println!("0 channels resolved — nothing to collect");
        }
        return 1;
    }

    if json_output {
        let output = serde_json::json!({
            "total_rules": rules.len(),
            "channel_count": cycle_channels.len(),
            "channels": cycle_channels,
        });
        println!(
            "{}",
            serde_json::to_string_pretty(&output)
                .expect("serde_json Value serialization is infallible")
        );
    } else {
        println!("Resolved {} channel(s):", cycle_channels.len());
        for ch in &cycle_channels {
            println!("  {ch}");
        }
    }
    0
}

// ─── list-rules ───────────────────────────────────────────────────────────────

#[derive(serde::Serialize)]
struct RuleInfo {
    id: String,
    title: String,
    status: String,
    level: String,
    techniques: Vec<String>,
    path: String,
    art_link: String,
}

#[derive(serde::Serialize)]
struct CoverageInfo {
    total_rules: usize,
    with_data: usize,
    without_data: usize,
    rules_without_data: Vec<String>,
}

#[derive(serde::Serialize)]
struct ListRulesOutput {
    rules: Vec<RuleInfo>,
    coverage: Option<CoverageInfo>,
}

fn cmd_list_rules(args: &[String]) -> i32 {
    let mut json_output = false;
    let mut coverage = false;
    for arg in args {
        match arg.as_str() {
            "--json" => json_output = true,
            "--coverage" => coverage = true,
            other => {
                eprintln!("Unknown argument: {other}");
                return 1;
            }
        }
    }

    let config = match Config::load(&PathBuf::from("config.yaml")) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Failed to load config.yaml: {e}");
            return 1;
        }
    };

    let rules = match SigmahqRules::new() {
        Ok(r) => r,
        Err(e) => {
            eprintln!("Failed to load rules from ./sigma: {e}");
            return 1;
        }
    };
    let rules = rules.filter(config.filter.clone());

    if rules.is_empty() {
        eprintln!("0 rules loaded — adjust filter.* in config.yaml");
        return 1;
    }

    let sigma_repo_path = Path::new(&config.git.sigma_repo_path);
    let mut rule_infos: Vec<RuleInfo> = Vec::new();

    for rule in rules.rules() {
        let id = rule.id.as_deref().unwrap_or("no-id");
        let path = rule
            .id
            .as_deref()
            .and_then(|s| Uuid::parse_str(s).ok())
            .and_then(|u| rules.get_rule_path(&u))
            .map(|p| {
                p.strip_prefix(sigma_repo_path)
                    .unwrap_or(p)
                    .display()
                    .to_string()
                    .replace('\\', "/")
            })
            .unwrap_or_default();
        let techniques: Vec<String> = rule
            .attack_techniques()
            .into_iter()
            .map(|t| t.replace('t', "T"))
            .collect();
        let art_link = if techniques.is_empty() {
            String::new()
        } else {
            format!(
                "https://attack.mitre.org/techniques/{}/",
                techniques.join("/")
            )
        };

        rule_infos.push(RuleInfo {
            id: id.to_string(),
            title: rule.title.clone(),
            status: format!("{:?}", rule.status.as_ref().unwrap_or(&Status::Test)),
            level: format!("{:?}", rule.level.as_ref().unwrap_or(&Level::Informational)),
            techniques,
            path,
            art_link,
        });
    }

    let coverage_info = if coverage {
        let mut skip_set: BTreeSet<String> = BTreeSet::new();
        match SigmahqRegression::new_from_path(&sigma_repo_path.join("regression_data")) {
            Ok(reg) => {
                for id in reg.get_sigma_id() {
                    skip_set.insert(id.to_string());
                }
            }
            Err(e) => eprintln!("Warning: failed to scan local regression_data: {e}"),
        }
        let mut sigma_repo = SigmaRepo::new();
        sigma_repo.set_repo_path(sigma_repo_path.to_path_buf());
        match sigma_repo.pending_regression_rule_ids() {
            Ok(ids) => {
                for id in ids {
                    skip_set.insert(id.to_string());
                }
            }
            Err(e) => eprintln!("Warning: failed to scan pending branches: {e}"),
        }

        let total = rules.len();
        let mut with_data = 0usize;
        let mut without_data = Vec::new();
        for rule in rules.rules() {
            let id = rule.id.as_deref().unwrap_or("");
            if skip_set.contains(id) {
                with_data += 1;
            } else {
                without_data.push(rule.title.clone());
            }
        }
        Some(CoverageInfo {
            total_rules: total,
            with_data,
            without_data: without_data.len(),
            rules_without_data: without_data,
        })
    } else {
        None
    };

    if json_output {
        let output = ListRulesOutput {
            rules: rule_infos,
            coverage: coverage_info,
        };
        println!(
            "{}",
            serde_json::to_string_pretty(&output)
                .expect("serde_json Value serialization is infallible")
        );
    } else {
        println!("Loaded {} rule(s):\n", rule_infos.len());
        for r in &rule_infos {
            println!(
                "  {} | {} | {} | {} | {}",
                r.id, r.title, r.status, r.level, r.path
            );
            if !r.art_link.is_empty() {
                println!("    → {}", r.art_link);
            }
        }
        if let Some(cov) = &coverage_info {
            println!(
                "\nCoverage: {}/{} rules have regression data",
                cov.with_data, cov.total_rules
            );
            if !cov.rules_without_data.is_empty() {
                println!(
                    "  {} rule(s) without regression data",
                    cov.rules_without_data.len()
                );
            }
        }
    }
    0
}

// ─── get-atomic ───────────────────────────────────────────────────────────────

const DEFAULT_OUTPUT: &str = "run_atomic.ps1";
const SLEEP_SECONDS: u64 = 30;
const TIMEOUT_SECONDS: u64 = 120;

#[derive(serde::Serialize)]
struct AtomicInfo {
    rules_without_data: usize,
    technique_count: usize,
    techniques: Vec<String>,
    rules_without_attack_tag: Vec<String>,
}

fn atomic_techniques(rule: &sigmacatch_rule::SigmaRule) -> Vec<String> {
    rule.attack_techniques()
        .into_iter()
        .filter(|t| t.starts_with('t'))
        .collect()
}

fn cmd_get_atomic(args: &[String]) -> i32 {
    let mut output = PathBuf::from(DEFAULT_OUTPUT);
    let mut get_prereqs = false;
    let mut json_output = false;
    let mut args_iter = args.iter();
    while let Some(arg) = args_iter.next() {
        match arg.as_str() {
            "--output" => match args_iter.next() {
                Some(path) => output = PathBuf::from(path),
                None => {
                    eprintln!("--output requires a path argument");
                    return 1;
                }
            },
            "--getprereqs" => {
                get_prereqs = true;
            }
            "--json" => {
                json_output = true;
            }
            "--help" | "-h" => {
                println!(
                    "get-atomic: generate run_atomic.ps for rules without regression data\n\n\
                     Usage: get-atomic [--output <path>] [--getprereqs] [--json]\n\n\
                     Options:\n\
                      \x20 --output <path>    write the script to <path> (default: run_atomic.ps1)\n\
                     \x20 --getprereqs       generate Invoke-AtomicTest with -GetPrereqs flag\n\
                                            (downloads/installs prerequisites without running tests)\n\
                     \x20 --json             output results as JSON instead of text"
                );
                return 0;
            }
            other => {
                eprintln!("Unknown argument: {other}");
                return 1;
            }
        }
    }

    let config = match Config::load(&PathBuf::from("config.yaml")) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Failed to load config.yaml: {e}");
            return 1;
        }
    };
    let sigma_path = Path::new(&config.git.sigma_repo_path);

    let rules = match SigmahqRules::new_from_path(sigma_path) {
        Ok(r) => r.filter(config.filter.clone()),
        Err(e) => {
            eprintln!("Failed to load rules from {sigma_path:?}: {e}");
            return 1;
        }
    };
    if rules.is_empty() {
        eprintln!("0 rules loaded — adjust filter.* in config.yaml");
        return 1;
    }

    let mut skip_set: BTreeSet<String> = BTreeSet::new();
    match SigmahqRegression::new_from_path(&sigma_path.join("regression_data")) {
        Ok(regression) => {
            for id in regression.get_sigma_id() {
                skip_set.insert(id.to_string());
            }
        }
        Err(e) => eprintln!("Warning: failed to scan local regression_data: {e}"),
    }
    let mut sigma_repo = SigmaRepo::new();
    sigma_repo.set_repo_path(sigma_path.to_path_buf());
    match sigma_repo.pending_regression_rule_ids() {
        Ok(ids) => {
            for id in ids {
                skip_set.insert(id.to_string());
            }
        }
        Err(e) => eprintln!("Warning: failed to scan pending branches: {e}"),
    }

    let mut techniques: BTreeSet<String> = BTreeSet::new();
    let mut rules_without_data = 0usize;
    let mut rules_without_attack_tag: Vec<String> = Vec::new();
    for rule in rules.rules() {
        let id = rule.id.as_deref().unwrap_or("");
        if skip_set.contains(id) {
            continue;
        }
        rules_without_data += 1;
        let techs = atomic_techniques(rule);
        if techs.is_empty() {
            rules_without_attack_tag.push(rule.title.clone());
        } else {
            techniques.extend(techs);
        }
    }

    if rules_without_data == 0 {
        eprintln!("No rules without regression data — nothing to generate");
        return 1;
    }
    if techniques.is_empty() {
        eprintln!(
            "{} rule(s) without regression data have no attack.* technique tag",
            rules_without_attack_tag.len()
        );
        return 1;
    }

    let mut script = String::new();
    script.push_str("$ErrorActionPreference = \"Continue\"\n");
    script.push_str("Import-Module Invoke-AtomicRedTeam\n");
    script.push_str(&format!(
        "# {rules_without_data} rule(s) without regression data — {} technique(s)\n",
        techniques.len()
    ));
    script.push_str("Start-Sleep -Seconds 5\n");
    for technique in &techniques {
        if get_prereqs {
            script.push_str(&format!(
                "Invoke-AtomicTest {technique} -TimeoutSeconds {TIMEOUT_SECONDS} -GetPrereqs\n"
            ));
        } else {
            script.push_str(&format!(
                "Invoke-AtomicTest {technique} -TimeoutSeconds {TIMEOUT_SECONDS}\n"
            ));
            script.push_str(&format!("Start-Sleep -Seconds {SLEEP_SECONDS}\n"));
        }
    }

    if let Err(e) = std::fs::write(&output, script) {
        eprintln!("Failed to write {}: {e}", output.display());
        return 1;
    }

    if json_output {
        let info = AtomicInfo {
            rules_without_data,
            technique_count: techniques.len(),
            techniques: techniques.into_iter().collect(),
            rules_without_attack_tag,
        };
        println!(
            "{}",
            serde_json::to_string_pretty(&info)
                .expect("serde_json Value serialization is infallible")
        );
    } else {
        let mode = if get_prereqs {
            "get-prereqs"
        } else {
            "execute"
        };
        println!(
            "Wrote {} [{}] ({rules_without_data} rules, {} techniques)",
            output.display(),
            mode,
            techniques.len()
        );
        if !rules_without_attack_tag.is_empty() {
            println!(
                "\n{} rule(s) without attack.* tag (no Invoke-AtomicTest generated):",
                rules_without_attack_tag.len()
            );
            for title in &rules_without_attack_tag {
                println!("  - {title}");
            }
        }
    }
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_filter_config_default() {
        let config = SigmaFilterConfig::new();
        assert_eq!(config.product, "windows");
        assert!(config.min_status.is_none());
        assert!(config.min_level.is_none());
        assert!(config.author.is_none());
    }

    #[test]
    fn test_filter_config_normalize() {
        let mut config = SigmaFilterConfig {
            product: "windows".to_string(),
            min_status: None,
            min_level: None,
            author: Some("  Frack113  ".to_string()),
            max_rule_size: 1024 * 1024,
        };
        config.normalize();
        assert_eq!(config.author, Some("frack113".to_string()));
    }

    // These tests live in crates/sigmacatch-regression/src/lib.rs.
}
