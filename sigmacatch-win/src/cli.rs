// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 sigmacatch contributors

//! CLI subcommands for the main `sigmacatch-channel` binary.
//!
//! Always compiled into the `sigmacatch-channel` binary. Dispatched from
//! `main_winevt.rs` before `runner::run()` is entered.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use sigmacatch_config::{self, Config};
use sigmacatch_regression::SigmahqRegression;
use sigmacatch_repo::SigmaRepo;
use sigmacatch_rule::{
    Level, MinLevel, MinStatus, SigmaFilterConfig, SigmaRuleExt, SigmahqRules, Status,
};
use uuid::Uuid;

// ─── Dispatch ─────────────────────────────────────────────────────────────────

const TOOLS_HELP: &str = "\
sigmacatch-channel — diagnostics tools

USAGE:
    sigmacatch-channel [FLAGS] [OPTIONS]

FLAGS:
    --check-filter   Run filter-dimension tests against ground truth
    --list-rules     List all loaded rules with metadata
    --help           Print this help and exit
";

/// Dispatch on argv[1]. `None` = no/unknown subcommand → caller runs the
/// normal collection loop; `Some(code)` = subcommand handled → exit with code.
pub fn dispatch() -> Option<i32> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        return None; // no subcommand → fall through to normal loop
    }
    match args[1].as_str() {
        "--help" | "-h" => {
            print!("{TOOLS_HELP}");
            Some(0)
        }
        "--check-filter" | "check-filter" => {
            let rest = &args[2..];
            if rest.is_empty() || (rest.len() == 1 && (rest[0] == "--help" || rest[0] == "-h")) {
                print_check_filter_help();
                Some(0)
            } else {
                Some(cmd_check_filter(rest))
            }
        }
        "--list-rules" | "list-rules" => {
            let rest = &args[2..];
            if rest.is_empty() || (rest.len() == 1 && (rest[0] == "--help" || rest[0] == "-h")) {
                print_list_rules_help();
                Some(0)
            } else {
                Some(cmd_list_rules(rest))
            }
        }
        _ => None, // unknown subcommand → normal loop
    }
}

fn print_check_filter_help() {
    println!(
        "\
sigmacatch-channel check-filter — validate filter dimensions against ground truth

USAGE:
    sigmacatch-channel check-filter [OPTIONS]

OPTIONS:
    --json    Output results as JSON instead of human-readable text
"
    );
}

fn print_list_rules_help() {
    println!(
        "\
sigmacatch-channel list-rules — list all loaded rules with metadata

USAGE:
    sigmacatch-channel list-rules [OPTIONS]

OPTIONS:
    --json       Output results as JSON instead of human-readable text
    --coverage   Include coverage stats (rules with/without regression data)
"
    );
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
