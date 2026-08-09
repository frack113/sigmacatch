// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 sigmacatch contributors

//! check_filter: validate SigmaFilterConfig against real Sigma rules.
//!
//! Loads all rules from `./sigma`, applies every filter combination, and reports
//! detailed stats to verify correctness. No CLI args — runs all tests automatically.

use sigmacatch_rule::{Level, MinLevel, MinStatus, SigmaFilterConfig, SigmahqRules, Status};
use std::process;

// ─── Test runner ──────────────────────────────────────────────────────────────

struct FilterTest {
    name: &'static str,
    filters: Vec<SigmaFilterConfig>,
}

/// Independently count rules matching each filter dimension against the full set.
/// This is the ground truth — not derived from filter() stats.
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

fn run_tests(tests: &[FilterTest]) {
    let all_rules = match SigmahqRules::new() {
        Ok(r) => r,
        Err(e) => {
            eprintln!("Failed to load rules from ./sigma: {}", e);
            process::exit(1);
        }
    };

    println!("Loaded {} total rules from ./sigma", all_rules.len());
    println!();

    let mut total_passed = 0;
    let mut total_failed = 0;

    for test in tests {
        println!("{}", "=".repeat(60));
        println!("  TEST: {}", test.name);
        println!("{}", "=".repeat(60));

        let mut test_passed = true;

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
                "    GT: loaded={} prod={} stat={} lvl={} auth={} total={}  sum={}",
                gt_loaded, gt_product, gt_status, gt_level, gt_author, total, total
            );
            println!(
                "    filter: loaded={} prod={} stat={} lvl={} auth={} total={}  sum={}",
                stats.rules_loaded,
                stats.rules_filtered_product,
                stats.rules_filtered_status,
                stats.rules_filtered_level,
                stats.rules_filtered_author,
                stats.rules_total_candidate,
                stats.rules_loaded
                    + stats.rules_filtered_product
                    + stats.rules_filtered_status
                    + stats.rules_filtered_level
                    + stats.rules_filtered_author,
            );

            if !all_ok {
                println!("    ❌ MISMATCH:");
                if !loaded_ok {
                    println!(
                        "       loaded:  stats={} != GT={}",
                        stats.rules_loaded, gt_loaded
                    );
                    test_passed = false;
                }
                if !product_ok {
                    println!(
                        "       product: stats={} != GT={}",
                        stats.rules_filtered_product, gt_product
                    );
                    test_passed = false;
                }
                if !status_ok {
                    println!(
                        "       status:  stats={} != GT={}",
                        stats.rules_filtered_status, gt_status
                    );
                    test_passed = false;
                }
                if !level_ok {
                    println!(
                        "       level:   stats={} != GT={}",
                        stats.rules_filtered_level, gt_level
                    );
                    test_passed = false;
                }
                if !author_ok {
                    println!(
                        "       author:  stats={} != GT={}",
                        stats.rules_filtered_author, gt_author
                    );
                    test_passed = false;
                }
                if !total_ok {
                    println!(
                        "       total:   stats={} != GT={}",
                        stats.rules_total_candidate, total
                    );
                    test_passed = false;
                }
            } else {
                println!("    ✅ all dimensions match ground truth");
            }

            if stats.rules_loaded == 0 && test.name != "empty_filter" {
                println!("    WARN: 0 rules loaded with this filter combination");
            }
        }

        if test_passed {
            total_passed += 1;
            println!("  ✅ PASS\n");
        } else {
            total_failed += 1;
            println!("  ❌ FAIL\n");
        }
    }

    println!("{}", "=".repeat(60));
    println!("  SUMMARY");
    println!("{}", "=".repeat(60));
    println!("  Passed: {}", total_passed);
    println!("  Failed: {}", total_failed);
    println!("{}", "=".repeat(60));

    if total_failed > 0 {
        process::exit(1);
    }
}

// ─── Main ─────────────────────────────────────────────────────────────────────

fn main() {
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

    run_tests(&tests);
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
}
