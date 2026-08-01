// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 sigmacatch contributors

//! check_filter: validate SigmaFilterConfig against real Sigma rules.
//!
//! Loads all rules from `./sigma`, applies filter combinations, and reports
//! detailed stats to verify correctness.
//!
//! Usage:
//!   cargo run --release --bin check_filter              # all tests
//!   cargo run --release --bin check_filter -- product    # product filter only
//!   cargo run --release --bin check_filter -- status     # status filter only
//!   cargo run --release --bin check_filter -- level      # level filter only
//!   cargo run --release --bin check_filter -- author     # author filter only
//!   cargo run --release --bin check_filter -- all        # all filter combinations

use sigmacatch_rule::{Level, MinLevel, MinStatus, SigmaFilterConfig, SigmahqRules, Status};
use std::process;

// ─── Test runner ──────────────────────────────────────────────────────────────

struct FilterTest {
    name: &'static str,
    filters: Vec<SigmaFilterConfig>,
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

            // Invariant: total = loaded + all filtered counts
            let sum = stats.rules_loaded
                + stats.rules_filtered_product
                + stats.rules_filtered_status
                + stats.rules_filtered_level
                + stats.rules_filtered_author;

            let ok = sum == stats.rules_total_candidate;

            println!(
                "  product={} status={:?} level={:?} author={:?}  →  {} loaded / {} total (sum={}) {}",
                filters.product,
                filters.min_status,
                filters.min_level,
                filters.author,
                stats.rules_loaded,
                stats.rules_total_candidate,
                sum,
                if ok { "✅" } else { "❌ MISMATCH" }
            );

            if !ok {
                println!(
                    "    FAIL: {} != {} (loaded + product + status + level + author)",
                    sum, stats.rules_total_candidate
                );
                test_passed = false;
            }

            if stats.rules_loaded == 0 && test.name != "empty_filter" {
                println!(
                    "    WARN: 0 rules loaded with this filter combination"
                );
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
    let args: Vec<String> = std::env::args().skip(1).collect();

    // Parse filter mode from cli args (after --)
    let mode = if args.len() > 1 {
        args[1].as_str()
    } else {
        "all"
    };

    let tests = match mode {
        "product" => vec![
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
        ],
        "status" => vec![
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
        ],
        "level" => vec![
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
        ],
        "author" => vec![
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
        ],
        "all" => vec![
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
        ],
        _ => {
            eprintln!("Unknown filter mode: {}. Use: product, status, level, author, all", mode);
            process::exit(1);
        }
    };

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
