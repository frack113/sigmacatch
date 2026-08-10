// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 sigmacatch contributors

//! coverage: big-picture coverage stats for the current filter config.
//!
//! Outputs:
//!   - total_sigma_rules: total rules matching the filter
//!   - rules_with_regression: rules already having regression data locally
//!   - pending_regression_rules: rules with regression data on remote branches
//!   - rules_without_data: rules that still need regression data
//!   - coverage_pct: percentage of rules that have regression data
//!
//! Usage:
//!   cargo run --release --bin coverage [--json]

use sigmacatch_config::Config;
use sigmacatch_regression::SigmahqRegression;
use sigmacatch_repo::SigmaRepo;
use sigmacatch_rule::SigmahqRules;
use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::process;

fn main() {
    let mut json_output = false;
    for arg in std::env::args().skip(1) {
        if arg == "--json" {
            json_output = true;
        }
    }

    let config = match Config::load(&PathBuf::from("config.yaml")) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Failed to load config.yaml: {}", e);
            process::exit(1);
        }
    };

    let sigma_path = Path::new(&config.git.sigma_repo_path);

    let rules = match SigmahqRules::new_from_path(sigma_path) {
        Ok(r) => r.filter(config.filter.clone()),
        Err(e) => {
            eprintln!("Failed to load rules from {sigma_path:?}: {}", e);
            process::exit(1);
        }
    };

    let total_rules = rules.len();
    if total_rules == 0 {
        eprintln!("0 rules loaded — adjust filter.* in config.yaml");
        process::exit(1);
    }

    let mut skip_set: HashSet<uuid::Uuid> = HashSet::new();

    // Local regression data
    match SigmahqRegression::new_from_path(&sigma_path.join("regression_data")) {
        Ok(regression) => {
            for id in regression.get_sigma_id() {
                skip_set.insert(id);
            }
        }
        Err(e) => eprintln!("Warning: failed to scan local regression_data: {}", e),
    }

    // Pending remote branches
    let mut sigma_repo = SigmaRepo::new();
    sigma_repo.set_repo_path(sigma_path.to_path_buf());
    match sigma_repo.pending_regression_rule_ids() {
        Ok(ids) => {
            for id in ids {
                skip_set.insert(id);
            }
        }
        Err(e) => eprintln!("Warning: failed to scan pending branches: {}", e),
    }

    let rules_with_data = skip_set.len();
    let rules_without_data = total_rules - rules_with_data;
    let coverage_pct = (rules_with_data as f64 / total_rules as f64) * 100.0;

    if json_output {
        let output = serde_json::json!({
            "total_sigma_rules": total_rules,
            "rules_with_regression": rules_with_data,
            "rules_without_data": rules_without_data,
            "coverage_pct": (coverage_pct * 10.0).round() / 10.0,
            "filter": {
                "product": config.filter.product,
                "min_status": config.filter.min_status,
                "min_level": config.filter.min_level,
                "author": config.filter.author,
            },
        });
        println!("{}", serde_json::to_string_pretty(&output).unwrap());
    } else {
        println!(
            "{} rules match the filter (product={}, min_status={:?}, min_level={:?}, author={:?})",
            total_rules,
            config.filter.product,
            config.filter.min_status,
            config.filter.min_level,
            config.filter.author,
        );
        println!("  {rules_with_data} with regression data (local + pending branches)");
        println!("  {rules_without_data} still need regression data");
        println!("  coverage: {:.1}%", coverage_pct);
    }
}
