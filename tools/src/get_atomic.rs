// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 sigmacatch contributors

//! get_atomic: generate a `run_atomic.ps` script chaining `Invoke-AtomicTest`
//! commands for the MITRE ATT&CK techniques of rules without regression data.
//!
//! Pipeline:
//!   1. Load `config.yaml` (filter section)
//!   2. Load all Sigma rules from `./sigma` + apply filter
//!   3. Compute the skip set (rules already having regression data):
//!      local `regression_data/` ∪ pending remote `sigmacatch/*` branches
//!   4. Extract `attack.t1xxx.xxx` techniques from the remaining rules
//!   5. Dedupe + sort the techniques
//!   6. Write a `run_atomic.ps` chaining one `Invoke-AtomicTest` per technique
//!
//! The generated script is copied to the Windows VM and executed there;
//! sigmacatch captures the generated events and produces the regression data.
//!
//! Usage:
//!   cargo run --release --bin get_atomic [--output run_atomic.ps]

use sigmacatch_config::Config;
use sigmacatch_regression::SigmahqRegression;
use sigmacatch_repo::SigmaRepo;
use sigmacatch_rule::{SigmaRuleExt, SigmahqRules};
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process;

const DEFAULT_OUTPUT: &str = "run_atomic.ps";
const SLEEP_SECONDS: u64 = 30;
const TIMEOUT_SECONDS: u64 = 120;

fn parse_args() -> PathBuf {
    let mut output = PathBuf::from(DEFAULT_OUTPUT);
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--output" => match args.next() {
                Some(path) => output = PathBuf::from(path),
                None => {
                    eprintln!("--output requires a path argument");
                    process::exit(1);
                }
            },
            "--help" | "-h" => {
                println!(
                    "get_atomic: generate run_atomic.ps for rules without regression data\n\n\
                     Usage: get_atomic [--output <path>]\n\n\
                     Options:\n\
                     \x20 --output <path>  write the script to <path> (default: run_atomic.ps)"
                );
                process::exit(0);
            }
            other => {
                eprintln!("Unknown argument: {other}");
                process::exit(1);
            }
        }
    }
    output
}

/// Extract the ATT&CK techniques usable as `Invoke-AtomicTest` targets
/// (`t1xxx` / `t1xxx.xxx`), excluding tactical groups.
fn atomic_techniques(rule: &sigmacatch_rule::SigmaRule) -> Vec<String> {
    rule.attack_techniques()
        .into_iter()
        .filter(|t| t.starts_with('t'))
        .collect()
}

fn main() {
    let output = parse_args();

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
    if rules.is_empty() {
        eprintln!("0 rules loaded — adjust filter.* in config.yaml");
        process::exit(1);
    }

    let mut skip_set: BTreeSet<String> = BTreeSet::new();
    match SigmahqRegression::new_from_path(&sigma_path.join("regression_data")) {
        Ok(regression) => {
            for id in regression.get_sigma_id() {
                skip_set.insert(id.to_string());
            }
        }
        Err(e) => eprintln!("Warning: failed to scan local regression_data: {}", e),
    }
    let mut sigma_repo = SigmaRepo::new();
    sigma_repo.set_repo_path(sigma_path.to_path_buf());
    match sigma_repo.pending_regression_rule_ids() {
        Ok(ids) => {
            for id in ids {
                skip_set.insert(id.to_string());
            }
        }
        Err(e) => eprintln!("Warning: failed to scan pending branches: {}", e),
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
        process::exit(1);
    }
    if techniques.is_empty() {
        eprintln!(
            "{} rule(s) without regression data have no attack.* technique tag",
            rules_without_attack_tag.len()
        );
        process::exit(1);
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
        script.push_str(&format!(
            "Invoke-AtomicTest {technique} -TimeoutSeconds {TIMEOUT_SECONDS}\n"
        ));
        script.push_str(&format!("Start-Sleep -Seconds {SLEEP_SECONDS}\n"));
    }

    if let Err(e) = std::fs::write(&output, script) {
        eprintln!("Failed to write {}: {}", output.display(), e);
        process::exit(1);
    }

    println!(
        "Wrote {} ({rules_without_data} rules, {} techniques)",
        output.display(),
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
