// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 sigmacatch contributors

//! list_rules: list the loaded Sigma rules matching the current filter config.
//!
//! Pipeline:
//!   1. Load `config.yaml` (filter section)
//!   2. Load all Sigma rules from `./sigma` + apply filter
//!   3. Print each rule with id, title, status, level, techniques, path, ART
//!
//! Usage:
//!   cargo run --release --bin list_rules

use sigmacatch_config::Config;
use sigmacatch_rule::{SigmaRuleExt, SigmahqRules, Status};
use std::path::{Path, PathBuf};
use std::process;
use uuid::Uuid;

fn main() {
    let config = match Config::load(&PathBuf::from("config.yaml")) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Failed to load config.yaml: {}", e);
            process::exit(1);
        }
    };

    let rules = match SigmahqRules::new() {
        Ok(r) => r,
        Err(e) => {
            eprintln!("Failed to load rules from ./sigma: {}", e);
            process::exit(1);
        }
    };
    let rules = rules.filter(config.filter.clone());

    if rules.is_empty() {
        eprintln!("0 rules loaded — adjust filter.* in config.yaml");
        process::exit(1);
    }
    println!("Loaded {} rules after filtering", rules.len());
    println!();

    let sigma_repo_path = Path::new(&config.git.sigma_repo_path);
    let mut count = 0;
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
        let techniques = rule.attack_techniques();
        let art_link = techniques
            .iter()
            .find(|t| t.starts_with('t'))
            .map(|t| format!("https://atomicredteam.io/technique/{}/", t))
            .unwrap_or_default();
        let status_str = rule
            .status
            .as_ref()
            .map(|s| match s {
                Status::Stable => "stable",
                Status::Test => "test",
                Status::Experimental => "experimental",
                Status::Deprecated => "deprecated",
                Status::Unsupported => "unsupported",
            })
            .unwrap_or("unknown");
        let level_str = rule.level.as_ref().map(|l| l.as_str()).unwrap_or("unknown");
        println!(
            "\n{separator}\nID:          {id}\nTitle:       {title}\nStatus:      {status_str}\nLevel:       {level_str}\nTechniques:  {techniques_str}\nPath:        {path}\nART:         {art}",
            separator = "─".repeat(72),
            title = rule.title,
            status_str = status_str,
            level_str = level_str,
            techniques_str = techniques.join(", "),
            art = art_link,
        );
        count += 1;
    }
    println!();
    println!("{count} rules listed");
}
