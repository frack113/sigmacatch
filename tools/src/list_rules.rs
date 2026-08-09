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
//!   cargo run --release --bin list_rules [--json]

use sigmacatch_config::Config;
use sigmacatch_rule::{SigmaRuleExt, SigmahqRules, Status};
use std::path::{Path, PathBuf};
use std::process;
use uuid::Uuid;

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

    let sigma_repo_path = Path::new(&config.git.sigma_repo_path);
    let mut count = 0;
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

        if json_output {
            rule_infos.push(RuleInfo {
                id: id.to_string(),
                title: rule.title.clone(),
                status: status_str.to_string(),
                level: level_str.to_string(),
                techniques: techniques.clone(),
                path: path.clone(),
                art_link: art_link.clone(),
            });
        } else {
            println!(
                "\n{separator}\nID:          {id}\nTitle:       {title}\nStatus:      {status_str}\nLevel:       {level_str}\nTechniques:  {techniques_str}\nPath:        {path}\nART:         {art}",
                separator = "─".repeat(72),
                title = rule.title,
                status_str = status_str,
                level_str = level_str,
                techniques_str = techniques.join(", "),
                art = art_link,
            );
        }
        count += 1;
    }

    if json_output {
        let output = serde_json::json!({
            "total_rules": count,
            "rules": rule_infos,
        });
        println!("{}", serde_json::to_string_pretty(&output).unwrap());
    } else {
        println!();
        println!("{count} rules listed");
    }
}
