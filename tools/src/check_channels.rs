// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 sigmacatch contributors

//! check_channels: resolve and list the Windows event channels the detection
//! engine would collect with the current config.
//!
//! Pipeline:
//!   1. Load `config.yaml` (filter section)
//!   2. Load all Sigma rules from `./sigma` + apply filter
//!   3. Build a DetectionEngine and resolve the channels (incl. custom map)
//!   4. Print the channel list
//!
//! Usage:
//!   cargo run --release --bin check_channels [--json]

use sigmacatch_config::{self, load_custom_channel_mapping, Config};
use sigmacatch_detection::DetectionEngine;
use sigmacatch_rule::SigmahqRules;
use std::path::PathBuf;
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

    let engine = match DetectionEngine::new(&rules) {
        Ok(e) => e,
        Err(e) => {
            eprintln!("Failed to build engine: {}", e);
            process::exit(1);
        }
    };

    let custom_map = load_custom_channel_mapping(PathBuf::from("custom_channels.yaml").as_path());
    let cycle_channels = engine.resolve_channels(&custom_map);

    if cycle_channels.is_empty() {
        if json_output {
            let output = serde_json::json!({
                "total_rules": rules.len(),
                "channel_count": 0,
                "channels": Vec::<String>::new(),
            });
            println!("{}", serde_json::to_string_pretty(&output).unwrap());
        } else {
            println!("0 channels resolved — nothing to collect");
        }
        process::exit(1);
    }

    if json_output {
        let output = serde_json::json!({
            "total_rules": rules.len(),
            "channel_count": cycle_channels.len(),
            "channels": cycle_channels,
        });
        println!("{}", serde_json::to_string_pretty(&output).unwrap());
    } else {
        println!("{} channel(s):", cycle_channels.len());
        for ch in &cycle_channels {
            println!("  {ch}");
        }
    }
}
