// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 sigmacatch contributors

//! check_dry_run: run the git diagnostics of `--dry-run` without starting the
//! collection loop.
//!
//! Reuses `Config::load_with_cli` + `dry_run_git` from `sigmacatch-config`.
//! Accepts the same CLI args as the main binary (`--author`, `--offline`,
//! `--contrib`, `--help`, `--json`).
//!
//! Usage:
//!   cargo run --release --bin check_dry_run
//!   cargo run --release --bin check_dry_run -- --author someuser --json

use anyhow::Result;
use sigmacatch_config::{Config, dry_run_git, parse_args};
use std::path::PathBuf;

#[tokio::main]
async fn main() -> Result<()> {
    let mut json_output = false;
    let cli = parse_args();

    for arg in std::env::args().skip(1) {
        if arg == "--json" {
            json_output = true;
        }
    }
    let config_path = PathBuf::from("config.yaml");
    let config = Config::load_with_cli(&config_path, &cli)?;
    dry_run_git(&config).await?;

    if json_output {
        println!(
            "{}",
            serde_json::json!({
                "dry_run": "ok",
                "author": config.git.author,
                "email": config.git.email,
                "sigma_repo_path": config.git.sigma_repo_path,
                "offline": config.git.offline,
                "contrib": config.git.contrib,
            })
        );
    }

    Ok(())
}
