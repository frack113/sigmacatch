// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 sigmacatch contributors

//! check_dry_run: run the git diagnostics of `--dry-run` without starting the
//! collection loop.
//!
//! Reuses `Config::load_with_cli` + `dry_run_git` from `sigmacatch-config`.
//! Accepts the same CLI args as the main binary (`--author`, `--offline`,
//! `--contrib`, `--help`).
//!
//! Usage:
//!   cargo run --release --bin check_dry_run
//!   cargo run --release --bin check_dry_run -- --author someuser

use anyhow::Result;
use sigmacatch_config::{dry_run_git, parse_args, Config};
use std::path::PathBuf;

#[tokio::main]
async fn main() -> Result<()> {
    let cli = parse_args();
    let config_path = PathBuf::from("config.yaml");
    let config = Config::load_with_cli(&config_path, &cli)?;
    dry_run_git(&config).await?;
    Ok(())
}
