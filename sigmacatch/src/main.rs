// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 sigmacatch contributors

use anyhow::Result;
use sigmacatch_config::{self, dry_run_git, parse_args, Config};
use sigmacatch_detection::DetectionEngine;
use sigmacatch_logger::init as init_logger;
use sigmacatch_regression::RegressionData;
use sigmacatch_repo::{self, github, SigmaRepo};
use sigmacatch_rule::SigmahqRules;
use sigmacatch_types::{Event, EventProducer};
use std::collections::HashSet;
use std::path::{Path, PathBuf};
use tokio::signal;
use tokio::sync::mpsc;
use tracing::{info, warn};

#[cfg(windows)]
fn setup_console() {
    use windows::Win32::System::Console::*;
    unsafe {
        let _ = SetConsoleOutputCP(65001);
        if let Ok(handle) = GetStdHandle(STD_OUTPUT_HANDLE) {
            let mut mode = CONSOLE_MODE::default();
            if GetConsoleMode(handle, &mut mode).is_ok() {
                mode |= ENABLE_VIRTUAL_TERMINAL_PROCESSING;
                let _ = SetConsoleMode(handle, mode);
            }
        }
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = parse_args();

    let config_path = PathBuf::from("config.yaml");
    let mut config = Config::load(&config_path)?;

    if let Some(ref author) = cli.author {
        config.git.author.clone_from(author);
        if !config
            .git
            .author
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-')
        {
            anyhow::bail!(
                "--author must be a valid GitHub username (alphanumeric + hyphens), got {:?}",
                config.git.author
            );
        }
    }

    if config.git.author == "sigmacatch" {
        eprintln!("── config.yaml not configured ──────────────");
        eprintln!("  Update the 'author' field in config.yaml");
        eprintln!("  before running.");
        eprintln!("──────────────────────────────────────────────");
        std::process::exit(1);
    }

    if cli.all_rules {
        info!("All-rules mode enabled — skip set will be empty");
    }

    if cli.dry_run {
        dry_run_git(&config).await?;
        return Ok(());
    }

    #[cfg(windows)]
    setup_console();

    let _guard = init_logger(&config)?;

    info!(
        "Sigma Regression Generator v{} — build {}",
        env!("CARGO_PKG_VERSION"),
        env!("BUILD_TIME")
    );

    info!(
        "Sigmacatch started for {} <{}>",
        config.git.author, config.git.email
    );
    let branch_name = sigmacatch_repo::create_branch_name();
    info!("Branch name: {branch_name}");
    let fork_config = github::fork::detect_fork(&config.git.author, &branch_name).await?;

    config.ensure_dirs()?;
    {
        let mut sigma_repo = SigmaRepo::new(std::path::Path::new(&config.git.sigma_repo_path))
            .with_transport(config.git.transport)
            .with_ssh_key_path(config.git.ssh_key_path.clone());
        let url = fork_config.fork_url.trim_end_matches(".git").to_string() + ".git";
        sigma_repo = sigma_repo
            .with_remote_url(url)
            .with_fork_branch(fork_config.branch_name.clone());
        if !config.git.github_token.trim().is_empty() {
            sigma_repo = sigma_repo.with_token(config.git.github_token.trim().to_string());
        }
        sigma_repo.init().await?;
    }

    let existing_rules: HashSet<String> = if cli.all_rules {
        HashSet::new()
    } else {
        let sigma_regression_dir =
            PathBuf::from(&config.git.sigma_repo_path).join("regression_data");
        let existing = sigmacatch_regression::list_sigma_id(&sigma_regression_dir);
        if !existing.is_empty() {
            info!(
                "{} rules with existing regression data (skipped)",
                existing.len()
            );
        }
        existing.into_iter().collect()
    };

    let sigma_path = std::path::Path::new(&config.git.sigma_repo_path);
    let mut rules = SigmahqRules::new(sigma_path)?;

    for id in &existing_rules {
        rules.remove_id(id);
    }

    let mut rules = rules.filter(
        Some(config.sigma.product.as_str()),
        Some(config.sigma.min_status),
        Some(config.sigma.min_level),
    );
    let stats = rules.stats();

    info!(
        "Loaded {} rules ({} skipped by existing regression, {} filtered by product, {} filtered by status, {} filtered by level)",
        stats.rules_loaded,
        existing_rules.len(),
        stats.rules_filtered_product,
        stats.rules_filtered_status,
        stats.rules_filtered_level,
    );

    if stats.rules_loaded == 0 {
        anyhow::bail!(
            "0 rules loaded — the filter config (min_status={}, min_level={}) is too restrictive. \
             Adjust sigma.min_status and sigma.min_level in config.yaml or load rules with matching metadata.",
            config.sigma.min_status,
            config.sigma.min_level,
        );
    }

    let custom_map = sigmacatch_config::load_custom_channel_mapping(
        PathBuf::from("custom_channels.yaml").as_path(),
    );
    let cycle_channels = rules.channels(&custom_map);

    if cycle_channels.is_empty() {
        warn!("0 channels resolved — nothing to collect");
        return Ok(());
    }

    let mut engine = DetectionEngine::new(&rules)?;

    if cli.channels_only {
        info!("Channels only mode — listing channels and exiting");
        for ch in &cycle_channels {
            println!("  {ch}");
        }
        return Ok(());
    }

    // ─── Shutdown signal (Ctrl+C) ────────────────────────────────────────
    let (shutdown_tx, mut shutdown_rx) = tokio::sync::watch::channel(false);
    let stx = shutdown_tx.clone();
    tokio::spawn(async move {
        if let Err(e) = signal::ctrl_c().await {
            warn!("Failed to register Ctrl+C handler: {}", e);
            return;
        }
        info!("Ctrl+C received, shutting down…");
        let _ = stx.send(true);
    });
    info!("Ctrl+C handler registered");

    // ─── Paths ───────────────────────────────────────────────────────────
    let sigma_repo_path = Path::new(&config.git.sigma_repo_path);
    let output_base = sigma_repo_path.join("regression_data");

    // ─── Spawn continuous collector ──────────────────────────────────────
    sigmacatch_regression::clean_partial_artifacts(&output_base);

    let (tx, mut rx) = mpsc::channel::<Event>(100_000);
    let producer_channels = cycle_channels.clone();
    let collector_stop = shutdown_rx.clone();
    let collector_handle = tokio::spawn(async move {
        let collector = input_windows_channels::EventCollector::new(producer_channels);
        if let Err(e) = collector.run(tx, collector_stop).await {
            warn!("Collector finished with error: {}", e);
        }
    });
    info!("Continuous collector started");

    // ─── Generate timer (every 30s) ──────────────────────────────────────
    let mut generate_interval = tokio::time::interval(std::time::Duration::from_secs(30));
    generate_interval.tick().await; // skip immediate first tick

    // ─── Continuous event loop ───────────────────────────────────────────

    loop {
        tokio::select! {
            _ = shutdown_rx.changed() => {
                info!("Shutting down…");
                break;
            }
            Some(event) = rx.recv() => {
                engine.put_events(vec![event]);
            }
            _ = generate_interval.tick() => {
                let created_files = process_and_generate(
                    &mut engine,
                    &mut rules,
                    &output_base,
                    &config.git.author,
                    sigma_repo_path,
                );

                if !created_files.is_empty() {
                    if let Err(e) = sigmacatch_repo::github::commit::commit_all_rules(
                        sigma_repo_path,
                        &created_files,
                        &config.git.author,
                        &config.git.email,
                    ) {
                        warn!("Failed to commit regression data: {}", e);
                    }
                }
            }
        }
    }

    // ─── Final shutdown flush ────────────────────────────────────────────
    // Signal the collector to stop, wait for its tasks to finish (which drops
    // the last Sender clones), then drain any remaining events. Draining before
    // the collector exits would never terminate: the collector only stops when
    // the receiver is dropped, and the receiver is needed to drain.
    info!("Final flush — draining remaining events");
    let _ = collector_handle.await;
    while let Some(event) = rx.recv().await {
        engine.put_events(vec![event]);
    }
    drop(rx);

    let created_files = process_and_generate(
        &mut engine,
        &mut rules,
        &output_base,
        &config.git.author,
        sigma_repo_path,
    );

    if !created_files.is_empty() {
        if let Err(e) = sigmacatch_repo::github::commit::commit_all_rules(
            sigma_repo_path,
            &created_files,
            &config.git.author,
            &config.git.email,
        ) {
            warn!("Failed to commit regression data: {}", e);
        }
    }

    let github_token =
        (!config.git.github_token.trim().is_empty()).then(|| config.git.github_token.trim());
    if let Err(e) = sigmacatch_repo::push(
        sigma_repo_path,
        &fork_config.branch_name,
        config.git.transport,
        github_token,
        config.git.ssh_key_path.as_deref(),
    ) {
        warn!("Failed to push branch: {}", e);
    } else {
        info!(
            "Branch '{}' pushed to origin. Next step: create PR at https://github.com/SigmaHQ/sigma/pulls",
            fork_config.branch_name
        );
    }

    info!("Sigmacatch finished");
    Ok(())
}

fn process_and_generate(
    engine: &mut DetectionEngine,
    rules: &mut SigmahqRules,
    output_base: &Path,
    author: &str,
    sigma_repo_path: &Path,
) -> Vec<String> {
    engine.process_events();
    let alerts = engine.get_alerts();

    if alerts.is_empty() {
        return Vec::new();
    }

    let unique_match_count = {
        let ids: std::collections::HashSet<&str> =
            alerts.iter().map(|a| a.rule_id.as_str()).collect();
        ids.len()
    };

    info!(
        events_processed = engine.stats().events_processed,
        matches_found = unique_match_count,
        alerts_count = alerts.len(),
        "evaluation complete"
    );

    let mut reg = RegressionData::new(output_base);
    reg.set_author(author);
    reg.set_sigma_repo_path(sigma_repo_path);
    let is_contrib = sigma_repo_path.file_name().is_some_and(|n| n == "sigma");
    reg.set_is_contrib(is_contrib);

    let mut created_files: Vec<String> = Vec::new();
    let mut retired_ids: Vec<String> = Vec::new();
    for alert in alerts {
        if let Some(files) = reg.generate_from_alert(&alert) {
            created_files.extend(files);
            // AD-4: retire the rule once its regression data is generated
            retired_ids.push(alert.rule_id.clone());
        }
    }

    // AD-4: exclude retired rules and reload the engine in one batch.
    // Reloading once per batch avoids a full recompile per alert.
    if !retired_ids.is_empty() {
        for id in &retired_ids {
            rules.remove_id(id);
        }
        if let Err(e) = engine.reload_rules(rules) {
            warn!(
                "Failed to reload engine after retiring {} rules: {}",
                retired_ids.len(),
                e
            );
        }
    }

    info!(
        regression_data_generated = created_files.len(),
        rules_retired = retired_ids.len(),
        "batch complete"
    );
    created_files
}
