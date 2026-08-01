// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 sigmacatch contributors

use anyhow::Result;
use sigmacatch_config::{self, dry_run_git, parse_args, Config};
use sigmacatch_detection::DetectionEngine;
use sigmacatch_logger::init as init_logger;
use sigmacatch_regression::SigmahqRegression;
use sigmacatch_repo::SigmaRepo;
use sigmacatch_rule::SigmahqRules;
use sigmacatch_types::{Event, EventProducer};
use std::collections::HashSet;
use std::path::{Path, PathBuf};
use tokio::signal;
use tokio::sync::mpsc;
use tracing::{info, warn};
use uuid::Uuid;

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
    let mut config = Config::load_with_cli(&config_path, &cli)?;

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
    let branch_name = format!("sigmacatch-contrib/{}", config.git.author);
    info!("Branch name: {branch_name}");
    let push_branch = branch_name.clone();

    config.ensure_dirs()?;
    let fork_url = format!("https://github.com/{}/sigma", config.git.author);
    let mut sigma_repo = SigmaRepo::new();
    sigma_repo.set_info_user(&config.git.author, &config.git.email);

    match config.git.transport {
        sigmacatch_config::GitTransport::Http => sigma_repo.set_info_http(&config.git.github_token),
        sigmacatch_config::GitTransport::Ssh => {
            sigma_repo.set_info_ssh(config.git.ssh_key_path.as_deref())
        }
    };

    sigma_repo.set_remote_url(fork_url.clone()).await?;
    sigma_repo.set_working_branch(branch_name)?;

    let mut regression = match SigmahqRegression::new() {
        Ok(r) => r,
        Err(e) => anyhow::bail!("Failed to load regression data: {e}"),
    };
    regression.set_author(config.git.author.clone());

    let existing_rules: HashSet<Uuid> = if cli.all_rules {
        HashSet::new()
    } else {
        let existing: HashSet<Uuid> = regression.get_sigma_id().into_iter().collect();
        if !existing.is_empty() {
            info!(
                "{} rules with existing regression data (skipped)",
                existing.len()
            );
        }
        existing
    };

    let mut rules = SigmahqRules::new()?;

    for id in &existing_rules {
        rules.remove_id(id);
    }

    config.sigma.normalize();
    let mut rules = rules.filter(config.sigma.clone());
    let stats = rules.stats();

    info!(
        "Loaded {} rules ({} skipped by existing regression, {} filtered by product, {} filtered by status, {} filtered by level, {} filtered by author)",
        stats.rules_loaded,
        existing_rules.len(),
        stats.rules_filtered_product,
        stats.rules_filtered_status,
        stats.rules_filtered_level,
        stats.rules_filtered_author,
    );

    if stats.rules_loaded == 0 {
        anyhow::bail!(
            "0 rules loaded — the filter config (product={}, min_status={:?}, min_level={:?}, author={:?}) is too restrictive. \
             Adjust sigma.* filters in config.yaml or load rules with matching metadata.",
            config.sigma.product,
            config.sigma.min_status,
            config.sigma.min_level,
            config.sigma.author,
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
                let created_files = process_and_generate(&mut engine, &mut rules, &mut regression);

                if !created_files.is_empty() {
                    if let Err(e) = sigma_repo.commit_files(&created_files) {
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

    let created_files = process_and_generate(&mut engine, &mut rules, &mut regression);

    if !created_files.is_empty() {
        if let Err(e) = sigma_repo.commit_files(&created_files) {
            warn!("Failed to commit regression data: {}", e);
        }
    }

    if let Err(e) = sigma_repo.push() {
        warn!("Failed to push branch: {}", e);
    } else {
        info!(
            "Branch '{}' pushed to origin. Next step: create PR at https://github.com/SigmaHQ/sigma/pulls",
            push_branch
        );
    }

    info!("Sigmacatch finished");
    Ok(())
}

fn process_and_generate(
    engine: &mut DetectionEngine,
    rules: &mut SigmahqRules,
    regression: &mut SigmahqRegression,
) -> Vec<String> {
    engine.process_events();
    let alerts = engine.get_alerts();

    if alerts.is_empty() {
        return Vec::new();
    }

    let unique_match_count = {
        let ids: std::collections::HashSet<&Uuid> = alerts.iter().map(|a| &a.rule_id).collect();
        ids.len()
    };

    info!(
        events_processed = engine.stats().events_processed,
        matches_found = unique_match_count,
        alerts_count = alerts.len(),
        "evaluation complete"
    );

    let mut created_files: Vec<String> = Vec::new();
    let mut retired_ids: Vec<Uuid> = Vec::new();
    for alert in alerts {
        if let Some(files) = regression.add(&alert) {
            created_files.extend(files);
            // AD-4: retire the rule once its regression data is generated
            retired_ids.push(alert.rule_id);
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
