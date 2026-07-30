// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 sigmacatch contributors

use anyhow::{Context, Result};
use sigmacatch_config::{self, dry_run_git, parse_args, Config};
use sigmacatch_detection::DetectionEngine;
use sigmacatch_logger::init as init_logger;
use sigmacatch_regression::RegressionData;
use sigmacatch_repo::{self, github, SigmaRepo};
use sigmacatch_types::{Event, EventProducer, Stats};
use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tokio::signal;
use tokio::sync::mpsc;
use tracing::{info, info_span, warn};

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
    let filter = sigmacatch_rule::LoadFilter {
        product: config.sigma.product.as_str().to_string(),
        min_status: Some(config.sigma.min_status),
        min_level: Some(config.sigma.min_level),
        max_rules: config.sigma.max_rules,
        max_rule_size: config.sigma.max_rule_size,
    };
    let load_result = sigmacatch_rule::load_rules_from(sigma_path, &filter, &existing_rules)?;
    let stats = &load_result.stats;

    info!(
        "Loaded {} rules ({} skipped by existing regression, {} filtered by status, {} filtered by level)",
        stats.rules_loaded,
        existing_rules.len(),
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

    let mut engine = DetectionEngine::new();
    engine.load_collection(load_result.collection)?;
    let hir_blob = engine.save_hir()?;

    let custom_map = sigmacatch_config::load_custom_channel_mapping(
        PathBuf::from("custom_channels.yaml").as_path(),
    );
    let cycle_channels =
        input_windows_channels::mapping::resolve_channels(engine.rule_count() > 0, &custom_map);

    if cycle_channels.is_empty() {
        warn!("0 channels resolved — nothing to collect");
        return Ok(());
    }

    if cli.channels_only {
        info!("Channels only mode — listing channels and exiting");
        for ch in &cycle_channels {
            println!("  {ch}");
        }
        return Ok(());
    }

    let running = Arc::new(AtomicBool::new(true));
    let running_clone = running.clone();
    tokio::spawn(async move {
        if let Err(e) = signal::ctrl_c().await {
            warn!("Failed to wait for Ctrl+C: {}", e);
            return;
        }
        info!("Ctrl+C received, stopping…");
        running_clone.store(false, Ordering::Relaxed);
    });
    info!("Ctrl+C handler registered");

    let mut cycle = 0u32;
    loop {
        if !running.load(Ordering::Relaxed) {
            info!("Interrupted, shutting down");
            let sigma_path = std::path::Path::new(&config.git.sigma_repo_path);
            let github_token = (!config.git.github_token.trim().is_empty())
                .then(|| config.git.github_token.trim());
            if let Err(e) = sigmacatch_repo::push(
                sigma_path,
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
            break;
        }

        cycle += 1;
        let _span = info_span!("cycle", cycle_id = cycle).entered();
        info!("collecting…");

        let mut engine = DetectionEngine::new();
        engine.load_hir(&hir_blob)?;

        let (tx, mut rx) = mpsc::channel::<Event>(10_000);
        let producer_channels = cycle_channels.clone();
        let producer = tokio::spawn(async move {
            let collector = input_windows_channels::EventCollector::new(producer_channels);
            collector.run(tx).await
        });
        while let Some(event) = rx.recv().await {
            engine.put_events(vec![event]);
        }
        if let Err(e) = producer.await.context("Producer panicked")? {
            warn!("Producer returned error: {}", e);
        }
        engine.process_events();
        let event_count = engine.stats().events_processed;
        let alerts = engine.get_alerts();
        let unique_match_count = {
            let ids: std::collections::HashSet<&str> =
                alerts.iter().map(|a| a.rule_id.as_str()).collect();
            ids.len()
        };
        let stats = Stats {
            events_processed: event_count,
            matches_found: unique_match_count as u64,
            regression_data_generated: 0,
        };
        info!(
            events_processed = stats.events_processed,
            matches_found = stats.matches_found,
            "evaluation complete"
        );

        let sigma_repo_path = Path::new(&config.git.sigma_repo_path);
        let output_base = sigma_repo_path.join("regression_data");
        let mut reg = RegressionData::new(&output_base);
        reg.set_author(&config.git.author);
        reg.set_sigma_repo_path(sigma_repo_path);
        let is_contrib = sigma_repo_path.file_name().is_some_and(|n| n == "sigma");
        reg.set_is_contrib(is_contrib);
        sigmacatch_regression::clean_partial_artifacts(&output_base);

        let mut created_files: Vec<String> = Vec::new();
        for alert in alerts {
            if let Some(files) = reg.generate_from_alert(&alert) {
                created_files.extend(files);
            }
        }

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
        let generated_count = created_files.len();

        info!(
            events_processed = stats.events_processed,
            regression_data_generated = generated_count,
            "cycle complete"
        );

        let github_token =
            (!config.git.github_token.trim().is_empty()).then(|| config.git.github_token.trim());
        if let Err(e) = sigmacatch_repo::push(
            std::path::Path::new(&config.git.sigma_repo_path),
            &fork_config.branch_name,
            config.git.transport,
            github_token,
            config.git.ssh_key_path.as_deref(),
        ) {
            warn!("Failed to push branch: {}", e);
        } else {
            info!("Branch '{}' pushed to origin", fork_config.branch_name);
        }

        info!("waiting 30s before next cycle…");
        tokio::time::sleep(std::time::Duration::from_secs(30)).await;
    }

    Ok(())
}
