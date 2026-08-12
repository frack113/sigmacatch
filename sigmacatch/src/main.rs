// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 sigmacatch contributors

use anyhow::Result;
use sigmacatch_config::{self, parse_args, Collector, Config};
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
use tracing::{error, info, warn};
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

    #[cfg(windows)]
    setup_console();

    let _guard = init_logger(&config, cli.verbose)?;

    info!(
        "Sigma Regression Generator v{} — build {}",
        env!("CARGO_PKG_VERSION"),
        env!("BUILD_TIME")
    );

    info!(
        "Sigmacatch started for {} <{}>",
        config.git.author, config.git.email
    );
    let branch_name = format!("sigmacatch/{}", chrono::Local::now().format("%Y%m%d"));
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

    if matches!(config.git.transport, sigmacatch_config::GitTransport::Ssh) {
        if let Err(e) = sigmacatch_repo::ensure_ssh_host_config(config.git.ssh_key_path.as_deref())
        {
            warn!("Failed to write SSH host-config: {e}");
        }
    }

    if let Some(ref key_path) = config.git.ssh_key_path {
        sigma_repo.set_signing_key(Some(std::path::PathBuf::from(key_path)));
    }

    sigma_repo.set_git_operations(config.git.is_offline(), config.git.is_contrib());

    if config.git.is_offline() {
        info!("Offline mode: pull disabled — using existing repository");
    }
    if config.git.is_contrib() {
        info!("Contrib mode: push enabled — will push to remote fork");
    } else {
        info!("No-contrib mode: push disabled — commits will be local only");
    }

    sigma_repo.set_remote_url(fork_url.clone()).await?;
    sigma_repo.set_working_branch(branch_name.clone())?;
    sigma_repo.check_remote_working_branch()?;

    let mut regression = match SigmahqRegression::new() {
        Ok(r) => r,
        Err(e) => anyhow::bail!("Failed to load regression data: {e}"),
    };
    regression.set_author(config.git.author.clone());

    let existing_rules: HashSet<Uuid> = if cli.all_rules {
        HashSet::new()
    } else {
        let mut existing: HashSet<Uuid> = regression.get_sigma_id().into_iter().collect();
        if !existing.is_empty() {
            info!(
                "{} rules with existing regression data (skipped)",
                existing.len()
            );
        }
        // Union with rules committed on pending `sigmacatch/*` PR branches
        // (not yet merged into main): a fresh VM only sees main, so without
        // this scan an open PR's rules would be re-captured and duplicated.
        match sigma_repo.pending_regression_rule_ids() {
            Ok(pending) => {
                if !pending.is_empty() {
                    let before = existing.len();
                    existing.extend(pending);
                    info!(
                        "{} rules with regression data on pending sigmacatch/* branches (skipped)",
                        existing.len() - before
                    );
                }
            }
            Err(e) => {
                warn!(
                    "Failed to scan pending sigmacatch/* branches for existing regression data: {}",
                    e
                );
            }
        }
        existing
    };

    let mut rules = SigmahqRules::new()?;

    for id in &existing_rules {
        rules.remove_id(id);
    }

    config.filter.normalize();
    let mut rules = rules.filter(config.filter.clone());
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
             Adjust filter.* filters in config.yaml or load rules with matching metadata.",
            config.filter.product,
            config.filter.min_status,
            config.filter.min_level,
            config.filter.author,
        );
    }

    let custom_map = sigmacatch_config::load_custom_channel_mapping(
        PathBuf::from("custom_channels.yaml").as_path(),
    );
    let mut engine = DetectionEngine::new(&rules)?;
    let cycle_channels = if config.collector == Collector::Winevt {
        let channels = engine.resolve_channels(&custom_map);
        if channels.is_empty() {
            warn!("0 channels resolved — nothing to collect");
            return Ok(());
        }
        channels
    } else {
        #[cfg(not(windows))]
        warn!("collector: etw is a no-op on non-Windows — no events will be collected");
        Vec::new()
    };

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

    let sigma_repo_path = Path::new(&config.git.sigma_repo_path);
    let output_base = sigma_repo_path.join("regression_data");

    sigmacatch_regression::clean_partial_artifacts(&output_base);

    let (tx, mut rx) = mpsc::channel::<Event>(100_000);
    let collector_stop = shutdown_rx.clone();
    #[cfg(windows)]
    let collector: Box<dyn EventProducer> = match config.collector {
        Collector::Winevt => Box::new(input_windows_channels::EventCollector::new(
            cycle_channels.clone(),
        )),
        Collector::Etw => Box::new(input_windows_etw::EventCollector::new()),
    };
    #[cfg(not(windows))]
    let collector: Box<dyn EventProducer> = Box::new(input_windows_channels::EventCollector::new(
        cycle_channels.clone(),
    ));
    let collector_handle = tokio::spawn(async move {
        if let Err(e) = collector.run(tx, collector_stop).await {
            warn!("Collector finished with error: {}", e);
        }
    });
    info!(
        "Continuous collector started (mode: {:?})",
        config.collector
    );

    let mut generate_interval = tokio::time::interval(std::time::Duration::from_secs(30));
    generate_interval.tick().await; // skip immediate first tick

    let mut branch_pushed = false;

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
                let batches = process_and_generate(&mut engine, &mut rules, &mut regression);

                if !batches.is_empty() {
                    upload_regression(&sigma_repo, batches, &mut branch_pushed, &push_branch);
                }
            }
        }
    }

    // Signal the collector to stop and wait for it to exit (dropping its Sender
    // clones), then drain the remaining events. Draining before the collector
    // exits would never terminate: it only stops when the receiver is dropped,
    // and the receiver is needed for the drain.
    info!("Final flush — draining remaining events");
    let collector_stop = std::time::Duration::from_secs(30);
    match tokio::time::timeout(collector_stop, collector_handle).await {
        Ok(join_result) => {
            if let Err(e) = join_result {
                warn!("Collector task join error: {}", e);
            }
        }
        Err(_) => warn!(
            "Collector did not stop within {:?} — forcing shutdown",
            collector_stop
        ),
    }
    while let Some(event) = rx.recv().await {
        engine.put_events(vec![event]);
    }
    drop(rx);

    let batches = process_and_generate(&mut engine, &mut rules, &mut regression);

    if !batches.is_empty() {
        upload_regression(&sigma_repo, batches, &mut branch_pushed, &push_branch);
    }

    info!("Sigmacatch finished");
    Ok(())
}

/// Commit + push regression data rule by rule. On push failure the local branch
/// is rolled back to its pre-batch tip so an orphaned local commit cannot
/// diverge from the remote (which would cause `RejectNonFastForward` on the
/// next run). The generated files remain on disk and are regenerated at next
/// startup; without contrib the commits stay local.
fn upload_regression(
    sigma_repo: &SigmaRepo,
    batches: Vec<(Uuid, Vec<String>)>,
    branch_pushed: &mut bool,
    push_branch: &str,
) {
    if batches.is_empty() {
        return;
    }

    if let Err(e) = sigma_repo.upload_rule_batches(batches) {
        error!("Failed to commit/push regression data: {}", e);
    } else if sigma_repo.contrib_enabled() && !*branch_pushed {
        *branch_pushed = true;
        info!(
            "Branch '{}' pushed to origin. Next step: create PR at https://github.com/SigmaHQ/sigma/pulls",
            push_branch
        );
    }
}

fn process_and_generate(
    engine: &mut DetectionEngine,
    rules: &mut SigmahqRules,
    regression: &mut SigmahqRegression,
) -> Vec<(Uuid, Vec<String>)> {
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

    let mut batches: Vec<(Uuid, Vec<String>)> = Vec::new();
    let mut retired_ids: Vec<Uuid> = Vec::new();
    for alert in alerts {
        if let Some(files) = regression.add(&alert) {
            // AD-4: retire the rule once its data is generated. `add()` returns
            // None for an already-retired/existing rule, so each rule_id appears
            // at most once per batch.
            retired_ids.push(alert.rule_id);
            batches.push((alert.rule_id, files));
        }
    }

    // AD-4: exclude retired rules and reload the engine once per batch to
    // avoid a full recompile per alert.
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

    let created_files: usize = batches.iter().map(|(_, files)| files.len()).sum();
    info!(
        regression_data_generated = created_files,
        rules_retired = retired_ids.len(),
        "batch complete"
    );
    batches
}
