// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 sigmacatch contributors

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

use anyhow::Result;
use sigmacatch_config::{self, parse_args, Config};
use sigmacatch_detection::DetectionEngine;
use sigmacatch_logger::init as init_logger;
use sigmacatch_regression::SigmahqRegression;
use sigmacatch_repo::SigmaRepo;
use sigmacatch_rule::SigmahqRules;
use sigmacatch_types::{Event, EventProducer};
use tokio::signal;
use tokio::sync::mpsc;
use tracing::{error, info, warn};
use uuid::Uuid;

type EvtxWriteFn = Box<dyn Fn(&str, &str, Option<u64>, bool, &Path) -> anyhow::Result<()>>;

/// Collector-specific behaviour injected by each binary.
pub trait CollectorKind {
    /// Binary name used in log messages.
    fn name(&self) -> &'static str;

    /// Short description of the collection mode (startup log).
    fn mode(&self) -> &'static str;

    /// Channels to collect, or `None` when the collector does not need channel
    /// resolution (ETW). `Some(empty)` means nothing to collect (early exit).
    fn channels(
        &self,
        engine: &DetectionEngine,
        custom_map: &HashMap<String, String>,
    ) -> Option<Vec<String>>;

    /// Build the collector for the resolved channels.
    fn build(&self, channels: &[String]) -> Box<dyn EventProducer>;
}

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

/// Run the sigmacatch pipeline with the given collector.
pub async fn run<C: CollectorKind>(kind: &C) -> Result<()> {
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
        "{} started for {} <{}>",
        kind.name(),
        config.git.author,
        config.git.email
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

    if matches!(config.git.transport, sigmacatch_config::GitTransport::Ssh)
        && config.git.needs_network()
    {
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
        info!(
            "Offline mode: all git operations skipped — on-disk files used as-is (no commit/push)"
        );
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
    regression.set_max_failed_cycles(config.regression.max_failed_cycles);

    let write_fn: EvtxWriteFn = Box::new(sigmacatch_regression::write_evtx);

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
        if !config.git.is_offline() {
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
    let cycle_channels = match kind.channels(&engine, &custom_map) {
        Some(channels) => {
            if channels.is_empty() {
                warn!("0 channels resolved — nothing to collect");
                return Ok(());
            }
            channels
        }
        None => Vec::new(),
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
    let collector = kind.build(&cycle_channels);
    // Keep a clone of the sender in the main task so we can drop it
    // after the loop breaks, forcing the channel to close once the
    // collector finishes.
    let main_tx = tx.clone();
    let collector_handle = tokio::spawn(async move {
        if let Err(e) = collector.run(tx, collector_stop).await {
            warn!("Collector finished with error: {}", e);
        }
    });
    info!("Continuous collector started ({})", kind.mode());

    let mut generate_interval = tokio::time::interval(std::time::Duration::from_secs(30));
    generate_interval.tick().await; // skip immediate first tick

    let mut branch_pushed = false;
    let max_runs = cli.max_runs;
    let mut runs_completed: u32 = 0;
    let mut max_runs_reached = false;

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
                let batches = process_and_generate(&mut engine, &mut rules, &mut regression, &write_fn);
                runs_completed += 1;
                info!("Cycle {} completed", runs_completed);

                if let Some(limit) = max_runs {
                    if runs_completed >= limit {
                        info!("Reached max-runs limit ({}), shutting down", limit);
                        max_runs_reached = true;
                        let _ = shutdown_tx.send(true);
                        break;
                    }
                }

                if !batches.is_empty() {
                    upload_regression(&sigma_repo, batches, &mut branch_pushed, &push_branch);
                }
            }
        }
    }

    info!("Final flush — draining remaining events");
    let collector_stop = std::time::Duration::from_secs(10);
    let collector_abort = collector_handle.abort_handle();
    match tokio::time::timeout(collector_stop, async {
        // Drop the sender reference held by the main task so the channel
        // closes as soon as the collector stops — this lets the drain
        // complete immediately instead of waiting for the 5s timeout.
        drop(main_tx);
        collector_handle.await
    })
    .await
    {
        Ok(join_result) => {
            if let Err(e) = join_result {
                warn!("Collector task join error: {}", e);
            }
        }
        Err(_) => {
            warn!(
                "Collector did not stop within {:?} — aborting",
                collector_stop
            );
            collector_abort.abort();
        }
    }
    let drain_stop = std::time::Duration::from_secs(5);
    match tokio::time::timeout(drain_stop, async {
        while let Some(event) = rx.recv().await {
            engine.put_events(vec![event]);
        }
    })
    .await
    {
        Ok(()) => {}
        Err(_) => {
            warn!(
                "Event drain timed out — dropping {} buffered events",
                rx.len()
            );
        }
    }
    drop(rx);

    if !max_runs_reached {
        let batches = process_and_generate(&mut engine, &mut rules, &mut regression, &write_fn);
        if !batches.is_empty() {
            upload_regression(&sigma_repo, batches, &mut branch_pushed, &push_branch);
        }
    }

    info!("{} finished", kind.name());
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

fn process_and_generate<F>(
    engine: &mut DetectionEngine,
    rules: &mut SigmahqRules,
    regression: &mut SigmahqRegression,
    write_fn: F,
) -> Vec<(Uuid, Vec<String>)>
where
    F: Fn(&str, &str, Option<u64>, bool, &Path) -> anyhow::Result<()>,
{
    engine.process_events();
    let alerts = engine.get_alerts();

    if alerts.is_empty() {
        return Vec::new();
    }

    regression.begin_cycle();

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
        if let Some(files) = regression.add(&alert, &write_fn) {
            retired_ids.push(alert.rule_id);
            batches.push((alert.rule_id, files));
        }
    }

    retired_ids.extend(regression.take_blocked());

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
