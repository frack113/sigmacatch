// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 sigmacatch contributors

mod collector;
mod config;
mod contrib;
mod evtx;
mod logger;
mod parser;
mod regression;
mod sigma;

use anyhow::Result;
use config::Config;
use sigma::engine::SigmaEngine;
use sigma::loader::{find_rules_dirs, SigmaRepo};
use sigma::mapping::build_logsource_to_channels;
use sigma::mapping::custom::load_custom_mapping;
use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tokio::signal;
use tokio::sync::mpsc;
use tracing::{debug, error, info, info_span, warn};

struct Stats {
    events_processed: u64,
    matches_found: u64,
    regression_data_generated: u64,
}

struct AggregatedRule {
    header: rsigma_eval::result::RuleHeader,
    events: Vec<(serde_json::Value, String, String)>,
    rule_path: Option<PathBuf>,
    description: Option<String>,
}

async fn stage_0_init(_config: &Config) -> Result<()> {
    info!("directory structure ready");
    Ok(())
}

async fn stage_1_update_repo(_config: &Config, offline: bool, fork_config: Option<&contrib::fork::ForkConfig>) -> Result<()> {
    let mut sigma_repo = SigmaRepo::new(std::path::Path::new("sigma")).with_offline(offline);

    if let Some(fc) = fork_config {
        if fc.is_fork {
            let base_url = fc.fork_url.strip_suffix(".git").unwrap_or(&fc.fork_url);
            let clone_url = format!("{}.git", base_url);
            sigma_repo = sigma_repo.with_remote_url(clone_url);
        }
    }

    sigma_repo.init().await?;

    if let Some(fc) = fork_config {
        contrib::branch::create_branch(&sigma_repo.path, &fc.branch_name)?;
    }

    info!("Sigma repository ready");
    Ok(())
}

fn stage_2_existing_rules(_config: &Config) -> HashSet<String> {
    let rules_dir = PathBuf::from("regression_data").join("rules");
    let sigma_regression_dir = PathBuf::from("sigma").join("regression_data");

    let skip_set = regression::build_skip_set(
        &[
            ("regression_data/rules", &rules_dir),
            ("sigma_regression", &sigma_regression_dir),
        ],
        64,
    );

    let existing_rules = skip_set.into_rule_ids();

    if !existing_rules.is_empty() {
        info!(
            "{} rules with existing regression data (skipped)",
            existing_rules.len()
        );
    }

    existing_rules
}

fn stage_3_load_rules(
    _config: &Config,
    existing_rules: &HashSet<String>,
) -> Result<(SigmaEngine, u64)> {
    let rules_dirs = find_rules_dirs(std::path::Path::new("sigma"))?;
    if rules_dirs.is_empty() {
        anyhow::bail!(
            "Scanned \"sigma\" — found 0 rules directories. \
             The repository may be empty or incomplete."
        );
    }

    let mut engine = SigmaEngine::new();
    let rules_count = engine.load_rules_from_dirs(
        &rules_dirs.iter().map(|d| d.as_path()).collect::<Vec<_>>(),
        existing_rules,
    )?;

    info!(
        "Loaded {} rules from {} directories",
        rules_count,
        rules_dirs.len()
    );
    Ok((engine, rules_count as u64))
}

#[allow(clippy::too_many_arguments)]
async fn stage_4_work_winevt(
    channels: Vec<String>,
    engine: &SigmaEngine,
    retired: &mut HashSet<String>,
    aggregated: &mut HashMap<String, AggregatedRule>,
    stats: &mut Stats,
    custom_map: &HashMap<String, String>,
    author: &str,
    email: &str,
    contrib_enabled: bool,
    sigma_repo_path: &std::path::Path,
) -> Result<()> {
    let output_base = if contrib_enabled {
        sigma_repo_path.join("regression_data")
    } else {
        std::path::PathBuf::from("regression_data")
    };

    info!("Starting winevt collection on channels: {:?}", channels);

    let (tx, mut rx) = mpsc::channel::<collector::winevt::WinevtEvent>(1024);

    // Spawn one task per channel
    let mut collector_tasks = Vec::new();
    for channel in channels {
        let tx = tx.clone();
        let task = tokio::spawn(async move {
            let channel_name = channel.clone();
            let collector = collector::winevt::WinevtCollector::new(channel);
            if let Err(e) = collector.stream(tx).await {
                error!("WinevtCollector error on channel '{}': {}", channel_name, e);
            }
        });
        collector_tasks.push(task);
    }

    drop(tx); // Drop original sender so rx will close when all tasks are done

    // Process events from all channels
    while let Some(event) = rx.recv().await {
        stats.events_processed += 1;

        // Use pre-parsed JSON from collector, fall back to parsing XML
        let event_json = match event.event_json {
            Some(json) => json,
            None => {
                let json_parser = parser::XmlParser {};
                match json_parser.parse(&event.raw_xml) {
                    Ok(json) => json,
                    Err(e) => {
                        warn!(
                            "Failed to parse event XML (EventID={}, channel={}): {} — skipping",
                            event.event_id, event.channel, e.xml_truncated
                        );
                        continue;
                    }
                }
            }
        };

        // Evaluate against all rules
        let _eval_span = info_span!(
            "evaluate",
            event_id = event.event_id,
            channel = event.channel
        )
        .entered();
        let provider = event_json
            .get("ProviderName")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let event_id_num = event_json
            .get("EventID_num")
            .and_then(|v| v.as_u64())
            .unwrap_or(0) as u32;
        let logsource = crate::sigma::mapping::resolve_logsource(
            &event.channel,
            provider,
            event_id_num,
            custom_map,
        );
        let matches = engine.evaluate_event_with_logsource(&event_json, &logsource);

        for match_result in &matches {
            let rule_id = match_result
                .header
                .rule_id
                .clone()
                .unwrap_or_else(|| "unknown".to_string());

            if retired.contains(&rule_id) {
                continue;
            }

            debug!("Rule {} matched", rule_id);

            stats.matches_found += 1;

            let entry = aggregated
                .entry(rule_id.clone())
                .or_insert_with(|| AggregatedRule {
                    header: match_result.header.clone(),
                    events: Vec::new(),
                    rule_path: engine.rule_path(&rule_id).cloned(),
                    description: engine.rule_description(&rule_id).map(|s| s.to_string()),
                });
            entry.events.push((
                event_json.clone(),
                event.raw_xml.clone(),
                provider.to_string(),
            ));
        }
    }

    // Wait for all collector tasks to complete
    for task in collector_tasks {
        if let Err(e) = task.await {
            error!("Collector task error: {}", e);
        }
    }

    info!(
        "{} events processed, {} rule matches",
        stats.events_processed, stats.matches_found
    );

    // Generate regression data
    let mut to_generate: Vec<(
        regression::generator::RegressionData,
        Option<PathBuf>,
        String,
    )> = Vec::new();
    for agg in aggregated.values_mut() {
        let rule_rel_path = agg.rule_path.as_ref().and_then(|p| {
            p.strip_prefix("sigma")
                .ok()
                .map(|rel| rel.with_extension(""))
        });

        let mut reg = regression::generator::RegressionData::new(
            agg.header.clone(),
            &output_base,
            rule_rel_path.as_deref(),
            Some(author),
            agg.description.as_deref(),
        );
        if reg.exists() {
            continue;
        }

        for (event_json, raw_xml, provider) in &agg.events {
            let channel = event_json
                .get("Channel")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let record_id = event_json.get("EventRecordID_num").and_then(|v| v.as_u64());
            reg.add_event(
                event_json.clone(),
                raw_xml.clone(),
                channel,
                record_id,
                provider.clone(),
            );
        }
        let rule_id = agg
            .header
            .rule_id
            .clone()
            .unwrap_or_else(|| "unknown".to_string());
        to_generate.push((reg, agg.rule_path.clone(), rule_id));
    }

    if to_generate.is_empty() {
        info!("No new regression data to generate");
    } else {
        info!(
            "Generating regression data for {} rules…",
            to_generate.len()
        );
        for (reg, rule_path_opt, rule_id) in &to_generate {
            let _gen_span = info_span!("generate", rule_id = %rule_id).entered();
            match reg.generate() {
                Ok(_) => {
                    stats.regression_data_generated += 1;
                    retired.insert(rule_id.clone());
                    info!("Rule {} retired from detection engine", rule_id);
                    let rel_dir = reg
                        .sigma_rel_dir()
                        .unwrap_or_else(|| format!("regression_data/rules/{}", rule_id));
                    let tests_path = format!("{}/info.yml", rel_dir.replace('\\', "/"));
                    if let Some(rule_yaml_path) = rule_path_opt {
                        if let Ok(content) = std::fs::read(rule_yaml_path) {
                            let needs_newline =
                                !content.is_empty() && *content.last().unwrap() != b'\n';
                            let prefix = if needs_newline { "\n" } else { "" };
                            let line = format!("{}regression_tests_path: {}\n", prefix, tests_path);
                            let _ = std::fs::OpenOptions::new()
                                .append(true)
                                .open(rule_yaml_path)
                                .and_then(|mut file| {
                                    std::io::Write::write_all(&mut file, line.as_bytes())
                                });
                        }
                    }
                }
                Err(e) => {
                    let rid = reg.header.rule_id.as_deref().unwrap_or("?");
                    error!("Failed to generate regression for {}: {}", rid, e);
                }
            }
        }
    }

    // Commit regression data if contrib is enabled
    if contrib_enabled && !to_generate.is_empty() {
        let committed_rules: Vec<String> = to_generate.iter().map(|(_, _, rid)| rid.clone()).collect();
        if let Err(e) = contrib::commit::commit_all_rules(sigma_repo_path, &committed_rules, author, email) {
            warn!("Failed to commit regression data: {}", e);
        }
    }

    Ok(())
}

fn resolve_channels_from_rules(
    engine: &SigmaEngine,
    custom_map: &HashMap<String, String>,
) -> Vec<String> {
    let map = build_logsource_to_channels(custom_map);
    let active_services = engine.active_services();
    let all_services = engine.all_services();
    let active_categories = engine.active_categories();
    let all_categories = engine.all_categories();

    let mut channels_set: HashSet<String> = active_services
        .iter()
        .filter_map(|service| map.get(service.as_str()))
        .flat_map(|targets| targets.iter().map(|t| t.channel.to_string()))
        .collect();

    for category in active_categories {
        for service in active_services {
            let composite = format!("{}:{}", service, category);
            if let Some(targets) = map.get(composite.as_str()) {
                for t in targets {
                    channels_set.insert(t.channel.to_string());
                }
            }
        }
    }

    let mut channels: Vec<String> = channels_set.into_iter().collect();
    channels.sort();

    let mut active: Vec<&str> = active_services.iter().map(|s| s.as_str()).collect();
    active.sort();
    info!("Active services: {:?}", active);

    let mut active_cats: Vec<&str> = active_categories.iter().map(|s| s.as_str()).collect();
    active_cats.sort();
    info!("Active categories: {:?}", active_cats);

    let skipped: Vec<&str> = all_services
        .difference(active_services)
        .map(|s| s.as_str())
        .collect();
    if !skipped.is_empty() {
        info!("Skipped services: {:?} (all rules skipped)", skipped);
    }

    let skipped_cats: Vec<&str> = all_categories
        .difference(active_categories)
        .map(|s| s.as_str())
        .collect();
    if !skipped_cats.is_empty() {
        info!("Skipped categories: {:?} (all rules skipped)", skipped_cats);
    }

    info!("Channels to collect: {:?}", channels);

    channels
}

async fn setup_pipeline(
    config: &Config,
    offline: bool,
    fork_config: Option<&contrib::fork::ForkConfig>,
) -> Result<(SigmaEngine, Vec<String>, HashMap<String, String>)> {
    stage_0_init(config).await?;
    stage_1_update_repo(config, offline, fork_config).await?;

    let existing_rules = stage_2_existing_rules(config);

    let (engine, rules_count) = stage_3_load_rules(config, &existing_rules)?;
    let skipped = existing_rules.len();
    if skipped > 0 {
        info!(
            "done: {} rules loaded, {} skipped (existing regression)",
            rules_count, skipped
        );
    } else {
        info!("done: {} rules loaded", rules_count);
    }

    let custom_map = load_custom_mapping(PathBuf::from("custom_channels.yaml").as_path());
    let channels = resolve_channels_from_rules(&engine, &custom_map);

    if channels.is_empty() {
        warn!("0 channels resolved — nothing to collect");
    }

    Ok((engine, channels, custom_map))
}

/// Configure Windows console for UTF-8 output and ANSI escape sequences.
/// Required for proper emoji/unicode rendering in Windows Terminal.
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

async fn run_cycle(
    channels: Vec<String>,
    engine: &SigmaEngine,
    retired: &mut HashSet<String>,
    custom_map: &HashMap<String, String>,
    author: &str,
    email: &str,
    contrib_enabled: bool,
) -> Result<Stats> {
    let mut stats = Stats {
        events_processed: 0,
        matches_found: 0,
        regression_data_generated: 0,
    };

    if channels.is_empty() {
        return Ok(stats);
    }

    let mut aggregated: HashMap<String, AggregatedRule> = HashMap::new();
    {
        let _span = info_span!("collect").entered();
        stage_4_work_winevt(
            channels,
            engine,
            retired,
            &mut aggregated,
            &mut stats,
            custom_map,
            author,
            email,
            contrib_enabled,
            std::path::Path::new("sigma"),
        )
        .await?;
    }

    info!(
        events_processed = stats.events_processed,
        matches_found = stats.matches_found,
        regression_data_generated = stats.regression_data_generated,
        "cycle complete"
    );

    Ok(stats)
}

#[tokio::main]
async fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    let flags: Vec<&str> = args.iter().skip(1).map(|s| s.as_str()).collect();
    let flag = |name: &str| flags.contains(&name);
    let flag_value = |name: &str| -> Option<String> {
        let mut iter = flags.iter();
        while let Some(f) = iter.next() {
            if *f == name {
                return iter.next().map(|v| v.to_string());
            }
        }
        None
    };

    std::fs::create_dir_all("sigma")?;
    std::fs::create_dir_all("regression_data")?;
    std::fs::create_dir_all("regression_data/rules")?;
    std::fs::create_dir_all("logs")?;

    let config_path = PathBuf::from("config.yaml");
    let just_created = !config_path.exists();
    let mut config = Config::load(&config_path)?;

    if just_created {
        eprintln!("── config.yaml created ──────────────────────");
        eprintln!("  Edit config.yaml with your settings,");
        eprintln!("  then run sigmacatch again.");
        eprintln!("──────────────────────────────────────────────");
        std::process::exit(1);
    }

    if let Some(author) = flag_value("--author") {
        config.author = author;
    }
    if flag("--offline") {
        config.offline = true;
    }

    if config.author == "sigmacatch" {
        eprintln!("── config.yaml not configured ──────────────");
        eprintln!("  Update the 'author' field in config.yaml");
        eprintln!("  before running.");
        eprintln!("──────────────────────────────────────────────");
        std::process::exit(1);
    }

    let mut fork_config: Option<contrib::fork::ForkConfig> = None;
    let branch_name;
    if config.contrib {
        if config.email.is_empty() {
            anyhow::bail!("config.yaml 'email' field required for contrib workflow.");
        }
        info!("Contrib workflow enabled for {} <{}>", config.author, config.email);
        branch_name = contrib::branch::create_branch_name(&config.author);
        info!("Branch name: {}", branch_name);
        fork_config = Some(contrib::fork::detect_fork(&config.author, &branch_name).await?);
        if let Some(ref fc) = fork_config {
            if !fc.is_fork {
                warn!(
                    "Fork not detected for '{}'. Using SigmaHQ/sigma as remote. \
                     Push will fail without a fork. Please create a fork at: \
                     https://github.com/SigmaHQ/sigma/fork",
                    config.author
                );
            }
        }
    }

    #[cfg(windows)]
    setup_console();

    let _guard = logger::init(&config)?;

    info!(
        "Sigma Regression Generator v{} — build {}",
        env!("CARGO_PKG_VERSION"),
        env!("BUILD_TIME")
    );

    let (engine, cycle_channels, custom_map) = setup_pipeline(&config, config.offline, fork_config.as_ref()).await?;

    if cycle_channels.is_empty() {
        info!("No channels resolved — exiting cleanly");
        return Ok(());
    }

    let mut retired: HashSet<String> = HashSet::new();
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
            if let Some(ref fc) = fork_config {
                if fc.is_fork {
                    if let Err(e) = contrib::branch::push_branch(
                        std::path::Path::new("sigma"),
                        &fc.branch_name,
                        "origin",
                    ) {
                        warn!("Failed to push branch: {}", e);
                    } else {
                        info!(
                            "Branch '{}' pushed to origin. Next step: create PR at https://github.com/SigmaHQ/sigma/pulls",
                            fc.branch_name
                        );
                    }
                } else {
                    warn!(
                        "No fork detected for '{}'. Cannot push. \
                         Please create a fork at https://github.com/SigmaHQ/sigma/fork",
                        config.author
                    );
                }
            }
            break;
        }

        cycle += 1;
        {
            let _span = info_span!("cycle", cycle_id = cycle).entered();
            info!("collecting…");

            let channels = cycle_channels.clone();
            run_cycle(channels, &engine, &mut retired, &custom_map, &config.author, &config.email, config.contrib).await?;
        }

        info!("waiting 30s before next cycle…");
        tokio::time::sleep(std::time::Duration::from_secs(30)).await;
    }

    Ok(())
}
