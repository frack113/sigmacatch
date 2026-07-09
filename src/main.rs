mod collector;
mod config;
mod evtx;
mod logger;
mod parser;
mod regression;
mod sigma;

use anyhow::Result;
use config::Config;
use sigma::engine::SigmaEngine;
use sigma::loader::{find_rules_dirs, SigmaRepo};
use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tokio::signal;
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};

struct Stats {
    rules_loaded: u64,
    events_processed: u64,
    matches_found: u64,
    regression_data_generated: u64,
    status: String,
}

struct AggregatedRule {
    header: rsigma_eval::result::RuleHeader,
    events: Vec<(serde_json::Value, String)>,
    rule_path: Option<PathBuf>,
}

async fn stage_0_init(_config: &Config) -> Result<()> {
    info!("ensuring directory structure…");
    std::fs::create_dir_all("sigma")?;
    std::fs::create_dir_all("regression_data")?;
    std::fs::create_dir_all("logs")?;

    let config_path = PathBuf::from("config.yaml");
    if !config_path.exists() {
        let config = Config::default();
        let yaml = serde_yaml::to_string(&config)?;
        std::fs::write(&config_path, yaml)?;
        tracing::info!("Created default config file at {:?}", config_path);
    }

    Ok(())
}

async fn stage_1_update_repo(_config: &Config, offline: bool) -> Result<()> {
    let sigma_repo = SigmaRepo::new(std::path::Path::new("sigma")).with_offline(offline);
    sigma_repo.init().await?;
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

async fn stage_4_work_winevt(
    config: &Config,
    engine: &SigmaEngine,
    retired: &mut HashSet<String>,
    aggregated: &mut HashMap<String, AggregatedRule>,
    stats: &mut Stats,
) -> Result<()> {
    info!(
        "Starting winevt collection on channels: {:?}",
        config.channels
    );

    let (tx, mut rx) = mpsc::channel::<collector::winevt::WinevtEvent>(1024);

    let channels: Vec<String> = config.channels.clone();

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

        // Parse XML → JSON
        let json_parser = parser::XmlParser {};
        let event_json = match json_parser.parse(&event.raw_xml) {
            Ok(json) => json,
            Err(e) => {
                warn!(
                    "Failed to parse event XML (EventID={}, channel={}): {} — skipping",
                    event.event_id, event.channel, e.xml_truncated
                );
                continue;
            }
        };

        // Evaluate against all rules
        let provider = event_json
            .get("ProviderName")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let event_id_num = event_json
            .get("EventID_num")
            .and_then(|v| v.as_u64())
            .unwrap_or(0) as u32;
        let category = crate::sigma::engine::event_id_to_category(event_id_num, provider);
        let logsource = crate::sigma::engine::provider_to_logsource(provider, category.as_deref());
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
                });
            entry
                .events
                .push((event_json.clone(), event.raw_xml.clone()));
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
            std::path::Path::new("regression_data"),
            rule_rel_path.as_deref(),
            None,
        );
        if reg.exists() {
            continue;
        }

        for (event_json, raw_xml) in &agg.events {
            reg.add_event(event_json.clone(), raw_xml.clone());
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
            match reg.generate() {
                Ok(_) => {
                    stats.regression_data_generated += 1;
                    retired.insert(rule_id.clone());
                    info!("Rule {} retired from detection engine", rule_id);
                    let rel_dir = reg
                        .sigma_rel_dir()
                        .unwrap_or_else(|| format!("regression_data/rules/{}", rule_id));
                    let tests_path = format!("{}/info.yml", rel_dir);
                    let append =
                        format!("\nregression_tests_path: {}", tests_path.replace('\\', "/"));
                    if let Some(rule_yaml_path) = rule_path_opt {
                        if let Ok(mut file) = std::fs::OpenOptions::new()
                            .append(true)
                            .open(rule_yaml_path)
                        {
                            let _ = std::io::Write::write_all(&mut file, append.as_bytes());
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

    Ok(())
}

async fn setup_pipeline(config: &Config, offline: bool) -> Result<(SigmaEngine, u64)> {
    stage_0_init(config).await?;
    stage_1_update_repo(config, offline).await?;

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

    Ok((engine, rules_count))
}

async fn run_cycle(
    config: &Config,
    engine: &SigmaEngine,
    retired: &mut HashSet<String>,
) -> Result<Stats> {
    let mut stats = Stats {
        rules_loaded: 0,
        events_processed: 0,
        matches_found: 0,
        regression_data_generated: 0,
        status: "Completed".to_string(),
    };

    let mut aggregated: HashMap<String, AggregatedRule> = HashMap::new();
    stage_4_work_winevt(config, engine, retired, &mut aggregated, &mut stats).await?;

    info!(
        "cycle complete: {} events processed, {} matches found, {} regressions generated",
        stats.events_processed, stats.matches_found, stats.regression_data_generated
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

    let config_path = PathBuf::from("config.yaml");
    let mut config = Config::load(&config_path)?;

    if flag("--create-config") {
        if let Some(author) = flag_value("--author") {
            config.author = author;
        }
        if flag("--once") {
            config.once = true;
        }
        if flag("--offline") {
            config.offline = true;
        }
        Config::save(&config_path, &config)?;
        println!("Config file created at {:?}", config_path);
        println!("{:?}", config);
        return Ok(());
    }

    if let Some(author) = flag_value("--author") {
        config.author = author;
    }
    if flag("--once") {
        config.once = true;
    }
    if flag("--offline") {
        config.offline = true;
    }

    let _guard = logger::init(&config)?;

    info!("Sigma Regression Generator v{}", env!("CARGO_PKG_VERSION"));

    let (engine, rules_count) = setup_pipeline(&config, config.offline).await?;

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
            break;
        }

        cycle += 1;
        info!("=== cycle {}: collecting… ===", cycle);

        let mut stats = run_cycle(&config, &engine, &mut retired).await?;
        stats.rules_loaded = rules_count;

        if config.once {
            let output = serde_json::json!({
                "rules_loaded": stats.rules_loaded,
                "events_processed": stats.events_processed,
                "matches_found": stats.matches_found,
                "regression_data_generated": stats.regression_data_generated,
                "status": stats.status,
            });
            println!("{}", serde_json::to_string_pretty(&output)?);
            break;
        }

        info!("waiting 30s before next cycle…");
        tokio::time::sleep(std::time::Duration::from_secs(30)).await;
    }

    Ok(())
}
