// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 sigmacatch contributors

//! `sigmacatch-evtx` — Generate Sigma regression data from EVTX files.
//!
//! Recursively scans a directory for `.evtx` files, parses them, matches against
//! Sigma rules, and generates SigmaHQ-format regression data under
//! `sigma/regression_data/`.

use std::path::{Path, PathBuf};

use anyhow::Result;
use clap::Parser;
use sigmacatch_config::Config;
use sigmacatch_detection::DetectionEngine;
use sigmacatch_regression::{DataFormat, clean_partial_artifacts};
use sigmacatch_rule::SigmahqRules;
use sigmacatch_runner::logging::init as init_logger;
use sigmacatch_types::{Alert, Event};
use tracing::{info, warn};
use walkdir::WalkDir;

#[derive(Parser, Debug)]
#[command(
    name = "sigmacatch-evtx",
    about = "Generate Sigma regression data from EVTX files",
    long_about = "Recursively scans a directory for .evtx files, parses them, matches against Sigma rules, and generates SigmaHQ-format regression data under sigma/regression_data/."
)]
struct Args {
    /// Directory containing EVTX files (scanned recursively)
    #[arg(long = "evtx", default_value = r"C:\Windows\System32\winevt\Logs")]
    evtx_path: PathBuf,

    /// Path to config.yaml
    #[arg(long, default_value = "config.yaml")]
    config: PathBuf,

    /// Verbose output (info log level on stderr)
    #[arg(short = 'v', long, help = "Enable verbose logging (info level on stderr)", action = clap::ArgAction::SetTrue)]
    verbose: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    // Load config first for logger setup
    let config = Config::load(&args.config)?;

    // Initialize logging (stderr + file)
    let _guard = init_logger(&config, args.verbose)?;

    info!(
        "Sigma Regression Generator v{} — build {}",
        env!("CARGO_PKG_VERSION"),
        option_env!("BUILD_TIME").unwrap_or("unknown")
    );

    info!(
        "sigmacatch-evtx started for {} <{}>",
        config.git.author, config.git.email
    );

    run(args, config).await
}

async fn run(args: Args, config: Config) -> Result<()> {
    // Resolve relative paths to absolute based on config file's directory
    let config_dir = args
        .config
        .parent()
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|| PathBuf::from("."));
    let sigma_repo_path = if Path::new(&config.git.sigma_repo_path).is_relative() {
        config_dir.join(&config.git.sigma_repo_path)
    } else {
        PathBuf::from(&config.git.sigma_repo_path)
    };
    let output_path = sigma_repo_path.join("regression_data");

    // Validate input path
    if !args.evtx_path.exists() {
        anyhow::bail!("Path does not exist: {}", args.evtx_path.display());
    }
    if !args.evtx_path.is_dir() {
        anyhow::bail!("Path is not a directory: {}", args.evtx_path.display());
    }

    info!("Loaded config: author={}", config.git.author);

    // Initialize Sigma repository and regression handler (single bootstrap, AD-6)
    let (repo, _branch_name, mut regression) =
        sigmacatch_runner::bootstrap_repo_regression(&config, &sigma_repo_path).await?;

    // Load Sigma rules with filters
    let rules = SigmahqRules::new_from_path(&sigma_repo_path)?;
    let rules = rules.filter(config.filter.clone());
    let stats = rules.stats();

    info!(
        "Loaded {} rules ({} candidates, {} filtered by product, {} by status, {} by level, {} by author)",
        stats.rules_loaded,
        stats.rules_total_candidate,
        stats.rules_filtered_product,
        stats.rules_filtered_status,
        stats.rules_filtered_level,
        stats.rules_filtered_author,
    );

    if stats.rules_loaded == 0 {
        anyhow::bail!(
            "0 rules loaded — the filter config (product={}, min_status={:?}, min_level={:?}, author={:?}) is too restrictive",
            config.filter.product,
            config.filter.min_status,
            config.filter.min_level,
            config.filter.author,
        );
    }

    // Create detection engine
    let mut engine = DetectionEngine::new(&rules)?;
    info!("Detection engine created");

    // Configure regression handler (created by bootstrap)
    let author = config.git.author.trim();
    if author.is_empty() {
        anyhow::bail!("config.git.author is empty; set your GitHub username in config.yaml");
    }
    clean_partial_artifacts(&output_path);
    regression.set_author(author.to_string());
    regression.set_format(DataFormat::Evtx);
    regression.set_add_json_output(config.regression.add_json_output);
    regression.set_max_failed_cycles(config.regression.max_failed_cycles);
    info!(
        "Regression handler initialized (output: {})",
        output_path.display()
    );

    // Find all EVTX files recursively
    let evtx_files = find_evtx_files(&args.evtx_path)?;
    if evtx_files.is_empty() {
        anyhow::bail!("No EVTX files found in {}", args.evtx_path.display());
    }
    info!("Found {} EVTX file(s)", evtx_files.len());

    // Set up Ctrl+C handler for graceful shutdown
    let shutdown = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    {
        let shutdown = shutdown.clone();
        ctrlc::set_handler(move || {
            shutdown.store(true, std::sync::atomic::Ordering::Relaxed);
            eprintln!("\nCtrl+C received, shutting down gracefully...");
        })
        .expect("Failed to set Ctrl+C handler");
    }

    // Process each EVTX file
    let mut total_events = 0usize;
    for evtx_path in &evtx_files {
        if shutdown.load(std::sync::atomic::Ordering::Relaxed) {
            info!("Shutdown requested, stopping processing");
            break;
        }
        info!("Processing {}", evtx_path.display());
        match process_evtx_file(evtx_path) {
            Ok(events) => {
                total_events += events.len();
                if !events.is_empty() {
                    engine.put_events(events);
                }
            }
            Err(e) => {
                warn!("Failed to parse {}: {}", evtx_path.display(), e);
            }
        }
    }

    info!("Total events parsed: {}", total_events);

    // Process all events through detection engine
    if !shutdown.load(std::sync::atomic::Ordering::Relaxed) {
        engine.process_events();
    }
    let alerts = engine.get_alerts();

    if alerts.is_empty() {
        info!("No rule matches found");
        return Ok(());
    }

    info!("Found {} alert(s)", alerts.len());

    // Generate regression data
    regression.begin_cycle();
    let mut generated = 0usize;
    let mut seen_rules = std::collections::HashSet::new();
    let mut batches = Vec::new();
    for mut alert in alerts {
        if shutdown.load(std::sync::atomic::Ordering::Relaxed) {
            info!("Shutdown requested, stopping regression generation");
            break;
        }
        // Static EVTX input: the events came from a file, not the live event
        // log. Drop the record id so regression data is written with the
        // pure-Rust EVTX writer instead of re-exporting via EvtExportLog
        // (which would query the live log and match nothing).
        strip_record_id(&mut alert);
        // Deduplicate by rule_id to avoid duplicate regression entries
        if seen_rules.insert(alert.rule_id)
            && let Some(files) = regression.add(&alert)
        {
            generated += files.len();
            batches.push((alert.rule_id, files.clone()));
            info!(
                "Generated regression data for rule {}: {} file(s)",
                alert.rule_id,
                files.len()
            );
        }
    }

    // Calculate rules count based on actual files per rule (evtx + info.yml + optional json)
    let files_per_rule = if config.regression.add_json_output {
        3
    } else {
        2
    };
    if generated > 0 {
        info!(
            "Successfully generated regression data for {} rule(s)",
            generated / files_per_rule
        );
    } else {
        info!("No new regression data generated (rules may already have data)");
    }

    // Commit and push regression data if not offline
    if !config.git.is_offline() && !batches.is_empty() {
        info!("Committing and pushing regression data...");
        repo.upload_rule_batches(batches, &|| {
            shutdown.load(std::sync::atomic::Ordering::Relaxed)
        })?;
        info!("Regression data committed and pushed");
    } else if config.git.is_offline() && !batches.is_empty() {
        info!("Offline mode — regression data written to disk only (no commit/push)");
    }

    Ok(())
}

/// Recursively find all *.evtx files in a directory (case-insensitive).
fn find_evtx_files(dir: &Path) -> Result<Vec<PathBuf>> {
    let mut files = Vec::new();
    for entry in WalkDir::new(dir).follow_links(false).into_iter() {
        let entry = entry.map_err(|e| anyhow::anyhow!("WalkDir error: {e}"))?;
        let path = entry.path();
        if path.is_file()
            && let Some(ext) = path.extension()
            && ext.eq_ignore_ascii_case("evtx")
        {
            files.push(path.to_path_buf());
        }
    }
    files.sort();
    Ok(files)
}

/// Parse a single EVTX file into a vector of `Event` objects.
fn process_evtx_file(path: &Path) -> Result<Vec<Event>> {
    input_windows_evtx::parse_evtx_file(path).map_err(|e| anyhow::anyhow!("EVTX parse error: {e}"))
}

/// Remove `EventRecordID` from an alert's event JSON.
///
/// `Alert::record_id()` reads it, and `write_evtx` re-exports events that have
/// one from the live Event Log (`EvtExportLog`). Events parsed from a static
/// EVTX file are not present in the live log, so they must take the pure-Rust
/// EVTX writer path instead (record id absent).
fn strip_record_id(alert: &mut Alert) {
    if let Some(system) = alert
        .event_json
        .get_mut("Event")
        .and_then(|v| v.get_mut("System"))
        .and_then(|v| v.as_object_mut())
    {
        system.remove("EventRecordID");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::tempdir;

    #[test]
    fn test_find_evtx_files_empty_dir() {
        let dir = tempdir().unwrap();
        let files = find_evtx_files(dir.path()).unwrap();
        assert!(files.is_empty());
    }

    #[test]
    fn test_find_evtx_files_with_evtx() {
        let dir = tempdir().unwrap();
        let file1 = dir.path().join("test1.evtx");
        let file2 = dir.path().join("test2.EVTX");
        let file3 = dir.path().join("test.txt");
        fs::write(&file1, b"").unwrap();
        fs::write(&file2, b"").unwrap();
        fs::write(&file3, b"").unwrap();

        let files = find_evtx_files(dir.path()).unwrap();
        assert_eq!(files.len(), 2);
        assert!(files.iter().any(|p| p.file_name().unwrap() == "test1.evtx"));
        assert!(files.iter().any(|p| p.file_name().unwrap() == "test2.EVTX"));
    }

    #[test]
    fn test_find_evtx_files_recursive() {
        let dir = tempdir().unwrap();
        let subdir = dir.path().join("subdir");
        fs::create_dir(&subdir).unwrap();
        let file1 = dir.path().join("root.evtx");
        let file2 = subdir.join("nested.evtx");
        fs::write(&file1, b"").unwrap();
        fs::write(&file2, b"").unwrap();

        let files = find_evtx_files(dir.path()).unwrap();
        assert_eq!(files.len(), 2);
    }
}
