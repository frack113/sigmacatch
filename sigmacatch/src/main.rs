// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 sigmacatch contributors

use sigmacatch::collectors;
use sigmacatch::config;
use sigmacatch::detection::SigmaDetectionEngine;
use sigmacatch::github;
use sigmacatch::logger;
use sigmacatch::regression;
use sigmacatch::repo;
use sigmacatch::sigma;

use anyhow::Result;
use config::Config;
use sigma::engine::SigmaEngine;
use sigma::loader::{find_rules_dirs, SigmaRepo};
use sigma::mapping::build_logsource_to_channels;
use sigma::mapping::custom::load_custom_mapping;
use sigma_regression::generator::EvtxWriter;
use sigmacatch_types::{Alert, Event};
use std::collections::{HashMap, HashSet};
use std::path::Path;
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
    header: sigmacatch_types::RegressionHeader,
    alerts: Vec<Alert>,
    rule_path: Option<PathBuf>,
    description: Option<String>,
}

struct WorkContext {
    retired: HashSet<String>,
    aggregated: HashMap<String, AggregatedRule>,
    stats: Stats,
    author: String,
    email: String,
    sigma_repo_path: std::path::PathBuf,
    custom_map: HashMap<String, String>,
}

struct WinEvtxWriter;

impl EvtxWriter for WinEvtxWriter {
    fn write_evtx(
        &self,
        xml: &str,
        channel: &str,
        record_id: Option<u64>,
        path: &Path,
    ) -> Result<()> {
        sigmacatch::evtx::writer::write_evtx(xml, channel, record_id, path)
    }
}

struct DryRunConfig {
    token_source: String,
    token_len: usize,
    token_prefix: String,
    fork_exists: Option<bool>,
    api_auth_login: Option<String>,
    api_auth_valid: bool,
    refs_found: usize,
    repo_complete: bool,
}

impl DryRunConfig {
    fn new() -> Self {
        Self {
            token_source: String::new(),
            token_len: 0,
            token_prefix: String::new(),
            fork_exists: None,
            api_auth_login: None,
            api_auth_valid: false,
            refs_found: 0,
            repo_complete: false,
        }
    }

    fn resolve_tokens(config: &Config) -> (Option<String>, String) {
        let config_token = if !config.github_token.trim().is_empty() {
            Some(config.github_token.trim())
        } else {
            None
        };
        let env_token = std::env::var("GITHUB_TOKEN").ok();
        let has_config = config_token.is_some();
        let has_env = env_token.is_some();

        println!("\n1. Token resolution");
        println!(
            "   config.yaml github_token: {}",
            if has_config { "SET" } else { "missing" }
        );
        println!(
            "   GITHUB_TOKEN env var:     {}",
            if has_env { "SET" } else { "missing" }
        );

        let effective_token = config_token.map(|t| t.to_string()).or(env_token.clone());
        let source = if has_config {
            "config"
        } else if has_env {
            "env"
        } else {
            "none"
        };
        match &effective_token {
            Some(t) => {
                println!(
                    "   effective token:          {} chars, prefix={}",
                    t.len(),
                    &t[..t.len().min(4)]
                );
            }
            None => {
                println!(
                    "   effective token:          NONE — all git operations will be unauthenticated"
                );
                println!("\n   ⚠  No token configured. Set github_token in config.yaml or GITHUB_TOKEN env var.");
                println!("      Create a token at https://github.com/settings/tokens");
            }
        }
        (effective_token, source.to_string())
    }

    async fn check_fork(&mut self, config: &Config, client: &reqwest::Client) -> Result<()> {
        let username = &config.author;
        let fork_url = format!("https://github.com/{}/sigma", username);

        println!("\n2. Fork detection (HTTP HEAD)");
        println!("   URL: {}", fork_url);
        match client.head(&fork_url).send().await {
            Ok(resp) => {
                let status = resp.status();
                println!(
                    "   HTTP {} {}",
                    status.as_u16(),
                    status.canonical_reason().unwrap_or("?")
                );
                if status.is_success() {
                    println!("   → Fork exists");
                    self.fork_exists = Some(true);
                } else if status == reqwest::StatusCode::NOT_FOUND {
                    println!(
                        "   → Fork NOT found. Create one at: https://github.com/SigmaHQ/sigma/fork"
                    );
                    self.fork_exists = Some(false);
                } else if status == reqwest::StatusCode::FORBIDDEN
                    || status == reqwest::StatusCode::TOO_MANY_REQUESTS
                {
                    println!("   → Rate-limited or forbidden — cannot determine fork status");
                } else {
                    println!("   → Unexpected status");
                }
            }
            Err(e) => {
                println!("   → Network error: {}", e);
            }
        }
        Ok(())
    }

    async fn check_api_auth(&mut self, token: &str, client: &reqwest::Client) -> Result<()> {
        println!("\n3. GitHub API auth check (/user)");
        let api_url = "https://api.github.com/user";
        let api_req = client
            .get(api_url)
            .header("User-Agent", "sigmacatch/0.2.0")
            .header("Authorization", format!("Bearer {}", token));
        match api_req.send().await {
            Ok(resp) => {
                let status = resp.status();
                println!(
                    "   HTTP {} {}",
                    status.as_u16(),
                    status.canonical_reason().unwrap_or("?")
                );
                if status.is_success() {
                    let text = resp.text().await.unwrap_or_default();
                    if let Ok(body) = serde_json::from_str::<serde_json::Value>(&text) {
                        let login = body.get("login").and_then(|v| v.as_str()).unwrap_or("?");
                        println!("   → Authenticated as: {}", login);
                        self.api_auth_login = Some(login.to_string());
                        self.api_auth_valid = true;
                    }
                } else if status == reqwest::StatusCode::UNAUTHORIZED {
                    println!("   → Token INVALID or expired. Generate a new one at https://github.com/settings/tokens");
                } else if status == reqwest::StatusCode::FORBIDDEN {
                    println!("   → Token lacks required scopes (need 'repo' scope)");
                } else {
                    let _ = resp.text().await;
                    println!("   → Unexpected response");
                }
            }
            Err(e) => {
                println!("   → Network error: {}", e);
            }
        }
        Ok(())
    }

    async fn check_git_info_refs(
        &mut self,
        clone_url: &str,
        token: &str,
        client: &reqwest::Client,
    ) -> Result<()> {
        println!("\n4. Git smart HTTP info/refs (no protocol version header)");
        let info_refs_url = format!("{}/info/refs?service=git-upload-pack", clone_url);
        println!("   URL: {}", info_refs_url);
        let git_req = client
            .get(&info_refs_url)
            .header("User-Agent", "sigmacatch/0.2.0")
            .header("Authorization", format!("Bearer {}", token));
        match git_req.send().await {
            Ok(resp) => {
                let status = resp.status();
                println!(
                    "   HTTP {} {}",
                    status.as_u16(),
                    status.canonical_reason().unwrap_or("?")
                );
                if status.is_success() {
                    let bytes = resp.bytes().await.unwrap_or_default();
                    let text = String::from_utf8_lossy(&bytes);
                    let refs: Vec<&str> = text.lines().filter(|l| l.contains("refs/")).collect();
                    self.refs_found = refs.len();
                    println!(
                        "   → {} refs advertised (showing up to 10):",
                        self.refs_found
                    );
                    for r in refs.iter().take(10) {
                        println!("     {}", r);
                    }
                    if refs.is_empty() {
                        println!("   → No refs found via line parsing.");
                        let raw_refs: Vec<&str> =
                            text.split('\0').filter(|s| s.contains("refs/")).collect();
                        if !raw_refs.is_empty() {
                            println!("   → Found {} refs via null-byte parsing:", raw_refs.len());
                            for r in raw_refs.iter().take(10) {
                                println!(
                                    "     {}",
                                    r.trim_start_matches(|c: char| !c.is_alphanumeric())
                                );
                            }
                        } else {
                            println!("   → Raw response (first 500 bytes):");
                            let snippet = String::from_utf8_lossy(&bytes[..bytes.len().min(500)]);
                            for line in snippet.lines() {
                                println!("     {:?}", line);
                            }
                            if bytes.len() > 500 {
                                println!("     ... ({} total bytes)", bytes.len());
                            }
                        }
                    }
                } else if status == reqwest::StatusCode::UNAUTHORIZED
                    || status == reqwest::StatusCode::FORBIDDEN
                {
                    println!(
                        "   → Access denied. Token needed for private fork, or fork doesn't exist."
                    );
                    println!("     For a private fork, ensure token has 'repo' scope.");
                } else if status == reqwest::StatusCode::NOT_FOUND {
                    println!("   → Repository not found at this URL");
                } else {
                    let body = resp.text().await.unwrap_or_default();
                    println!(
                        "   → Unexpected: {}",
                        body.chars().take(200).collect::<String>()
                    );
                }
            }
            Err(e) => {
                println!("   → Network error: {}", e);
            }
        }
        Ok(())
    }

    fn check_repo_state(&mut self) -> bool {
        println!("\n5. Repo directory state");
        let sigma_dir = std::path::Path::new("sigma");
        let git_dir = sigma_dir.join(".git");
        if git_dir.exists() {
            let packed_refs = git_dir.join("packed-refs").exists();
            let has_pack = git_dir
                .join("objects")
                .join("pack")
                .read_dir()
                .map(|mut d| d.next().is_some())
                .unwrap_or(false);
            let has_refs = git_dir
                .join("refs")
                .join("heads")
                .read_dir()
                .map(|mut d| d.next().is_some())
                .unwrap_or(false);
            println!("   sigma/.git exists:         yes");
            println!(
                "   packed-refs:               {}",
                if packed_refs { "yes" } else { "no" }
            );
            println!(
                "   objects/pack:              {}",
                if has_pack { "yes" } else { "no" }
            );
            println!(
                "   refs/heads:                {}",
                if has_refs { "yes" } else { "no" }
            );
            if !packed_refs && !has_pack && !has_refs {
                println!("   → INCOMPLETE repo — delete sigma/.git and re-run");
                self.repo_complete = false;
            } else {
                self.repo_complete = true;
            }
        } else {
            println!("   sigma/.git:                not present (will clone)");
            self.repo_complete = false;
        }
        self.repo_complete
    }
}

async fn dry_run_git(config: &Config) -> Result<()> {
    let sep = "─".repeat(60);
    println!("{}", sep);
    println!("  DRY-RUN: git diagnostics");
    println!("{}", sep);

    let mut dry_run = DryRunConfig::new();
    let (effective_token, source) = DryRunConfig::resolve_tokens(config);
    dry_run.token_source = source;

    if let Some(ref t) = effective_token {
        dry_run.token_len = t.len();
        dry_run.token_prefix = t[..t.len().min(4)].to_string();
    }

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()?;

    dry_run.check_fork(config, &client).await?;

    if let Some(ref t) = effective_token {
        dry_run.check_api_auth(t, &client).await?;
    }

    let username = &config.author;
    let fork_url = format!("https://github.com/{}/sigma", username);
    let clone_url = format!("{}.git", fork_url);

    if let Some(ref t) = effective_token {
        dry_run.check_git_info_refs(&clone_url, t, &client).await?;
    }

    dry_run.check_repo_state();

    println!("\n{}", sep);
    println!("  Done. Review output above to identify the failure point.");
    println!("{}\n", sep);
    Ok(())
}

async fn stage_0_init() -> Result<()> {
    std::fs::create_dir_all("sigma")?;
    std::fs::create_dir_all("logs")?;
    info!("directory structure ready");
    Ok(())
}

async fn stage_1_update_repo(
    config: &Config,
    fork_config: Option<&github::fork::ForkConfig>,
) -> Result<()> {
    let mut sigma_repo = SigmaRepo::new(std::path::Path::new("sigma"));

    if let Some(fc) = fork_config {
        let base_url = fc.fork_url.strip_suffix(".git").unwrap_or(&fc.fork_url);
        let clone_url = format!("{}.git", base_url);
        sigma_repo = sigma_repo.with_remote_url(clone_url);
    }

    let has_config_token = !config.github_token.trim().is_empty();
    if has_config_token {
        sigma_repo = sigma_repo.with_token(config.github_token.trim().to_string());
    }

    // Switch to master/main before pulling, so the contrib branch is created
    // from the latest tracking branch, not from a stale contrib branch.
    let sigma_path = PathBuf::from("sigma");
    let git_dir = sigma_path.join(".git");
    if git_dir.exists() {
        // read_loose_or_packed_ref is used here to check if the tracking ref
        // exists after a shallow fetch. If not, we stay on the current branch
        // and git_pull will fast-forward it.
        for candidate in &["master", "main"] {
            let local_ref = format!("refs/heads/{}", candidate);
            if repo::read_loose_or_packed_ref(&git_dir, &local_ref).is_some() {
                if let Err(e) = repo::switch_head(&git_dir, candidate) {
                    warn!("Failed to switch to '{}': {}", candidate, e);
                }
                break;
            }
        }
    }

    sigma_repo.init().await?;

    if let Some(fc) = fork_config {
        repo::create_branch(&sigma_repo.path.join(".git"), &fc.branch_name)?;
    }

    info!("Sigma repository ready");
    Ok(())
}

fn stage_2_existing_rules(_config: &Config) -> HashSet<String> {
    let sigma_regression_dir = PathBuf::from("sigma").join("regression_data");

    let skip_set =
        regression::build_skip_set(&[("sigma/regression_data", &sigma_regression_dir)], 64);

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
    config: &Config,
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
        &config.sigma,
    )?;

    engine.print_rule_table(&config.sigma);

    info!(
        "Loaded {} rules from {} directories",
        rules_count,
        rules_dirs.len()
    );
    Ok((engine, rules_count as u64))
}

/// Delete regression directories under `base` that contain generated files
/// (.json/.evtx) but no `info.yml`. Such directories are partial artifacts from
/// a prior run that aborted before committing; they are never part of the skip
/// set and must not be carried into the current run's commit.
fn clean_partial_regressions(base: &std::path::Path) {
    if !base.exists() {
        return;
    }
    let walk = match std::fs::read_dir(base) {
        Ok(w) => w,
        Err(_) => return,
    };
    for entry in walk.flatten() {
        let sub = entry.path();
        if !sub.is_dir() {
            continue;
        }
        for inner in std::fs::read_dir(&sub).into_iter().flatten().flatten() {
            let dir = inner.path();
            if !dir.is_dir() {
                continue;
            }
            let has_info = dir.join("info.yml").exists();
            if !has_info {
                if let Err(e) = std::fs::remove_dir_all(&dir) {
                    warn!("Failed to clean partial regression dir {:?}: {}", dir, e);
                } else {
                    info!("Cleaned partial regression dir {:?}", dir);
                }
            }
        }
    }
}

async fn stage_4_work_winevt(
    channels: Vec<String>,
    engine: &SigmaEngine,
    mut ctx: WorkContext,
) -> Result<(
    HashSet<String>,
    Stats,
    Vec<(String, String, Option<String>)>,
)> {
    let output_base = ctx.sigma_repo_path.join("regression_data");

    // Remove partial regression artifacts left by a crashed/aborted prior run
    // (a directory tree under regression_data/ that has generated files but no
    // info.yml). These are not part of the skip set and would otherwise be
    // re-staged and committed, polluting the branch.
    clean_partial_regressions(&output_base);

    info!("Starting winevt collection on channels: {:?}", channels);

    let (tx, mut rx) = mpsc::channel::<Event>(1024);

    // Spawn one task per channel
    let mut collector_tasks = Vec::new();
    for channel in channels {
        let tx = tx.clone();
        let task = tokio::spawn(async move {
            let channel_name = channel.clone();
            let collector = collectors::event_log::WinevtCollector::new(channel);
            if let Err(e) = collector.stream(tx).await {
                error!("WinevtCollector error on channel '{}': {}", channel_name, e);
            }
        });
        collector_tasks.push(task);
    }

    drop(tx); // Drop original sender so rx will close when all tasks are done

    // Create detection engine once before the event loop
    let det_engine = SigmaDetectionEngine::new(engine, &ctx.custom_map);

    // Process events from all channels
    while let Some(event) = rx.recv().await {
        let _event_span =
            info_span!("event", event_id = event.event_id(), channel = %event.channel()).entered();
        ctx.stats.events_processed += 1;

        // Evaluate via SigmaDetectionEngine
        let alerts = det_engine.evaluate(&event);

        for alert in alerts {
            let rule_id = &alert.rule_id;

            if ctx.retired.contains(rule_id) {
                continue;
            }

            debug!("Rule {} matched", rule_id);
            ctx.stats.matches_found += 1;

            ctx.aggregated
                .entry(rule_id.clone())
                .or_insert_with(|| AggregatedRule {
                    header: sigmacatch_types::RegressionHeader::new(
                        rule_id.clone(),
                        alert.rule_title.clone(),
                    ),
                    alerts: Vec::new(),
                    rule_path: engine.rule_path(rule_id).cloned(),
                    description: engine.rule_description(rule_id).map(|s| s.to_string()),
                })
                .alerts
                .push(alert);
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
        ctx.stats.events_processed, ctx.stats.matches_found
    );

    // Generate regression data
    let mut to_generate: Vec<(
        regression::generator::RegressionData,
        Option<PathBuf>,
        String,
    )> = Vec::new();
    for agg in ctx.aggregated.values_mut() {
        let rule_rel_path = agg.rule_path.as_ref().and_then(|p| {
            p.strip_prefix("sigma")
                .ok()
                .map(|rel| rel.with_extension(""))
        });

        let mut reg = regression::generator::RegressionData::new(
            agg.header.clone(),
            &output_base,
            rule_rel_path.as_deref(),
            Some(&ctx.author),
            agg.description.as_deref(),
            ctx.sigma_repo_path
                .file_name()
                .is_some_and(|n| n == "sigma"),
        );
        if reg.exists() {
            continue;
        }

        for alert in &agg.alerts {
            reg.add_alert(alert.clone());
        }
        let rule_id = agg.header.rule_id.clone();
        to_generate.push((reg, agg.rule_path.clone(), rule_id));
    }

    let mut committed_rules: Vec<(String, String, Option<String>)> = Vec::new();

    if to_generate.is_empty() {
        info!("No new regression data to generate");
    } else {
        info!(
            "Generating regression data for {} rules…",
            to_generate.len()
        );
        for (reg, rule_path_opt, rule_id) in &to_generate {
            let _gen_span = info_span!("generate", rule_id = %rule_id).entered();
            match reg.generate(&WinEvtxWriter) {
                Ok(_) => {
                    ctx.stats.regression_data_generated += 1;
                    ctx.retired.insert(rule_id.clone());
                    info!("Rule {} retired from detection engine", rule_id);
                    let rel_dir = reg.sigma_rel_dir().unwrap_or_else(|| {
                        if reg.is_contrib {
                            format!("sigma/regression_data/rules/{}", rule_id)
                        } else {
                            format!("regression_data/rules/{}", rule_id)
                        }
                    });
                    let rule_yaml_rel = rule_path_opt
                        .as_ref()
                        .and_then(|p| p.strip_prefix(&ctx.sigma_repo_path).ok())
                        .and_then(|p| p.to_str())
                        .map(|s| s.to_string().replace('\\', "/"));
                    committed_rules.push((rule_id.clone(), rel_dir.clone(), rule_yaml_rel));
                    let tests_path = format!("{}/info.yml", rel_dir.replace('\\', "/"));
                    if let Some(rule_yaml_path) = rule_path_opt {
                        if let Ok(content) = std::fs::read(rule_yaml_path) {
                            let text = String::from_utf8_lossy(&content).to_string();
                            let expected_line = format!("regression_tests_path: {}", tests_path);
                            let has_correct = text.lines().any(|l| l.trim() == expected_line);
                            // Drop any stale regression_tests_path line (e.g. an older run
                            // wrote it with a `sigma/` prefix that the CI cannot resolve).
                            let filtered: Vec<&str> = text
                                .lines()
                                .filter(|l| {
                                    !l.trim().starts_with("regression_tests_path:")
                                        || l.trim() == expected_line
                                })
                                .collect();
                            if !has_correct {
                                let mut new_text = filtered.join("\n");
                                if !new_text.is_empty() && !new_text.ends_with('\n') {
                                    new_text.push('\n');
                                }
                                new_text.push_str(&format!("{}\n", expected_line));
                                if let Err(e) = std::fs::write(rule_yaml_path, new_text) {
                                    warn!(
                                        "Failed to update regression_tests_path in {:?}: {}",
                                        rule_yaml_path, e
                                    );
                                }
                            }
                        }
                    }
                }
                Err(e) => {
                    let rid = &reg.header.rule_id;
                    error!("Failed to generate regression for {}: {}", rid, e);
                }
            }
        }

        // Commit regression data
        if !committed_rules.is_empty() {
            if let Err(e) = github::commit::commit_all_rules(
                &ctx.sigma_repo_path,
                &committed_rules,
                &ctx.author,
                &ctx.email,
            ) {
                warn!("Failed to commit regression data: {}", e);
            }
        }
    }

    Ok((ctx.retired, ctx.stats, committed_rules))
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
    fork_config: Option<&github::fork::ForkConfig>,
) -> Result<(SigmaEngine, Vec<String>, HashMap<String, String>)> {
    stage_0_init().await?;
    stage_1_update_repo(config, fork_config).await?;

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
        warn!(
            "Loaded {} rules, {} active services, {} active categories",
            engine.rules_count(),
            engine.active_services().len(),
            engine.active_categories().len()
        );
        if !engine.all_services().is_empty() {
            let all: Vec<&str> = engine.all_services().iter().map(|s| s.as_str()).collect();
            info!("All known services in rules: {:?}", all);
        }
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
    mut retired: HashSet<String>,
    custom_map: HashMap<String, String>,
    author: String,
    email: String,
) -> Result<(
    HashSet<String>,
    Stats,
    Vec<(String, String, Option<String>)>,
)> {
    let ctx = WorkContext {
        retired: std::mem::take(&mut retired),
        aggregated: HashMap::new(),
        stats: Stats {
            events_processed: 0,
            matches_found: 0,
            regression_data_generated: 0,
        },
        author,
        email,
        sigma_repo_path: std::path::PathBuf::from("sigma"),
        custom_map,
    };

    if channels.is_empty() {
        return Ok((retired, ctx.stats, Vec::new()));
    }

    let (retired, stats, committed_rules) = {
        let _span = info_span!("collect").entered();
        stage_4_work_winevt(channels, engine, ctx).await?
    };

    info!(
        events_processed = stats.events_processed,
        matches_found = stats.matches_found,
        regression_data_generated = stats.regression_data_generated,
        "cycle complete"
    );

    Ok((retired, stats, committed_rules))
}

#[tokio::main]
async fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    let flags: Vec<&str> = args.iter().skip(1).map(|s| s.as_str()).collect();
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
        if !config
            .author
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-')
        {
            anyhow::bail!(
                "--author must be a valid GitHub username (alphanumeric + hyphens), got {:?}",
                config.author
            );
        }
    }

    if config.author == "sigmacatch" {
        eprintln!("── config.yaml not configured ──────────────");
        eprintln!("  Update the 'author' field in config.yaml");
        eprintln!("  before running.");
        eprintln!("──────────────────────────────────────────────");
        std::process::exit(1);
    }

    if flags.contains(&"--dry-run") {
        dry_run_git(&config).await?;
        return Ok(());
    }

    if flags.contains(&"--channels-only") {
        stage_0_init().await?;
        let custom_map = load_custom_mapping(PathBuf::from("custom_channels.yaml").as_path());
        let load_all = flags.contains(&"--all-rules");
        let existing_rules = if load_all {
            HashSet::new()
        } else {
            stage_2_existing_rules(&config)
        };
        let engine_path = std::path::Path::new("sigma");
        let rules_dirs = find_rules_dirs(engine_path)?;
        if rules_dirs.is_empty() {
            anyhow::bail!("No rules directories found in sigma/");
        }
        let mut engine = SigmaEngine::new();
        let filter = config::SigmaFilterConfig {
            min_status: config::MinStatus::Unsupported,
            min_level: config::MinLevel::Informational,
        };
        let rules_count = engine.load_rules_from_dirs(
            &rules_dirs.iter().map(|d| d.as_path()).collect::<Vec<_>>(),
            &existing_rules,
            &filter,
        )?;
        let channels = resolve_channels_from_rules(&engine, &custom_map);
        let active_services = engine.active_services();
        let all_services = engine.all_services();
        let active_categories = engine.active_categories();
        let all_categories = engine.all_categories();

        let sep = "─".repeat(60);
        println!("\n{}", sep);
        println!("  CHANNEL RESOLUTION RESULT");
        println!("{}", sep);

        println!(
            "\nRules: {} loaded, {} skipped (existing regression)",
            rules_count,
            existing_rules.len()
        );
        println!("Active services ({}):", active_services.len());
        let mut sorted_active: Vec<_> = active_services.iter().map(|s| s.as_str()).collect();
        sorted_active.sort();
        for svc in &sorted_active {
            if let Some(targets) = build_logsource_to_channels(&custom_map).get(*svc) {
                let channels: Vec<&str> = targets.iter().map(|t| t.channel.as_str()).collect();
                println!("  {} → {} channel(s)", svc, targets.len());
                for ch in &channels {
                    println!("    - {}", ch);
                }
            } else {
                println!("  {} → (no mapping)", svc);
            }
        }

        println!("\nActive categories ({}):", active_categories.len());
        let mut sorted_cats: Vec<_> = active_categories.iter().map(|s| s.as_str()).collect();
        sorted_cats.sort();
        for cat in &sorted_cats {
            for svc in sorted_active.iter() {
                let composite = format!("{}:{}", svc, cat);
                if let Some(targets) =
                    build_logsource_to_channels(&custom_map).get(composite.as_str())
                {
                    println!("  {}:{}", svc, cat);
                    for t in targets {
                        println!("    - {} (EventID: {:?})", t.channel, t.event_ids);
                    }
                }
            }
        }

        println!(
            "\nSkipped services ({}):",
            all_services.len() - active_services.len()
        );
        let skipped: Vec<&str> = all_services
            .difference(active_services)
            .map(|s| s.as_str())
            .collect();
        for svc in &skipped {
            println!("  - {}", svc);
        }

        println!(
            "\nSkipped categories ({}):",
            all_categories.len() - active_categories.len()
        );
        let skipped_cats: Vec<&str> = all_categories
            .difference(active_categories)
            .map(|s| s.as_str())
            .collect();
        for cat in &skipped_cats {
            println!("  - {}", cat);
        }

        println!("\nChannels to collect ({}):", channels.len());
        for ch in &channels {
            println!("  - {}", ch);
        }
        println!("\n{}", sep);

        return Ok(());
    }

    #[cfg(windows)]
    setup_console();

    let _guard = logger::init(&config)?;

    info!(
        "Sigma Regression Generator v{} — build {}",
        env!("CARGO_PKG_VERSION"),
        env!("BUILD_TIME")
    );

    info!(
        "Sigmacatch started for {} <{}>",
        config.author, config.email
    );
    let branch_name = repo::create_branch_name();
    info!("Branch name: {}", branch_name);
    let fork_config = github::fork::detect_fork(&config.author, &branch_name).await?;

    let (engine, cycle_channels, custom_map) = setup_pipeline(&config, Some(&fork_config)).await?;

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
            if let Err(e) = repo::git_push(
                std::path::Path::new("sigma"),
                "origin",
                &fork_config.branch_name,
                if !config.github_token.trim().is_empty() {
                    Some(config.github_token.trim())
                } else {
                    None
                },
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
        {
            let _span = info_span!("cycle", cycle_id = cycle).entered();
            info!("collecting…");

            let channels = cycle_channels.clone();
            let (mut retired, stats, committed_rules) = run_cycle(
                channels,
                &engine,
                std::mem::take(&mut retired),
                custom_map.clone(),
                config.author.clone(),
                config.email.clone(),
            )
            .await?;
            retired.extend(committed_rules.into_iter().map(|(rule_id, _, _)| rule_id));
            info!(
                events_processed = stats.events_processed,
                matches_found = stats.matches_found,
                regression_data_generated = stats.regression_data_generated,
                "cycle complete"
            );
        }

        if let Err(e) = repo::git_push(
            std::path::Path::new("sigma"),
            "origin",
            &fork_config.branch_name,
            if !config.github_token.trim().is_empty() {
                Some(config.github_token.trim())
            } else {
                None
            },
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
