// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 sigmacatch contributors

//! Application configuration types and loading.

use serde::{Deserialize, Serialize};
use sigmacatch_repo::DEFAULT_SIGMA_REPO_URL;
use sigmacatch_rule::{Level, MinLevel, MinStatus, Status};
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;

/// Git transport protocol re-exported from sigmacatch-repo.
pub use sigmacatch_repo::GitTransport;

/// Git transport configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct GitConfig {
    /// GitHub username for contrib workflow.
    pub author: String,
    /// Email address for git commits.
    pub email: String,
    /// GitHub token (or set GITHUB_TOKEN env var) — required for HTTP transport.
    pub github_token: String,
    /// Transport protocol: `http` (default) or `ssh`.
    pub transport: GitTransport,
    /// Path to SSH private key (optional). If empty, uses default SSH agent.
    pub ssh_key_path: Option<String>,
    /// Sigma repository URL to clone/fetch from.
    #[serde(default = "default_sigma_repo_url")]
    pub sigma_repo_url: String,
    /// Local path to store the sigma repository.
    #[serde(default = "default_sigma_repo_path")]
    pub sigma_repo_path: String,
    /// Enable offline mode: skip git pull/fetch at startup (use existing repo as-is).
    /// Default: false (pull enabled). Set to true for air-gapped environments.
    #[serde(default)]
    pub offline: Option<bool>,
    /// Enable contrib workflow: push commits to remote fork.
    /// Default: false (no push, local commits only). Set to true to contribute.
    #[serde(default)]
    pub contrib: Option<bool>,
}

fn default_sigma_repo_url() -> String {
    DEFAULT_SIGMA_REPO_URL.to_string()
}

fn default_sigma_repo_path() -> String {
    "sigma".to_string()
}

impl GitConfig {
    /// Returns true if offline mode is enabled (skip pull).
    pub fn is_offline(&self) -> bool {
        self.offline.unwrap_or(false)
    }

    /// Returns true if contrib (push) is enabled.
    pub fn is_contrib(&self) -> bool {
        self.contrib.unwrap_or(false)
    }

    /// Returns true if any network operation is needed (pull or push).
    pub fn needs_network(&self) -> bool {
        !self.is_offline() || self.is_contrib()
    }
}

impl Default for GitConfig {
    fn default() -> Self {
        Self {
            author: "sigmacatch".to_string(),
            email: String::new(),
            github_token: String::new(),
            transport: GitTransport::Http,
            ssh_key_path: None,
            sigma_repo_url: default_sigma_repo_url(),
            sigma_repo_path: default_sigma_repo_path(),
            offline: None, // None → false (pull enabled)
            contrib: None, // None → false (push disabled)
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LogLevel {
    Debug,
    Info,
    Warn,
    Error,
}

impl LogLevel {
    pub fn as_str(&self) -> &'static str {
        match self {
            LogLevel::Debug => "debug",
            LogLevel::Info => "info",
            LogLevel::Warn => "warn",
            LogLevel::Error => "error",
        }
    }
}

/// Re-export Product from sigmacatch_types for rule filtering.
pub use sigmacatch_types::Product;

/// Re-export rule filter config from sigmacatch_rule.
pub use sigmacatch_rule::SigmaFilterConfig;

/// Log configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct LogConfig {
    /// Log level for file output.
    #[serde(default = "default_level_file")]
    pub level_file: LogLevel,
}

fn default_level_file() -> LogLevel {
    LogLevel::Debug
}

impl Default for LogConfig {
    fn default() -> Self {
        Self {
            level_file: default_level_file(),
        }
    }
}

/// Main application configuration.
#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    pub log: LogConfig,
    #[serde(default)]
    pub filter: SigmaFilterConfig,
    #[serde(default)]
    pub git: GitConfig,
}

impl Config {
    fn load_unvalidated(path: &PathBuf) -> anyhow::Result<Self> {
        if !path.exists() {
            let default = Config::default();
            default.save(path)?;
            eprintln!("── config.yaml created ──────────────────────");
            eprintln!("  Edit config.yaml with your settings,");
            eprintln!("  then run sigmacatch again.");
            eprintln!("──────────────────────────────────────────────");
            std::process::exit(1);
        }

        #[cfg(unix)]
        if let Ok(metadata) = std::fs::metadata(path) {
            let mode = metadata.permissions().mode() & 0o777;
            if mode != 0o600 {
                eprintln!(
                    "⚠️  config.yaml has open permissions (0{:o}), fixing to 0600",
                    mode
                );
                if let Err(e) = std::fs::set_permissions(path, PermissionsExt::from_mode(0o600)) {
                    eprintln!("⚠️  Failed to fix config.yaml permissions: {}", e);
                }
            }
        }

        let yaml = std::fs::read_to_string(path)
            .map_err(|e| anyhow::anyhow!("Failed to read config file: {}", e))?;
        serde_yaml::from_str(&yaml)
            .map_err(|e| anyhow::anyhow!("Failed to parse config file: {}", e))
    }

    pub fn load(path: &PathBuf) -> anyhow::Result<Self> {
        let config = Self::load_unvalidated(path)?;
        config.validate()?;
        Ok(config)
    }

    pub fn load_with_cli(path: &PathBuf, cli: &CliArgs) -> anyhow::Result<Self> {
        let mut config = Self::load_unvalidated(path)?;
        if let Some(author) = &cli.author {
            config.git.author.clone_from(author);
        }
        if cli.offline {
            config.git.offline = Some(true);
        }
        if cli.contrib {
            config.git.contrib = Some(true);
        }
        config.validate()?;
        Ok(config)
    }

    pub fn save(&self, path: &PathBuf) -> anyhow::Result<()> {
        let yaml = serde_yaml::to_string(self)
            .map_err(|e| anyhow::anyhow!("Failed to serialize config: {}", e))?;

        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        std::fs::write(path, yaml)?;

        #[cfg(unix)]
        std::fs::set_permissions(path, PermissionsExt::from_mode(0o600))?;

        Ok(())
    }

    pub fn validate(&self) -> anyhow::Result<()> {
        if self.git.author == "sigmacatch" {
            anyhow::bail!(
                "config: 'git.author' is the placeholder 'sigmacatch'. \
                 Set 'author' to your GitHub username in config.yaml"
            );
        }
        if !self.git.author.is_empty()
            && !self
                .git
                .author
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-')
        {
            anyhow::bail!(
                "config: 'git.author' must be a valid GitHub username (alphanumeric + hyphens), got {:?}",
                self.git.author
            );
        }
        if self.git.email.is_empty() {
            anyhow::bail!("config: 'git.email' is required");
        }
        if !self.git.email.contains('@') {
            anyhow::bail!(
                "config: 'git.email' must contain '@', got {:?}",
                self.git.email
            );
        }
        // SSH transport is not yet implemented on Windows
        #[cfg(windows)]
        if self.git.transport == GitTransport::Ssh {
            anyhow::bail!(
                "SSH transport is not yet implemented on Windows; \
                 set transport = http in config.yaml"
            );
        }

        // Validate SSH key path if configured
        if let Some(ref key_path) = self.git.ssh_key_path {
            if !key_path.is_empty() {
                // On Windows, reject unix-style absolute paths early (e.g. /home/user/.ssh/id)
                #[cfg(windows)]
                if key_path.starts_with('/') || key_path.starts_with('~') {
                    anyhow::bail!(
                        "config: SSH key path '{}' looks like a unix-style path on Windows; \
                         use a windows path (e.g. 'C:\\Users\\user\\.ssh\\id_sigmacatch') \
                         or set transport = http",
                        key_path
                    );
                }

                let meta = std::fs::metadata(key_path).map_err(|_| {
                    anyhow::anyhow!(
                        "config: SSH key path '{}' does not exist (transport={}); \
                         remove ssh_key_path from config or switch to transport = http",
                        key_path,
                        self.git.transport
                    )
                })?;
                if !meta.is_file() {
                    anyhow::bail!(
                        "config: SSH key path '{}' is not a file (transport={}); \
                         remove ssh_key_path from config or switch to transport = http",
                        key_path,
                        self.git.transport
                    );
                }
                #[cfg(unix)]
                {
                    let mode = meta.permissions().mode() & 0o777;
                    if mode & 0o077 != 0 {
                        tracing::warn!(
                            "config: SSH key '{}' has overly permissive mode 0{:o} — should be 0600. \
                             SSH may refuse to use it. Run: chmod 600 {}",
                            key_path,
                            mode,
                            key_path
                        );
                    }
                    // Also check that the key is readable by the current user
                    if mode & 0o400 == 0 {
                        tracing::warn!(
                            "config: SSH key '{}' is not readable by the owner (mode 0{:o}). \
                             SSH will reject it. Run: chmod 400 {}",
                            key_path,
                            mode,
                            key_path
                        );
                    }
                }
            }
        }

        // Token is only required for HTTP transport when a network operation
        // is enabled (pull or push). Fully offline mode needs no token.
        if self.git.transport == GitTransport::Http && self.git.needs_network() {
            let has_config_token = !self.git.github_token.trim().is_empty();
            let has_env_token = std::env::var("GITHUB_TOKEN")
                .map(|t| !t.trim().is_empty())
                .unwrap_or(false);
            if !has_config_token && !has_env_token {
                anyhow::bail!(
                    "config: 'git.github_token' is required for HTTP transport when offline=false or contrib=true. \
                     Set git.github_token in config.yaml or GITHUB_TOKEN env var. \
                     Create a token at https://github.com/settings/tokens. \
                     Alternatively, set offline: true and contrib: false for fully offline mode (no network)."
                );
            }
            if has_config_token {
                let trimmed = self.git.github_token.trim();
                if trimmed.contains(char::is_whitespace) {
                    anyhow::bail!("config: 'git.github_token' contains whitespace — trim it");
                }
            }
        }

        if self.filter.max_rule_size < 1024 {
            anyhow::bail!(
                "config: 'filter.max_rule_size' must be at least 1024 bytes, got {}",
                self.filter.max_rule_size
            );
        }

        if self.filter.max_rule_size > 10 * 1024 * 1024 {
            anyhow::bail!(
                "config: 'filter.max_rule_size' exceeds maximum allowed value (10MB), got {}",
                self.filter.max_rule_size
            );
        }

        // Validate sigma_repo_path — reject empty, path traversal, and absolute paths
        if self.git.sigma_repo_path.trim().is_empty() {
            anyhow::bail!(
                "config: 'git.sigma_repo_path' must not be empty, got {:?}",
                self.git.sigma_repo_path
            );
        }
        if std::path::Path::new(&self.git.sigma_repo_path)
            .components()
            .any(|c| c == std::path::Component::ParentDir)
        {
            anyhow::bail!(
                "config: 'git.sigma_repo_path' contains '..' path traversal, got {:?}",
                self.git.sigma_repo_path
            );
        }
        if std::path::Path::new(&self.git.sigma_repo_path).is_absolute() {
            anyhow::bail!(
                "config: 'git.sigma_repo_path' must be a relative path, got {:?}",
                self.git.sigma_repo_path
            );
        }

        if self
            .filter
            .min_status
            .as_ref()
            .is_some_and(|s| *s >= MinStatus(Status::Stable))
        {
            tracing::warn!(
                "filter.min_status = {} — very restrictive, only stable rules will be loaded",
                self.filter.min_status.as_ref().unwrap()
            );
        }
        if self
            .filter
            .min_level
            .as_ref()
            .is_some_and(|l| *l >= MinLevel(Level::High))
        {
            tracing::warn!(
                "filter.min_level = {} — very restrictive, only {} and higher rules will be loaded",
                self.filter.min_level.as_ref().unwrap(),
                self.filter.min_level.as_ref().unwrap()
            );
        }
        Ok(())
    }

    /// Ensure required directories exist.
    pub fn ensure_dirs(&self) -> anyhow::Result<()> {
        let repo = std::path::Path::new(&self.git.sigma_repo_path);
        std::fs::create_dir_all(repo)?;
        std::fs::create_dir_all("logs")?;
        tracing::info!("directory structure ready");
        Ok(())
    }
}

/// Custom channel mappings from custom_channels.yaml.
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct CustomChannels {
    pub channels: std::collections::HashMap<String, String>,
}

/// Parsed CLI arguments.
#[derive(Debug, Clone, Default)]
pub struct CliArgs {
    pub author: Option<String>,
    pub dry_run: bool,
    pub channels_only: bool,
    pub all_rules: bool,
    pub list_rules: bool,
    pub offline: bool,
    pub contrib: bool,
}

const HELP: &str = "\
sigmacatch — Sigma regression data generator

USAGE:
    sigmacatch [OPTIONS]

FLAGS:
    --dry-run          Run git diagnostics and exit (clone, branch check, etc.)
    --channels-only    Resolve and list channels, then exit
    --all-rules        Skip rules that already have regression data
    --list-rules       List all loaded rules with their paths
    --offline          Skip pull at startup (existing repo required)
    --contrib          Enable push to remote fork (requires git.contrib=true)
    --help             Print this help and exit

OPTIONS:
    --author <NAME>    Override GitHub username from config.yaml
";

/// Parse CLI arguments from environment.
pub fn parse_args() -> CliArgs {
    let args: Vec<String> = std::env::args().collect();
    for arg in &args {
        if arg == "--help" || arg == "-h" {
            print!("{HELP}");
            std::process::exit(0);
        }
    }
    let mut author = None;
    let mut dry_run = false;
    let mut channels_only = false;
    let mut all_rules = false;
    let mut list_rules = false;
    let mut offline = false;
    let mut contrib = false;
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--author" => {
                i += 1;
                author = args.get(i).cloned();
            }
            "--dry-run" => dry_run = true,
            "--channels-only" => channels_only = true,
            "--all-rules" => all_rules = true,
            "--list-rules" => list_rules = true,
            "--offline" => offline = true,
            "--contrib" => contrib = true,
            _ => {}
        }
        i += 1;
    }
    CliArgs {
        author,
        dry_run,
        channels_only,
        all_rules,
        list_rules,
        offline,
        contrib,
    }
}

/// Load custom channel mappings from a YAML file.
/// Returns an empty HashMap if the file does not exist or cannot be parsed.
pub fn load_custom_channel_mapping(
    path: &std::path::Path,
) -> std::collections::HashMap<String, String> {
    if !path.exists() {
        return std::collections::HashMap::new();
    }
    match std::fs::read_to_string(path) {
        Ok(content) => {
            if content.trim().is_empty() {
                tracing::info!("Empty custom_channels.yaml at {:?}", path);
                return std::collections::HashMap::new();
            }
            match serde_yaml::from_str::<CustomChannels>(&content) {
                Ok(custom) => {
                    tracing::info!(
                        "Loaded {} custom channel mappings from {:?}",
                        custom.channels.len(),
                        path
                    );
                    custom.channels
                }
                Err(e) => {
                    tracing::warn!("Failed to parse custom_channels.yaml at {:?}: {}", path, e);
                    std::collections::HashMap::new()
                }
            }
        }
        Err(e) => {
            tracing::warn!("Failed to read custom_channels.yaml at {:?}: {}", path, e);
            std::collections::HashMap::new()
        }
    }
}

// ─── DryRunConfig (git diagnostics) ─────────────────────────────────────

/// Configuration for dry-run git diagnostics.
#[derive(Debug, Clone)]
pub struct DryRunConfig {
    pub token_source: String,
    pub token_len: usize,
    pub token_prefix: String,
    pub fork_exists: Option<bool>,
    pub api_auth_login: Option<String>,
    pub api_auth_valid: bool,
    pub refs_found: usize,
    pub repo_complete: bool,
}

impl DryRunConfig {
    pub fn new() -> Self {
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

    /// Resolve GitHub token from config or environment.
    pub fn resolve_tokens(config: &Config) -> (Option<String>, String) {
        let config_token = if !config.git.github_token.trim().is_empty() {
            Some(config.git.github_token.trim())
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
                println!("   effective token:          NONE — all git operations will be unauthenticated");
                println!("\n   ⚠  No token configured. Set github_token in config.yaml or GITHUB_TOKEN env var.");
                println!("      Create a token at https://github.com/settings/tokens");
            }
        }
        (effective_token, source.to_string())
    }

    /// Check if the user's fork exists on GitHub.
    pub async fn check_fork(
        &mut self,
        config: &Config,
        client: &reqwest::Client,
    ) -> anyhow::Result<()> {
        let username = &config.git.author;
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

    /// Check GitHub API authentication.
    pub async fn check_api_auth(
        &mut self,
        token: &str,
        client: &reqwest::Client,
    ) -> anyhow::Result<()> {
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
                    let text = resp
                        .text()
                        .await
                        .map_err(|e| anyhow::anyhow!("Failed to read /user response body: {e}"))?;
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

    /// Check git smart HTTP info/refs endpoint.
    pub async fn check_git_info_refs(
        &mut self,
        clone_url: &str,
        token: &str,
        client: &reqwest::Client,
    ) -> anyhow::Result<()> {
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
                    let bytes = resp
                        .bytes()
                        .await
                        .map_err(|e| anyhow::anyhow!("Failed to read info/refs response: {e}"))?;
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
                    let body = resp.text().await.ok().unwrap_or_default();
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

    /// Check local repository directory state.
    pub fn check_repo_state(&mut self) -> bool {
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

impl Default for DryRunConfig {
    fn default() -> Self {
        Self::new()
    }
}

/// Run git diagnostics in dry-run mode.
pub async fn dry_run_git(config: &Config) -> anyhow::Result<()> {
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

    let username = &config.git.author;
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn test_load_custom_mapping_missing_file() {
        let path = std::path::Path::new("/nonexistent/custom_channels_nonexistent.yaml");
        let result = load_custom_channel_mapping(path);
        assert!(
            result.is_empty(),
            "missing file should return empty HashMap"
        );
    }

    #[test]
    fn test_load_custom_mapping_valid_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("custom_channels.yaml");
        {
            let mut file = std::fs::File::create(&path).unwrap();
            writeln!(file, "channels:").unwrap();
            writeln!(file, "  'Custom-Channel/Operational': 'custom_service'").unwrap();
            writeln!(file, "  'Another-Channel': 'another_service'").unwrap();
        }
        let result = load_custom_channel_mapping(&path);
        assert_eq!(result.len(), 2);
        assert_eq!(
            result.get("Custom-Channel/Operational"),
            Some(&"custom_service".to_string())
        );
        assert_eq!(
            result.get("Another-Channel"),
            Some(&"another_service".to_string())
        );
    }

    #[test]
    fn test_load_custom_mapping_malformed_yaml() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("custom_channels.yaml");
        {
            let mut file = std::fs::File::create(&path).unwrap();
            writeln!(file, "channels: {{invalid yaml content<<<").unwrap();
        }
        let result = load_custom_channel_mapping(&path);
        assert!(
            result.is_empty(),
            "malformed YAML should return empty HashMap"
        );
    }

    #[test]
    fn test_load_custom_mapping_empty_yaml() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("custom_channels.yaml");
        std::fs::File::create(&path).unwrap();
        let result = load_custom_channel_mapping(&path);
        assert!(
            result.is_empty(),
            "empty YAML should return empty HashMap without warning"
        );
    }

    #[test]
    fn test_is_offline_default_false() {
        let cfg = GitConfig::default();
        assert!(!cfg.is_offline(), "offline must default to false");
    }

    #[test]
    fn test_is_contrib_default_false() {
        let cfg = GitConfig::default();
        assert!(!cfg.is_contrib(), "contrib must default to false");
    }

    #[test]
    fn test_is_offline_true_when_some_true() {
        let cfg = GitConfig {
            offline: Some(true),
            ..GitConfig::default()
        };
        assert!(cfg.is_offline());
    }

    #[test]
    fn test_is_contrib_true_when_some_true() {
        let cfg = GitConfig {
            contrib: Some(true),
            ..GitConfig::default()
        };
        assert!(cfg.is_contrib());
    }

    /// Fully offline + no contrib → no network needed (no token required).
    #[test]
    fn test_needs_network_false_fully_offline() {
        let cfg = GitConfig {
            offline: Some(true),
            contrib: Some(false),
            ..GitConfig::default()
        };
        assert!(!cfg.needs_network());
    }

    /// Default config pulls at startup → network needed.
    #[test]
    fn test_needs_network_true_default() {
        let cfg = GitConfig::default();
        assert!(cfg.needs_network());
    }

    /// `offline: true` + `contrib: true` still needs the network for the push.
    #[test]
    fn test_needs_network_true_offline_with_contrib() {
        let cfg = GitConfig {
            offline: Some(true),
            contrib: Some(true),
            ..GitConfig::default()
        };
        assert!(cfg.needs_network());
    }

    /// `--offline` / `--contrib` flags must override the parsed config.
    #[test]
    fn test_load_with_cli_applies_offline_and_contrib() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.yaml");
        {
            let mut file = std::fs::File::create(&path).unwrap();
            writeln!(file, "git:").unwrap();
            writeln!(file, "  author: my-user").unwrap();
            writeln!(file, "  email: me@example.com").unwrap();
            writeln!(file, "  github_token: ghp_token").unwrap();
        }
        let cli = CliArgs {
            offline: true,
            contrib: true,
            ..CliArgs::default()
        };
        let config = Config::load_with_cli(&path, &cli).unwrap();
        assert!(config.git.is_offline(), "CLI --offline must enable offline");
        assert!(config.git.is_contrib(), "CLI --contrib must enable contrib");
    }
}
