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

/// Errors produced by loading, saving or validating `config.yaml`.
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    /// Filesystem failure while reading, writing or chmod'ing config.yaml.
    #[error("config.yaml filesystem error: {0}")]
    Io(#[from] std::io::Error),
    /// YAML could not be parsed or serialized.
    #[error("config.yaml format error: {0}")]
    Format(String),
    /// A validation rule rejected the configuration.
    #[error("{0}")]
    Invalid(String),
}

/// Crate-local result alias over [`ConfigError`].
pub type Result<T> = std::result::Result<T, ConfigError>;

/// Git transport configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
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
    /// Enable offline mode: skip all git operations (no pull/fetch/checkout/
    /// commit/push). On-disk files are used as-is; `.git` is not required.
    /// Default: false (pull enabled). Set to true for air-gapped environments.
    #[serde(default)]
    pub offline: Option<bool>,
    /// Enable contrib workflow: push commits to remote fork.
    /// Default: false (no push, local commits only). Set to true to contribute.
    /// Neutralized (forced to false) when offline is enabled.
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
    /// Returns true if offline mode is enabled (all git operations skipped).
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
            offline: None,
            contrib: None,
        }
    }
}

/// Log verbosity levels accepted in `config.yaml`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LogLevel {
    /// Verbose tracing output (file log level).
    Debug,
    /// Informational lifecycle messages.
    Info,
    /// Recoverable issues worth surfacing.
    Warn,
    /// Errors only (default stderr level).
    Error,
}

impl LogLevel {
    /// Lowercase config spelling of the level.
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
#[serde(default, deny_unknown_fields)]
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

/// Regression generation configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct RegressionConfig {
    /// Number of consecutive failed cycles after which a rule is blocked
    /// (logged, removed from the skip-set, no more re-capture). Default: 3.
    #[serde(default = "default_max_failed_cycles")]
    pub max_failed_cycles: u32,
    /// Write the auxiliary `<rule_id>.json` next to the data file
    /// (`.evtx`/`.log`). The data file + info.yml are always written.
    /// Default: false.
    #[serde(default)]
    pub add_json_output: bool,
}

fn default_max_failed_cycles() -> u32 {
    3
}

impl Default for RegressionConfig {
    fn default() -> Self {
        Self {
            max_failed_cycles: default_max_failed_cycles(),
            add_json_output: false,
        }
    }
}

/// Main application configuration.
/// Root configuration document (`config.yaml`).
#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    /// Logging setup (levels, file rotation).
    pub log: LogConfig,
    /// Rule-loading filters.
    #[serde(default)]
    pub filter: SigmaFilterConfig,
    /// Git/fork/contrib behaviour.
    #[serde(default)]
    pub git: GitConfig,
    /// Event collection backend: `winevt` (default) or `etw`.
    #[serde(default)]
    pub regression: RegressionConfig,
}

impl Config {
    fn load_unvalidated(path: &PathBuf) -> Result<Self> {
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

        let yaml = std::fs::read_to_string(path)?;
        serde_yaml::from_str(&yaml).map_err(|e| ConfigError::Format(e.to_string()))
    }

    /// Load, normalize and validate a config file.
    pub fn load(path: &PathBuf) -> Result<Self> {
        let mut config = Self::load_unvalidated(path)?;
        config.normalize_git();
        config.validate()?;
        Ok(config)
    }

    /// Load with CLI overrides applied on top of file values.
    pub fn load_with_cli(path: &PathBuf, cli: &CliArgs) -> Result<Self> {
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
        config.normalize_git();
        config.validate()?;
        Ok(config)
    }

    /// Fully offline mode wins over contrib: force `contrib = false` so a run
    /// with `offline: true` can never attempt a network push. Emitted on stderr
    /// (not `tracing`) because this runs before the logger subscriber exists.
    fn normalize_git(&mut self) {
        if self.git.is_offline() && self.git.is_contrib() {
            eprintln!(
                "⚠️  config: 'git.contrib' is ignored because 'git.offline' is enabled — no push will be attempted"
            );
            self.git.contrib = Some(false);
        }
    }

    /// Write the config back as YAML with 0600 permissions.
    pub fn save(&self, path: &PathBuf) -> Result<()> {
        let yaml = serde_yaml::to_string(self).map_err(|e| ConfigError::Format(e.to_string()))?;

        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        std::fs::write(path, yaml)?;

        #[cfg(unix)]
        std::fs::set_permissions(path, PermissionsExt::from_mode(0o600))?;

        Ok(())
    }

    /// Reject placeholder/inconsistent values before first run.
    pub fn validate(&self) -> Result<()> {
        if self.git.author == "sigmacatch" {
            return Err(ConfigError::Invalid(
                "config: 'git.author' is the placeholder 'sigmacatch'. \
                 Set 'author' to your GitHub username in config.yaml"
                    .to_string(),
            ));
        }
        if !self.git.author.is_empty()
            && !self
                .git
                .author
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-')
        {
            return Err(ConfigError::Invalid(format!(
                "config: 'git.author' must be a valid GitHub username (alphanumeric + hyphens), got {:?}",
                self.git.author
            )));
        }
        if self.git.email.is_empty() {
            return Err(ConfigError::Invalid(
                "config: 'git.email' is required".to_string(),
            ));
        }
        if !self.git.email.contains('@') {
            return Err(ConfigError::Invalid(format!(
                "config: 'git.email' must contain '@', got {:?}",
                self.git.email
            )));
        }
        // Validate SSH key path if configured. Skipped offline: no network op
        // can use the key, so a stale path must not block an offline startup.
        if self.git.needs_network()
            && let Some(ref key_path) = self.git.ssh_key_path
            && !key_path.is_empty()
        {
            let path = std::path::Path::new(key_path);
            if !path.is_absolute() {
                return Err(ConfigError::Invalid(format!(
                    "config: SSH key path '{}' is not absolute (transport={}); \
                             use a full path like /home/user/.ssh/id or C:\\Users\\user\\.ssh\\id",
                    key_path, self.git.transport
                )));
            }
            let meta = std::fs::metadata(key_path).map_err(|_| {
                ConfigError::Invalid(format!(
                    "config: SSH key path '{}' does not exist (transport={}); \
                             remove ssh_key_path from config or switch to transport = http",
                    key_path, self.git.transport
                ))
            })?;
            if !meta.is_file() {
                return Err(ConfigError::Invalid(format!(
                    "config: SSH key path '{}' is not a file (transport={}); \
                             remove ssh_key_path from config or switch to transport = http",
                    key_path, self.git.transport
                )));
            }
            #[cfg(unix)]
            {
                let mode = meta.permissions().mode() & 0o777;
                if mode & 0o077 != 0 {
                    // Pre-logger warning: validate() runs before init_logger,
                    // so tracing events would be dropped here.
                    eprintln!(
                        "WARNING: config: SSH key '{}' has overly permissive mode 0{:o} — should be 0600. \
                         SSH may refuse to use it. Run: chmod 600 {}",
                        key_path, mode, key_path
                    );
                }
                // Also check that the key is readable by the current user
                if mode & 0o400 == 0 {
                    eprintln!(
                        "WARNING: config: SSH key '{}' is not readable by the owner (mode 0{:o}). \
                         SSH will reject it. Run: chmod 400 {}",
                        key_path, mode, key_path
                    );
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
                return Err(ConfigError::Invalid("config: 'git.github_token' is required for HTTP transport when offline=false or contrib=true. \
                     Set git.github_token in config.yaml or GITHUB_TOKEN env var. \
                     Create a token at https://github.com/settings/tokens. \
                     Alternatively, set offline: true and contrib: false for fully offline mode (no network).".to_string()));
            }
            if has_config_token {
                let trimmed = self.git.github_token.trim();
                if trimmed.contains(char::is_whitespace) {
                    return Err(ConfigError::Invalid(
                        "config: 'git.github_token' contains whitespace — trim it".to_string(),
                    ));
                }
            }
        }

        if self.filter.max_rule_size < 1024 {
            return Err(ConfigError::Invalid(format!(
                "config: 'filter.max_rule_size' must be at least 1024 bytes, got {}",
                self.filter.max_rule_size
            )));
        }

        if self.filter.max_rule_size > 10 * 1024 * 1024 {
            return Err(ConfigError::Invalid(format!(
                "config: 'filter.max_rule_size' exceeds maximum allowed value (10MB), got {}",
                self.filter.max_rule_size
            )));
        }

        if self.regression.max_failed_cycles < 1 {
            return Err(ConfigError::Invalid(format!(
                "config: 'regression.max_failed_cycles' must be at least 1, got {}",
                self.regression.max_failed_cycles
            )));
        }

        // Validate sigma_repo_path — reject empty, path traversal, and absolute paths
        if self.git.sigma_repo_path.trim().is_empty() {
            return Err(ConfigError::Invalid(format!(
                "config: 'git.sigma_repo_path' must not be empty, got {:?}",
                self.git.sigma_repo_path
            )));
        }
        if std::path::Path::new(&self.git.sigma_repo_path)
            .components()
            .any(|c| c == std::path::Component::ParentDir)
        {
            return Err(ConfigError::Invalid(format!(
                "config: 'git.sigma_repo_path' contains '..' path traversal, got {:?}",
                self.git.sigma_repo_path
            )));
        }
        if std::path::Path::new(&self.git.sigma_repo_path).is_absolute() {
            return Err(ConfigError::Invalid(format!(
                "config: 'git.sigma_repo_path' must be a relative path, got {:?}",
                self.git.sigma_repo_path
            )));
        }

        if let Some(status) = self
            .filter
            .min_status
            .as_ref()
            .filter(|s| **s >= MinStatus(Status::Stable))
        {
            // Pre-logger warning: validate() runs before init_logger.
            eprintln!(
                "WARNING: filter.min_status = {status} — very restrictive, only stable rules will be loaded"
            );
        }
        if let Some(level) = self
            .filter
            .min_level
            .as_ref()
            .filter(|l| **l >= MinLevel(Level::High))
        {
            eprintln!(
                "WARNING: filter.min_level = {level} — very restrictive, only {level} and higher rules will be loaded"
            );
        }
        Ok(())
    }

    /// Ensure required directories exist.
    pub fn ensure_dirs(&self) -> Result<()> {
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
    /// channel name → custom channel override.
    pub channels: std::collections::HashMap<String, String>,
}

/// Parsed CLI arguments.
#[derive(Debug, Clone, Default)]
pub struct CliArgs {
    /// `--author`: override git author for this run.
    pub author: Option<String>,
    /// `-a/--all-rules`: skip nothing, even rules with existing data.
    pub all_rules: bool,
    /// `-o/--offline`: no git operations at all.
    pub offline: bool,
    /// `-c/--contrib`: enable push to the fork.
    pub contrib: bool,
    /// `-v/--verbose`: raise stderr log level to info.
    pub verbose: bool,
    /// Maximum number of collection cycles before auto-exit (0 = unlimited).
    pub max_runs: Option<u32>,
}

const HELP: &str = "\
sigmacatch — Sigma regression data generator

USAGE:
    sigmacatch [OPTIONS]

FLAGS:
    -a, --all-rules    Load all rules (skip those with existing regression data)
    -c, --contrib      Enable push to remote fork (neutralized by --offline)
    -o, --offline      Skip all git operations (use on-disk files as-is, no commit/push)
    -r, --max-runs <N> Exit after N collection cycles (0 = unlimited)
    -v, --verbose      Enable verbose logging (info level on stderr)
    --help             Print this help and exit

OPTIONS:
    --author <NAME>           Override GitHub username from config.yaml
";

/// Parse CLI arguments from environment.
pub fn parse_args() -> CliArgs {
    let args: Vec<String> = std::env::args().collect();
    parse_args_from(&args)
}

/// Core argument parsing over an explicit argv (`args[0]` = program name).
fn parse_args_from(args: &[String]) -> CliArgs {
    for arg in args {
        if arg == "--help" || arg == "-h" {
            print!("{HELP}");
            std::process::exit(0);
        }
    }
    let mut author = None;
    let mut all_rules = false;
    let mut offline = false;
    let mut contrib = false;
    let mut verbose = false;
    let mut max_runs: Option<u32> = None;
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--author" => {
                i += 1;
                match args.get(i) {
                    Some(v) if !v.starts_with('-') => author = Some(v.clone()),
                    _ => {
                        eprintln!("Error: --author requires a value");
                        std::process::exit(1);
                    }
                }
            }
            "-a" | "--all-rules" => all_rules = true,
            "-c" | "--contrib" => contrib = true,
            "-o" | "--offline" => offline = true,
            "-r" | "--max-runs" => {
                i += 1;
                if let Some(n) = args.get(i) {
                    match n.parse::<u32>() {
                        // 0 = unlimited (documented in --help): mapped to no limit.
                        Ok(v) if v > 0 => max_runs = Some(v),
                        Ok(_) => max_runs = None,
                        Err(_) => {
                            eprintln!("Error: --max-runs requires a numeric value");
                            std::process::exit(1);
                        }
                    }
                } else {
                    eprintln!("Error: --max-runs requires a value");
                    std::process::exit(1);
                }
            }
            "-v" | "--verbose" => verbose = true,
            unknown => {
                eprintln!("Error: unknown flag `{}`", unknown);
                std::process::exit(1);
            }
        }
        i += 1;
    }
    CliArgs {
        author,
        all_rules,
        offline,
        contrib,
        verbose,
        max_runs,
    }
}

#[cfg(test)]
mod cli_tests {
    use super::*;

    fn args(list: &[&str]) -> Vec<String> {
        std::iter::once("sigmacatch")
            .chain(list.iter().copied())
            .map(String::from)
            .collect()
    }

    #[test]
    fn test_parse_author_takes_next_token() {
        let parsed = parse_args_from(&args(&["--author", "frack113"]));
        assert_eq!(parsed.author.as_deref(), Some("frack113"));
    }

    #[test]
    fn test_parse_max_runs_zero_means_unlimited() {
        let parsed = parse_args_from(&args(&["-r", "0"]));
        assert_eq!(parsed.max_runs, None);
    }

    #[test]
    fn test_parse_max_runs_positive() {
        let parsed = parse_args_from(&args(&["--max-runs", "3"]));
        assert_eq!(parsed.max_runs, Some(3));
    }

    #[test]
    fn test_parse_flags_combined() {
        let parsed = parse_args_from(&args(&["-a", "-c", "-o", "-v", "--author", "bob"]));
        assert!(parsed.all_rules);
        assert!(parsed.contrib);
        assert!(parsed.offline);
        assert!(parsed.verbose);
        assert_eq!(parsed.author.as_deref(), Some("bob"));
        assert_eq!(parsed.max_runs, None);
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

    /// The predicate stays defensive: if a raw `GitConfig` somehow carries both
    /// flags (normalization already forces `contrib = false` at `Config` level),
    /// the push would still need the network.
    #[test]
    fn test_needs_network_true_offline_with_contrib() {
        let cfg = GitConfig {
            offline: Some(true),
            contrib: Some(true),
            ..GitConfig::default()
        };
        assert!(cfg.needs_network());
    }

    /// `--offline` / `--contrib` flags must override the parsed config, and
    /// offline wins over contrib (normalized to `false`).
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
        assert!(
            !config.git.is_contrib(),
            "offline must normalize contrib to false"
        );
    }

    /// `--contrib` alone (no `--offline`) must enable contrib.
    #[test]
    fn test_load_with_cli_contrib_only_enables_contrib() {
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
            offline: false,
            contrib: true,
            ..CliArgs::default()
        };
        let config = Config::load_with_cli(&path, &cli).unwrap();
        assert!(!config.git.is_offline());
        assert!(config.git.is_contrib(), "CLI --contrib must enable contrib");
    }

    /// `offline: true` + `contrib: true` in config.yaml is accepted but contrib
    /// is normalized to `false` (offline wins).
    #[test]
    fn test_load_offline_and_contrib_from_yaml_normalizes() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.yaml");
        {
            let mut file = std::fs::File::create(&path).unwrap();
            writeln!(file, "git:").unwrap();
            writeln!(file, "  author: my-user").unwrap();
            writeln!(file, "  email: me@example.com").unwrap();
            writeln!(file, "  offline: true").unwrap();
            writeln!(file, "  contrib: true").unwrap();
        }
        let config = Config::load(&path).unwrap();
        assert!(config.git.is_offline());
        assert!(
            !config.git.is_contrib(),
            "offline must normalize contrib to false"
        );
        assert!(
            !config.git.needs_network(),
            "normalized offline config must not need the network"
        );
    }
}
