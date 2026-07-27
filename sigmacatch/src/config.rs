// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 sigmacatch contributors

use serde::{Deserialize, Serialize};
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;

/// Git transport protocol for clone/fetch/push operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum GitTransport {
    /// HTTPS with token auth (default). Uses `github_token` or `GITHUB_TOKEN` env var.
    #[default]
    Http,
    /// SSH with key-based auth. Uses `ssh_key_path` or default SSH agent.
    Ssh,
}

impl std::fmt::Display for GitTransport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            GitTransport::Http => write!(f, "http"),
            GitTransport::Ssh => write!(f, "ssh"),
        }
    }
}

/// Default SigmaHQ repository URL.
pub const DEFAULT_SIGMA_REPO_URL: &str = "https://github.com/SigmaHQ/sigma.git";

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
}

fn default_sigma_repo_url() -> String {
    DEFAULT_SIGMA_REPO_URL.to_string()
}

fn default_sigma_repo_path() -> String {
    "sigma".to_string()
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

/// Error parsing a MinStatus string.
#[derive(Debug, Clone)]
pub struct ParseMinStatusError(pub String);

impl std::fmt::Display for ParseMinStatusError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "unknown status '{}', expected: unsupported, deprecated, experimental, test, stable",
            self.0
        )
    }
}

impl std::error::Error for ParseMinStatusError {}

/// Error parsing a MinLevel string.
#[derive(Debug, Clone)]
pub struct ParseMinLevelError(pub String);

impl std::fmt::Display for ParseMinLevelError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "unknown level '{}', expected: informational, low, medium, high, critical",
            self.0
        )
    }
}

impl std::error::Error for ParseMinLevelError {}

/// Minimum Sigma rule status threshold (inclusive).
///
/// Rules with `status >= min_status` are loaded.
/// Hierarchy: unsupported < deprecated < experimental < test < stable.
/// Rules without a status field are always accepted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum MinStatus {
    Unsupported,
    Deprecated,
    Experimental,
    Test,
    Stable,
}

impl MinStatus {
    /// Returns ordinal value for comparison (0 = lowest, 4 = highest).
    pub fn ordinal(&self) -> u8 {
        match self {
            MinStatus::Unsupported => 0,
            MinStatus::Deprecated => 1,
            MinStatus::Experimental => 2,
            MinStatus::Test => 3,
            MinStatus::Stable => 4,
        }
    }

    /// Returns `true` if `rule_status` meets or exceeds this threshold.
    pub fn accepts(&self, rule_status: &rsigma_parser::Status) -> bool {
        MinStatus::from(rule_status).ordinal() >= self.ordinal()
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            MinStatus::Unsupported => "unsupported",
            MinStatus::Deprecated => "deprecated",
            MinStatus::Experimental => "experimental",
            MinStatus::Test => "test",
            MinStatus::Stable => "stable",
        }
    }
}

impl From<&rsigma_parser::Status> for MinStatus {
    fn from(s: &rsigma_parser::Status) -> Self {
        match s {
            rsigma_parser::Status::Unsupported => MinStatus::Unsupported,
            rsigma_parser::Status::Deprecated => MinStatus::Deprecated,
            rsigma_parser::Status::Experimental => MinStatus::Experimental,
            rsigma_parser::Status::Test => MinStatus::Test,
            rsigma_parser::Status::Stable => MinStatus::Stable,
        }
    }
}

impl std::fmt::Display for MinStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl std::str::FromStr for MinStatus {
    type Err = ParseMinStatusError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "unsupported" => Ok(MinStatus::Unsupported),
            "deprecated" => Ok(MinStatus::Deprecated),
            "experimental" => Ok(MinStatus::Experimental),
            "test" => Ok(MinStatus::Test),
            "stable" => Ok(MinStatus::Stable),
            _ => Err(ParseMinStatusError(s.to_string())),
        }
    }
}

/// Re-export Product from sigmacatch_types for rule filtering.
pub use sigmacatch_types::Product;

/// Minimum Sigma rule level threshold (inclusive).
///
/// Rules with `level >= min_level` are loaded.
/// Hierarchy: informational < low < medium < high < critical.
/// Rules without a level field are always accepted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum MinLevel {
    Informational,
    Low,
    Medium,
    High,
    Critical,
}

impl MinLevel {
    /// Returns ordinal value for comparison (0 = lowest, 4 = highest).
    pub fn ordinal(&self) -> u8 {
        match self {
            MinLevel::Informational => 0,
            MinLevel::Low => 1,
            MinLevel::Medium => 2,
            MinLevel::High => 3,
            MinLevel::Critical => 4,
        }
    }

    /// Returns `true` if `rule_level` meets or exceeds this threshold.
    pub fn accepts(&self, rule_level: &rsigma_parser::Level) -> bool {
        MinLevel::from(rule_level).ordinal() >= self.ordinal()
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            MinLevel::Informational => "informational",
            MinLevel::Low => "low",
            MinLevel::Medium => "medium",
            MinLevel::High => "high",
            MinLevel::Critical => "critical",
        }
    }
}

impl From<&rsigma_parser::Level> for MinLevel {
    fn from(l: &rsigma_parser::Level) -> Self {
        match l {
            rsigma_parser::Level::Informational => MinLevel::Informational,
            rsigma_parser::Level::Low => MinLevel::Low,
            rsigma_parser::Level::Medium => MinLevel::Medium,
            rsigma_parser::Level::High => MinLevel::High,
            rsigma_parser::Level::Critical => MinLevel::Critical,
        }
    }
}

impl std::fmt::Display for MinLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl std::str::FromStr for MinLevel {
    type Err = ParseMinLevelError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "informational" => Ok(MinLevel::Informational),
            "low" => Ok(MinLevel::Low),
            "medium" => Ok(MinLevel::Medium),
            "high" => Ok(MinLevel::High),
            "critical" => Ok(MinLevel::Critical),
            _ => Err(ParseMinLevelError(s.to_string())),
        }
    }
}

/// Configuration for rule loading filters.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct SigmaFilterConfig {
    /// Target product for rule filtering: windows, linux, or macos.
    pub product: Product,
    /// Minimum rule status (inclusive): unsupported < deprecated < experimental < test < stable.
    #[serde(default = "default_min_status")]
    pub min_status: MinStatus,
    /// Minimum rule level (inclusive): informational < low < medium < high < critical.
    #[serde(default = "default_min_level")]
    pub min_level: MinLevel,
    /// Maximum number of rules to load (0 = unlimited).
    #[serde(default = "default_max_rules")]
    pub max_rules: u64,
    /// Maximum size of a single rule file in bytes (default 1MB).
    #[serde(default = "default_max_rule_size")]
    pub max_rule_size: usize,
}

fn default_max_rules() -> u64 {
    0
}

fn default_max_rule_size() -> usize {
    1024 * 1024
}

fn default_min_status() -> MinStatus {
    MinStatus::Stable
}

fn default_min_level() -> MinLevel {
    MinLevel::Critical
}

impl Default for SigmaFilterConfig {
    fn default() -> Self {
        Self {
            product: Product::default(),
            min_status: default_min_status(),
            min_level: default_min_level(),
            max_rules: default_max_rules(),
            max_rule_size: default_max_rule_size(),
        }
    }
}

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
    pub sigma: SigmaFilterConfig,
    #[serde(default)]
    pub git: GitConfig,
}

impl Config {
    pub fn load(path: &PathBuf) -> anyhow::Result<Self> {
        if path.exists() {
            #[cfg(unix)]
            if let Ok(metadata) = std::fs::metadata(path) {
                let mode = metadata.permissions().mode() & 0o777;
                if mode != 0o600 {
                    eprintln!(
                        "⚠️  config.yaml has open permissions (0{:o}), fixing to 0600",
                        mode
                    );
                    if let Err(e) = std::fs::set_permissions(path, PermissionsExt::from_mode(0o600))
                    {
                        eprintln!("⚠️  Failed to fix config.yaml permissions: {}", e);
                    }
                }
            }
        }

        let yaml = std::fs::read_to_string(path)
            .map_err(|e| anyhow::anyhow!("Failed to read config file: {}", e))?;
        let config: Config = serde_yaml::from_str(&yaml)
            .map_err(|e| anyhow::anyhow!("Failed to parse config file: {}", e))?;

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
        if !self.git.author.is_empty()
            && self.git.author != "sigmacatch"
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
        // Validate SSH key path if configured
        if let Some(ref key_path) = self.git.ssh_key_path {
            if !key_path.is_empty() {
                let meta = std::fs::metadata(key_path).map_err(|e| {
                    anyhow::anyhow!("config: SSH key path '{}' does not exist: {}", key_path, e)
                })?;
                if !meta.is_file() {
                    anyhow::bail!("config: SSH key path '{}' is not a file", key_path);
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

        // Token is only required for HTTP transport
        if self.git.transport == GitTransport::Http {
            let has_config_token = !self.git.github_token.trim().is_empty();
            let has_env_token = std::env::var("GITHUB_TOKEN")
                .map(|t| !t.trim().is_empty())
                .unwrap_or(false);
            if !has_config_token && !has_env_token {
                anyhow::bail!(
                    "config: 'git.github_token' is required for HTTP transport. Set git.github_token in config.yaml or GITHUB_TOKEN env var. \
                     Create a token at https://github.com/settings/tokens"
                );
            }
            if has_config_token {
                let trimmed = self.git.github_token.trim();
                if trimmed.contains(char::is_whitespace) {
                    anyhow::bail!("config: 'git.github_token' contains whitespace — trim it");
                }
            }
        }

        if self.sigma.max_rules > 100000 {
            anyhow::bail!(
                "config: 'sigma.max_rules' exceeds maximum allowed value (100000), got {}",
                self.sigma.max_rules
            );
        }

        if self.sigma.max_rule_size < 1024 {
            anyhow::bail!(
                "config: 'sigma.max_rule_size' must be at least 1024 bytes, got {}",
                self.sigma.max_rule_size
            );
        }

        if self.sigma.max_rule_size > 10 * 1024 * 1024 {
            anyhow::bail!(
                "config: 'sigma.max_rule_size' exceeds maximum allowed value (10MB), got {}",
                self.sigma.max_rule_size
            );
        }

        // Validate sigma_repo_path — reject path traversal and absolute paths
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
        if std::path::Path::new(&self.git.sigma_repo_path).is_absolute() {
            anyhow::bail!(
                "config: 'git.sigma_repo_path' must be a relative path, got {:?}",
                self.git.sigma_repo_path
            );
        }

        if self.sigma.min_status.ordinal() >= MinStatus::Stable.ordinal() {
            tracing::warn!(
                "sigma.min_status = {} — very restrictive, only stable rules will be loaded",
                self.sigma.min_status
            );
        }
        if self.sigma.min_level.ordinal() >= MinLevel::High.ordinal() {
            tracing::warn!(
                "sigma.min_level = {} — very restrictive, only {} and higher rules will be loaded",
                self.sigma.min_level,
                self.sigma.min_level
            );
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config_has_default_author() {
        let config = Config::default();
        assert_eq!(config.git.author, "sigmacatch");
    }

    #[test]
    fn test_default_config_has_default_email() {
        let config = Config::default();
        assert!(config.git.email.is_empty());
    }

    #[test]
    fn test_load_config_minimal() {
        let yaml = r#"
git:
  author: testuser
  email: user@example.com
log:
  level_file: debug
"#;
        let config: Config = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(config.git.author, "testuser");
        assert_eq!(config.git.email, "user@example.com");
    }

    #[test]
    fn test_deny_unknown_fields() {
        let yaml = r#"
git:
  author: testuser
  email: user@example.com
unknown_field: oops
log:
  level_file: debug
"#;
        let result: Result<Config, _> = serde_yaml::from_str(yaml);
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_invalid_author_chars() {
        let config = Config {
            log: LogConfig::default(),
            sigma: SigmaFilterConfig::default(),
            git: GitConfig {
                author: "user space".to_string(),
                email: "user@example.com".to_string(),
                github_token: String::new(),
                ..GitConfig::default()
            },
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_validate_email_required() {
        let config = Config {
            log: LogConfig::default(),
            sigma: SigmaFilterConfig::default(),
            git: GitConfig {
                author: "validuser".to_string(),
                email: String::new(),
                github_token: String::new(),
                ..GitConfig::default()
            },
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_validate_invalid_email() {
        let config = Config {
            log: LogConfig::default(),
            sigma: SigmaFilterConfig::default(),
            git: GitConfig {
                author: "validuser".to_string(),
                email: "notanemail".to_string(),
                github_token: String::new(),
                ..GitConfig::default()
            },
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_validate_valid_config() {
        let config = Config {
            log: LogConfig::default(),
            sigma: SigmaFilterConfig::default(),
            git: GitConfig {
                author: "valid-user".to_string(),
                email: "user@example.com".to_string(),
                github_token: "ghp_validtoken123".to_string(),
                ..GitConfig::default()
            },
        };
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_save_and_load_config() {
        let config = Config {
            log: LogConfig::default(),
            sigma: SigmaFilterConfig::default(),
            git: GitConfig {
                author: "devuser".to_string(),
                email: "dev@example.com".to_string(),
                github_token: String::new(),
                ..GitConfig::default()
            },
        };
        let yaml = serde_yaml::to_string(&config).unwrap();
        let loaded: Config = serde_yaml::from_str(&yaml).unwrap();
        assert_eq!(loaded.git.author, "devuser");
        assert_eq!(loaded.git.email, "dev@example.com");
        assert_eq!(loaded.git.github_token, "");
    }

    #[test]
    fn test_min_status_round_trip_via_serde_display_fromstr() {
        let variants = [
            MinStatus::Unsupported,
            MinStatus::Deprecated,
            MinStatus::Experimental,
            MinStatus::Test,
            MinStatus::Stable,
        ];
        for v in &variants {
            let display = v.to_string();
            let parsed: MinStatus = display.parse().unwrap();
            assert_eq!(&parsed, v, "round-trip failed for {:?}", v);
            let ser = serde_yaml::to_string(v).unwrap();
            let deser: MinStatus = serde_yaml::from_str(&ser).unwrap();
            assert_eq!(deser, *v, "serde round-trip failed for {:?}", v);
        }
    }

    #[test]
    fn test_min_level_round_trip_via_serde_display_fromstr() {
        let variants = [
            MinLevel::Informational,
            MinLevel::Low,
            MinLevel::Medium,
            MinLevel::High,
            MinLevel::Critical,
        ];
        for v in &variants {
            let display = v.to_string();
            let parsed: MinLevel = display.parse().unwrap();
            assert_eq!(&parsed, v, "round-trip failed for {:?}", v);
            let ser = serde_yaml::to_string(v).unwrap();
            let deser: MinLevel = serde_yaml::from_str(&ser).unwrap();
            assert_eq!(deser, *v, "serde round-trip failed for {:?}", v);
        }
    }

    #[test]
    fn test_config_default_product() {
        let config = Config::default();
        assert_eq!(config.sigma.product, Product::Windows);
    }

    #[test]
    fn test_config_load_product_linux() {
        let yaml = r#"
sigma:
  product: linux
git:
  author: testuser
  email: user@example.com
log:
  level_file: debug
"#;
        let config: Config = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(config.sigma.product, Product::Linux);
    }

    #[test]
    fn test_config_load_product_macos() {
        let yaml = r#"
sigma:
  product: macos
git:
  author: testuser
  email: user@example.com
log:
  level_file: debug
"#;
        let config: Config = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(config.sigma.product, Product::Macos);
    }

    #[test]
    fn test_config_invalid_product() {
        let yaml = r#"
sigma:
  product: invalid
git:
  author: testuser
  email: user@example.com
log:
  level_file: debug
"#;
        let result: Result<Config, _> = serde_yaml::from_str(yaml);
        assert!(result.is_err()); // serde rejects it — field is typed Product enum
    }

    #[test]
    fn test_config_load_repo_url_and_path() {
        let yaml = r#"
sigma:
  product: windows
git:
  author: testuser
  email: user@example.com
  sigma_repo_url: https://github.com/custom/sigma.git
  sigma_repo_path: /opt/sigma/
log:
  level_file: debug
"#;
        let config: Config = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(
            config.git.sigma_repo_url,
            "https://github.com/custom/sigma.git"
        );
        assert_eq!(config.git.sigma_repo_path, "/opt/sigma/");
    }

    #[test]
    fn test_config_default_repo_url() {
        let yaml = r#"
sigma:
  product: windows
git:
  author: testuser
  email: user@example.com
log:
  level_file: debug
"#;
        let config: Config = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(
            config.git.sigma_repo_url,
            "https://github.com/SigmaHQ/sigma.git"
        );
        assert_eq!(config.git.sigma_repo_path, "sigma");
    }

    #[test]
    fn test_config_validate_path_traversal() {
        let config = Config {
            log: LogConfig::default(),
            sigma: SigmaFilterConfig::default(),
            git: GitConfig {
                author: "testuser".to_string(),
                email: "user@example.com".to_string(),
                sigma_repo_path: "../escape".to_string(),
                ..GitConfig::default()
            },
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_config_validate_path_traversal_dot_slash() {
        let config = Config {
            log: LogConfig::default(),
            sigma: SigmaFilterConfig::default(),
            git: GitConfig {
                author: "testuser".to_string(),
                email: "user@example.com".to_string(),
                sigma_repo_path: "././../escape".to_string(),
                ..GitConfig::default()
            },
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_config_max_rules_too_high() {
        let config = Config {
            log: LogConfig::default(),
            sigma: SigmaFilterConfig {
                max_rules: 200000,
                ..SigmaFilterConfig::default()
            },
            git: GitConfig {
                author: "testuser".to_string(),
                email: "user@example.com".to_string(),
                ..GitConfig::default()
            },
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_config_max_rule_size_too_small() {
        let config = Config {
            log: LogConfig::default(),
            sigma: SigmaFilterConfig {
                max_rule_size: 512,
                ..SigmaFilterConfig::default()
            },
            git: GitConfig {
                author: "testuser".to_string(),
                email: "user@example.com".to_string(),
                ..GitConfig::default()
            },
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_config_max_rule_size_too_large() {
        let config = Config {
            log: LogConfig::default(),
            sigma: SigmaFilterConfig {
                max_rule_size: 20 * 1024 * 1024,
                ..SigmaFilterConfig::default()
            },
            git: GitConfig {
                author: "testuser".to_string(),
                email: "user@example.com".to_string(),
                ..GitConfig::default()
            },
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_config_load_with_max_rules() {
        let yaml = r#"
sigma:
  product: windows
  max_rules: 10000
  max_rule_size: 2097152
git:
  author: testuser
  email: user@example.com
  transport: ssh
log:
  level_file: debug
"#;
        let config: Config = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(config.sigma.max_rules, 10000);
        assert_eq!(config.sigma.max_rule_size, 2097152);
        assert!(config.validate().is_ok());
    }
}
