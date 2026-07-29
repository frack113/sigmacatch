// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 sigmacatch contributors

//! Application configuration types and loading.

use serde::{Deserialize, Serialize};
use sigmacatch_repo::DEFAULT_SIGMA_REPO_URL;
use sigmacatch_rule::{MinLevel, MinStatus};
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

/// Re-export Product from sigmacatch_types for rule filtering.
pub use sigmacatch_types::Product;

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

        if self.sigma.min_status >= MinStatus::Stable {
            tracing::warn!(
                "sigma.min_status = {} — very restrictive, only stable rules will be loaded",
                self.sigma.min_status
            );
        }
        if self.sigma.min_level >= MinLevel::High {
            tracing::warn!(
                "sigma.min_level = {} — very restrictive, only {} and higher rules will be loaded",
                self.sigma.min_level,
                self.sigma.min_level
            );
        }
        Ok(())
    }
}

/// Custom channel mappings from custom_channels.yaml.
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct CustomChannels {
    pub channels: std::collections::HashMap<String, String>,
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
}
