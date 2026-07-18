// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 sigmacatch contributors

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

fn default_author() -> String {
    "sigmacatch".to_string()
}

fn default_email() -> String {
    String::new()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LogLevel {
    Debug,
    Info,
    Warn,
    Error,
}

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
    pub fn ordinal(&self) -> u8 {
        match self {
            MinStatus::Unsupported => 0,
            MinStatus::Deprecated => 1,
            MinStatus::Experimental => 2,
            MinStatus::Test => 3,
            MinStatus::Stable => 4,
        }
    }

    pub fn accepts(&self, rule_status: &rsigma_parser::Status) -> bool {
        let rule_ord = match rule_status {
            rsigma_parser::Status::Unsupported => 0,
            rsigma_parser::Status::Deprecated => 1,
            rsigma_parser::Status::Experimental => 2,
            rsigma_parser::Status::Test => 3,
            rsigma_parser::Status::Stable => 4,
        };
        rule_ord >= self.ordinal()
    }
}

impl std::fmt::Display for MinStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MinStatus::Unsupported => write!(f, "unsupported"),
            MinStatus::Deprecated => write!(f, "deprecated"),
            MinStatus::Experimental => write!(f, "experimental"),
            MinStatus::Test => write!(f, "test"),
            MinStatus::Stable => write!(f, "stable"),
        }
    }
}

impl std::str::FromStr for MinStatus {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "unsupported" => Ok(MinStatus::Unsupported),
            "deprecated" => Ok(MinStatus::Deprecated),
            "experimental" => Ok(MinStatus::Experimental),
            "test" => Ok(MinStatus::Test),
            "stable" => Ok(MinStatus::Stable),
            _ => Err(format!(
                "unknown status '{}', expected: unsupported, deprecated, experimental, test, stable",
                s
            )),
        }
    }
}

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
    pub fn ordinal(&self) -> u8 {
        match self {
            MinLevel::Informational => 0,
            MinLevel::Low => 1,
            MinLevel::Medium => 2,
            MinLevel::High => 3,
            MinLevel::Critical => 4,
        }
    }

    pub fn accepts(&self, rule_level: &rsigma_parser::Level) -> bool {
        let rule_ord = match rule_level {
            rsigma_parser::Level::Informational => 0,
            rsigma_parser::Level::Low => 1,
            rsigma_parser::Level::Medium => 2,
            rsigma_parser::Level::High => 3,
            rsigma_parser::Level::Critical => 4,
        };
        rule_ord >= self.ordinal()
    }
}

impl std::fmt::Display for MinLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MinLevel::Informational => write!(f, "informational"),
            MinLevel::Low => write!(f, "low"),
            MinLevel::Medium => write!(f, "medium"),
            MinLevel::High => write!(f, "high"),
            MinLevel::Critical => write!(f, "critical"),
        }
    }
}

impl std::str::FromStr for MinLevel {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "informational" => Ok(MinLevel::Informational),
            "low" => Ok(MinLevel::Low),
            "medium" => Ok(MinLevel::Medium),
            "high" => Ok(MinLevel::High),
            "critical" => Ok(MinLevel::Critical),
            _ => Err(format!(
                "unknown level '{}', expected: informational, low, medium, high, critical",
                s
            )),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct SigmaFilterConfig {
    pub min_status: MinStatus,
    pub min_level: MinLevel,
}

impl Default for SigmaFilterConfig {
    fn default() -> Self {
        Self {
            min_status: MinStatus::Stable,
            min_level: MinLevel::Critical,
        }
    }
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

#[derive(Debug, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct LogConfig {
    pub level_file: LogLevel,
}

impl Default for LogConfig {
    fn default() -> Self {
        Self {
            level_file: LogLevel::Info,
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    #[serde(default = "default_author")]
    pub author: String,
    #[serde(default = "default_email")]
    pub email: String,
    #[serde(default)]
    pub github_token: String,
    pub log: LogConfig,
    #[serde(default)]
    pub sigma: SigmaFilterConfig,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            author: default_author(),
            email: default_email(),
            github_token: String::new(),
            log: LogConfig::default(),
            sigma: SigmaFilterConfig::default(),
        }
    }
}

impl Config {
    pub fn load(path: &PathBuf) -> anyhow::Result<Self> {
        if path.exists() {
            let content = std::fs::read_to_string(path)?;
            let config: Config = serde_yaml::from_str(&content)?;
            config.validate()?;
            Ok(config)
        } else {
            let config = Self::default();
            let yaml = serde_yaml::to_string(&config)?;
            std::fs::write(path, &yaml)?;
            tracing::info!("Created default config file at {:?}", path);
            Ok(config)
        }
    }

    pub fn validate(&self) -> anyhow::Result<()> {
        if !self.author.is_empty()
            && self.author != "sigmacatch"
            && !self
                .author
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-')
        {
            anyhow::bail!(
                "config: 'author' must be a valid GitHub username (alphanumeric + hyphens), got {:?}",
                self.author
            );
        }
        if self.email.is_empty() {
            anyhow::bail!("config: 'email' is required");
        }
        if !self.email.contains('@') {
            anyhow::bail!("config: 'email' must contain '@', got {:?}", self.email);
        }
        let has_config_token = !self.github_token.trim().is_empty();
        let has_env_token = std::env::var("GITHUB_TOKEN")
            .map(|t| !t.trim().is_empty())
            .unwrap_or(false);
        if !has_config_token && !has_env_token {
            anyhow::bail!(
                "config: 'github_token' is required. Set github_token in config.yaml or GITHUB_TOKEN env var. \
                 Create a token at https://github.com/settings/tokens"
            );
        }
        if has_config_token {
            let trimmed = self.github_token.trim();
            if trimmed.contains(char::is_whitespace) {
                anyhow::bail!("config: 'github_token' contains whitespace — trim it");
            }
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
        assert_eq!(config.author, "sigmacatch");
    }

    #[test]
    fn test_default_config_has_default_email() {
        let config = Config::default();
        assert!(config.email.is_empty());
    }

    #[test]
    fn test_load_config_minimal() {
        let yaml = r#"
author: testuser
email: user@example.com
log:
  level_file: debug
"#;
        let config: Config = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(config.author, "testuser");
        assert_eq!(config.email, "user@example.com");
    }

    #[test]
    fn test_deny_unknown_fields() {
        let yaml = r#"
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
            author: "user space".to_string(),
            email: "user@example.com".to_string(),
            github_token: String::new(),
            log: LogConfig::default(),
            sigma: SigmaFilterConfig::default(),
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_validate_email_required() {
        let config = Config {
            author: "validuser".to_string(),
            email: String::new(),
            github_token: String::new(),
            log: LogConfig::default(),
            sigma: SigmaFilterConfig::default(),
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_validate_invalid_email() {
        let config = Config {
            author: "validuser".to_string(),
            email: "notanemail".to_string(),
            github_token: String::new(),
            log: LogConfig::default(),
            sigma: SigmaFilterConfig::default(),
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_validate_valid_config() {
        let config = Config {
            author: "valid-user".to_string(),
            email: "user@example.com".to_string(),
            github_token: "ghp_validtoken123".to_string(),
            log: LogConfig::default(),
            sigma: SigmaFilterConfig::default(),
        };
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_save_and_load_config() {
        let config = Config {
            author: "devuser".to_string(),
            email: "dev@example.com".to_string(),
            github_token: String::new(),
            log: LogConfig::default(),
            sigma: SigmaFilterConfig::default(),
        };
        let yaml = serde_yaml::to_string(&config).unwrap();
        let loaded: Config = serde_yaml::from_str(&yaml).unwrap();
        assert_eq!(loaded.author, "devuser");
        assert_eq!(loaded.email, "dev@example.com");
        assert_eq!(loaded.github_token, "");
    }
}
