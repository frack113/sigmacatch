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

/// Sigma rule filter configuration (status and level thresholds).
///
/// Applied during rule loading to exclude rules below configured thresholds.
/// Rules missing a status or level field are always accepted (pass-through).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct SigmaFilterConfig {
    /// Minimum status threshold (default: stable). Only rules with `status >= min_status` are loaded.
    pub min_status: MinStatus,
    /// Minimum level threshold (default: critical). Only rules with `level >= min_level` are loaded.
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

            let has_sigma = serde_yaml::from_str::<serde_yaml::Value>(&content)
                .ok()
                .is_some_and(|v| v.get("sigma").is_some());

            let config: Config = serde_yaml::from_str(&content)?;

            if !has_sigma {
                eprintln!(
                    "⚠️  config.yaml missing 'sigma' section — using defaults: min_status={}, min_level={}",
                    config.sigma.min_status,
                    config.sigma.min_level,
                );

                if let Ok(mut doc) = serde_yaml::from_str::<serde_yaml::Value>(&content) {
                    if let serde_yaml::Value::Mapping(ref mut map) = doc {
                        if let Ok(sigma_val) = serde_yaml::to_value(SigmaFilterConfig::default()) {
                            map.insert(serde_yaml::Value::String("sigma".to_string()), sigma_val);
                            if let Ok(new_yaml) = serde_yaml::to_string(&doc) {
                                let _ = std::fs::write(path, &new_yaml);
                                eprintln!("   ✓ Fixed: added default sigma section to config.yaml — next run will be clean");
                            }
                        }
                    }
                }
            }

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
    fn test_min_status_accepts_ordering() {
        let filter = SigmaFilterConfig {
            min_status: MinStatus::Test,
            min_level: MinLevel::Informational,
        };
        assert!(filter.min_status.accepts(&rsigma_parser::Status::Test));
        assert!(filter.min_status.accepts(&rsigma_parser::Status::Stable));
        assert!(!filter
            .min_status
            .accepts(&rsigma_parser::Status::Experimental));
        assert!(!filter
            .min_status
            .accepts(&rsigma_parser::Status::Deprecated));
        assert!(!filter
            .min_status
            .accepts(&rsigma_parser::Status::Unsupported));
    }

    #[test]
    fn test_min_level_accepts_ordering() {
        let filter = SigmaFilterConfig {
            min_status: MinStatus::Unsupported,
            min_level: MinLevel::Medium,
        };
        assert!(filter.min_level.accepts(&rsigma_parser::Level::Medium));
        assert!(filter.min_level.accepts(&rsigma_parser::Level::High));
        assert!(filter.min_level.accepts(&rsigma_parser::Level::Critical));
        assert!(!filter.min_level.accepts(&rsigma_parser::Level::Low));
        assert!(!filter
            .min_level
            .accepts(&rsigma_parser::Level::Informational));
    }
}
