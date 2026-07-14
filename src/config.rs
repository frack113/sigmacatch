// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 sigmacatch contributors

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[allow(dead_code)]
fn default_author() -> String {
    String::new()
}

fn default_contrib() -> bool {
    false
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

#[derive(Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct LogConfig {
    pub level_file: LogLevel,
}

impl Default for LogConfig {
    fn default() -> Self {
        Self {
            level_file: LogLevel::Debug,
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct Config {
    #[serde(default = "default_author")]
    pub author: String,
    pub offline: bool,
    #[serde(default = "default_contrib")]
    pub contrib: bool,
    pub log: LogConfig,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            author: default_author(),
            offline: false,
            contrib: false,
            log: LogConfig::default(),
        }
    }
}

impl Config {
    pub fn load(path: &PathBuf) -> anyhow::Result<Self> {
        if path.exists() {
            let content = std::fs::read_to_string(path)?;
            let config: Config = serde_yaml::from_str(&content)?;
            Ok(config)
        } else {
            let config = Self::default();
            let yaml = serde_yaml::to_string(&config)?;
            std::fs::write(path, &yaml)?;
            tracing::info!("Created default config file at {:?}", path);
            Ok(config)
        }
    }

    pub fn save(path: &PathBuf, config: &Config) -> anyhow::Result<()> {
        let yaml = serde_yaml::to_string(config)?;
        std::fs::write(path, yaml)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config_has_empty_author() {
        let config = Config::default();
        assert!(config.author.is_empty());
    }

    #[test]
    fn test_default_config_has_contrib_false() {
        let config = Config::default();
        assert!(!config.contrib);
    }

    #[test]
    fn test_load_config_with_contrib() {
        let yaml = r#"
author: testuser
offline: false
contrib: true
log:
  level_file: debug
"#;
        let config: Config = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(config.author, "testuser");
        assert!(config.contrib);
        assert!(!config.offline);
    }

    #[test]
    fn test_load_config_without_contrib_defaults_to_false() {
        let yaml = r#"
author: testuser
offline: false
log:
  level_file: info
"#;
        let config: Config = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(config.author, "testuser");
        assert!(!config.contrib);
    }

    #[test]
    fn test_save_and_load_config() {
        let config = Config {
            author: "devuser".to_string(),
            offline: true,
            contrib: true,
            log: LogConfig::default(),
        };
        let yaml = serde_yaml::to_string(&config).unwrap();
        let loaded: Config = serde_yaml::from_str(&yaml).unwrap();
        assert_eq!(loaded.author, "devuser");
        assert!(loaded.offline);
        assert!(loaded.contrib);
    }
}
