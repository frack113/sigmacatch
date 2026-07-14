use serde::{Deserialize, Serialize};
use std::path::PathBuf;

fn default_author() -> String {
    whoami::username().unwrap_or_default()
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
    pub log: LogConfig,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            author: default_author(),
            offline: false,
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
