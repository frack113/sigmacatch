// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 sigmacatch contributors

use once_cell::sync::Lazy;
use serde::Deserialize;
use std::collections::HashMap;

/// Embedded channel_mapping.yml from pipeline_generator output.
/// Maps WinEventLog channel names to Sigma services.
static CHANNEL_MAPPING_YAML: &str = include_str!("channel_mapping.yml");

#[derive(Deserialize)]
struct ChannelMappingFile {
    channel_to_service: HashMap<String, String>,
}

/// Parsed channel-to-service mapping, initialized once at runtime.
pub static CHANNEL_TO_SERVICE_MAP: Lazy<HashMap<String, String>> = Lazy::new(|| {
    let mapping: ChannelMappingFile =
        serde_yaml::from_str(CHANNEL_MAPPING_YAML).expect("channel_mapping.yml is valid YAML");
    mapping.channel_to_service
});

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_channel_mapping_parsed() {
        assert!(!CHANNEL_TO_SERVICE_MAP.is_empty());
        assert!(CHANNEL_TO_SERVICE_MAP.contains_key("WinEventLog:Application"));
    }

    #[test]
    fn test_channel_mapping_sysmon_channel() {
        let service =
            CHANNEL_TO_SERVICE_MAP.get("WinEventLog:Microsoft-Windows-Sysmon/Operational");
        assert!(service.is_some(), "sysmon channel should be mapped");
        assert_eq!(service.unwrap(), "sysmon");
    }

    #[test]
    fn test_channel_mapping_applocker_multiple_channels() {
        let services: Vec<&String> = CHANNEL_TO_SERVICE_MAP
            .iter()
            .filter(|(ch, _)| ch.starts_with("WinEventLog:Microsoft-Windows-AppLocker"))
            .map(|(_, s)| s)
            .collect();
        assert!(
            services.len() >= 4,
            "expected >=4 applocker channels mapped, got {}",
            services.len()
        );
        assert!(services.iter().all(|s| *s == "applocker"));
    }

    #[test]
    fn test_channel_mapping_unknown_channel_returns_none() {
        assert!(CHANNEL_TO_SERVICE_MAP.get("Unknown/Channel").is_none());
    }
}
