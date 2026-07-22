// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 sigmacatch contributors

use anyhow::anyhow;
use serde::{Deserialize, Serialize};
use std::path::Path;

#[derive(Debug, Serialize, Deserialize)]
pub struct RuleMetadata {
    pub id: String,
    pub title: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RegressionTestInfo {
    pub name: String,
    #[serde(rename = "type")]
    pub test_type: String,
    pub provider: String,
    #[serde(default)]
    pub match_count: usize,
    pub path: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct InfoYml {
    pub id: String,
    pub description: String,
    pub date: String,
    pub author: String,
    pub rule_metadata: Vec<RuleMetadata>,
    pub regression_tests_info: Vec<RegressionTestInfo>,
}

impl InfoYml {
    pub fn new(
        rule_id: &str,
        rule_title: &str,
        event_count: usize,
        sigma_evtx_path: &str,
        author: &str,
        description: &str,
        provider: &str,
    ) -> Self {
        Self {
            id: uuid::Uuid::new_v4().to_string(),
            description: description.to_string(),
            date: chrono::Utc::now().format("%Y-%m-%d").to_string(),
            author: author.to_string(),
            rule_metadata: vec![RuleMetadata {
                id: rule_id.to_string(),
                title: rule_title.to_string(),
            }],
            regression_tests_info: vec![RegressionTestInfo {
                name: "Positive Detection Test".to_string(),
                test_type: "evtx".to_string(),
                provider: provider.to_string(),
                match_count: event_count,
                path: sigma_evtx_path.to_string(),
            }],
        }
    }

    /// Serialize to YAML using serde_yaml.
    pub fn save(&self, path: &Path) -> anyhow::Result<()> {
        let file = std::fs::File::create(path)?;
        serde_yaml::to_writer(file, self)?;
        Ok(())
    }

    /// Load from YAML file.
    pub fn load(path: &Path) -> anyhow::Result<Self> {
        let content =
            std::fs::read_to_string(path).map_err(|e| anyhow!("Failed to read info.yml: {}", e))?;
        serde_yaml::from_str(&content).map_err(|e| anyhow!("Failed to parse info.yml: {}", e))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn info_yml_serializes_correctly() {
        let info = InfoYml::new(
            "7595ba94-cf3b-4471-aa03-4f6baa9e5fad",
            "Important Scheduled Task Deleted/Disabled",
            1,
            "regression_data/rules/windows/builtin/security/win_security_susp_scheduled_task_delete_or_disable/7595ba94-cf3b-4471-aa03-4f6baa9e5fad.evtx",
            "Swachchhanda Shrawan Poudel (Nextron Systems)",
            "N/A",
            "Microsoft-Windows-Sysmon",
        );
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("info.yml");
        info.save(&path).unwrap();
        let content = std::fs::read_to_string(&path).unwrap();
        let parsed: InfoYml = serde_yaml::from_str(&content).unwrap();
        assert_eq!(parsed.id, info.id);
        assert_eq!(parsed.description, "N/A");
        assert_eq!(
            parsed.author,
            "Swachchhanda Shrawan Poudel (Nextron Systems)"
        );
        assert_eq!(parsed.rule_metadata.len(), 1);
        assert_eq!(
            parsed.rule_metadata[0].id,
            "7595ba94-cf3b-4471-aa03-4f6baa9e5fad"
        );
        assert_eq!(
            parsed.rule_metadata[0].title,
            "Important Scheduled Task Deleted/Disabled"
        );
        assert_eq!(parsed.regression_tests_info.len(), 1);
        assert_eq!(
            parsed.regression_tests_info[0].name,
            "Positive Detection Test"
        );
        assert_eq!(parsed.regression_tests_info[0].test_type, "evtx");
        assert_eq!(
            parsed.regression_tests_info[0].provider,
            "Microsoft-Windows-Sysmon"
        );
        assert_eq!(parsed.regression_tests_info[0].match_count, 1);
        assert_eq!(
            parsed.regression_tests_info[0].path,
            "regression_data/rules/windows/builtin/security/win_security_susp_scheduled_task_delete_or_disable/7595ba94-cf3b-4471-aa03-4f6baa9e5fad.evtx"
        );
    }
}
