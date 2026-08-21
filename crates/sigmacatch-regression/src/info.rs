// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 sigmacatch contributors

use anyhow::anyhow;
use serde::{Deserialize, Serialize};
use std::path::Path;
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleMetadata {
    pub id: Uuid,
    pub title: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegressionTestInfo {
    pub name: String,
    #[serde(rename = "type")]
    pub test_type: String,
    pub provider: String,
    #[serde(default)]
    pub match_count: usize,
    pub path: String,
}

/// Configuration of the positive-detection test entry written to `info.yml`.
#[derive(Debug, Clone)]
pub struct TestConfig {
    pub test_type: String,
    pub provider: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InfoYml {
    pub id: Uuid,
    pub description: String,
    pub date: String,
    pub author: String,
    pub rule_metadata: Vec<RuleMetadata>,
    pub regression_tests_info: Vec<RegressionTestInfo>,
}

impl InfoYml {
    pub fn new(
        rule_id: &Uuid,
        rule_title: &str,
        event_count: usize,
        sigma_data_path: &str,
        author: &str,
        description: &str,
        test_config: &TestConfig,
    ) -> Self {
        Self {
            id: Uuid::new_v4(),
            description: description.to_string(),
            date: chrono::Utc::now().format("%Y-%m-%d").to_string(),
            author: author.to_string(),
            rule_metadata: vec![RuleMetadata {
                id: *rule_id,
                title: rule_title.to_string(),
            }],
            regression_tests_info: vec![RegressionTestInfo {
                name: "Positive Detection Test".to_string(),
                test_type: test_config.test_type.clone(),
                provider: test_config.provider.clone(),
                match_count: event_count,
                path: sigma_data_path.to_string(),
            }],
        }
    }

    pub fn save(&self, path: &Path) -> anyhow::Result<()> {
        let path = crate::long_path::long_path(path);
        let file = std::fs::File::create(&path)?;
        serde_yaml::to_writer(file, self)?;
        Ok(())
    }

    pub fn load(path: &Path) -> anyhow::Result<Self> {
        let path = crate::long_path::long_path(path);
        let mut content = std::fs::read_to_string(&path)
            .map_err(|e| anyhow!("Failed to read info.yml: {}", e))?;
        if content.starts_with('\u{feff}') {
            let mut chars = content.chars();
            chars.next();
            content = chars.as_str().to_string();
        }
        serde_yaml::from_str(&content).map_err(|e| anyhow!("Failed to parse info.yml: {}", e))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn info_yml_serializes_correctly() {
        let rule_id = Uuid::parse_str("7595ba94-cf3b-4471-aa03-4f6baa9e5fad").unwrap();
        let info = InfoYml::new(
            &rule_id,
            "Important Scheduled Task Deleted/Disabled",
            1,
            "regression_data/rules/windows/builtin/security/win_security_susp_scheduled_task_delete_or_disable/7595ba94-cf3b-4471-aa03-4f6baa9e5fad.evtx",
            "Swachchhanda Shrawan Poudel (Nextron Systems)",
            "N/A",
            &TestConfig {
                test_type: "evtx".to_string(),
                provider: "Microsoft-Windows-Sysmon".to_string(),
            },
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
        assert_eq!(parsed.rule_metadata[0].id, rule_id);
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
