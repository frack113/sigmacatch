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
                provider: "Microsoft-Windows-Sysmon".to_string(),
                match_count: event_count,
                path: sigma_evtx_path.to_string(),
            }],
        }
    }

    pub fn save(&self, path: &Path) -> anyhow::Result<()> {
        let content = serde_yaml::to_string(self)?;
        std::fs::write(path, content)?;
        Ok(())
    }
}
