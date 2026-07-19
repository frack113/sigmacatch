// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 sigmacatch contributors

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

    /// Serialize to YAML matching the exact SigmaHQ format:
    ///   - 4-space indent under `rule_metadata` and `regression_tests_info`
    ///   - description defaults to `N/A`
    ///   - UTF-8, LF line endings, trailing newline
    pub fn save(&self, path: &Path) -> anyhow::Result<()> {
        let test = &self.regression_tests_info[0];
        let meta = &self.rule_metadata[0];
        let content = format!(
            "id: {id}\n\
             description: {description}\n\
             date: {date}\n\
             author: {author}\n\
             rule_metadata:\n\
             \x20\x20\x20\x20- id: {meta_id}\n\
             \x20\x20\x20\x20  title: {meta_title}\n\
             regression_tests_info:\n\
             \x20\x20\x20\x20- name: {test_name}\n\
             \x20\x20\x20\x20  type: {test_type}\n\
             \x20\x20\x20\x20  provider: {provider}\n\
             \x20\x20\x20\x20  match_count: {match_count}\n\
             \x20\x20\x20\x20  path: {path}\n",
            id = self.id,
            description = self.description,
            date = self.date,
            author = self.author,
            meta_id = meta.id,
            meta_title = meta.title,
            test_name = test.name,
            test_type = test.test_type,
            provider = test.provider,
            match_count = test.match_count,
            path = test.path,
        );
        std::fs::write(path, content)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn info_yml_matches_sigmahq_format() {
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
        // Must be 100% identical to SigmaHQ format (aside from id/date which are dynamic)
        let expected = format!(
            "id: {}\n\
             description: N/A\n\
             date: {}\n\
             author: Swachchhanda Shrawan Poudel (Nextron Systems)\n\
             rule_metadata:\n\
             \x20\x20\x20\x20- id: 7595ba94-cf3b-4471-aa03-4f6baa9e5fad\n\
             \x20\x20\x20\x20  title: Important Scheduled Task Deleted/Disabled\n\
             regression_tests_info:\n\
             \x20\x20\x20\x20- name: Positive Detection Test\n\
             \x20\x20\x20\x20  type: evtx\n\
             \x20\x20\x20\x20  provider: Microsoft-Windows-Sysmon\n\
             \x20\x20\x20\x20  match_count: 1\n\
             \x20\x20\x20\x20  path: regression_data/rules/windows/builtin/security/win_security_susp_scheduled_task_delete_or_disable/7595ba94-cf3b-4471-aa03-4f6baa9e5fad.evtx\n",
            info.id, info.date
        );
        assert_eq!(content, expected);
    }
}
