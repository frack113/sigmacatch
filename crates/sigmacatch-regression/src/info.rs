// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 sigmacatch contributors

use serde::{Deserialize, Serialize};
use std::path::Path;
use uuid::Uuid;

/// Deserialize a rule id enforcing the documented contract: canonical
/// lowercase 8-4-4-4-12 form, UUID version 4.
fn deserialize_lowercase_v4<'de, D>(d: D) -> Result<Uuid, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let s = String::deserialize(d)?;
    let u = Uuid::parse_str(&s).map_err(|e| {
        serde::de::Error::custom(format!("rule_metadata[0].id is not a valid UUID: {e}"))
    })?;
    if u.get_version_num() != 4 {
        return Err(serde::de::Error::custom(format!(
            "rule_metadata[0].id '{s}' must be a UUID v4 (got version {})",
            u.get_version_num()
        )));
    }
    if s != u.hyphenated().to_string() {
        return Err(serde::de::Error::custom(format!(
            "rule_metadata[0].id '{s}' must be in lowercase canonical 8-4-4-4-12 form"
        )));
    }
    Ok(u)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleMetadata {
    #[serde(deserialize_with = "deserialize_lowercase_v4")]
    pub id: Uuid,
    pub title: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegressionTestInfo {
    pub name: String,
    #[serde(rename = "type")]
    pub test_type: String,
    // Optional on read: upstream-style entries (ex. cisco) may omit it.
    #[serde(default)]
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
    // Optional on read: upstream-style entries may omit the test section.
    #[serde(default)]
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

    pub fn save(&self, path: &Path) -> crate::Result<()> {
        let path = crate::long_path::long_path(path);
        let file = std::fs::File::create(&path)?;
        serde_yaml::to_writer(file, self)
            .map_err(|e| crate::RegressionError::Yaml(e.to_string()))?;
        Ok(())
    }

    pub fn load(path: &Path) -> crate::Result<Self> {
        let path = crate::long_path::long_path(path);
        let mut content = std::fs::read_to_string(&path).map_err(|e| {
            crate::RegressionError::Invalid(format!("Failed to read info.yml: {}", e))
        })?;
        if content.starts_with('\u{feff}') {
            let mut chars = content.chars();
            chars.next();
            content = chars.as_str().to_string();
        }
        let info: Self = serde_yaml::from_str(&content)
            .map_err(|e| crate::RegressionError::Yaml(e.to_string()))?;
        if info.rule_metadata.is_empty() {
            return Err(crate::RegressionError::Invalid(
                "info.yml: 'rule_metadata' must be a non-empty sequence".to_string(),
            ));
        }
        Ok(info)
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

    #[test]
    fn load_accepts_missing_provider_and_tests() {
        // Upstream-style entries (ex. cisco) may omit provider and the whole
        // regression_tests_info section.
        let content = r#"
id: a1b2c3d4-e5f6-7890-abcd-ef1234567890
description: N/A
date: 2024-01-15
author: sigmacatch
rule_metadata:
  - id: d059842b-6b9d-4ed1-b5c3-5b89143c6ede
    title: Some Cisco Rule
"#;
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("info.yml");
        std::fs::write(&path, content).unwrap();

        let info = InfoYml::load(&path).unwrap();
        assert!(info.regression_tests_info.is_empty());
    }

    #[test]
    fn load_rejects_uppercase_rule_id() {
        let content = r#"
id: a1b2c3d4-e5f6-7890-abcd-ef1234567890
description: N/A
date: 2024-01-15
author: sigmacatch
rule_metadata:
  - id: D059842B-6B9D-4ED1-B5C3-5B89143C6EDE
    title: Uppercase Rule Id
"#;
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("info.yml");
        std::fs::write(&path, content).unwrap();

        let err = InfoYml::load(&path).unwrap_err().to_string();
        assert!(err.contains("lowercase canonical"), "got: {err}");
    }

    #[test]
    fn load_rejects_non_v4_rule_id() {
        let content = r#"
id: a1b2c3d4-e5f6-7890-abcd-ef1234567890
description: N/A
date: 2024-01-15
author: sigmacatch
rule_metadata:
  - id: 00000000-0000-0000-0000-000000000000
    title: Nil UUID Is Not V4
"#;
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("info.yml");
        std::fs::write(&path, content).unwrap();

        let err = InfoYml::load(&path).unwrap_err().to_string();
        assert!(err.contains("UUID v4"), "got: {err}");
    }

    #[test]
    fn load_rejects_empty_rule_metadata() {
        let content = r#"
id: a1b2c3d4-e5f6-7890-abcd-ef1234567890
description: N/A
date: 2024-01-15
author: sigmacatch
rule_metadata: []
"#;
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("info.yml");
        std::fs::write(&path, content).unwrap();

        let err = InfoYml::load(&path).unwrap_err().to_string();
        assert!(err.contains("non-empty"), "got: {err}");
    }
}
