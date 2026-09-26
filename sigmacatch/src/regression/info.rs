// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 sigmacatch contributors

//! Parsed representation of a SigmaHQ `info.yml` file.

use serde::{Deserialize, Serialize};
use std::io::Write;
use std::path::Path;
use uuid::Uuid;

/// Deserialize a rule id. Hard-fails on unparsable values only; warns but
/// accepts ids that are not UUID v4 or not in lowercase canonical 8-4-4-4-12
/// form — upstream SigmaHQ ships such ids and the regression workflow must
/// not drop their entries.
fn deserialize_rule_id<'de, D>(d: D) -> Result<Uuid, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let s = String::deserialize(d)?;
    let u = Uuid::parse_str(&s).map_err(|e| {
        serde::de::Error::custom(format!("rule_metadata[0].id is not a valid UUID: {e}"))
    })?;
    if u.get_version_num() != 4 {
        tracing::warn!(
            "rule_metadata[0].id '{s}' is not a UUID v4 (got version {}), accepted",
            u.get_version_num()
        );
    }
    if s != u.hyphenated().to_string() {
        tracing::warn!(
            "rule_metadata[0].id '{s}' is not in lowercase canonical 8-4-4-4-12 form, accepted"
        );
    }
    Ok(u)
}

/// Reference to the Sigma rule under test.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleMetadata {
    /// Rule UUID (v4 lowercase canonical expected; other forms warn).
    #[serde(deserialize_with = "deserialize_rule_id")]
    pub id: Uuid,
    /// Human-readable rule title.
    pub title: String,
}

/// A single regression test entry declared in `info.yml`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegressionTestInfo {
    /// Test display name.
    pub name: String,
    /// Data format (`evtx`, `log`, `json`).
    #[serde(rename = "type")]
    pub test_type: String,
    /// Event provider (e.g. `Microsoft-Windows-Sysmon`).
    #[serde(default)]
    pub provider: String,
    /// Expected number of matching detections.
    #[serde(default)]
    pub match_count: usize,
    /// Optional pipeline field-mapping files (JSON entries only).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pipelines: Option<Vec<String>>,
    /// Optional Sigma filter files applied during conversion (JSON entries
    /// only). Modelled so a `filters:` key is not silently dropped on load.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub filters: Option<Vec<String>>,
    /// Relative path to the data file.
    pub path: String,
}

/// Configuration of the positive-detection test entry written to `info.yml`.
#[derive(Debug, Clone)]
pub struct TestConfig {
    /// Data format (`evtx`, `log`, `json`).
    pub test_type: String,
    /// Event provider name.
    pub provider: String,
}

/// Top-level `info.yml` document.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InfoYml {
    /// Unique ID of this test-info file.
    pub id: Uuid,
    /// Free-form description.
    pub description: String,
    /// ISO date string (`YYYY-MM-DD`).
    pub date: String,
    /// Author name.
    pub author: String,
    /// The Sigma rule(s) under test.
    pub rule_metadata: Vec<RuleMetadata>,
    /// Declared regression test entries.
    #[serde(default)]
    pub regression_tests_info: Vec<RegressionTestInfo>,
}

impl InfoYml {
    /// Create a new `InfoYml` with a single rule and test entry.
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
                pipelines: None,
                filters: None,
                path: sigma_data_path.to_string(),
            }],
        }
    }

    /// Write to `path` in SigmaHQ 4-space indentation style.
    pub fn save(&self, path: &Path) -> crate::regression::Result<()> {
        let path = crate::regression::long_path::long_path(path);
        let mut yaml = self.canonical_yaml()?;
        if !yaml.ends_with('\n') {
            yaml.push('\n');
        }
        let mut file = std::fs::File::create(&path)?;
        file.write_all(yaml.as_bytes())
            .map_err(|e| crate::regression::RegressionError::Yaml(e.to_string()))?;
        Ok(())
    }

    /// Convert `serde_yaml` output (which never indents block sequences) to
    /// SigmaHQ's canonical 4-space layout: a sequence item sits 4 columns under
    /// the key that owns it, and the item's own keys 2 columns further in.
    ///
    /// `serde_yaml` emits a `pipelines:` key and its `- item` lines at the *same*
    /// column. A flat per-line lookup cannot tell that pair from an ordinary
    /// key/value pair, so it collapses the sequence onto its key — the +0 form
    /// seen in some committed SigmaHQ files. Tracking the open key is what
    /// produces the +4 form the SigmaHQ README documents.
    pub fn to_sigma_indent(yaml: &str) -> String {
        let mut out: Vec<String> = Vec::with_capacity(yaml.lines().count());
        // Source and canonical column of the innermost open bare key.
        let mut open_key: Option<(usize, usize)> = None;

        for line in yaml.lines() {
            let trimmed = line.trim_start();
            let spaces = line.len() - trimmed.len();

            if trimmed.is_empty() || trimmed.starts_with('#') {
                out.push(line.to_string());
                continue;
            }

            let is_item = trimmed == "-" || trimmed.starts_with("- ");
            let new_spaces = if is_item {
                // A sequence under an open key is indented one level (4
                // columns) below that key. The key stays open across the whole
                // sequence, so every item lands on the same column.
                match open_key {
                    Some((key_src, key_col)) if key_src == spaces => key_col + 4,
                    _ if spaces == 0 => 4,
                    _ => match spaces {
                        2 => 6,
                        n => n + 4,
                    },
                }
            } else {
                match spaces {
                    0 => 0,
                    2 => 6,
                    n if n >= 4 => n + 4,
                    n => n,
                }
            };

            out.push(format!("{}{}", " ".repeat(new_spaces), trimmed));

            if is_item {
                continue;
            }
            open_key = if Self::is_bare_key(trimmed) {
                Some((spaces, new_spaces))
            } else if open_key.is_some_and(|(key_src, _)| spaces <= key_src) {
                // Sibling of the open key: its value block is over.
                None
            } else {
                // Deeper than the key, so the value is a mapping and the key's
                // block is still open. No open key stays `None`.
                open_key
            };
        }

        out.join("\n")
    }

    /// True when a line opens a block: `key:` with no inline value.
    fn is_bare_key(trimmed: &str) -> bool {
        let head = trimmed.split_once(" #").map_or(trimmed, |(h, _)| h);
        head.trim_end().ends_with(':')
    }

    /// Return the canonical 4-space-indented YAML representation.
    pub fn canonical_yaml(&self) -> crate::regression::Result<String> {
        let yaml = serde_yaml::to_string(self)
            .map_err(|e| crate::regression::RegressionError::Yaml(e.to_string()))?;
        Ok(Self::to_sigma_indent(&yaml))
    }

    /// Parse an `info.yml` file, stripping BOM if present.
    pub fn load(path: &Path) -> crate::regression::Result<Self> {
        let path = crate::regression::long_path::long_path(path);
        let mut content = std::fs::read_to_string(&path).map_err(|e| {
            crate::regression::RegressionError::Invalid(format!("Failed to read info.yml: {}", e))
        })?;
        if content.starts_with('\u{feff}') {
            let mut chars = content.chars();
            chars.next();
            content = chars.as_str().to_string();
        }
        let info: Self = serde_yaml::from_str(&content)
            .map_err(|e| crate::regression::RegressionError::Yaml(e.to_string()))?;
        if info.rule_metadata.is_empty() {
            return Err(crate::regression::RegressionError::Invalid(
                "info.yml: 'rule_metadata' must be a non-empty sequence".to_string(),
            ));
        }
        Ok(info)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// serde_yaml never indents block sequences: a key and its `- item` lines
    /// share a column. This is the exact shape `to_sigma_indent` receives.
    const SERDE_YAML_PIPELINES: &str = "regression_tests_info:\n- name: Positive Detection Test\n  type: json\n  match_count: 1\n  pipelines:\n  - regression_data/pipelines/process_creation_fieldmapping.yml\n  - regression_data/pipelines/other.yml\n  path: a.json\n";

    #[test]
    fn to_sigma_indent_nests_a_sequence_four_columns_under_its_key() {
        let out = InfoYml::to_sigma_indent(SERDE_YAML_PIPELINES);
        let lines: Vec<&str> = out.lines().collect();
        assert_eq!(lines[0], "regression_tests_info:");
        assert_eq!(lines[1], "    - name: Positive Detection Test");
        assert_eq!(lines[2], "      type: json");
        assert_eq!(lines[3], "      match_count: 1");
        assert_eq!(lines[4], "      pipelines:");
        // +4 under `pipelines:` (6) — the README form, not the +0 form.
        assert_eq!(
            lines[5],
            "          - regression_data/pipelines/process_creation_fieldmapping.yml"
        );
        // A second item stays on the same column: the key is still open.
        assert_eq!(lines[6], "          - regression_data/pipelines/other.yml");
        // The key's block closes on the next sibling.
        assert_eq!(lines[7], "      path: a.json");
    }

    #[test]
    fn to_sigma_indent_keeps_the_plain_four_six_layout() {
        let serde = "rule_metadata:\n- id: 7595ba94-cf3b-4471-aa03-4f6baa9e5fad\n  title: T\nregression_tests_info:\n- name: T\n  type: evtx\n  path: a.evtx\n";
        let out = InfoYml::to_sigma_indent(serde);
        assert_eq!(
            out,
            "rule_metadata:\n    - id: 7595ba94-cf3b-4471-aa03-4f6baa9e5fad\n      title: T\nregression_tests_info:\n    - name: T\n      type: evtx\n      path: a.evtx"
        );
    }

    /// `serde_yaml` output carries no comments, so key tracking only ever sees
    /// contiguous lines; comments and blanks are still copied verbatim.
    #[test]
    fn to_sigma_indent_passes_comments_and_blanks_through() {
        let serde = "# info.yml\npipelines:\n- a.yml\n\n- b.yml\npath: x\n";
        let out = InfoYml::to_sigma_indent(serde);
        assert_eq!(
            out,
            "# info.yml\npipelines:\n    - a.yml\n\n    - b.yml\npath: x"
        );
    }

    /// A mapping value is not a sequence: a deeper child line keeps the 2→6
    /// mapping and must not be read as an item of the open key.
    #[test]
    fn to_sigma_indent_does_not_treat_a_mapping_value_as_a_sequence() {
        let serde = "meta:\n  owner: a\nnext: b\n";
        let out = InfoYml::to_sigma_indent(serde);
        assert_eq!(out, "meta:\n      owner: a\nnext: b");
    }

    #[test]
    fn is_bare_key_ignores_an_inline_comment() {
        assert!(InfoYml::is_bare_key("pipelines:"));
        assert!(InfoYml::is_bare_key("pipelines:   # which mapping"));
        assert!(!InfoYml::is_bare_key("path: a.json"));
        assert!(!InfoYml::is_bare_key("time: 12:30"));
    }

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
    fn load_accepts_uppercase_rule_id() {
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

        let info = InfoYml::load(&path).unwrap();
        assert_eq!(
            info.rule_metadata[0].id.hyphenated().to_string(),
            "d059842b-6b9d-4ed1-b5c3-5b89143c6ede"
        );
    }

    #[test]
    fn load_accepts_non_v4_rule_id() {
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

        let info = InfoYml::load(&path).unwrap();
        assert!(info.rule_metadata[0].id.is_nil());
    }

    #[test]
    fn load_rejects_unparsable_rule_id() {
        let content = r#"
id: a1b2c3d4-e5f6-7890-abcd-ef1234567890
description: N/A
date: 2024-01-15
author: sigmacatch
rule_metadata:
  - id: not-a-uuid
    title: Broken Id
"#;
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("info.yml");
        std::fs::write(&path, content).unwrap();

        let err = InfoYml::load(&path).unwrap_err().to_string();
        assert!(err.contains("not a valid UUID"), "got: {err}");
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
