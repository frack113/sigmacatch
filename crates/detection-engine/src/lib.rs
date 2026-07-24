// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 sigmacatch contributors

//! Detection engine — thin wrapper around rsigma-eval for loading pipelines and
//! rules, then evaluating events. No filtering, no skip sets — just the bare
//! essentials for testing and validation.

use anyhow::{anyhow, Result};
use rsigma_eval::event::JsonEvent;
use rsigma_eval::pipeline::parse_pipeline;
use rsigma_eval::Engine;
use rsigma_parser::{parse_sigma_yaml, LogSource, SigmaCollection};
use serde_json::Value;
use std::path::Path;
use tracing::info;

use sigmacatch_types::validate_event_id;

pub use sigmacatch_types::Alert;

/// Default flatten-winevt pipeline YAML used to prep processing of raw Winevt XML events.
pub const FLATTEN_WINEVT_PIPELINE: &str = include_str!("../pipelines/flatten_winevt.yml");

/// Default Windows pipeline YAML for SigmaHQ rule transformation (logsource → Sysmon EventID conditions).
pub const WINDOWS_PIPELINE: &str = include_str!("../pipelines/windows.yml");

/// Bare evaluation engine — no tracking, no filtering, just pipelines + rules + evaluate.
pub struct BareEngine {
    engine: Engine,
}

impl BareEngine {
    /// Create a new engine with embedded pipelines loaded automatically.
    pub fn new() -> Self {
        let mut engine = Engine::new();
        engine.set_include_event(true);
        let mut be = Self { engine };
        be.load_pipelines();
        be
    }

    /// Create a new engine and load rules from a directory in one call.
    pub fn from_rules_dir(dir: &Path) -> Result<Self> {
        let mut be = Self::new();
        be.load_rules_recursive(dir, 0)?;
        Ok(be)
    }

    /// Create a new engine and load rules from multiple directories.
    /// Non-existent directories are silently skipped.
    pub fn from_rules_dirs(dirs: &[&Path]) -> Result<Self> {
        let mut be = Self::new();
        for dir in dirs {
            be.load_rules_recursive(dir, 0)?;
        }
        Ok(be)
    }

    /// Evaluate a JSON event against loaded rules with an explicit logsource.
    pub fn evaluate(
        &self,
        event: &Value,
        logsource: &LogSource,
    ) -> Vec<rsigma_eval::EvaluationResult> {
        let validated = validate_event_id(event);
        let json_event = JsonEvent::borrow(&validated);
        self.engine.evaluate_with_logsource(&json_event, logsource)
    }

    /// Number of rules currently loaded in the engine.
    pub fn rule_count(&self) -> usize {
        self.engine.rule_count()
    }

    // ─── private helpers ─────────────────────────────────────────────────

    fn load_pipelines(&mut self) {
        let flatten_pipeline =
            parse_pipeline(FLATTEN_WINEVT_PIPELINE).expect("flatten_winevt pipeline YAML is valid");
        self.engine.add_pipeline(flatten_pipeline);

        let windows_pipeline =
            parse_pipeline(WINDOWS_PIPELINE).expect("windows pipeline YAML is valid");
        self.engine.add_pipeline(windows_pipeline);
    }

    fn load_rules_recursive(&mut self, dir: &Path, depth: u32) -> Result<()> {
        if depth > 16 {
            return Ok(());
        }

        if !dir.exists() {
            return Ok(());
        }

        let mut collection = SigmaCollection::default();

        let entries = match std::fs::read_dir(dir) {
            Ok(e) => e,
            Err(_) => return Ok(()),
        };

        for entry in entries.flatten() {
            let ep = entry.path();
            if ep.is_file() {
                if let Some(ext) = ep.extension().and_then(|e| e.to_str()) {
                    if ext == "yml" || ext == "yaml" {
                        if let Some(name) = ep.file_name().and_then(|n| n.to_str()) {
                            if name == "index.yml" {
                                continue;
                            }
                        }
                        match std::fs::read_to_string(&ep) {
                            Ok(content) => match parse_sigma_yaml(&content) {
                                Ok(c) => collection.rules.extend(c.rules),
                                Err(e) => {
                                    info!("Failed to parse {:?}: {}", ep, e);
                                }
                            },
                            Err(e) => {
                                info!("Failed to read {:?}: {}", ep, e);
                            }
                        }
                    }
                }
            } else if ep.is_dir() {
                self.load_rules_recursive(&ep, depth + 1)?;
            }
        }

        if !collection.rules.is_empty() {
            self.engine.add_collection(&collection).map_err(|e| {
                anyhow!(
                    "Engine add_collection failed for {:?}: {}",
                    dir.display(),
                    e
                )
            })?;
        }

        Ok(())
    }
}

impl Default for BareEngine {
    fn default() -> Self {
        Self::new()
    }
}

/// Re-export renamed type for backward compatibility.
#[allow(deprecated)]
#[deprecated(since = "0.3.0", note = "renamed to BareEngine")]
pub type DetectionEngine = BareEngine;

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use tempfile::TempDir;

    const MINIMAL_RULE_YAML: &str = r#"title: Test Rule
id: test-rule-001
status: test
description: A minimal test rule
author: Test Author
logsource:
  product: test
detection:
  selection:
    event_id: 1
  condition: selection
"#;

    fn write_rule_to_dir(dir: &TempDir, name: &str, yaml: &str) -> std::path::PathBuf {
        let path = dir.path().join(name);
        std::fs::write(&path, yaml).expect("write rule file");
        path
    }

    #[test]
    fn test_new_engine_has_pipelines() {
        let dir = tempfile::tempdir().unwrap();
        write_rule_to_dir(&dir, "pipeline_test.yml", MINIMAL_RULE_YAML);
        let engine = BareEngine::from_rules_dir(dir.path()).unwrap();
        let count = engine.rule_count();
        assert_eq!(
            count, 1,
            "engine should have 1 rule after loading with pipelines, got {}",
            count
        );
    }

    #[test]
    fn test_from_rules_dir_nonexistent() {
        let result = BareEngine::from_rules_dir(Path::new("/nonexistent"));
        assert!(
            result.is_ok(),
            "from_rules_dir should succeed for nonexistent dir"
        );
        let engine = result.unwrap();
        assert_eq!(
            engine.rule_count(),
            0,
            "engine should have 0 rules when loaded from nonexistent directory"
        );
    }

    #[test]
    fn test_evaluate_no_rules() {
        // Build engine with an empty rules dir (nonexistent, so 0 rules loaded)
        let engine = BareEngine::from_rules_dir(Path::new("/nonexistent")).unwrap();
        assert_eq!(engine.rule_count(), 0);

        let logsource = LogSource {
            product: Some("test".to_string()),
            category: None,
            service: None,
            definition: None,
            custom: HashMap::new(),
        };
        let event = serde_json::json!({ "EventID": 1 });

        let results = engine.evaluate(&event, &logsource);
        assert!(
            results.is_empty(),
            "evaluate with no rules should return empty vec, got {} results",
            results.len()
        );
    }

    #[test]
    fn test_rule_count() {
        let dir = tempfile::tempdir().unwrap();
        write_rule_to_dir(&dir, "test_rule.yml", MINIMAL_RULE_YAML);

        let engine = BareEngine::from_rules_dir(dir.path()).unwrap();
        let count = engine.rule_count();
        assert_eq!(
            count, 1,
            "engine should have exactly 1 rule loaded, got {}",
            count
        );
    }

    #[test]
    fn test_load_rules_depth_limit() {
        // Create a deeply nested directory structure (beyond depth limit)
        let tmp = tempfile::tempdir().unwrap();
        let mut current = tmp.path().to_path_buf();
        for i in 0..20 {
            current = current.join(format!("level_{}", i));
            std::fs::create_dir(&current).unwrap();
        }
        // The rule is at depth 20 (beyond the 16 limit)
        let rule_content = MINIMAL_RULE_YAML.replace("test-rule", "deep-rule");
        std::fs::write(current.join("deep.yml"), rule_content).unwrap();

        let engine = BareEngine::from_rules_dir(tmp.path()).unwrap();
        assert_eq!(
            engine.rule_count(),
            0,
            "rules beyond depth 16 should not be loaded"
        );
    }

    #[test]
    fn test_load_rules_at_depth_limit() {
        // Create a directory structure at exactly depth 16
        let tmp = tempfile::tempdir().unwrap();
        let mut current = tmp.path().to_path_buf();
        for i in 0..15 {
            current = current.join(format!("level_{}", i));
            std::fs::create_dir(&current).unwrap();
        }
        let rule_content = MINIMAL_RULE_YAML.replace("test-rule", "edge-rule");
        std::fs::write(current.join("edge.yml"), rule_content).unwrap();

        let engine = BareEngine::from_rules_dir(tmp.path()).unwrap();
        assert_eq!(engine.rule_count(), 1, "rules at depth 16 should be loaded");
    }
}
