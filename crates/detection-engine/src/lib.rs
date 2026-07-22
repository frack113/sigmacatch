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
use std::path::Path;
use tracing::info;

use winevt_xml::xml_parser::validate_event_id;

pub struct DetectionEngine {
    engine: Engine,
}

impl Default for DetectionEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl DetectionEngine {
    pub fn new() -> Self {
        let mut engine = Engine::new();
        engine.set_include_event(true);
        Self { engine }
    }

    /// Load the two embedded pipelines: flatten_winevt.yml (field name mapping)
    /// and windows.yml (EventID condition injection).
    pub fn load_default_pipelines(&mut self) {
        let flatten_yaml = include_str!("../pipelines/flatten_winevt.yml");
        let flatten_pipeline =
            parse_pipeline(flatten_yaml).expect("flatten_winevt pipeline YAML is valid");
        self.engine.add_pipeline(flatten_pipeline);

        let windows_yaml = include_str!("../pipelines/windows.yml");
        let windows_pipeline =
            parse_pipeline(windows_yaml).expect("windows pipeline YAML is valid");
        self.engine.add_pipeline(windows_pipeline);
    }

    /// Load a single pipeline from a YAML file.
    pub fn load_pipeline(&mut self, path: &Path) -> Result<()> {
        let yaml = std::fs::read_to_string(path)
            .map_err(|e| anyhow!("Failed to read pipeline {:?}: {}", path, e))?;
        let pipeline = parse_pipeline(&yaml)
            .map_err(|e| anyhow!("Failed to parse pipeline {:?}: {}", path, e))?;
        self.engine.add_pipeline(pipeline);
        Ok(())
    }

    /// Load a single Sigma rule from a YAML file.
    pub fn load_sigma_rule(&mut self, path: &Path) -> Result<()> {
        let content = std::fs::read_to_string(path)
            .map_err(|e| anyhow!("Failed to read rule {:?}: {}", path, e))?;
        let collection = parse_sigma_yaml(&content)
            .map_err(|e| anyhow!("Failed to parse rule {:?}: {}", path, e))?;
        if !collection.rules.is_empty() {
            self.engine
                .add_collection(&collection)
                .map_err(|e| anyhow!("Engine add_collection failed for {:?}: {}", path, e))?;
        }
        Ok(())
    }

    /// Load all Sigma rules from a directory recursively.
    /// Batches rules per subdirectory for efficient index building.
    pub fn load_rules_from_dir(&mut self, dir: &Path) -> Result<()> {
        if !dir.exists() {
            return Err(anyhow!("Directory does not exist: {}", dir.display()));
        }
        self.load_rules_recursive(dir)?;
        Ok(())
    }

    fn load_rules_recursive(&mut self, dir: &Path) -> Result<()> {
        let entries = match std::fs::read_dir(dir) {
            Ok(e) => e,
            Err(_) => return Ok(()),
        };

        let mut collection = SigmaCollection::default();

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
                self.load_rules_recursive(&ep)?;
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

    /// Evaluate a JSON event against loaded rules with an explicit logsource.
    pub fn evaluate(
        &self,
        event: &serde_json::Value,
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
}
