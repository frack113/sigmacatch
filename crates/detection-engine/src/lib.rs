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

use winevt_xml::xml_parser::validate_event_id;

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
        be.load_rules_recursive(dir)?;
        Ok(be)
    }

    /// Create a new engine and load rules from multiple directories.
    /// Non-existent directories are silently skipped.
    pub fn from_rules_dirs(dirs: &[&Path]) -> Result<Self> {
        let mut be = Self::new();
        for dir in dirs {
            be.load_rules_recursive(dir)?;
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

    fn load_rules_recursive(&mut self, dir: &Path) -> Result<()> {
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
