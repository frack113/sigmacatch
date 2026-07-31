// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 sigmacatch contributors

//! `RuleIndex` — single point of interaction for Sigma rule management.
//!
//! Owns the `SigmaCollection` (loaded + filtered rules), the skip set
//! (rule IDs excluded from evaluation), and load statistics. Provides
//! rule querying, channel resolution, and skip-set management.
//!
//! `DetectionEngine` consumes `RuleIndex` in read-only mode via
//! `get_collection()`. The rsigma-eval `Engine`
//! holds the compiled rules; `RuleIndex` is the data hub.

use crate::channel_resolver::resolve_channels;
use crate::loader::{load_all_rules, LoadFilter, LoadStats};
use crate::scanner::find_rules_dirs;
use anyhow::Result;
use rsigma_parser::SigmaCollection;
use std::collections::{HashMap, HashSet};
use std::path::Path;

/// Central data hub for Sigma rule management.
///
/// Owns the `SigmaCollection`, skip set, and load statistics.
/// `DetectionEngine` reads rules from this via `get_collection()`. Channel
/// resolution and skip-set management
/// are also exposed here, making RuleIndex the single point of
/// interaction for all rule-related operations.
#[derive(Debug, Clone)]
pub struct RuleIndex {
    collection: SigmaCollection,
    skip_ids: HashSet<String>,
    stats: LoadStats,
}

impl Default for RuleIndex {
    fn default() -> Self {
        Self::new()
    }
}

impl RuleIndex {
    /// Create a new empty rule index.
    pub fn new() -> Self {
        Self {
            collection: SigmaCollection::default(),
            skip_ids: HashSet::new(),
            stats: LoadStats::default(),
        }
    }

    // ─── Loading ─────────────────────────────────────────────────────

    /// Load rules from a list of directories, applying status/level filters
    /// and skipping rules whose IDs are in `skip_ids`.
    ///
    /// The skip set is applied at load time for efficiency — rules in the set
    /// are not parsed or added to the collection. The provided `skip_ids` are
    /// stored in the index so `skip_count()` reflects the full skip set. For
    /// runtime exclusions after loading, use `exclude_rule_id()` +
    /// `DetectionEngine::reload_rules()`.
    pub fn load_from_dirs(
        &mut self,
        dirs: &[&Path],
        skip_ids: &HashSet<String>,
        filter: &LoadFilter,
    ) -> Result<()> {
        let result = load_all_rules(dirs, skip_ids, filter)?;
        self.collection = result.collection;
        self.stats = result.stats;
        self.skip_ids.extend(skip_ids.iter().cloned());
        Ok(())
    }

    /// Load rules from a SigmaHQ repository root path.
    ///
    /// Convenience wrapper: calls `find_rules_dirs()` then `load_from_dirs()`.
    pub fn load_from_sigma_path(
        &mut self,
        sigma_path: &Path,
        skip_ids: &HashSet<String>,
        filter: &LoadFilter,
    ) -> Result<()> {
        let dirs = find_rules_dirs(sigma_path)?;
        if dirs.is_empty() {
            anyhow::bail!(
                "No rules directories found in {:?} — the repository may be empty or incomplete",
                sigma_path
            );
        }
        let dirs_refs: Vec<&Path> = dirs.iter().map(|d| d.as_path()).collect();
        self.load_from_dirs(&dirs_refs, skip_ids, filter)
    }

    // ─── Skip set ────────────────────────────────────────────────────

    /// Exclude a rule by ID — adds to skip set and removes from collection.
    ///
    /// After calling this, `DetectionEngine::reload_rules(&self)` should
    /// be called to update the rsigma-eval Engine.
    pub fn exclude_rule_id(&mut self, id: &str) {
        if self.skip_ids.insert(id.to_string()) {
            self.stats.rules_loaded = self.stats.rules_loaded.saturating_sub(1);
        }
        self.collection
            .rules
            .retain(|r| r.id.as_deref() != Some(id));
    }

    /// Total number of rules excluded (at load time or via `exclude_rule_id()`).
    pub fn skip_count(&self) -> usize {
        self.skip_ids.len()
    }

    // ─── Rule access ─────────────────────────────────────────────────

    /// Get the underlying `SigmaCollection` (for engine loading).
    pub fn get_collection(&self) -> &SigmaCollection {
        &self.collection
    }

    /// Number of rules currently loaded (after exclusions).
    pub fn rule_count(&self) -> usize {
        self.collection.rules.len()
    }

    // ─── Channel resolution ──────────────────────────────────────────

    /// Resolve Windows Event Log channels from loaded rules.
    ///
    /// Delegates to `resolve_channels_from_collection()` using the
    /// SigmaCollection owned by this RuleIndex.
    pub fn get_channels(&self, custom_map: &HashMap<String, String>) -> Vec<String> {
        resolve_channels(&self.collection.rules, custom_map)
    }

    // ─── Stats ───────────────────────────────────────────────────────

    /// Load statistics (rules loaded, filtered by status/level).
    pub fn stats(&self) -> &LoadStats {
        &self.stats
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    const MINIMAL_RULE_YAML: &str = r#"title: Test Rule
id: test-rule-001
status: stable
description: A minimal test rule
author: Test Author
logsource:
  product: windows
detection:
  selection:
    event_id: 1
  condition: selection
"#;

    fn write_rule_to_dir(dir: &tempfile::TempDir, name: &str, yaml: &str) {
        let path = dir.path().join(name);
        std::fs::write(&path, yaml).expect("write rule file");
    }

    #[test]
    fn test_rule_index_new_empty() {
        let idx = RuleIndex::new();
        assert_eq!(idx.rule_count(), 0);
        assert_eq!(idx.skip_count(), 0);
    }

    #[test]
    fn test_rule_index_load_from_dirs() {
        let dir = tempfile::tempdir().unwrap();
        let rules_dir = dir.path().join("rules");
        fs::create_dir(&rules_dir).unwrap();
        write_rule_to_dir(&dir, "rules/win_rule.yml", MINIMAL_RULE_YAML);

        let mut idx = RuleIndex::new();
        idx.load_from_dirs(
            &[rules_dir.as_path()],
            &HashSet::new(),
            &LoadFilter::default(),
        )
        .unwrap();

        assert_eq!(idx.rule_count(), 1);
        assert!(idx
            .get_collection()
            .rules
            .iter()
            .any(|r| r.id.as_deref() == Some("test-rule-001")));
    }

    #[test]
    fn test_rule_index_exclude_rule_id() {
        let dir = tempfile::tempdir().unwrap();
        let rules_dir = dir.path().join("rules");
        fs::create_dir(&rules_dir).unwrap();
        write_rule_to_dir(&dir, "rules/win_rule.yml", MINIMAL_RULE_YAML);

        let mut idx = RuleIndex::new();
        idx.load_from_dirs(
            &[rules_dir.as_path()],
            &HashSet::new(),
            &LoadFilter::default(),
        )
        .unwrap();

        assert_eq!(idx.rule_count(), 1);
        assert_eq!(idx.skip_count(), 0);

        idx.exclude_rule_id("test-rule-001");
        assert_eq!(idx.rule_count(), 0);
        assert_eq!(idx.skip_count(), 1);
    }

    #[test]
    fn test_rule_index_get_collection() {
        let dir = tempfile::tempdir().unwrap();
        let rules_dir = dir.path().join("rules");
        fs::create_dir(&rules_dir).unwrap();
        write_rule_to_dir(&dir, "rules/win_rule.yml", MINIMAL_RULE_YAML);

        let mut idx = RuleIndex::new();
        idx.load_from_dirs(
            &[rules_dir.as_path()],
            &HashSet::new(),
            &LoadFilter::default(),
        )
        .unwrap();

        let collection = idx.get_collection();
        assert_eq!(collection.rules.len(), 1);
    }

    #[test]
    fn test_rule_index_stats() {
        let dir = tempfile::tempdir().unwrap();
        let rules_dir = dir.path().join("rules");
        fs::create_dir(&rules_dir).unwrap();
        write_rule_to_dir(&dir, "rules/win_rule.yml", MINIMAL_RULE_YAML);

        let mut idx = RuleIndex::new();
        idx.load_from_dirs(
            &[rules_dir.as_path()],
            &HashSet::new(),
            &LoadFilter::default(),
        )
        .unwrap();

        let stats = idx.stats();
        assert_eq!(stats.rules_loaded, 1);
        assert_eq!(stats.rules_total_candidate, 1);
    }

    #[test]
    fn test_rule_index_load_with_skip_ids() {
        let dir = tempfile::tempdir().unwrap();
        let rules_dir = dir.path().join("rules");
        fs::create_dir(&rules_dir).unwrap();
        write_rule_to_dir(&dir, "rules/win_rule.yml", MINIMAL_RULE_YAML);

        let mut skip = HashSet::new();
        skip.insert("test-rule-001".to_string());

        let mut idx = RuleIndex::new();
        idx.load_from_dirs(&[rules_dir.as_path()], &skip, &LoadFilter::default())
            .unwrap();

        assert_eq!(idx.rule_count(), 0);
        assert_eq!(idx.skip_count(), 1);
        assert_eq!(idx.stats().rules_total_candidate, 0);
    }

    #[test]
    fn test_rule_index_exclude_updates_stats() {
        let dir = tempfile::tempdir().unwrap();
        let rules_dir = dir.path().join("rules");
        fs::create_dir(&rules_dir).unwrap();
        write_rule_to_dir(&dir, "rules/win_rule.yml", MINIMAL_RULE_YAML);

        let mut idx = RuleIndex::new();
        idx.load_from_dirs(
            &[rules_dir.as_path()],
            &HashSet::new(),
            &LoadFilter::default(),
        )
        .unwrap();

        assert_eq!(idx.stats().rules_loaded, 1);
        idx.exclude_rule_id("test-rule-001");
        assert_eq!(idx.stats().rules_loaded, 0);
        assert_eq!(idx.skip_count(), 1);

        idx.exclude_rule_id("test-rule-001");
        assert_eq!(idx.skip_count(), 1, "re-excluding must not double count");
    }
}
