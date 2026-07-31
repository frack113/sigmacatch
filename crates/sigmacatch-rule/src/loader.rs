// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 sigmacatch contributors

use crate::SigmahqRules;
use crate::{Level, SigmaCollection, Status};
use anyhow::Result;
use std::collections::HashSet;
use std::path::Path;

/// Statistics returned by `load_all_rules`.
///
/// Invariant: `rules_loaded + rules_filtered_status + rules_filtered_level == rules_total_candidate`.
/// Each candidate rule is counted in exactly one bucket. Cascade filtering means a rule with both
/// bad status AND bad level is counted only in `rules_filtered_status` (level check never fires).
///
/// `rules_total_candidate` = rules matching `filter.product` that passed the skip set check (before status/level filtering).
/// `rules_filtered_status` = rules rejected because their status is below `min_status`.
/// `rules_filtered_level` = rules that passed status check but were rejected because their level is below `min_level`.
/// `rules_loaded` = rules that passed all filters and were added to the collection.
#[derive(Debug, Clone, Default)]
pub struct LoadStats {
    /// Rules added to the collection (passed all filters).
    pub rules_loaded: u64,
    /// Rules filtered out because their `status` is below the configured threshold.
    pub rules_filtered_status: u64,
    /// Rules filtered out because their `level` is below the configured threshold (passed status check).
    pub rules_filtered_level: u64,
    /// Total Windows rules that passed the skip set check (before status/level filtering).
    pub rules_total_candidate: u64,
}

/// Result of loading rules: the SigmaCollection and associated load statistics.
pub struct LoadResult {
    pub collection: SigmaCollection,
    pub stats: LoadStats,
}

/// Filter configuration for loading Sigma rules.
///
/// Controls which rules are loaded based on product, status, level thresholds,
/// and resource limits.
#[derive(Debug, Clone)]
pub struct LoadFilter {
    /// Target product (e.g. "windows", "linux", "macos"). `None` = no
    /// product restriction.
    pub product: Option<String>,
    /// Minimum status threshold.
    pub min_status: Option<MinStatus>,
    /// Minimum level threshold.
    pub min_level: Option<MinLevel>,
    /// Maximum number of rules to load (0 = unlimited).
    pub max_rules: u64,
    /// Maximum rule file size in bytes.
    pub max_rule_size: usize,
}

impl Default for LoadFilter {
    fn default() -> Self {
        Self {
            product: None,
            min_status: Some(MinStatus(Status::Stable)),
            min_level: Some(MinLevel(Level::Critical)),
            max_rules: 0,
            max_rule_size: 1024 * 1024,
        }
    }
}

impl LoadFilter {
    pub fn accepts_status(&self, status: &Option<Status>) -> bool {
        match (&self.min_status, status) {
            (Some(threshold), Some(s)) => threshold.accepts(s),
            _ => true,
        }
    }

    pub fn accepts_level(&self, level: &Option<Level>) -> bool {
        match (&self.min_level, level) {
            (Some(threshold), Some(l)) => threshold.accepts(l),
            _ => true,
        }
    }
}

// ─── Status filtering ──────────────────────────────────────────────────────

/// Minimum Sigma rule status threshold (newtype over rsigma's `Status` with
/// ordinal ordering). `accepts` is inclusive: a rule is loaded when its status
/// is at least the configured threshold.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(transparent)]
pub struct MinStatus(pub Status);

impl MinStatus {
    fn rank(&self) -> u8 {
        match self.0 {
            Status::Unsupported => 0,
            Status::Deprecated => 1,
            Status::Experimental => 2,
            Status::Test => 3,
            Status::Stable => 4,
        }
    }

    pub fn accepts(&self, rule_status: &Status) -> bool {
        let rule_rank = match rule_status {
            Status::Unsupported => 0,
            Status::Deprecated => 1,
            Status::Experimental => 2,
            Status::Test => 3,
            Status::Stable => 4,
        };
        rule_rank >= self.rank()
    }
}

impl Default for MinStatus {
    fn default() -> Self {
        MinStatus(Status::Stable)
    }
}

impl PartialOrd for MinStatus {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for MinStatus {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.rank().cmp(&other.rank())
    }
}

impl std::fmt::Display for MinStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self.0 {
            Status::Unsupported => "unsupported",
            Status::Deprecated => "deprecated",
            Status::Experimental => "experimental",
            Status::Test => "test",
            Status::Stable => "stable",
        };
        write!(f, "{s}")
    }
}

// ─── Level filtering ───────────────────────────────────────────────────────

/// Minimum Sigma rule level threshold (newtype over rsigma's `Level` with
/// ordinal ordering). `accepts` is inclusive: a rule is loaded when its level
/// is at least the configured threshold.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(transparent)]
pub struct MinLevel(pub Level);

impl MinLevel {
    fn rank(&self) -> u8 {
        match self.0 {
            Level::Informational => 0,
            Level::Low => 1,
            Level::Medium => 2,
            Level::High => 3,
            Level::Critical => 4,
        }
    }

    pub fn accepts(&self, rule_level: &Level) -> bool {
        let rule_rank = match rule_level {
            Level::Informational => 0,
            Level::Low => 1,
            Level::Medium => 2,
            Level::High => 3,
            Level::Critical => 4,
        };
        rule_rank >= self.rank()
    }
}

impl Default for MinLevel {
    fn default() -> Self {
        MinLevel(Level::Critical)
    }
}

impl PartialOrd for MinLevel {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for MinLevel {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.rank().cmp(&other.rank())
    }
}

impl std::fmt::Display for MinLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self.0 {
            Level::Informational => "informational",
            Level::Low => "low",
            Level::Medium => "medium",
            Level::High => "high",
            Level::Critical => "critical",
        };
        write!(f, "{s}")
    }
}

// ─── Rule loading ──────────────────────────────────────────────────────────

/// Load all Sigma rules from the given directories, applying status/level filters
/// and skipping rules in the skip set.
///
/// Thin adapter over [`SigmahqRules::load`] that returns the engine-facing
/// `SigmaCollection`. Use `SigmahqRules` directly when the in-memory rules
/// (raw YAML + source path) must be kept without re-reading from disk.
pub fn load_all_rules(
    dirs: &[&Path],
    skip_ids: &HashSet<String>,
    filter: &LoadFilter,
) -> Result<LoadResult> {
    let set = SigmahqRules::load(dirs, skip_ids, filter)?;
    Ok(LoadResult {
        collection: set.to_collection(),
        stats: set.stats().clone(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn make_rule_yaml(
        title: &str,
        status: Option<&str>,
        level: Option<&str>,
        event_id: Option<u16>,
    ) -> String {
        let mut yaml = format!(
            "id: test_uuid\ntitle: {title}\nlogsource:\n  product: windows\ndetection:\n  sel:\n    EventID: {eid}\n  condition:\n    - sel\n",
            eid = event_id.map(|v| v.to_string()).unwrap_or_default()
        );
        if let Some(s) = status {
            yaml.push_str(&format!("status: {s}\n"));
        }
        if let Some(l) = level {
            yaml.push_str(&format!("level: {l}\n"));
        }
        yaml
    }

    #[test]
    fn test_filter_status_experimental_below_stable() {
        let tmp = tempfile::tempdir().unwrap();
        let rules_dir = tmp.path().join("rules");
        fs::create_dir(&rules_dir).unwrap();
        fs::write(
            rules_dir.join("test_rule.yml"),
            make_rule_yaml("test rule", Some("experimental"), Some("high"), Some(1)),
        )
        .unwrap();

        let dirs = vec![rules_dir.as_path()];
        let filter = LoadFilter {
            product: Some("windows".to_string()),
            min_status: Some(MinStatus(Status::Stable)),
            min_level: Some(MinLevel(Level::Critical)),
            max_rules: 0,
            max_rule_size: 1024 * 1024,
        };
        let result = load_all_rules(&dirs, &HashSet::new(), &filter).unwrap();

        assert_eq!(result.stats.rules_loaded, 0);
        assert_eq!(result.stats.rules_filtered_status, 1);
        assert_eq!(result.stats.rules_filtered_level, 0);
        assert_eq!(result.stats.rules_total_candidate, 1);
        assert!(result.collection.rules.is_empty());
    }

    #[test]
    fn test_filter_level_informational_below_critical() {
        let tmp = tempfile::tempdir().unwrap();
        let rules_dir = tmp.path().join("rules");
        fs::create_dir(&rules_dir).unwrap();
        fs::write(
            rules_dir.join("test_rule.yml"),
            make_rule_yaml("test rule", Some("stable"), Some("informational"), Some(1)),
        )
        .unwrap();

        let dirs = vec![rules_dir.as_path()];
        let filter = LoadFilter {
            product: Some("windows".to_string()),
            min_status: Some(MinStatus(Status::Stable)),
            min_level: Some(MinLevel(Level::Critical)),
            max_rules: 0,
            max_rule_size: 1024 * 1024,
        };
        let result = load_all_rules(&dirs, &HashSet::new(), &filter).unwrap();

        assert_eq!(result.stats.rules_loaded, 0);
        assert_eq!(result.stats.rules_filtered_status, 0);
        assert_eq!(result.stats.rules_filtered_level, 1);
        assert_eq!(result.stats.rules_total_candidate, 1);
        assert!(result.collection.rules.is_empty());
    }

    #[test]
    fn test_pass_through_no_status_no_level() {
        let tmp = tempfile::tempdir().unwrap();
        let rules_dir = tmp.path().join("rules");
        fs::create_dir(&rules_dir).unwrap();
        fs::write(
            rules_dir.join("test_rule.yml"),
            make_rule_yaml("test rule", None, None, Some(1)),
        )
        .unwrap();

        let dirs = vec![rules_dir.as_path()];
        let filter = LoadFilter {
            product: Some("windows".to_string()),
            min_status: Some(MinStatus(Status::Stable)),
            min_level: Some(MinLevel(Level::Critical)),
            max_rules: 0,
            max_rule_size: 1024 * 1024,
        };
        let result = load_all_rules(&dirs, &HashSet::new(), &filter).unwrap();

        assert_eq!(result.stats.rules_loaded, 1);
        assert_eq!(result.stats.rules_filtered_status, 0);
        assert_eq!(result.stats.rules_filtered_level, 0);
        assert_eq!(result.stats.rules_total_candidate, 1);
        assert_eq!(result.collection.rules.len(), 1);
    }

    #[test]
    fn test_cascade_status_then_level() {
        let tmp = tempfile::tempdir().unwrap();
        let rules_dir = tmp.path().join("rules");
        fs::create_dir(&rules_dir).unwrap();
        fs::write(
            rules_dir.join("test_rule.yml"),
            make_rule_yaml(
                "test rule",
                Some("experimental"),
                Some("informational"),
                Some(1),
            ),
        )
        .unwrap();

        let dirs = vec![rules_dir.as_path()];
        let filter = LoadFilter {
            product: Some("windows".to_string()),
            min_status: Some(MinStatus(Status::Stable)),
            min_level: Some(MinLevel(Level::Critical)),
            max_rules: 0,
            max_rule_size: 1024 * 1024,
        };
        let result = load_all_rules(&dirs, &HashSet::new(), &filter).unwrap();

        assert_eq!(result.stats.rules_loaded, 0);
        assert_eq!(result.stats.rules_filtered_status, 1);
        assert_eq!(result.stats.rules_filtered_level, 0);
        assert_eq!(result.stats.rules_total_candidate, 1);
    }

    #[test]
    fn test_pass_stable_high() {
        let tmp = tempfile::tempdir().unwrap();
        let rules_dir = tmp.path().join("rules");
        fs::create_dir(&rules_dir).unwrap();
        fs::write(
            rules_dir.join("test_rule.yml"),
            make_rule_yaml("test rule", Some("stable"), Some("high"), Some(1)),
        )
        .unwrap();

        let dirs = vec![rules_dir.as_path()];
        let filter = LoadFilter {
            product: Some("windows".to_string()),
            min_status: Some(MinStatus(Status::Stable)),
            min_level: Some(MinLevel(Level::High)),
            max_rules: 0,
            max_rule_size: 1024 * 1024,
        };
        let result = load_all_rules(&dirs, &HashSet::new(), &filter).unwrap();

        assert_eq!(result.stats.rules_loaded, 1);
        assert_eq!(result.stats.rules_filtered_status, 0);
        assert_eq!(result.stats.rules_filtered_level, 0);
        assert_eq!(result.stats.rules_total_candidate, 1);
    }

    #[test]
    fn test_skip_set_prevents_counting() {
        let tmp = tempfile::tempdir().unwrap();
        let rules_dir = tmp.path().join("rules");
        fs::create_dir(&rules_dir).unwrap();
        fs::write(
            rules_dir.join("test_rule.yml"),
            make_rule_yaml("test rule", Some("stable"), Some("critical"), Some(1)),
        )
        .unwrap();

        let dirs = vec![rules_dir.as_path()];
        let mut skip = HashSet::new();
        skip.insert("test_uuid".to_string());
        let filter = LoadFilter::default();
        let result = load_all_rules(&dirs, &skip, &filter).unwrap();

        assert_eq!(result.stats.rules_loaded, 0);
        assert_eq!(result.stats.rules_total_candidate, 0);
    }

    #[test]
    fn test_filter_product_windows_loads_windows_rules() {
        let tmp = tempfile::tempdir().unwrap();
        let rules_dir = tmp.path().join("rules");
        fs::create_dir(&rules_dir).unwrap();
        fs::write(
            rules_dir.join("rule_windows.yml"),
            make_rule_yaml("windows rule", Some("stable"), Some("critical"), Some(1)),
        )
        .unwrap();
        fs::write(
            rules_dir.join("rule_linux.yml"),
            "id: test_uuid2\ntitle: linux rule\nlogsource:\n  product: linux\ndetection:\n  sel:\n    EventID: 1\n  condition:\n    - sel\n",
        )
        .unwrap();

        let dirs = vec![rules_dir.as_path()];
        let filter = LoadFilter {
            product: Some("windows".to_string()),
            min_status: Some(MinStatus(Status::Stable)),
            min_level: Some(MinLevel(Level::Critical)),
            max_rules: 0,
            max_rule_size: 1024 * 1024,
        };
        let result = load_all_rules(&dirs, &HashSet::new(), &filter).unwrap();

        assert_eq!(result.stats.rules_loaded, 1);
        assert_eq!(result.stats.rules_total_candidate, 1);
    }

    #[test]
    fn test_filter_product_linux_loads_linux_rules() {
        let tmp = tempfile::tempdir().unwrap();
        let rules_dir = tmp.path().join("rules");
        fs::create_dir(&rules_dir).unwrap();
        fs::write(
            rules_dir.join("rule_linux.yml"),
            "id: test_uuid2\ntitle: linux rule\nlogsource:\n  product: linux\ndetection:\n  sel:\n    EventID: 1\n  condition:\n    - sel\n",
        )
        .unwrap();
        fs::write(
            rules_dir.join("rule_windows.yml"),
            make_rule_yaml("windows rule", Some("stable"), Some("critical"), Some(1)),
        )
        .unwrap();

        let dirs = vec![rules_dir.as_path()];
        let filter = LoadFilter {
            product: Some("linux".to_string()),
            min_status: Some(MinStatus(Status::Stable)),
            min_level: Some(MinLevel(Level::Critical)),
            max_rules: 0,
            max_rule_size: 1024 * 1024,
        };
        let result = load_all_rules(&dirs, &HashSet::new(), &filter).unwrap();

        assert_eq!(result.stats.rules_loaded, 1);
        assert_eq!(result.stats.rules_total_candidate, 1);
    }

    #[test]
    fn test_filter_product_macos_loads_macos_rules() {
        let tmp = tempfile::tempdir().unwrap();
        let rules_dir = tmp.path().join("rules");
        fs::create_dir(&rules_dir).unwrap();
        fs::write(
            rules_dir.join("rule_macos.yml"),
            "id: test_uuid3\ntitle: macos rule\nlogsource:\n  product: macos\ndetection:\n  sel:\n    EventID: 1\n  condition:\n    - sel\n",
        )
        .unwrap();

        let dirs = vec![rules_dir.as_path()];
        let filter = LoadFilter {
            product: Some("macos".to_string()),
            min_status: Some(MinStatus(Status::Stable)),
            min_level: Some(MinLevel(Level::Critical)),
            max_rules: 0,
            max_rule_size: 1024 * 1024,
        };
        let result = load_all_rules(&dirs, &HashSet::new(), &filter).unwrap();

        assert_eq!(result.stats.rules_loaded, 1);
        assert_eq!(result.stats.rules_total_candidate, 1);
    }

    #[test]
    fn test_max_rules_limits_loaded_rules() {
        let tmp = tempfile::tempdir().unwrap();
        let rules_dir = tmp.path().join("rules");
        fs::create_dir(&rules_dir).unwrap();
        for i in 0..5 {
            let content = format!(
                "id: test_rule_{i}\ntitle: rule {i}\nlogsource:\n  product: windows\ndetection:\n  sel:\n    EventID: {i}\n  condition:\n    - sel\n"
            );
            fs::write(rules_dir.join(format!("rule_{i}.yml")), content).unwrap();
        }

        let dirs = vec![rules_dir.as_path()];
        let filter = LoadFilter {
            product: Some("windows".to_string()),
            min_status: Some(MinStatus(Status::Stable)),
            min_level: Some(MinLevel(Level::Critical)),
            max_rules: 3,
            max_rule_size: 1024 * 1024,
        };
        let result = load_all_rules(&dirs, &HashSet::new(), &filter).unwrap();

        assert!(result.stats.rules_loaded <= 3);
        assert_eq!(
            result.collection.rules.len() as u64,
            result.stats.rules_loaded
        );
    }

    #[test]
    fn test_max_rule_size_filters_large_files() {
        let tmp = tempfile::tempdir().unwrap();
        let rules_dir = tmp.path().join("rules");
        fs::create_dir(&rules_dir).unwrap();
        let small_content = make_rule_yaml("small rule", Some("stable"), Some("critical"), Some(1));
        let large_content = format!(
            "{}\ndetection:\n  sel:\n    EventID: 1\n    Padding:\n{}",
            small_content.trim(),
            "A".repeat(50000)
        );
        fs::write(rules_dir.join("small.yml"), small_content).unwrap();
        fs::write(rules_dir.join("large.yml"), large_content).unwrap();

        let dirs = vec![rules_dir.as_path()];
        let filter = LoadFilter {
            product: Some("windows".to_string()),
            min_status: Some(MinStatus(Status::Stable)),
            min_level: Some(MinLevel(Level::Critical)),
            max_rules: 0,
            max_rule_size: 1024,
        };
        let result = load_all_rules(&dirs, &HashSet::new(), &filter).unwrap();

        assert_eq!(result.stats.rules_loaded, 1);
    }

    // ─── MinStatus / MinLevel newtype behavior ─────────────────────────

    #[test]
    fn test_min_status_serde_roundtrip_lowercase() {
        let yaml = serde_yaml::to_string(&MinStatus(Status::Stable)).unwrap();
        assert_eq!(yaml.trim(), "stable");
        let parsed: MinStatus = serde_yaml::from_str("experimental").unwrap();
        assert_eq!(parsed, MinStatus(Status::Experimental));
    }

    #[test]
    fn test_min_level_serde_roundtrip_lowercase() {
        let yaml = serde_yaml::to_string(&MinLevel(Level::Critical)).unwrap();
        assert_eq!(yaml.trim(), "critical");
        let parsed: MinLevel = serde_yaml::from_str("high").unwrap();
        assert_eq!(parsed, MinLevel(Level::High));
    }

    #[test]
    fn test_min_status_default_stable() {
        assert_eq!(MinStatus::default(), MinStatus(Status::Stable));
        assert_eq!(MinLevel::default(), MinLevel(Level::Critical));
    }

    #[test]
    fn test_min_status_ordinal_order() {
        assert!(MinStatus(Status::Stable) > MinStatus(Status::Test));
        assert!(MinStatus(Status::Test) > MinStatus(Status::Experimental));
        assert!(MinStatus(Status::Experimental) > MinStatus(Status::Deprecated));
        assert!(MinStatus(Status::Deprecated) > MinStatus(Status::Unsupported));
        assert!(MinStatus(Status::Unsupported) >= MinStatus(Status::Unsupported));
    }

    #[test]
    fn test_min_level_ordinal_order() {
        assert!(MinLevel(Level::Critical) > MinLevel(Level::High));
        assert!(MinLevel(Level::High) > MinLevel(Level::Medium));
        assert!(MinLevel(Level::Medium) > MinLevel(Level::Low));
        assert!(MinLevel(Level::Low) > MinLevel(Level::Informational));
    }

    #[test]
    fn test_min_status_display_lowercase() {
        assert_eq!(MinStatus(Status::Stable).to_string(), "stable");
        assert_eq!(MinLevel(Level::Critical).to_string(), "critical");
    }
}
