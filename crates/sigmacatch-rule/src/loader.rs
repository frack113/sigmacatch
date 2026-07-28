// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 sigmacatch contributors

use crate::{parse_sigma_yaml, Level, SigmaCollection, Status};
use anyhow::Result;
use std::collections::HashSet;
use std::path::Path;
use tracing::info;

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
#[derive(Debug, Clone)]
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
    /// Target product (e.g. "windows", "linux", "macos").
    pub product: String,
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
            product: "windows".to_string(),
            min_status: Some(MinStatus::Stable),
            min_level: Some(MinLevel::Critical),
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

/// Sigma rule status with ordinal comparison.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, serde::Serialize, serde::Deserialize,
)]
#[serde(rename_all = "lowercase")]
pub enum MinStatus {
    Unsupported = 0,
    Deprecated = 1,
    Experimental = 2,
    Test = 3,
    Stable = 4,
}

impl MinStatus {
    pub fn accepts(&self, rule_status: &Status) -> bool {
        let threshold = *self as u8;
        let rule_val = match rule_status {
            Status::Unsupported => 0,
            Status::Deprecated => 1,
            Status::Experimental => 2,
            Status::Test => 3,
            Status::Stable => 4,
        };
        rule_val >= threshold
    }
}

impl From<&Status> for MinStatus {
    fn from(s: &Status) -> Self {
        match s {
            Status::Unsupported => MinStatus::Unsupported,
            Status::Deprecated => MinStatus::Deprecated,
            Status::Experimental => MinStatus::Experimental,
            Status::Test => MinStatus::Test,
            Status::Stable => MinStatus::Stable,
        }
    }
}

impl std::fmt::Display for MinStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MinStatus::Unsupported => write!(f, "unsupported"),
            MinStatus::Deprecated => write!(f, "deprecated"),
            MinStatus::Experimental => write!(f, "experimental"),
            MinStatus::Test => write!(f, "test"),
            MinStatus::Stable => write!(f, "stable"),
        }
    }
}

/// Parse a status string from YAML config.
impl std::str::FromStr for MinStatus {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "unsupported" => Ok(MinStatus::Unsupported),
            "deprecated" => Ok(MinStatus::Deprecated),
            "experimental" => Ok(MinStatus::Experimental),
            "test" => Ok(MinStatus::Test),
            "stable" => Ok(MinStatus::Stable),
            _ => Err(format!("Invalid status: '{}'", s)),
        }
    }
}

// ─── Level filtering ───────────────────────────────────────────────────────

/// Sigma rule level with ordinal comparison.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, serde::Serialize, serde::Deserialize,
)]
#[serde(rename_all = "lowercase")]
pub enum MinLevel {
    Informational = 0,
    Low = 1,
    Medium = 2,
    High = 3,
    Critical = 4,
}

impl MinLevel {
    pub fn accepts(&self, rule_level: &Level) -> bool {
        let threshold = *self as u8;
        let rule_val = match rule_level {
            Level::Informational => 0,
            Level::Low => 1,
            Level::Medium => 2,
            Level::High => 3,
            Level::Critical => 4,
        };
        rule_val >= threshold
    }
}

impl From<&Level> for MinLevel {
    fn from(l: &Level) -> Self {
        match l {
            Level::Informational => MinLevel::Informational,
            Level::Low => MinLevel::Low,
            Level::Medium => MinLevel::Medium,
            Level::High => MinLevel::High,
            Level::Critical => MinLevel::Critical,
        }
    }
}

impl std::fmt::Display for MinLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MinLevel::Informational => write!(f, "informational"),
            MinLevel::Low => write!(f, "low"),
            MinLevel::Medium => write!(f, "medium"),
            MinLevel::High => write!(f, "high"),
            MinLevel::Critical => write!(f, "critical"),
        }
    }
}

/// Parse a level string from YAML config.
impl std::str::FromStr for MinLevel {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "informational" => Ok(MinLevel::Informational),
            "low" => Ok(MinLevel::Low),
            "medium" => Ok(MinLevel::Medium),
            "high" => Ok(MinLevel::High),
            "critical" => Ok(MinLevel::Critical),
            _ => Err(format!("Invalid level: '{}'", s)),
        }
    }
}

// ─── Rule loading ──────────────────────────────────────────────────────────

/// Load all Sigma rules from the given directories, applying status/level filters
/// and skipping rules in the skip set.
pub fn load_all_rules(
    dirs: &[&Path],
    skip_ids: &HashSet<String>,
    filter: &LoadFilter,
) -> Result<LoadResult> {
    let mut collection = SigmaCollection::default();
    let mut rules_total_candidate: u64 = 0;
    let mut rules_filtered_status: u64 = 0;
    let mut rules_filtered_level: u64 = 0;

    let mut done = false;
    for dir in dirs {
        if done {
            break;
        }
        let mut pending = vec![dir.to_path_buf()];

        while let Some(current) = pending.pop() {
            if done {
                break;
            }
            if !current.exists() || !current.is_dir() {
                continue;
            }

            for entry in std::fs::read_dir(&current)?.flatten() {
                let path = entry.path();
                if path.is_file() {
                    if let Some(ext) = path.extension().and_then(|e| e.to_str()) {
                        if ext == "yml" || ext == "yaml" {
                            if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
                                if name == "index.yml" {
                                    continue;
                                }
                            }
                            if let Ok(metadata) = std::fs::metadata(&path) {
                                if metadata.len() > filter.max_rule_size as u64 {
                                    continue;
                                }
                            }
                            if let Ok(content) = std::fs::read_to_string(&path) {
                                if filter.max_rules > 0
                                    && collection.rules.len() >= filter.max_rules as usize
                                {
                                    done = true;
                                    break;
                                }
                                match parse_sigma_yaml(&content) {
                                    Ok(parsed) => {
                                        for rule in parsed.rules {
                                            let rule_id = rule.id.clone().unwrap_or_default();
                                            if rule.logsource.product.as_deref()
                                                != Some(&filter.product)
                                            {
                                                continue;
                                            }
                                            if skip_ids.contains(&rule_id) {
                                                continue;
                                            }
                                            rules_total_candidate += 1;

                                            if !filter.accepts_status(&rule.status) {
                                                rules_filtered_status += 1;
                                                continue;
                                            }

                                            if !filter.accepts_level(&rule.level) {
                                                rules_filtered_level += 1;
                                                continue;
                                            }

                                            collection.rules.push(rule);
                                        }
                                    }
                                    Err(e) => {
                                        info!("Failed to parse {:?}: {}", path, e);
                                    }
                                }
                            }
                        }
                    }
                } else if path.is_dir() {
                    pending.push(path);
                }
            }
        }
    }

    let rules_loaded = collection.rules.len() as u64;

    Ok(LoadResult {
        collection,
        stats: LoadStats {
            rules_loaded,
            rules_filtered_status,
            rules_filtered_level,
            rules_total_candidate,
        },
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
            product: "windows".to_string(),
            min_status: Some(MinStatus::Stable),
            min_level: Some(MinLevel::Critical),
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
            product: "windows".to_string(),
            min_status: Some(MinStatus::Stable),
            min_level: Some(MinLevel::Critical),
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
            product: "windows".to_string(),
            min_status: Some(MinStatus::Stable),
            min_level: Some(MinLevel::Critical),
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
            product: "windows".to_string(),
            min_status: Some(MinStatus::Stable),
            min_level: Some(MinLevel::Critical),
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
            product: "windows".to_string(),
            min_status: Some(MinStatus::Stable),
            min_level: Some(MinLevel::High),
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
            product: "windows".to_string(),
            min_status: Some(MinStatus::Stable),
            min_level: Some(MinLevel::Critical),
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
            product: "linux".to_string(),
            min_status: Some(MinStatus::Stable),
            min_level: Some(MinLevel::Critical),
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
            product: "macos".to_string(),
            min_status: Some(MinStatus::Stable),
            min_level: Some(MinLevel::Critical),
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
            product: "windows".to_string(),
            min_status: Some(MinStatus::Stable),
            min_level: Some(MinLevel::Critical),
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
            product: "windows".to_string(),
            min_status: Some(MinStatus::Stable),
            min_level: Some(MinLevel::Critical),
            max_rules: 0,
            max_rule_size: 1024,
        };
        let result = load_all_rules(&dirs, &HashSet::new(), &filter).unwrap();

        assert_eq!(result.stats.rules_loaded, 1);
    }
}
