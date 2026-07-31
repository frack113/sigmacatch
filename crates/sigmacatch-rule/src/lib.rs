// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 sigmacatch contributors

//! Sigma rule management: loading, filtering, scanning, AST indexing.
//!
//! `lib.rs` is the crate's single public surface — modules stay private and
//! only the re-exports below are part of the API.
//!
//! [`SigmahqRules`] is the engine view: the in-memory `SigmaRule`s loaded once
//! from disk. Regression info is carried by `Event` / `Alert` (sigmacatch-types),
//! not by the rules themselves.

pub use rsigma_parser::{
    parse_sigma_yaml, Detections, Level, LogSource, SigmaCollection, SigmaRule, Status,
};

pub use crate::loader::{load_all_rules, LoadFilter, LoadResult, LoadStats, MinLevel, MinStatus};
pub use crate::rule_index::RuleIndex;
pub use crate::scanner::find_rules_dirs;

pub(crate) mod channel_resolver;
pub(crate) mod loader;
pub(crate) mod rule_index;
pub(crate) mod scanner;

use crate::channel_resolver::resolve_channels;
use anyhow::Result;
use std::collections::{HashMap, HashSet};
use std::path::Path;

/// In-memory collection of loaded SigmaHQ rules — the engine view.
///
/// Rules are loaded once from disk; nothing here re-reads files afterwards.
#[derive(Debug, Clone, Default)]
pub struct SigmahqRules {
    rules: Vec<SigmaRule>,
    stats: LoadStats,
}

impl SigmahqRules {
    /// Load rules from `./sigma` (`rules` / `rules-*` directories) into memory.
    ///
    /// Loads every product; use [`SigmahqRules::filter_product`] and
    /// [`SigmahqRules::filter`] to prune the in-memory rules afterwards.
    pub fn new() -> Result<Self> {
        Self::init_from_sigma_path(Path::new("sigma"), &HashSet::new(), &LoadFilter::default())
    }

    /// Prune the loaded rules to those meeting the status/level thresholds.
    ///
    /// In-memory only — no disk access. Returns a new set with recomputed
    /// stats (cascade: status check first, then level).
    pub fn filter(self, min_status: Option<MinStatus>, min_level: Option<MinLevel>) -> Self {
        let total = self.rules.len() as u64;
        let mut filtered_status = 0u64;
        let mut filtered_level = 0u64;
        let mut rules = Vec::new();

        for rule in self.rules {
            let status_ok = match (&min_status, &rule.status) {
                (Some(threshold), Some(s)) => threshold.accepts(s),
                _ => true,
            };
            if !status_ok {
                filtered_status += 1;
                continue;
            }
            let level_ok = match (&min_level, &rule.level) {
                (Some(threshold), Some(l)) => threshold.accepts(l),
                _ => true,
            };
            if !level_ok {
                filtered_level += 1;
                continue;
            }
            rules.push(rule);
        }

        let rules_loaded = rules.len() as u64;
        Self {
            rules,
            stats: LoadStats {
                rules_loaded,
                rules_filtered_status: filtered_status,
                rules_filtered_level: filtered_level,
                rules_total_candidate: total,
            },
        }
    }

    /// Prune the loaded rules to those targeting the given product.
    ///
    /// In-memory only — no disk access. Rules with another (or no) product are
    /// dropped; stats are recomputed as if the product filter had been applied
    /// at load time (non-matching rules are not counted as candidates).
    pub fn filter_product(self, product: &str) -> Self {
        let rules: Vec<SigmaRule> = self
            .rules
            .into_iter()
            .filter(|r| r.logsource.product.as_deref() == Some(product))
            .collect();
        let rules_loaded = rules.len() as u64;
        Self {
            rules,
            stats: LoadStats {
                rules_loaded,
                rules_filtered_status: 0,
                rules_filtered_level: 0,
                rules_total_candidate: rules_loaded,
            },
        }
    }

    /// Load rules from a SigmaHQ repository root (`rules` / `rules-*`
    /// directories), applying `filter` and skipping rules whose IDs are in
    /// `skip_ids`.
    pub fn init_from_sigma_path(
        sigma_path: &Path,
        skip_ids: &HashSet<String>,
        filter: &LoadFilter,
    ) -> Result<Self> {
        let dirs = find_rules_dirs(sigma_path)?;
        if dirs.is_empty() {
            anyhow::bail!(
                "No rules directories found in {:?} — the repository may be empty or incomplete",
                sigma_path
            );
        }
        let dirs_refs: Vec<&Path> = dirs.iter().map(|d| d.as_path()).collect();
        Self::load(&dirs_refs, skip_ids, filter)
    }

    /// Load rules from the given directories, applying `filter` and skipping
    /// rules whose IDs are in `skip_ids`.
    pub fn load(dirs: &[&Path], skip_ids: &HashSet<String>, filter: &LoadFilter) -> Result<Self> {
        let mut set = SigmahqRules::default();

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
                                        && set.rules.len() >= filter.max_rules as usize
                                    {
                                        done = true;
                                        break;
                                    }
                                    if let Ok(parsed) = parse_sigma_yaml(&content) {
                                        for rule in parsed.rules {
                                            let rule_id = rule.id.clone().unwrap_or_default();
                                            if let Some(product) = &filter.product {
                                                if rule.logsource.product.as_deref()
                                                    != Some(product.as_str())
                                                {
                                                    continue;
                                                }
                                            }
                                            if skip_ids.contains(&rule_id) {
                                                continue;
                                            }
                                            set.stats.rules_total_candidate += 1;

                                            if !filter.accepts_status(&rule.status) {
                                                set.stats.rules_filtered_status += 1;
                                                continue;
                                            }

                                            if !filter.accepts_level(&rule.level) {
                                                set.stats.rules_filtered_level += 1;
                                                continue;
                                            }

                                            set.rules.push(rule);
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

        set.stats.rules_loaded = set.rules.len() as u64;
        Ok(set)
    }

    /// Borrow all loaded rules (engine view).
    pub fn rules(&self) -> &[SigmaRule] {
        &self.rules
    }

    /// Consume the set and return the loaded rules.
    pub fn into_rules(self) -> Vec<SigmaRule> {
        self.rules
    }

    /// Load statistics.
    pub fn stats(&self) -> &LoadStats {
        &self.stats
    }

    /// Iterator over the loaded rules.
    pub fn iter(&self) -> std::slice::Iter<'_, SigmaRule> {
        self.rules.iter()
    }

    /// Number of loaded rules.
    pub fn len(&self) -> usize {
        self.rules.len()
    }

    /// Whether no rule is loaded.
    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }

    /// Find a rule by ID.
    pub fn get(&self, id: &str) -> Option<&SigmaRule> {
        self.rules.iter().find(|r| r.id.as_deref() == Some(id))
    }

    /// Remove the rule with the given ID (UUID v4 string).
    ///
    /// Returns `true` if a rule was removed. Updates `rules_loaded` in stats.
    pub fn remove_id(&mut self, id: &str) -> bool {
        let before = self.rules.len();
        self.rules.retain(|r| r.id.as_deref() != Some(id));
        let removed = self.rules.len() != before;
        if removed {
            self.stats.rules_loaded = self.rules.len() as u64;
        }
        removed
    }

    /// Resolve the Windows Event Log channels needed by the loaded rules.
    ///
    /// Iterates the rules and collects one channel per logsource match,
    /// deduplicated (sorted). Strict resolution: an unmapped logsource
    /// contributes no channel and is reported via a warning.
    pub fn channels(&self, custom_map: &HashMap<String, String>) -> Vec<String> {
        resolve_channels(&self.rules, custom_map)
    }

    /// Build an rsigma `SigmaCollection` from the loaded rules.
    ///
    /// Clones the contained `SigmaRule`s — only needed to feed the detection
    /// engine; the set itself never re-reads from disk.
    pub fn to_collection(&self) -> SigmaCollection {
        let mut collection = SigmaCollection::new();
        collection.rules = self.rules.clone();
        collection
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    const MINIMAL_RULE: &str = r#"title: Test Rule
id: 11111111-1111-1111-1111-111111111111
status: stable
level: critical
author: Test Author
logsource:
  product: windows
  service: sysmon
  category: process_creation
detection:
  selection:
    EventID: 1
  condition: selection
"#;

    fn write_rules(dir: &Path, files: &[(&str, &str)]) {
        for (name, content) in files {
            fs::write(dir.join(name), content).unwrap();
        }
    }

    #[test]
    fn test_ruleset_load_with_filter() {
        let tmp = tempfile::tempdir().unwrap();
        let rules_dir = tmp.path().join("rules");
        fs::create_dir(&rules_dir).unwrap();

        let windows_low = MINIMAL_RULE
            .replace(
                "id: 11111111-1111-1111-1111-111111111111",
                "id: 22222222-2222-2222-2222-222222222222",
            )
            .replace("level: critical", "level: low");
        let linux_critical = MINIMAL_RULE.replace("  product: windows", "  product: linux");

        write_rules(
            &rules_dir,
            &[
                ("win_crit.yml", MINIMAL_RULE),
                ("win_low.yml", &windows_low),
                ("linux.yml", &linux_critical),
            ],
        );

        let dirs = vec![rules_dir.as_path()];
        let filter = LoadFilter {
            product: Some("windows".to_string()),
            min_status: Some(MinStatus(Status::Stable)),
            min_level: Some(MinLevel(Level::Critical)),
            max_rules: 0,
            max_rule_size: 1024 * 1024,
        };
        let set = SigmahqRules::load(&dirs, &HashSet::new(), &filter).unwrap();

        assert_eq!(set.len(), 1);
        assert_eq!(
            set.rules()[0].id.as_deref(),
            Some("11111111-1111-1111-1111-111111111111")
        );
        assert_eq!(set.stats().rules_loaded, 1);
        assert_eq!(set.stats().rules_total_candidate, 2);
        assert_eq!(set.stats().rules_filtered_level, 1);
        assert_eq!(set.stats().rules_filtered_status, 0);
    }

    #[test]
    fn test_ruleset_skip_ids() {
        let tmp = tempfile::tempdir().unwrap();
        let rules_dir = tmp.path().join("rules");
        fs::create_dir(&rules_dir).unwrap();
        write_rules(&rules_dir, &[("win.yml", MINIMAL_RULE)]);

        let mut skip = HashSet::new();
        skip.insert("11111111-1111-1111-1111-111111111111".to_string());

        let dirs = vec![rules_dir.as_path()];
        let set = SigmahqRules::load(&dirs, &skip, &LoadFilter::default()).unwrap();

        assert!(set.is_empty());
        assert_eq!(set.stats().rules_total_candidate, 0);
    }

    #[test]
    fn test_ruleset_get() {
        let tmp = tempfile::tempdir().unwrap();
        let rules_dir = tmp.path().join("rules");
        fs::create_dir(&rules_dir).unwrap();
        write_rules(&rules_dir, &[("win.yml", MINIMAL_RULE)]);

        let dirs = vec![rules_dir.as_path()];
        let set = SigmahqRules::load(&dirs, &HashSet::new(), &LoadFilter::default()).unwrap();

        assert!(set.get("11111111-1111-1111-1111-111111111111").is_some());
        assert!(set.get("unknown-id").is_none());
    }

    #[test]
    fn test_ruleset_to_collection() {
        let tmp = tempfile::tempdir().unwrap();
        let rules_dir = tmp.path().join("rules");
        fs::create_dir(&rules_dir).unwrap();
        write_rules(&rules_dir, &[("win.yml", MINIMAL_RULE)]);

        let dirs = vec![rules_dir.as_path()];
        let set = SigmahqRules::load(&dirs, &HashSet::new(), &LoadFilter::default()).unwrap();

        let collection = set.to_collection();
        assert_eq!(collection.rules.len(), 1);
        assert_eq!(
            collection.rules[0].id.as_deref(),
            Some("11111111-1111-1111-1111-111111111111")
        );
    }

    #[test]
    fn test_ruleset_init_from_sigma_path() {
        let tmp = tempfile::tempdir().unwrap();
        let sigma = tmp.path().join("sigma");
        let rules = sigma.join("rules");
        let rules_windows = sigma.join("rules-windows");
        fs::create_dir_all(&rules).unwrap();
        fs::create_dir_all(&rules_windows).unwrap();
        write_rules(&rules, &[("win.yml", MINIMAL_RULE)]);

        let mut other = MINIMAL_RULE.to_string();
        other = other.replace(
            "id: 11111111-1111-1111-1111-111111111111",
            "id: 22222222-2222-2222-2222-222222222222",
        );
        write_rules(&rules_windows, &[("win2.yml", &other)]);

        let set =
            SigmahqRules::init_from_sigma_path(&sigma, &HashSet::new(), &LoadFilter::default())
                .unwrap();

        assert_eq!(set.len(), 2);
        assert_eq!(set.stats().rules_loaded, 2);
    }

    #[test]
    fn test_ruleset_init_from_sigma_path_empty() {
        let tmp = tempfile::tempdir().unwrap();
        let err =
            SigmahqRules::init_from_sigma_path(tmp.path(), &HashSet::new(), &LoadFilter::default())
                .unwrap_err();
        assert!(err.to_string().contains("No rules directories found"));
    }

    #[test]
    fn test_ruleset_filter_thresholds() {
        let tmp = tempfile::tempdir().unwrap();
        let rules_dir = tmp.path().join("rules");
        fs::create_dir(&rules_dir).unwrap();

        let windows_low = MINIMAL_RULE
            .replace(
                "id: 11111111-1111-1111-1111-111111111111",
                "id: 22222222-2222-2222-2222-222222222222",
            )
            .replace("level: critical", "level: low");

        write_rules(
            &rules_dir,
            &[
                ("win_crit.yml", MINIMAL_RULE),
                ("win_low.yml", &windows_low),
            ],
        );

        let dirs = vec![rules_dir.as_path()];
        let filter = LoadFilter {
            min_status: None,
            min_level: None,
            ..LoadFilter::default()
        };
        let set = SigmahqRules::load(&dirs, &HashSet::new(), &filter).unwrap();
        assert_eq!(set.len(), 2);

        let filtered = set.filter(
            Some(MinStatus(Status::Stable)),
            Some(MinLevel(Level::Critical)),
        );
        assert_eq!(filtered.len(), 1);
        assert_eq!(
            filtered.rules()[0].id.as_deref(),
            Some("11111111-1111-1111-1111-111111111111")
        );
        assert_eq!(filtered.stats().rules_loaded, 1);
        assert_eq!(filtered.stats().rules_total_candidate, 2);
        assert_eq!(filtered.stats().rules_filtered_status, 0);
        assert_eq!(filtered.stats().rules_filtered_level, 1);
    }

    #[test]
    fn test_ruleset_filter_no_thresholds_is_noop() {
        let tmp = tempfile::tempdir().unwrap();
        let rules_dir = tmp.path().join("rules");
        fs::create_dir(&rules_dir).unwrap();
        write_rules(&rules_dir, &[("win.yml", MINIMAL_RULE)]);

        let dirs = vec![rules_dir.as_path()];
        let set = SigmahqRules::load(&dirs, &HashSet::new(), &LoadFilter::default()).unwrap();

        let filtered = set.filter(None, None);
        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered.stats().rules_loaded, 1);
        assert_eq!(filtered.stats().rules_total_candidate, 1);
    }

    #[test]
    fn test_ruleset_filter_product() {
        let tmp = tempfile::tempdir().unwrap();
        let rules_dir = tmp.path().join("rules");
        fs::create_dir(&rules_dir).unwrap();

        let linux_critical = MINIMAL_RULE.replace("  product: windows", "  product: linux");
        write_rules(
            &rules_dir,
            &[("win.yml", MINIMAL_RULE), ("linux.yml", &linux_critical)],
        );

        let dirs = vec![rules_dir.as_path()];

        let windows = SigmahqRules::load(&dirs, &HashSet::new(), &LoadFilter::default())
            .unwrap()
            .filter_product("windows");
        assert_eq!(windows.len(), 1);
        assert_eq!(
            windows.rules()[0].id.as_deref(),
            Some("11111111-1111-1111-1111-111111111111")
        );
        assert_eq!(windows.stats().rules_loaded, 1);
        assert_eq!(windows.stats().rules_total_candidate, 1);

        let linux_filter = LoadFilter {
            product: Some("linux".to_string()),
            ..LoadFilter::default()
        };
        let linux = SigmahqRules::load(&dirs, &HashSet::new(), &linux_filter)
            .unwrap()
            .filter_product("linux");
        assert_eq!(linux.len(), 1);
        assert_eq!(linux.stats().rules_total_candidate, 1);

        let none = linux.filter_product("macos");
        assert!(none.is_empty());
        assert_eq!(none.stats().rules_total_candidate, 0);
    }

    #[test]
    fn test_ruleset_remove_id() {
        let tmp = tempfile::tempdir().unwrap();
        let rules_dir = tmp.path().join("rules");
        fs::create_dir(&rules_dir).unwrap();

        let windows_low = MINIMAL_RULE
            .replace(
                "id: 11111111-1111-1111-1111-111111111111",
                "id: 22222222-2222-2222-2222-222222222222",
            )
            .replace("level: critical", "level: low");
        write_rules(
            &rules_dir,
            &[
                ("win_crit.yml", MINIMAL_RULE),
                ("win_low.yml", &windows_low),
            ],
        );

        let dirs = vec![rules_dir.as_path()];
        let filter = LoadFilter {
            min_status: None,
            min_level: None,
            ..LoadFilter::default()
        };
        let mut set = SigmahqRules::load(&dirs, &HashSet::new(), &filter).unwrap();
        assert_eq!(set.len(), 2);

        assert!(set.remove_id("11111111-1111-1111-1111-111111111111"));
        assert_eq!(set.len(), 1);
        assert_eq!(set.stats().rules_loaded, 1);
        assert!(set.get("22222222-2222-2222-2222-222222222222").is_some());

        assert!(!set.remove_id("00000000-0000-0000-0000-000000000000"));
        assert_eq!(set.len(), 1);
    }

    #[test]
    fn test_ruleset_channels_dedup() {
        let tmp = tempfile::tempdir().unwrap();
        let rules_dir = tmp.path().join("rules");
        fs::create_dir(&rules_dir).unwrap();

        let service_only = MINIMAL_RULE
            .replace(
                "id: 11111111-1111-1111-1111-111111111111",
                "id: 22222222-2222-2222-2222-222222222222",
            )
            .replace("  category: process_creation\n", "");
        let linux = MINIMAL_RULE
            .replace(
                "id: 11111111-1111-1111-1111-111111111111",
                "id: 33333333-3333-3333-3333-333333333333",
            )
            .replace("  product: windows", "  product: linux");

        write_rules(
            &rules_dir,
            &[
                ("a_sysmon_proc.yml", MINIMAL_RULE),
                ("b_sysmon_only.yml", &service_only),
                ("c_linux.yml", &linux),
            ],
        );

        let dirs = vec![rules_dir.as_path()];
        let filter = LoadFilter {
            min_status: None,
            min_level: None,
            ..LoadFilter::default()
        };
        let set = SigmahqRules::load(&dirs, &HashSet::new(), &filter).unwrap();
        assert_eq!(set.len(), 3);

        let channels = set.channels(&HashMap::new());
        assert_eq!(channels, vec!["Microsoft-Windows-Sysmon/Operational"]);
    }
}
