// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 sigmacatch contributors

//! Sigma rule management: loading, filtering, discovering, AST indexing.

pub use rsigma_parser::{parse_sigma_yaml, Level, LogSource, SigmaCollection, SigmaRule, Status};

pub(crate) use crate::discover::find_rules_dirs;
pub use crate::thresholds::{LoadStats, MinLevel, MinStatus};

pub(crate) mod channel_resolver;
pub(crate) mod discover;
pub(crate) mod thresholds;

// Note: init_from_sigma_path was removed; use SigmahqRules::new() for production,
// SigmahqRules::new_from_path() for tests with custom directories.

use crate::channel_resolver::resolve_channels;
use anyhow::Result;
use std::collections::{HashMap, HashSet};
use std::path::Path;
use uuid::Uuid;

#[derive(Debug, Clone, Default)]
pub struct SigmahqRules {
    rules: Vec<SigmaRule>,
    stats: LoadStats,
}

impl SigmahqRules {
    pub fn new() -> Result<Self> {
        Self::new_from_path(Path::new("./sigma"))
    }

    pub fn new_from_path(sigma_path: &Path) -> Result<Self> {
        let dirs = find_rules_dirs(sigma_path)?;
        if dirs.is_empty() {
            anyhow::bail!(
                "No rules directories found in {:?} — the repository may be empty or incomplete",
                sigma_path
            );
        }
        let mut set = SigmahqRules::default();
        let mut seen_ids: HashSet<String> = HashSet::new();
        let mut skipped_dupes: u64 = 0;
        let mut skipped_parse_errors: u64 = 0;
        for dir in &dirs {
            let mut pending = vec![dir.clone()];
            while let Some(current) = pending.pop() {
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
                                if let Ok(content) = std::fs::read_to_string(&path) {
                                    if let Ok(parsed) = parse_sigma_yaml(&content) {
                                        for rule in parsed.rules {
                                            let id = rule.id.clone().unwrap_or_else(|| {
                                                format!("no-id-{}", path.display())
                                            });
                                            if seen_ids.insert(id.clone()) {
                                                set.rules.push(rule);
                                            } else {
                                                skipped_dupes += 1;
                                                tracing::debug!(
                                                    "Skipping duplicate rule id={id} from {path:?}"
                                                );
                                            }
                                        }
                                    } else {
                                        skipped_parse_errors += 1;
                                        tracing::warn!(
                                            "Failed to parse Sigma rule at {path:?} — skipping"
                                        );
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
        set.stats.rules_total_candidate = set.rules.len() as u64;
        if skipped_dupes > 0 {
            tracing::warn!("{skipped_dupes} duplicate rules skipped");
        }
        if skipped_parse_errors > 0 {
            tracing::warn!("{skipped_parse_errors} rule files failed to parse");
        }
        Ok(set)
    }

    pub fn filter(
        self,
        product: Option<&str>,
        min_status: Option<MinStatus>,
        min_level: Option<MinLevel>,
    ) -> Self {
        let total = self.rules.len() as u64;
        let mut filtered_product = 0u64;
        let mut filtered_status = 0u64;
        let mut filtered_level = 0u64;
        let mut rules = Vec::new();

        for rule in self.rules {
            let product_ok = match product {
                Some(p) => rule.logsource.product.as_deref() == Some(p),
                None => true,
            };
            if !product_ok {
                filtered_product += 1;
                continue;
            }
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
                rules_filtered_product: filtered_product,
                rules_filtered_status: filtered_status,
                rules_filtered_level: filtered_level,
                rules_total_candidate: total,
            },
        }
    }

    pub fn rules(&self) -> &[SigmaRule] {
        &self.rules
    }

    pub fn into_rules(self) -> Vec<SigmaRule> {
        self.rules
    }

    pub fn stats(&self) -> &LoadStats {
        &self.stats
    }

    pub fn iter(&self) -> std::slice::Iter<'_, SigmaRule> {
        self.rules.iter()
    }

    pub fn len(&self) -> usize {
        self.rules.len()
    }

    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }

    pub fn get(&self, id: &Uuid) -> Option<&SigmaRule> {
        let id_str = id.to_string();
        self.rules
            .iter()
            .find(|r| r.id.as_deref() == Some(id_str.as_str()))
    }

    pub fn remove_id(&mut self, id: &Uuid) -> bool {
        let id_str = id.to_string();
        let before = self.rules.len();
        self.rules
            .retain(|r| r.id.as_deref() != Some(id_str.as_str()));
        self.rules.len() != before
    }

    pub fn channels(&self, custom_map: &HashMap<String, String>) -> Vec<String> {
        resolve_channels(&self.rules, custom_map)
    }

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
        let sigma = tmp.path().join("sigma");
        let rules_dir = sigma.join("rules");
        fs::create_dir_all(&rules_dir).unwrap();

        let windows_low = MINIMAL_RULE
            .replace(
                "id: 11111111-1111-1111-1111-111111111111",
                "id: 22222222-2222-2222-2222-222222222222",
            )
            .replace("level: critical", "level: low");
        let linux_rule = MINIMAL_RULE
            .replace(
                "id: 11111111-1111-1111-1111-111111111111",
                "id: 33333333-3333-3333-3333-333333333333",
            )
            .replace("  product: windows", "  product: linux");

        write_rules(
            &rules_dir,
            &[
                ("win_crit.yml", MINIMAL_RULE),
                ("win_low.yml", &windows_low),
                ("linux.yml", &linux_rule),
            ],
        );

        let set = SigmahqRules::new_from_path(&sigma).unwrap().filter(
            Some("windows"),
            Some(MinStatus(Status::Stable)),
            Some(MinLevel(Level::Critical)),
        );

        assert_eq!(set.len(), 1);
        assert_eq!(
            set.rules()[0].id.as_deref(),
            Some("11111111-1111-1111-1111-111111111111")
        );
        assert_eq!(set.stats().rules_loaded, 1);
        assert_eq!(set.stats().rules_total_candidate, 3);
        assert_eq!(set.stats().rules_filtered_product, 1);
        assert_eq!(set.stats().rules_filtered_level, 1);
        assert_eq!(set.stats().rules_filtered_status, 0);
    }

    #[test]
    fn test_ruleset_skip_ids() {
        let tmp = tempfile::tempdir().unwrap();
        let sigma = tmp.path().join("sigma");
        let rules_dir = sigma.join("rules");
        fs::create_dir_all(&rules_dir).unwrap();
        write_rules(&rules_dir, &[("win.yml", MINIMAL_RULE)]);

        let mut set = SigmahqRules::new_from_path(&sigma).unwrap();
        let rule_id = Uuid::parse_str("11111111-1111-1111-1111-111111111111").unwrap();
        set.remove_id(&rule_id);

        assert!(set.is_empty());
    }

    #[test]
    fn test_ruleset_get() {
        let tmp = tempfile::tempdir().unwrap();
        let sigma = tmp.path().join("sigma");
        let rules_dir = sigma.join("rules");
        fs::create_dir_all(&rules_dir).unwrap();
        write_rules(&rules_dir, &[("win.yml", MINIMAL_RULE)]);

        let set = SigmahqRules::new_from_path(&sigma).unwrap();

        let rule_id = Uuid::parse_str("11111111-1111-1111-1111-111111111111").unwrap();
        assert!(set.get(&rule_id).is_some());
        assert!(set.get(&Uuid::nil()).is_none());
    }

    #[test]
    fn test_ruleset_to_collection() {
        let tmp = tempfile::tempdir().unwrap();
        let sigma = tmp.path().join("sigma");
        let rules_dir = sigma.join("rules");
        fs::create_dir_all(&rules_dir).unwrap();
        write_rules(&rules_dir, &[("win.yml", MINIMAL_RULE)]);

        let set = SigmahqRules::new_from_path(&sigma).unwrap();

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

        let set = SigmahqRules::new_from_path(&sigma).unwrap();

        assert_eq!(set.len(), 2);
        assert_eq!(set.stats().rules_loaded, 2);
    }

    #[test]
    fn test_ruleset_init_from_sigma_path_empty() {
        let tmp = tempfile::tempdir().unwrap();
        let err = SigmahqRules::new_from_path(tmp.path()).unwrap_err();
        assert!(err.to_string().contains("No rules directories found"));
    }

    #[test]
    fn test_ruleset_filter_thresholds() {
        let tmp = tempfile::tempdir().unwrap();
        let sigma_dir = tmp.path().join("sigma");
        let rules_dir = sigma_dir.join("rules");
        fs::create_dir_all(&rules_dir).unwrap();

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

        let set = SigmahqRules::new_from_path(&sigma_dir).unwrap();
        assert_eq!(set.len(), 2);

        let filtered = set.filter(
            Some("windows"),
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
        assert_eq!(filtered.stats().rules_filtered_product, 0);
    }

    #[test]
    fn test_ruleset_filter_no_thresholds_is_noop() {
        let tmp = tempfile::tempdir().unwrap();
        let sigma_dir = tmp.path().join("sigma");
        let rules_dir = sigma_dir.join("rules");
        fs::create_dir_all(&rules_dir).unwrap();
        write_rules(&rules_dir, &[("win.yml", MINIMAL_RULE)]);

        let set = SigmahqRules::new_from_path(&sigma_dir).unwrap();

        let filtered = set.filter(None, None, None);
        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered.stats().rules_loaded, 1);
        assert_eq!(filtered.stats().rules_total_candidate, 1);
    }

    #[test]
    fn test_ruleset_filter_product() {
        let tmp = tempfile::tempdir().unwrap();
        let sigma = tmp.path().join("sigma");
        let rules_dir = sigma.join("rules");
        fs::create_dir_all(&rules_dir).unwrap();

        let linux_crit = MINIMAL_RULE
            .replace(
                "id: 11111111-1111-1111-1111-111111111111",
                "id: 33333333-3333-3333-3333-333333333333",
            )
            .replace("  product: windows", "  product: linux");
        write_rules(
            &rules_dir,
            &[("win.yml", MINIMAL_RULE), ("linux.yml", &linux_crit)],
        );

        let all = SigmahqRules::new_from_path(&sigma).unwrap();

        let windows = all.clone().filter(Some("windows"), None, None);
        assert_eq!(windows.len(), 1);
        assert_eq!(
            windows.rules()[0].id.as_deref(),
            Some("11111111-1111-1111-1111-111111111111")
        );
        assert_eq!(windows.stats().rules_loaded, 1);
        assert_eq!(windows.stats().rules_total_candidate, 2);
        assert_eq!(windows.stats().rules_filtered_product, 1);

        let linux = all.clone().filter(Some("linux"), None, None);
        assert_eq!(linux.len(), 1);
        assert_eq!(linux.stats().rules_total_candidate, 2);
        assert_eq!(linux.stats().rules_filtered_product, 1);

        let none = all.filter(Some("macos"), None, None);
        assert!(none.is_empty());
        assert_eq!(none.stats().rules_total_candidate, 2);
        assert_eq!(none.stats().rules_filtered_product, 2);
    }

    #[test]
    fn test_ruleset_remove_id() {
        let tmp = tempfile::tempdir().unwrap();
        let sigma = tmp.path().join("sigma");
        let rules_dir = sigma.join("rules");
        fs::create_dir_all(&rules_dir).unwrap();

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

        let mut set = SigmahqRules::new_from_path(&sigma).unwrap();
        assert_eq!(set.len(), 2);

        let id1 = Uuid::parse_str("11111111-1111-1111-1111-111111111111").unwrap();
        let id2 = Uuid::parse_str("22222222-2222-2222-2222-222222222222").unwrap();
        let id_absent = Uuid::parse_str("00000000-0000-0000-0000-000000000000").unwrap();
        assert!(set.remove_id(&id1));
        assert_eq!(set.len(), 1);
        assert!(set.get(&id2).is_some());

        assert!(!set.remove_id(&id_absent));
        assert_eq!(set.len(), 1);
    }

    #[test]
    fn test_ruleset_channels_dedup() {
        let tmp = tempfile::tempdir().unwrap();
        let sigma = tmp.path().join("sigma");
        let rules_dir = sigma.join("rules");
        fs::create_dir_all(&rules_dir).unwrap();

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

        let set = SigmahqRules::new_from_path(&sigma).unwrap();
        assert_eq!(set.len(), 3);

        let channels = set.channels(&HashMap::new());
        assert_eq!(channels, vec!["Microsoft-Windows-Sysmon/Operational"]);
    }

    #[test]
    fn test_ruleset_filter_cascade_counts() {
        let tmp = tempfile::tempdir().unwrap();
        let sigma_dir = tmp.path().join("sigma");
        let rules_dir = sigma_dir.join("rules");
        fs::create_dir_all(&rules_dir).unwrap();

        let win_low = MINIMAL_RULE
            .replace(
                "id: 11111111-1111-1111-1111-111111111111",
                "id: 22222222-2222-2222-2222-222222222222",
            )
            .replace("level: critical", "level: low");
        let linux = MINIMAL_RULE
            .replace(
                "id: 11111111-1111-1111-1111-111111111111",
                "id: 33333333-3333-3333-3333-333333333333",
            )
            .replace("  product: windows", "  product: linux");

        write_rules(
            &rules_dir,
            &[
                ("win_crit.yml", MINIMAL_RULE),
                ("win_low.yml", &win_low),
                ("linux.yml", &linux),
            ],
        );

        let set = SigmahqRules::new_from_path(&sigma_dir).unwrap().filter(
            Some("windows"),
            Some(MinStatus(Status::Stable)),
            Some(MinLevel(Level::Critical)),
        );

        let s = set.stats();
        assert_eq!(
            s.rules_loaded
                + s.rules_filtered_product
                + s.rules_filtered_status
                + s.rules_filtered_level,
            s.rules_total_candidate
        );
    }
}
