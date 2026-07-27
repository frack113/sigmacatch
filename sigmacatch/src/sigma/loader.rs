// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 sigmacatch contributors

use anyhow::Result;
use rsigma_parser::{parse_sigma_yaml, SigmaCollection};
use std::collections::HashSet;
use std::path::{Path, PathBuf};
use tracing::{info, warn};

use crate::config::{GitConfig, SigmaFilterConfig};

#[derive(Debug, Clone)]
pub struct SigmaRepo {
    pub path: PathBuf,
    remote_url: Option<String>,
    token: Option<String>,
    git_config: GitConfig,
}

impl SigmaRepo {
    pub fn new(path: &Path) -> Self {
        Self {
            path: path.to_path_buf(),
            remote_url: None,
            token: None,
            git_config: GitConfig::default(),
        }
    }

    pub fn with_remote_url(mut self, url: String) -> Self {
        self.remote_url = Some(url);
        self
    }

    pub fn with_token(mut self, token: String) -> Self {
        self.token = Some(token);
        self
    }

    pub fn with_git_config(mut self, git_config: GitConfig) -> Self {
        self.git_config = git_config;
        self
    }

    pub async fn init(&self) -> Result<()> {
        let git_dir = self.path.join(".git");

        if git_dir.exists() && !is_repo_complete(&git_dir) {
            warn!(
                "Incomplete repository at {:?}, removing and re-cloning",
                self.path
            );
            std::fs::remove_dir_all(&git_dir)?;
        }

        let repo_exists = git_dir.exists();

        if repo_exists {
            info!("Sigma repository exists, pulling latest...");
            let git_dir_clone = git_dir.clone();
            let git_config = self.git_config.clone();
            let result = match git_config.transport {
                crate::config::GitTransport::Http => {
                    let token = self.token.clone();
                    tokio::task::spawn_blocking(move || {
                        crate::repo::git_pull(&git_dir_clone, token.as_deref())
                    })
                    .await
                    .map_err(|e| anyhow::anyhow!("Pull task panicked: {}", e))
                }
                crate::config::GitTransport::Ssh => {
                    let key_path = git_config.ssh_key_path.clone();
                    tokio::task::spawn_blocking(move || {
                        crate::repo::git_pull_ssh(&git_dir_clone, key_path.as_deref())
                    })
                    .await
                    .map_err(|e| anyhow::anyhow!("Pull task panicked: {}", e))
                }
            };
            if let Err(e) = result? {
                warn!(
                    "Failed to pull Sigma repository: {}. Removing incomplete repo.",
                    e
                );
                std::fs::remove_dir_all(&git_dir)?;
                return self.clone_repo().await;
            }
            return Ok(());
        }

        self.clone_repo().await
    }

    async fn clone_repo(&self) -> Result<()> {
        let url = self
            .remote_url
            .clone()
            .unwrap_or_else(|| crate::config::DEFAULT_SIGMA_REPO_URL.to_string());
        info!("Cloning Sigma repository from {}...", url);
        let path = self.path.clone();
        let git_config = self.git_config.clone();
        let token = self.token.clone();

        match git_config.transport {
            crate::config::GitTransport::Http => {
                tokio::task::spawn_blocking(move || {
                    crate::repo::git_clone(&url, &path, token.as_deref())
                })
                .await
                .map_err(|e| anyhow::anyhow!("Clone task panicked: {}", e))??;
            }
            crate::config::GitTransport::Ssh => {
                let ssh_url = crate::repo::https_to_ssh_url(&url)
                    .ok_or_else(|| anyhow::anyhow!("Cannot convert URL to SSH format: {}", url))?;
                let key_path = git_config.ssh_key_path.clone();
                tokio::task::spawn_blocking(move || {
                    crate::repo::git_clone_ssh(&ssh_url, &path, key_path.as_deref())
                })
                .await
                .map_err(|e| anyhow::anyhow!("Clone task panicked: {}", e))??;
            }
        }

        info!("Sigma repository cloned to {:?}", self.path);
        Ok(())
    }
}

fn is_repo_complete(git_dir: &Path) -> bool {
    let has_packed_refs = git_dir.join("packed-refs").exists();
    let has_objects = git_dir
        .join("objects")
        .join("pack")
        .read_dir()
        .map(|mut dir| dir.next().is_some())
        .unwrap_or(false);
    let has_refs = git_dir
        .join("refs")
        .join("heads")
        .read_dir()
        .map(|mut dir| dir.next().is_some())
        .unwrap_or(false);
    has_packed_refs || has_objects || has_refs
}

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

/// Load all Sigma rules from the given directories, applying status/level filters
/// and skipping rules in the skip set.
pub fn load_all_rules(
    dirs: &[&Path],
    skip_ids: &HashSet<String>,
    filter: &SigmaFilterConfig,
) -> Result<LoadResult> {
    let mut collection = SigmaCollection::default();
    let mut rules_total_candidate: u64 = 0;
    let mut rules_filtered_status: u64 = 0;
    let mut rules_filtered_level: u64 = 0;

    let skip_set = skip_ids.clone();
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
                                                != Some(filter.product.as_str())
                                            {
                                                continue;
                                            }
                                            if skip_set.contains(&rule_id) {
                                                continue;
                                            }
                                            rules_total_candidate += 1;

                                            // Apply min_status filter
                                            if let Some(ref status) = rule.status {
                                                if !filter.min_status.accepts(status) {
                                                    rules_filtered_status += 1;
                                                    continue;
                                                }
                                            }

                                            // Apply min_level filter
                                            if let Some(ref level) = rule.level {
                                                if !filter.min_level.accepts(level) {
                                                    rules_filtered_level += 1;
                                                    continue;
                                                }
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
    use crate::config::{MinLevel, MinStatus, Product};
    use detection_engine::find_rules_dirs;
    use std::fs;

    #[test]
    fn test_find_rules_dirs_nonexistent_root() {
        let result = find_rules_dirs(Path::new("/nonexistent/path/12345"));
        assert!(result.unwrap().is_empty());
    }

    #[test]
    fn test_find_rules_dirs_empty_dir() {
        let tmp = tempfile::tempdir().unwrap();
        let result = find_rules_dirs(tmp.path()).unwrap();
        assert!(result.is_empty());
    }

    #[test]
    fn test_find_rules_dirs_discover_rules() {
        let tmp = tempfile::tempdir().unwrap();
        fs::create_dir(tmp.path().join("rules")).unwrap();
        fs::write(tmp.path().join("rules").join("rule.yml"), "test: value").unwrap();
        let result = find_rules_dirs(tmp.path()).unwrap();
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].file_name().unwrap(), "rules");
    }

    #[test]
    fn test_find_rules_dirs_discover_rules_contrib() {
        let tmp = tempfile::tempdir().unwrap();
        fs::create_dir(tmp.path().join("rules-filestorage")).unwrap();
        fs::write(
            tmp.path().join("rules-filestorage").join("test.yml"),
            "test: value",
        )
        .unwrap();
        let result = find_rules_dirs(tmp.path()).unwrap();
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].file_name().unwrap(), "rules-filestorage");
    }

    #[test]
    fn test_find_rules_dirs_excludes_rules_compliance() {
        let tmp = tempfile::tempdir().unwrap();
        fs::create_dir(tmp.path().join("rules-compliance")).unwrap();
        fs::create_dir(tmp.path().join("rules")).unwrap();
        let result = find_rules_dirs(tmp.path()).unwrap();
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].file_name().unwrap(), "rules");
    }

    #[test]
    fn test_find_rules_dirs_multiple_rules_dirs() {
        let tmp = tempfile::tempdir().unwrap();
        fs::create_dir(tmp.path().join("rules")).unwrap();
        fs::write(tmp.path().join("rules").join("r.yml"), "test: 1").unwrap();
        fs::create_dir(tmp.path().join("rules-filestorage")).unwrap();
        fs::write(
            tmp.path().join("rules-filestorage").join("r.yml"),
            "test: 1",
        )
        .unwrap();
        fs::create_dir(tmp.path().join("rules-corporate")).unwrap();
        fs::write(tmp.path().join("rules-corporate").join("r.yml"), "test: 1").unwrap();
        let result = find_rules_dirs(tmp.path()).unwrap();
        assert_eq!(result.len(), 3);
    }

    #[test]
    fn test_find_rules_dirs_nested_not_discovered() {
        let tmp = tempfile::tempdir().unwrap();
        fs::create_dir(tmp.path().join("rules")).unwrap();
        let nested = tmp.path().join("rules").join("nested");
        fs::create_dir(&nested).unwrap();
        let result = find_rules_dirs(tmp.path()).unwrap();
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].file_name().unwrap(), "rules");
    }

    #[test]
    fn test_find_rules_dirs_nested_has_yml_discovered() {
        let tmp = tempfile::tempdir().unwrap();
        fs::create_dir(tmp.path().join("rules")).unwrap();
        let nested = tmp.path().join("rules").join("nested");
        fs::create_dir(&nested).unwrap();
        fs::write(nested.join("rule.yml"), "test: true").unwrap();
        let result = find_rules_dirs(tmp.path()).unwrap();
        // Only the top-level `rules` dir is discovered, not `rules/nested`
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].file_name().unwrap(), "rules");
    }

    #[test]
    fn test_is_repo_complete_with_packed_refs() {
        let tmp = tempfile::tempdir().unwrap();
        let git_dir = tmp.path().join(".git");
        fs::create_dir(&git_dir).unwrap();
        fs::write(git_dir.join("packed-refs"), "test").unwrap();
        assert!(is_repo_complete(&git_dir));
    }

    #[test]
    fn test_is_repo_complete_with_objects() {
        let tmp = tempfile::tempdir().unwrap();
        let git_dir = tmp.path().join(".git");
        fs::create_dir_all(git_dir.join("objects/pack")).unwrap();
        fs::write(git_dir.join("objects/pack/pack.idx"), "test").unwrap();
        assert!(is_repo_complete(&git_dir));
    }

    #[test]
    fn test_is_repo_complete_with_refs() {
        let tmp = tempfile::tempdir().unwrap();
        let git_dir = tmp.path().join(".git");
        fs::create_dir_all(git_dir.join("refs/heads")).unwrap();
        fs::write(git_dir.join("refs/heads/main"), "abc123").unwrap();
        assert!(is_repo_complete(&git_dir));
    }

    #[test]
    fn test_is_repo_complete_empty() {
        let tmp = tempfile::tempdir().unwrap();
        let git_dir = tmp.path().join(".git");
        fs::create_dir(&git_dir).unwrap();
        assert!(!is_repo_complete(&git_dir));
    }

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
        let filter = SigmaFilterConfig {
            product: Product::Windows,
            min_status: MinStatus::Stable,
            min_level: MinLevel::Critical,
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
        let filter = SigmaFilterConfig {
            product: Product::Windows,
            min_status: MinStatus::Stable,
            min_level: MinLevel::Critical,
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
        let filter = SigmaFilterConfig {
            product: Product::Windows,
            min_status: MinStatus::Stable,
            min_level: MinLevel::Critical,
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
        let filter = SigmaFilterConfig {
            product: Product::Windows,
            min_status: MinStatus::Stable,
            min_level: MinLevel::Critical,
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
        let filter = SigmaFilterConfig {
            product: Product::Windows,
            min_status: MinStatus::Stable,
            min_level: MinLevel::High,
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
        let filter = SigmaFilterConfig::default();
        let result = load_all_rules(&dirs, &skip, &filter).unwrap();

        assert_eq!(result.stats.rules_loaded, 0);
        assert_eq!(result.stats.rules_total_candidate, 0);
    }

    #[test]
    fn test_all_candidates_filtered_to_zero() {
        let tmp = tempfile::tempdir().unwrap();
        let rules_dir = tmp.path().join("rules");
        fs::create_dir(&rules_dir).unwrap();
        fs::write(
            rules_dir.join("rule_a.yml"),
            make_rule_yaml(
                "rule a",
                Some("experimental"),
                Some("informational"),
                Some(1),
            ),
        )
        .unwrap();
        fs::write(
            rules_dir.join("rule_b.yml"),
            make_rule_yaml("rule b", Some("deprecated"), Some("low"), Some(2)),
        )
        .unwrap();

        let dirs = vec![rules_dir.as_path()];
        let filter = SigmaFilterConfig {
            product: Product::Windows,
            min_status: MinStatus::Stable,
            min_level: MinLevel::Critical,
            max_rules: 0,
            max_rule_size: 1024 * 1024,
        };
        let result = load_all_rules(&dirs, &HashSet::new(), &filter).unwrap();

        assert_eq!(result.stats.rules_loaded, 0);
        assert_eq!(result.stats.rules_filtered_status, 2);
        assert_eq!(result.stats.rules_filtered_level, 0);
        assert_eq!(result.stats.rules_total_candidate, 2);
        assert!(result.collection.rules.is_empty());
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
            "id: test_uuid2\ntitle: linux rule\nlogsource:\n  product: linux\ndetection:\n  sel:\n    EventID: 1\n  condition:\n    - sel\n".to_string(),
        )
        .unwrap();

        let dirs = vec![rules_dir.as_path()];
        let filter = SigmaFilterConfig {
            product: Product::Windows,
            min_status: MinStatus::Stable,
            min_level: MinLevel::Critical,
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
            "id: test_uuid2\ntitle: linux rule\nlogsource:\n  product: linux\ndetection:\n  sel:\n    EventID: 1\n  condition:\n    - sel\n".to_string(),
        )
        .unwrap();
        fs::write(
            rules_dir.join("rule_windows.yml"),
            make_rule_yaml("windows rule", Some("stable"), Some("critical"), Some(1)),
        )
        .unwrap();

        let dirs = vec![rules_dir.as_path()];
        let filter = SigmaFilterConfig {
            product: Product::Linux,
            min_status: MinStatus::Stable,
            min_level: MinLevel::Critical,
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
            "id: test_uuid3\ntitle: macos rule\nlogsource:\n  product: macos\ndetection:\n  sel:\n    EventID: 1\n  condition:\n    - sel\n".to_string(),
        )
        .unwrap();

        let dirs = vec![rules_dir.as_path()];
        let filter = SigmaFilterConfig {
            product: Product::Macos,
            min_status: MinStatus::Stable,
            min_level: MinLevel::Critical,
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
        let filter = SigmaFilterConfig {
            product: Product::Windows,
            min_status: MinStatus::Stable,
            min_level: MinLevel::Critical,
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
        let filter = SigmaFilterConfig {
            product: Product::Windows,
            min_status: MinStatus::Stable,
            min_level: MinLevel::Critical,
            max_rules: 0,
            max_rule_size: 1024,
        };
        let result = load_all_rules(&dirs, &HashSet::new(), &filter).unwrap();

        assert_eq!(result.stats.rules_loaded, 1);
    }
}
