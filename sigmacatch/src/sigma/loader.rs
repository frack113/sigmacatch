// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 sigmacatch contributors

use anyhow::Result;
use rsigma_parser::{parse_sigma_yaml, SigmaCollection};
use std::collections::HashSet;
use std::path::{Path, PathBuf};
use tracing::{info, warn};

use crate::config::GitConfig;

pub(crate) const SIGMA_REPO_URL: &str = "https://github.com/SigmaHQ/sigma.git";

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
            .unwrap_or_else(|| SIGMA_REPO_URL.to_string());
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

/// Load all Sigma rules from the given directories, skipping rules in the skip set.
pub fn load_all_rules(dirs: &[&Path], skip_ids: &HashSet<String>) -> Result<SigmaCollection> {
    let mut collection = SigmaCollection::default();

    for dir in dirs {
        let skip_set = skip_ids.clone();
        let mut pending = vec![dir.to_path_buf()];

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
                                match parse_sigma_yaml(&content) {
                                    Ok(parsed) => {
                                        for rule in parsed.rules {
                                            let rule_id = rule.id.clone().unwrap_or_default();
                                            if rule.logsource.product.as_deref() != Some("windows")
                                            {
                                                continue;
                                            }
                                            if !skip_set.contains(&rule_id) {
                                                collection.rules.push(rule);
                                            }
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

    Ok(collection)
}

#[cfg(test)]
mod tests {
    use super::*;
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
}
