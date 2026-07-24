// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 sigmacatch contributors

use anyhow::Result;
#[cfg(unix)]
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use tracing::{info, warn};

pub(crate) const SIGMA_REPO_URL: &str = "https://github.com/SigmaHQ/sigma.git";

#[derive(Debug, Clone)]
pub struct SigmaRepo {
    pub path: PathBuf,
    remote_url: Option<String>,
    token: Option<String>,
}

impl SigmaRepo {
    pub fn new(path: &Path) -> Self {
        Self {
            path: path.to_path_buf(),
            remote_url: None,
            token: None,
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
            let token = self.token.clone();
            let result = tokio::task::spawn_blocking(move || {
                crate::repo::git_pull(&git_dir_clone, token.as_deref())
            })
            .await
            .map_err(|e| anyhow::anyhow!("Pull task panicked: {}", e))?;
            if let Err(e) = result {
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
        let token = self.token.clone();

        tokio::task::spawn_blocking(move || crate::repo::git_clone(&url, &path, token.as_deref()))
            .await
            .map_err(|e| anyhow::anyhow!("Clone task panicked: {}", e))??;

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
pub fn find_rules_dirs(root: &Path) -> Result<Vec<PathBuf>> {
    let mut dirs = Vec::new();
    let mut excluded = Vec::new();
    #[cfg(unix)]
    let mut visited_inodes = std::collections::HashSet::new();
    #[cfg(not(unix))]
    let mut visited_paths = std::collections::HashSet::new();
    if !root.exists() {
        warn!("Root directory does not exist: {:?}", root);
        return Ok(dirs);
    }

    let entries = std::fs::read_dir(root)?;
    for entry_result in entries {
        match entry_result {
            Ok(entry) => {
                let path = entry.path();
                if path.is_dir() {
                    #[cfg(unix)]
                    {
                        let inode = path.metadata().ok().map(|m| m.ino());
                        if let Some(id) = inode {
                            if !visited_inodes.insert(id) {
                                warn!("Skipping symlink cycle detected at: {:?}", path);
                                continue;
                            }
                        }
                    }
                    #[cfg(not(unix))]
                    {
                        let abs_path = dunce::canonicalize(&path).ok();
                        if let Some(abs) = abs_path {
                            if !visited_paths.insert(abs) {
                                warn!("Skipping symlink cycle detected at: {:?}", path);
                                continue;
                            }
                        }
                    }
                    if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
                        if name == "rules" || name.starts_with("rules-") {
                            if name.starts_with("rules-compliance") {
                                excluded.push(name.to_string());
                                continue;
                            }
                            if name.starts_with("rules-") && !has_yml_files(&path, 0) {
                                continue;
                            }
                            info!("Found rules directory: {:?}", path);
                            dirs.push(path);
                        }
                    } else {
                        warn!("Skipping non-UTF8 directory name: {:?}", path);
                    }
                }
            }
            Err(e) => {
                warn!("Skipping entry due to error: {}", e);
            }
        }
    }

    if dirs.is_empty() {
        warn!("No 'rules*' directories found in {:?}", root);
    }
    if !excluded.is_empty() {
        info!("Excluded non-detection directories: {:?}", excluded);
    }

    Ok(dirs)
}

fn has_yml_files(dir: &Path, depth: u32) -> bool {
    if depth > 8 {
        return false;
    }
    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(e) => {
            warn!(
                "Cannot read directory {:?} while scanning for rules: {}",
                dir, e
            );
            return false;
        }
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            if has_yml_files(&path, depth + 1) {
                return true;
            }
        } else if let Some(ext) = path
            .extension()
            .and_then(|e| e.to_str())
            .map(|e| e.to_ascii_lowercase())
        {
            if ext == "yml" || ext == "yaml" {
                return true;
            }
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;
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
    fn test_has_yml_files_with_yaml() {
        let tmp = tempfile::tempdir().unwrap();
        fs::write(tmp.path().join("test.yaml"), "test: value").unwrap();
        assert!(has_yml_files(tmp.path(), 0));
    }

    #[test]
    fn test_has_yml_files_with_yml() {
        let tmp = tempfile::tempdir().unwrap();
        fs::write(tmp.path().join("test.yml"), "test: value").unwrap();
        assert!(has_yml_files(tmp.path(), 0));
    }

    #[test]
    fn test_has_yml_files_no_yaml() {
        let tmp = tempfile::tempdir().unwrap();
        fs::write(tmp.path().join("test.txt"), "test").unwrap();
        assert!(!has_yml_files(tmp.path(), 0));
    }

    #[test]
    fn test_has_yml_files_deeply_nested() {
        let tmp = tempfile::tempdir().unwrap();
        let mut current = tmp.path().to_path_buf();
        for i in 0..5 {
            current = current.join(format!("level_{}", i));
            fs::create_dir(&current).unwrap();
        }
        fs::write(current.join("rule.yml"), "test: true").unwrap();
        assert!(has_yml_files(tmp.path(), 0));
    }

    #[test]
    fn test_has_yml_files_deeper_than_depth_limit() {
        let tmp = tempfile::tempdir().unwrap();
        let mut current = tmp.path().to_path_buf();
        for i in 0..10 {
            current = current.join(format!("level_{}", i));
            fs::create_dir(&current).unwrap();
        }
        fs::write(current.join("rule.yml"), "test: true").unwrap();
        assert!(!has_yml_files(tmp.path(), 0));
    }

    #[test]
    fn test_has_yml_files_case_insensitive() {
        let tmp = tempfile::tempdir().unwrap();
        fs::write(tmp.path().join("test.YML"), "test: value").unwrap();
        assert!(has_yml_files(tmp.path(), 0));
        let tmp2 = tempfile::tempdir().unwrap();
        fs::write(tmp2.path().join("test.YAML"), "test: value").unwrap();
        assert!(has_yml_files(tmp2.path(), 0));
    }

    #[test]
    fn test_has_yml_files_nested_yaml_found() {
        let tmp = tempfile::tempdir().unwrap();
        fs::create_dir(tmp.path().join("subdir")).unwrap();
        fs::write(tmp.path().join("subdir").join("rule.yml"), "test: true").unwrap();
        assert!(has_yml_files(tmp.path(), 0));
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
