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
            info!("Sigma repository exists, fetching latest...");
            let http_client = create_http_client(self.token.as_deref())?;
            let url = self
                .remote_url
                .clone()
                .unwrap_or_else(|| SIGMA_REPO_URL.to_string());
            if let Err(e) = crate::git::fetch_remote(&http_client, &git_dir, &url) {
                warn!(
                    "Failed to fetch Sigma repository: {}. Removing incomplete repo.",
                    e
                );
                std::fs::remove_dir_all(&git_dir)?;
                return self.clone_repo().await;
            }

            if let Some(ref new_url) = self.remote_url {
                update_remote_url(&git_dir, new_url)?;
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

        tokio::task::spawn_blocking(move || -> Result<()> {
            let http_client = create_http_client(token.as_deref())?;
            crate::git::clone_repo(&http_client, &url, &path)
        })
        .await
        .map_err(|e| {
            if e.is_panic() {
                let payload = e.into_panic();
                anyhow::anyhow!("Clone task panicked: {:?}", payload)
            } else {
                anyhow::anyhow!("Clone task failed: {}", e)
            }
        })??;

        info!("Sigma repository cloned to {:?}", self.path);
        Ok(())
    }
}

fn create_http_client(token: Option<&str>) -> Result<crate::git::AuthHttpClient> {
    let effective_token = token
        .map(|t| t.to_string())
        .or_else(|| std::env::var("GITHUB_TOKEN").ok());
    crate::git::AuthHttpClient::new(effective_token)
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

fn update_remote_url(git_dir: &Path, new_url: &str) -> Result<()> {
    let config_path = git_dir.join("config");
    let content = std::fs::read_to_string(&config_path)?;

    let line_ending = if content.contains("\r\n") {
        "\r\n"
    } else {
        "\n"
    };
    let lines: Vec<&str> = content.split(line_ending).collect();

    let mut new_lines = Vec::new();
    let mut in_remote_origin = false;
    let mut updated = false;

    for line in &lines {
        let trimmed = line.trim();
        if trimmed == "[remote \"origin\"]" || trimmed == "[remote origin]" {
            in_remote_origin = true;
            new_lines.push((*line).to_string());
        } else if in_remote_origin {
            if trimmed.starts_with('[') {
                if !updated {
                    new_lines.push(format!(
                        "\turl = {}",
                        crate::git::git_config_escape(new_url)
                    ));
                    updated = true;
                }
                in_remote_origin = false;
                new_lines.push((*line).to_string());
            } else if trimmed.starts_with("url") && trimmed.contains('=') {
                new_lines.push(format!(
                    "\turl = {}",
                    crate::git::git_config_escape(new_url)
                ));
                updated = true;
            } else {
                new_lines.push((*line).to_string());
            }
        } else {
            new_lines.push((*line).to_string());
        }
    }

    if in_remote_origin && !updated {
        new_lines.push(format!(
            "\turl = {}",
            crate::git::git_config_escape(new_url)
        ));
        updated = true;
    }

    if updated {
        std::fs::write(&config_path, new_lines.join(line_ending))?;
        info!("Updated remote 'origin' URL");
    }

    Ok(())
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
                        let abs_path = std::fs::canonicalize(&path).ok();
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
