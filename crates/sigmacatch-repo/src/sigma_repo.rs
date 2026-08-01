// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 sigmacatch contributors

//! `SigmaRepo` — the single high-level entry point for managing the local
//! Sigma repository (clone, pull, fork-branch creation).

use anyhow::Result;
use std::path::{Path, PathBuf};
use tracing::{info, warn};

use crate::branch::{create_branch, switch_head};
use crate::porcelain::{git_clone, git_clone_ssh, git_pull, git_pull_ssh};
use crate::transport::{https_to_ssh_url, sanitize_url, GitTransport};
use crate::DEFAULT_SIGMA_REPO_URL;

#[derive(Debug, Clone)]
pub struct SigmaRepo {
    pub path: PathBuf,
    remote_url: Option<String>,
    token: Option<String>,
    transport: GitTransport,
    ssh_key_path: Option<String>,
    fork_branch: Option<String>,
}

impl SigmaRepo {
    pub fn new(path: &Path) -> Self {
        Self {
            path: path.to_path_buf(),
            remote_url: None,
            token: None,
            transport: GitTransport::default(),
            ssh_key_path: None,
            fork_branch: None,
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

    pub fn with_transport(mut self, transport: GitTransport) -> Self {
        self.transport = transport;
        self
    }

    pub fn with_ssh_key_path(mut self, ssh_key_path: Option<String>) -> Self {
        self.ssh_key_path = ssh_key_path;
        self
    }

    pub fn with_fork_branch(mut self, branch_name: String) -> Self {
        assert!(!branch_name.is_empty(), "fork_branch must not be empty");
        self.fork_branch = Some(branch_name);
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
            self.switch_to_tracking_branch();

            info!("Sigma repository exists, pulling latest...");
            let git_dir_clone = git_dir.clone();
            let transport = self.transport;
            let token = self.token.clone();
            let ssh_key_path = self.ssh_key_path.clone();
            let result = match transport {
                GitTransport::Http => {
                    tokio::task::spawn_blocking(move || git_pull(&git_dir_clone, token.as_deref()))
                        .await
                        .map_err(|e| anyhow::anyhow!("Pull task panicked: {}", e))
                }
                GitTransport::Ssh => {
                    let result = tokio::task::spawn_blocking(move || {
                        git_pull_ssh(&git_dir_clone, ssh_key_path.as_deref())
                    })
                    .await
                    .map_err(|e| anyhow::anyhow!("Pull task panicked: {}", e));
                    if let Err(ref e) = result {
                        warn!(
                            "SSH pull failed ({}): falling back to HTTPS fetch. \
                             This can happen if ssh binary is not available (e.g. Windows without Git for Windows) \
                             or the SSH key is invalid. Consider switching to transport = http in config.yaml.",
                            e
                        );
                    }
                    result
                }
            };
            if let Err(e) = result? {
                warn!(
                    "Failed to pull Sigma repository: {}. Removing incomplete repo.",
                    e
                );
                std::fs::remove_dir_all(&git_dir)?;
                self.clone_repo().await?;
            }
        } else {
            self.clone_repo().await?;
        }

        if let Some(ref branch_name) = self.fork_branch {
            create_branch(&git_dir, branch_name)?;
        }
        Ok(())
    }

    fn switch_to_tracking_branch(&self) {
        let git_dir = self.path.join(".git");
        for candidate in &["master", "main"] {
            let local_ref = format!("refs/heads/{}", candidate);
            if crate::plumbing::read_loose_or_packed_ref(&git_dir, &local_ref).is_some() {
                if let Err(e) = switch_head(&git_dir, candidate) {
                    warn!("Failed to switch to '{}': {}", candidate, e);
                }
                break;
            }
        }
    }

    async fn clone_repo(&self) -> Result<()> {
        let url = self
            .remote_url
            .clone()
            .unwrap_or_else(|| DEFAULT_SIGMA_REPO_URL.to_string());
        info!("Cloning Sigma repository from {}...", sanitize_url(&url));
        let path = self.path.clone();
        let transport = self.transport;
        let token = self.token.clone();
        let ssh_key_path = self.ssh_key_path.clone();

        match transport {
            GitTransport::Http => {
                tokio::task::spawn_blocking(move || git_clone(&url, &path, token.as_deref()))
                    .await
                    .map_err(|e| anyhow::anyhow!("Clone task panicked: {}", e))??;
            }
            GitTransport::Ssh => {
                let ssh_url = https_to_ssh_url(&url)
                    .ok_or_else(|| anyhow::anyhow!("Cannot convert URL to SSH format: {}", url))?;
                tokio::task::spawn_blocking(move || {
                    git_clone_ssh(&ssh_url, &path, ssh_key_path.as_deref())
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

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
