// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 sigmacatch contributors

//! Git operations via grit-lib (pure Rust Git reimplementation).
//!
//! Architecture:
//!   Transport    → `AuthHttpClient` (HttpClient trait) for HTTPS auth
//!   Plumbing     → Raw git ops: Odb, Index, commit, checkout, refs (`plumbing/`)
//!   Porcelain    → High-level wrappers: clone, pull, push, add, commit (`porcelain.rs`)
//!   Branch       → Branch and HEAD management (`branch.rs`)
//!   SigmaRepo    → High-level sigma repository manager — the single entry point

pub(crate) mod branch;
pub(crate) mod plumbing;
pub(crate) mod porcelain;
pub(crate) mod transport;

#[cfg(test)]
mod regression_tests;

use anyhow::Result;
use grit_lib::objects::ObjectId;
use std::path::{Path, PathBuf};
use tracing::{info, warn};

use crate::branch::{create_branch, switch_head};
use crate::porcelain::{git_add, git_clone, git_clone_ssh, git_commit, git_pull, git_pull_ssh};
pub use crate::transport::GitTransport;
use crate::transport::{https_to_ssh_url, sanitize_url, AuthHttpClient};

/// Default SigmaHQ repository URL.
pub const DEFAULT_SIGMA_REPO_URL: &str = "https://github.com/SigmaHQ/sigma.git";

/// High-level Sigma repository manager — the single entry point.
#[derive(Debug, Clone)]
pub struct SigmaRepo {
    repo_path: PathBuf,
    remote_url: Option<String>,
    working_branch: Option<String>,
    // User info for git commits (defaults from Config)
    author: String,
    email: String,
    // Transport configuration
    token: Option<String>,
    transport: GitTransport,
    ssh_key_path: Option<String>,
}

impl SigmaRepo {
    pub fn new() -> Self {
        Self {
            repo_path: PathBuf::from("sigma"),
            remote_url: None,
            working_branch: None,
            author: String::new(),
            email: String::new(),
            token: None,
            transport: GitTransport::default(),
            ssh_key_path: None,
        }
    }

    /// Set git commit identity (author name and email).
    pub fn set_info_user(&mut self, author: &str, email: &str) {
        self.author = author.to_string();
        self.email = email.to_string();
    }

    /// Set HTTP transport with a GitHub token.
    pub fn set_info_http(&mut self, token: &str) {
        self.transport = GitTransport::Http;
        self.token = if token.trim().is_empty() {
            None
        } else {
            Some(token.trim().to_string())
        };
    }

    /// Set SSH transport with an optional SSH key path.
    pub fn set_info_ssh(&mut self, ssh_key_path: Option<&str>) {
        self.transport = GitTransport::Ssh;
        self.ssh_key_path = ssh_key_path.map(String::from);
    }

    pub fn set_working_branch(&mut self, branch_name: String) -> Result<()> {
        assert!(!branch_name.is_empty(), "working_branch must not be empty");
        self.working_branch = Some(branch_name);
        self.switch_to_working_branch()
    }

    pub async fn init(&mut self) -> Result<()> {
        let git_dir = self.repo_path.join(".git");

        if git_dir.exists() && !is_repo_complete(&git_dir) {
            warn!(
                "Incomplete repository at {:?}, removing and re-cloning",
                self.repo_path
            );
            std::fs::remove_dir_all(&git_dir)?;
        }

        let repo_exists = git_dir.exists();

        if repo_exists {
            self.switch_to_tracking_branch()?;

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

        Ok(())
    }

    pub async fn set_remote_url(&mut self, url: String) -> Result<()> {
        self.remote_url = Some(url);
        self.init().await
    }

    /// Switch to the contribution working branch.
    /// Creates it from the remote tracking ref (or HEAD for a fresh branch),
    /// then materializes and reconciles the working tree so the on-disk state
    /// is an exact mirror of the branch (files already pushed to the fork are
    /// present; stale local files are removed).
    pub fn switch_to_working_branch(&mut self) -> Result<()> {
        let branch_name = self.working_branch.clone().ok_or_else(|| {
            anyhow::anyhow!(
                "No working branch configured — call with_working_branch() before switching"
            )
        })?;
        let git_dir = self.repo_path.join(".git");
        create_branch(&git_dir, &branch_name)?;
        crate::plumbing::checkout_main_branch(&git_dir, &self.repo_path)?;
        Ok(())
    }

    /// Validate the remote tracking branch for the working branch, if present.
    ///
    /// Runs once at startup right after the working branch is set. A branch
    /// already pushed to the fork (same-day re-run) must be usable as the base
    /// for the next commit: the commit must be readable, have at least one
    /// parent (a child of master, never an orphan/root), and its tree must
    /// contain the `rules/` directory. A corrupt/amputated remote branch is
    /// rejected with an actionable message so the loop never commits onto it.
    /// Returns `Ok` when the branch does not exist on the fork yet (fresh day).
    pub fn check_remote_working_branch(&self) -> Result<()> {
        let branch = self
            .working_branch
            .as_deref()
            .ok_or_else(|| anyhow::anyhow!("No working branch configured"))?;
        let git_dir = self.repo_path.join(".git");
        let remote_ref = format!("refs/remotes/origin/{}", branch);

        let Some(oid_str) = crate::plumbing::read_loose_or_packed_ref(&git_dir, &remote_ref) else {
            info!(
                "No remote tracking ref '{}' — fresh working branch",
                remote_ref
            );
            return Ok(());
        };

        let oid = ObjectId::from_hex(&oid_str)
            .map_err(|e| anyhow::anyhow!("Invalid OID for '{}': {}", remote_ref, e))?;
        let odb = crate::plumbing::open_odb(&git_dir);
        let obj = odb.read(&oid).map_err(|e| {
            anyhow::anyhow!(
                "Remote working branch '{}' commit {} is unreadable: {}. \
                 Delete the branch on GitHub and re-run.",
                branch,
                oid,
                e
            )
        })?;
        let commit = grit_lib::objects::parse_commit(&obj.data).map_err(|e| {
            anyhow::anyhow!(
                "Remote working branch '{}' commit {} is not a valid commit: {}. \
                 Delete the branch on GitHub and re-run.",
                branch,
                oid,
                e
            )
        })?;
        if commit.parents.is_empty() {
            anyhow::bail!(
                "Remote working branch '{}' commit {} is an orphan/root commit (no parent). \
                 Expected a child of master. Delete the branch on GitHub and re-run.",
                branch,
                oid
            );
        }

        let tree_obj = odb.read(&commit.tree).map_err(|e| {
            anyhow::anyhow!(
                "Remote working branch '{}' tree {} is unreadable: {}. \
                 Delete the branch on GitHub and re-run.",
                branch,
                commit.tree,
                e
            )
        })?;
        let entries = grit_lib::objects::parse_tree(&tree_obj.data).map_err(|e| {
            anyhow::anyhow!(
                "Remote working branch '{}' tree {} is not a valid tree: {}. \
                 Delete the branch on GitHub and re-run.",
                branch,
                commit.tree,
                e
            )
        })?;
        let has_rules = entries
            .iter()
            .any(|e| e.mode == 0o040000 && e.name.as_slice() == b"rules");
        if !has_rules {
            anyhow::bail!(
                "Remote working branch '{}' tree is missing the 'rules/' directory — \
                 the branch is amputated/corrupt. Delete the branch on GitHub and re-run.",
                branch
            );
        }

        info!(
            "Remote working branch '{}' is valid (commit {} with rules/ tree)",
            branch,
            &oid_str[..12.min(oid_str.len())]
        );
        Ok(())
    }

    fn switch_to_tracking_branch(&self) -> Result<()> {
        let git_dir = self.repo_path.join(".git");
        for candidate in &["master", "main"] {
            let local_ref = format!("refs/heads/{}", candidate);
            if crate::plumbing::read_loose_or_packed_ref(&git_dir, &local_ref).is_some() {
                switch_head(&git_dir, candidate)?;
                break;
            }
        }
        Ok(())
    }

    async fn clone_repo(&self) -> Result<()> {
        let url = self
            .remote_url
            .clone()
            .unwrap_or_else(|| DEFAULT_SIGMA_REPO_URL.to_string());
        info!("Cloning Sigma repository from {}...", sanitize_url(&url));
        let path = self.repo_path.clone();
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

        info!("Sigma repository cloned to {:?}", self.repo_path);
        Ok(())
    }

    /// Stage files (relative to `work_tree`) into the git index and commit them
    /// in a single batch.
    fn valid_commit_paths(files: &[String]) -> Vec<&str> {
        files
            .iter()
            .filter(|f| {
                if f.contains('\0') || f.contains("..") {
                    warn!("Skipping commit for invalid path: {}", f);
                    false
                } else {
                    true
                }
            })
            .map(String::as_str)
            .collect()
    }

    pub fn git_upload(&self, files: Vec<String>, message: String) -> Result<()> {
        let git_dir = self.repo_path.join(".git");
        let name = self.author.trim();
        let addr = self.email.trim();

        let valid = Self::valid_commit_paths(&files);

        if valid.is_empty() {
            if files.is_empty() {
                info!("No files to commit");
            } else {
                info!("No valid files to commit");
            }
        } else {
            git_add(&git_dir, &self.repo_path, &valid)?;
            git_commit(&git_dir, &self.repo_path, message.as_str(), name, addr)?;
            info!("Committed {} file(s)", valid.len());
        }

        self.push()?;
        Ok(())
    }

    fn push(&self) -> Result<()> {
        let branch = self
            .working_branch
            .as_deref()
            .ok_or_else(|| anyhow::anyhow!("No working branch configured"))?;
        let git_dir = self.repo_path.join(".git");

        let head_target =
            crate::plumbing::symbolic_ref_target(&git_dir, "HEAD")?.ok_or_else(|| {
                anyhow::anyhow!(
                    "HEAD is detached (not on a branch) — refusing to push branch '{}'",
                    branch
                )
            })?;
        let expected_ref = format!("refs/heads/{branch}");
        if head_target != expected_ref {
            anyhow::bail!(
                "HEAD is not on branch '{}' (HEAD → {}). Refusing to push.",
                branch,
                head_target
            );
        }

        match self.transport {
            GitTransport::Http => {
                let http_client = AuthHttpClient::new(self.token.clone())?;
                let remote_url = crate::plumbing::read_remote_url_from_config(&git_dir, "origin")?;
                crate::plumbing::push_branch(&http_client, &git_dir, &remote_url, branch)
            }
            GitTransport::Ssh => {
                let remote_url = crate::plumbing::read_remote_url_from_config(&git_dir, "origin")?;
                let ssh_url = https_to_ssh_url(&remote_url).unwrap_or_else(|| remote_url.clone());
                let ssh_cmd =
                    crate::transport::build_ssh_shell_command(self.ssh_key_path.as_deref());
                crate::plumbing::push_branch_ssh(&git_dir, &ssh_url, branch, ssh_cmd.as_str())
            }
        }
    }
}

impl Default for SigmaRepo {
    fn default() -> Self {
        Self {
            repo_path: PathBuf::from("sigma"),
            remote_url: None,
            working_branch: None,
            author: String::new(),
            email: String::new(),
            token: None,
            transport: GitTransport::default(),
            ssh_key_path: None,
        }
    }
}

fn is_repo_complete(git_dir: &Path) -> bool {
    // A repository is usable when HEAD resolves to a commit object that is
    // readable in the ODB. This covers both real-git clones (packed refs +
    // packs) and grit's unpack_objects-based clones (loose objects only, no
    // `objects/pack` or `packed-refs`), which the previous check wrongly
    // treated as incomplete — deleting and re-cloning the repository on every
    // run.
    let Ok(head) = crate::plumbing::resolve_head(git_dir) else {
        return false;
    };
    crate::plumbing::open_odb(git_dir).read(&head).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::plumbing::init_repo;
    use grit_lib::objects::{CommitData, ObjectKind};
    use grit_lib::write_tree::write_tree_from_index;

    /// Build a `.git` with HEAD → refs/heads/main and one committed file
    /// (loose objects only — exactly what a grit clone produces).
    fn make_committed_repo(tmp: &tempfile::TempDir) {
        let git_dir = tmp.path().join(".git");
        let work_tree = tmp.path();
        init_repo(&git_dir, work_tree, "https://example.com/sigma.git").unwrap();
        let file = work_tree.join("a.txt");
        std::fs::write(&file, "hello\n").unwrap();
        let odb = crate::plumbing::open_odb(&git_dir);
        let mut index = grit_lib::index::Index::new();
        crate::plumbing::add_file_to_index(&git_dir, &file, work_tree, &mut index).unwrap();
        let tree = write_tree_from_index(&odb, &index, "").unwrap();
        let commit = CommitData {
            tree,
            parents: Vec::new(),
            author: "t <t@example.com> 0 +0000".to_string(),
            committer: "t <t@example.com> 0 +0000".to_string(),
            message: "init\n".to_string(),
            encoding: None,
            author_raw: Vec::new(),
            committer_raw: Vec::new(),
            raw_message: None,
        };
        let raw = grit_lib::objects::serialize_commit(&commit);
        let cid = odb.write(ObjectKind::Commit, &raw).unwrap();
        std::fs::create_dir_all(git_dir.join("refs/heads")).unwrap();
        std::fs::write(git_dir.join("refs/heads/main"), format!("{cid}\n")).unwrap();
        std::fs::write(git_dir.join("HEAD"), b"ref: refs/heads/main\n").unwrap();
    }

    #[test]
    fn test_is_repo_complete_with_loose_objects() {
        let tmp = tempfile::tempdir().unwrap();
        make_committed_repo(&tmp);
        assert!(is_repo_complete(&tmp.path().join(".git")));
    }

    #[test]
    fn test_is_repo_complete_after_init_only() {
        let tmp = tempfile::tempdir().unwrap();
        let git_dir = tmp.path().join(".git");
        init_repo(&git_dir, tmp.path(), "https://example.com/sigma.git").unwrap();
        assert!(!is_repo_complete(&git_dir));
    }

    #[test]
    fn test_is_repo_complete_empty() {
        let tmp = tempfile::tempdir().unwrap();
        let git_dir = tmp.path().join(".git");
        std::fs::create_dir(&git_dir).unwrap();
        assert!(!is_repo_complete(&git_dir));
    }

    #[test]
    fn test_set_info_user() {
        let mut repo = SigmaRepo::new();
        repo.set_info_user("testuser", "test@example.com");
        assert_eq!(repo.author, "testuser");
        assert_eq!(repo.email, "test@example.com");
    }

    #[test]
    fn test_set_info_user_empty() {
        let mut repo = SigmaRepo::new();
        repo.set_info_user("", "");
        assert_eq!(repo.author, "");
        assert_eq!(repo.email, "");
    }

    #[test]
    fn test_set_info_http() {
        let mut repo = SigmaRepo::new();
        repo.set_info_http("ghp_token123");
        assert_eq!(repo.transport, GitTransport::Http);
        assert_eq!(repo.token, Some("ghp_token123".to_string()));
    }

    #[test]
    fn test_set_info_http_empty() {
        let mut repo = SigmaRepo::new();
        repo.set_info_http("");
        assert_eq!(repo.transport, GitTransport::Http);
        assert_eq!(repo.token, None);
    }

    #[test]
    fn test_set_info_ssh() {
        let mut repo = SigmaRepo::new();
        repo.set_info_ssh(Some("/home/user/.ssh/id"));
        assert_eq!(repo.transport, GitTransport::Ssh);
        assert_eq!(repo.ssh_key_path, Some("/home/user/.ssh/id".to_string()));
    }

    #[test]
    fn test_set_info_ssh_none() {
        let mut repo = SigmaRepo::new();
        repo.set_info_ssh(None);
        assert_eq!(repo.transport, GitTransport::Ssh);
        assert_eq!(repo.ssh_key_path, None);
    }
}
