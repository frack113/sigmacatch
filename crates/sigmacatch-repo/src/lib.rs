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

use anyhow::Result;
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

    /// At startup, inspect the remote-tracking ref of the working branch.
    ///
    /// A prior buggy run could have pushed a commit whose tree deleted the whole
    /// repository content (leaving only `regression_data/`). Re-running on top
    /// of that branch produces commits the remote can't fast-forward, so pushes
    /// keep failing. Detect this early — before collecting any events — and
    /// bail with an actionable message so the user deletes the corrupted branch.
    ///
    /// Detection is `fail-open`: if the remote-tracking ref is absent (first
    /// run) or its objects can't be read, we proceed. Only a tree that is
    /// readable yet missing the canonical `rules/` directory is treated as
    /// corruption.
    pub fn check_remote_working_branch(&self) -> Result<()> {
        let branch = match &self.working_branch {
            Some(b) => b.as_str(),
            None => return Ok(()),
        };
        let git_dir = self.repo_path.join(".git");
        let remote_ref = format!("refs/remotes/origin/{branch}");
        let Some(oid_str) = crate::plumbing::read_loose_or_packed_ref(&git_dir, &remote_ref) else {
            info!("No existing remote working branch '{branch}' — proceeding (first run)");
            return Ok(());
        };
        let oid = grit_lib::objects::ObjectId::from_hex(&oid_str)
            .map_err(|e| anyhow::anyhow!("Invalid OID for remote branch '{branch}': {e}"))?;
        let odb = crate::plumbing::open_odb(&git_dir);
        let commit_obj = match odb.read(&oid) {
            Ok(o) => o,
            Err(e) => {
                warn!(
                    "Could not read remote branch commit for '{branch}' ({e}) — \
                     unable to verify health, proceeding"
                );
                return Ok(());
            }
        };
        let commit = grit_lib::objects::parse_commit(&commit_obj.data)
            .map_err(|e| anyhow::anyhow!("Failed to parse remote branch commit: {e}"))?;
        let tree_obj = match odb.read(&commit.tree) {
            Ok(o) => o,
            Err(e) => {
                warn!(
                    "Could not read remote branch tree for '{branch}' ({e}) — \
                     unable to verify health, proceeding"
                );
                return Ok(());
            }
        };
        let entries = grit_lib::objects::parse_tree(&tree_obj.data)
            .map_err(|e| anyhow::anyhow!("Failed to parse remote branch tree: {e}"))?;
        let has_rules = entries.iter().any(|e| {
            e.mode == 0o040000
                && std::str::from_utf8(&e.name)
                    .map(|n| n == "rules")
                    .unwrap_or(false)
        });
        if !has_rules {
            let top_entries: Vec<String> = entries
                .iter()
                .filter_map(|e| std::str::from_utf8(&e.name).ok().map(|n| n.to_string()))
                .collect();
            anyhow::bail!(
                "Remote working branch '{branch}' is corrupted — its root tree is missing \
                 the `rules/` directory (top-level entries: {:?}). \
                 A prior buggy commit deleted the repository content, and re-running on top \
                 of it would only produce push failures. \
                 Fix: delete the '{branch}' branch on your fork \
                 ({fork}) and re-run sigmacatch.",
                top_entries,
                fork = self.remote_url.as_deref().unwrap_or("<fork-url>")
            );
        }
        info!("Remote working branch '{branch}' is healthy — proceeding");
        Ok(())
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
    /// Creates it from HEAD if it doesn't exist locally, switches otherwise.
    pub fn switch_to_working_branch(&mut self) -> Result<()> {
        let branch_name = self.working_branch.clone().ok_or_else(|| {
            anyhow::anyhow!(
                "No working branch configured — call with_working_branch() before switching"
            )
        })?;
        let git_dir = self.repo_path.join(".git");
        create_branch(&git_dir, &branch_name)?;
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

    /// Stage, commit, and push `files` with `message` in one call. Each commit
    /// is published immediately (creating/updating the contrib branch on the
    /// remote), so a run interrupted after a commit can no longer strand it.
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

    /// Push the working branch to the remote.
    pub fn push(&self) -> Result<()> {
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
    (has_packed_refs && (has_objects || has_refs)) || (has_objects && has_refs)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_repo_complete_with_packed_refs() {
        let tmp = tempfile::tempdir().unwrap();
        let git_dir = tmp.path().join(".git");
        std::fs::create_dir(&git_dir).unwrap();
        std::fs::write(git_dir.join("packed-refs"), "test").unwrap();
        std::fs::create_dir_all(git_dir.join("objects/pack")).unwrap();
        std::fs::write(git_dir.join("objects/pack/pack.idx"), "test").unwrap();
        assert!(is_repo_complete(&git_dir));
    }

    #[test]
    fn test_is_repo_complete_with_objects() {
        let tmp = tempfile::tempdir().unwrap();
        let git_dir = tmp.path().join(".git");
        std::fs::create_dir_all(git_dir.join("objects/pack")).unwrap();
        std::fs::write(git_dir.join("objects/pack/pack.idx"), "test").unwrap();
        std::fs::create_dir_all(git_dir.join("refs/heads")).unwrap();
        std::fs::write(git_dir.join("refs/heads/main"), "abc123").unwrap();
        assert!(is_repo_complete(&git_dir));
    }

    #[test]
    fn test_is_repo_complete_with_refs() {
        let tmp = tempfile::tempdir().unwrap();
        let git_dir = tmp.path().join(".git");
        std::fs::create_dir_all(git_dir.join("refs/heads")).unwrap();
        std::fs::write(git_dir.join("refs/heads/main"), "abc123").unwrap();
        std::fs::create_dir_all(git_dir.join("objects/pack")).unwrap();
        std::fs::write(git_dir.join("objects/pack/pack.idx"), "test").unwrap();
        assert!(is_repo_complete(&git_dir));
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

    fn write_commit(
        git_dir: &Path,
        work_tree: &Path,
        files: &[(&str, &str)],
        parents: &[grit_lib::objects::ObjectId],
    ) -> grit_lib::objects::ObjectId {
        let odb = crate::plumbing::checkout::open_odb(git_dir);
        let mut index = grit_lib::index::Index::new();
        for (rel, content) in files {
            let full = work_tree.join(rel);
            if let Some(p) = full.parent() {
                std::fs::create_dir_all(p).unwrap();
            }
            std::fs::write(&full, content).unwrap();
            crate::plumbing::index::add_file_to_index(git_dir, &full, work_tree, &mut index)
                .unwrap();
        }
        let tree_oid = grit_lib::write_tree::write_tree_from_index(&odb, &index, "").unwrap();
        let commit = grit_lib::objects::CommitData {
            tree: tree_oid,
            parents: parents.to_vec(),
            author: "test <test@example.com> 0 +0000".to_string(),
            committer: "test <test@example.com> 0 +0000".to_string(),
            message: "commit\n".to_string(),
            encoding: None,
            author_raw: Vec::new(),
            committer_raw: Vec::new(),
            raw_message: None,
        };
        let raw = grit_lib::objects::serialize_commit(&commit);
        odb.write(grit_lib::objects::ObjectKind::Commit, &raw)
            .unwrap()
    }

    fn set_loose_ref(git_dir: &Path, ref_name: &str, oid: grit_lib::objects::ObjectId) {
        let path = git_dir.join(ref_name);
        if let Some(p) = path.parent() {
            std::fs::create_dir_all(p).unwrap();
        }
        std::fs::write(path, format!("{}\n", oid)).unwrap();
    }

    fn branch_name() -> String {
        "sigmacatch-contrib/frack113".to_string()
    }

    #[test]
    fn test_check_remote_working_branch_ok_when_absent() {
        let tmp = tempfile::tempdir().unwrap();
        let work_tree = tmp.path().to_path_buf();
        let git_dir = work_tree.join(".git");
        crate::plumbing::init::init_repo(&git_dir, &work_tree, "https://example.com/sigma.git")
            .unwrap();
        // No refs/remotes/origin/* exists yet → first run → must not stop.
        let mut repo = SigmaRepo::new();
        repo.repo_path = work_tree;
        repo.remote_url = Some("https://github.com/frack113/sigma".to_string());
        repo.working_branch = Some(branch_name());
        assert!(repo.check_remote_working_branch().is_ok());
    }

    #[test]
    fn test_check_remote_working_branch_ok_when_healthy() {
        let tmp = tempfile::tempdir().unwrap();
        let work_tree = tmp.path().to_path_buf();
        let git_dir = work_tree.join(".git");
        crate::plumbing::init::init_repo(&git_dir, &work_tree, "https://example.com/sigma.git")
            .unwrap();

        let main_oid = write_commit(
            &git_dir,
            &work_tree,
            &[("rules/windows/foo.yml", "title: Foo\n")],
            &[],
        );
        set_loose_ref(&git_dir, "refs/heads/main", main_oid);

        // A healthy working branch: its tree still carries `rules/` plus the
        // new regression file.
        let healthy_oid = write_commit(
            &git_dir,
            &work_tree,
            &[
                ("rules/windows/foo.yml", "title: Foo\n"),
                ("regression_data/rules/1234/info.yml", "id: 1234\n"),
            ],
            &[main_oid],
        );
        set_loose_ref(
            &git_dir,
            &format!("refs/remotes/origin/{}", branch_name()),
            healthy_oid,
        );

        let mut repo = SigmaRepo::new();
        repo.repo_path = work_tree;
        repo.remote_url = Some("https://github.com/frack113/sigma".to_string());
        repo.working_branch = Some(branch_name());
        assert!(repo.check_remote_working_branch().is_ok());
    }

    #[test]
    fn test_check_remote_working_branch_bails_when_corrupted() {
        let tmp = tempfile::tempdir().unwrap();
        let work_tree = tmp.path().to_path_buf();
        let git_dir = work_tree.join(".git");
        crate::plumbing::init::init_repo(&git_dir, &work_tree, "https://example.com/sigma.git")
            .unwrap();

        let main_oid = write_commit(
            &git_dir,
            &work_tree,
            &[("rules/windows/foo.yml", "title: Foo\n")],
            &[],
        );
        set_loose_ref(&git_dir, "refs/heads/main", main_oid);

        // Corrupted working branch: a commit whose tree contains ONLY
        // regression_data/ (the `rules/` directory is gone).
        let corrupted_oid = write_commit(
            &git_dir,
            &work_tree,
            &[("regression_data/rules/1234/info.yml", "id: 1234\n")],
            &[main_oid],
        );
        set_loose_ref(
            &git_dir,
            &format!("refs/remotes/origin/{}", branch_name()),
            corrupted_oid,
        );

        let mut repo = SigmaRepo::new();
        repo.repo_path = work_tree;
        repo.remote_url = Some("https://github.com/frack113/sigma".to_string());
        repo.working_branch = Some(branch_name());
        let err = repo.check_remote_working_branch().unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("corrupted"), "msg: {msg}");
        assert!(msg.contains(branch_name().as_str()), "msg: {msg}");
    }
}
