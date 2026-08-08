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
pub(crate) mod signing;
pub(crate) mod transport;

#[cfg(test)]
mod regression_tests;

use anyhow::Result;
use grit_lib::objects::ObjectId;
use std::collections::HashSet;
use std::path::{Path, PathBuf};
use tracing::{info, warn};
use uuid::Uuid;

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
    // Optional ed25519 key for signing regression commits (pure-Rust ssh-key)
    signing_key: Option<PathBuf>,
    // Operation modes
    offline: bool,
    contrib: bool,
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
            signing_key: None,
            offline: false,
            contrib: false,
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

    /// Set an ed25519 OpenSSH private key used to sign every regression commit
    /// (pure-Rust signing, no `ssh-keygen`/`gpg` binary needed). `None`
    /// disables signing.
    pub fn set_signing_key(&mut self, signing_key: Option<PathBuf>) {
        self.signing_key = signing_key;
    }

    /// Set git operation modes.
    ///
    /// When `offline` is true, `init()` skips the network pull (and refuses to
    /// clone a missing/incomplete repository). When `contrib` is true, commits
    /// are pushed to the remote fork; when false, commits stay local only.
    pub fn set_git_operations(&mut self, offline: bool, contrib: bool) {
        self.offline = offline;
        self.contrib = contrib;
    }

    /// Returns whether contrib (push to remote) is enabled.
    pub fn contrib_enabled(&self) -> bool {
        self.contrib
    }

    pub fn set_working_branch(&mut self, branch_name: String) -> Result<()> {
        assert!(!branch_name.is_empty(), "working_branch must not be empty");
        self.working_branch = Some(branch_name);
        self.switch_to_working_branch()
    }

    pub async fn init(&mut self) -> Result<()> {
        let git_dir = self.repo_path.join(".git");

        if git_dir.exists() && !is_repo_complete(&git_dir) {
            if self.offline {
                anyhow::bail!(
                    "Repository at {:?} is incomplete and offline mode is enabled. \
                     Delete the sigma/ directory and re-run with offline: false to clone a fresh copy.",
                    self.repo_path
                );
            }
            warn!(
                "Incomplete repository at {:?}, removing and re-cloning",
                self.repo_path
            );
            std::fs::remove_dir_all(&git_dir)?;
        }

        let repo_exists = git_dir.exists();

        if repo_exists {
            self.switch_to_tracking_branch()?;

            if self.offline {
                info!("Offline mode — using existing repository as-is (no pull)");
                return Ok(());
            }

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
        } else if self.offline {
            anyhow::bail!(
                "Repository does not exist at {:?} and offline mode is enabled. \
                 Run with offline: false first to clone the repository.",
                self.repo_path
            );
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
    ///
    /// The whole `sigmacatch/*` namespace is fetched first (glob refspec, one
    /// fetch): the pull in `init()` only fetches the default branch now, so
    /// without this `refs/remotes/origin/sigmacatch/<date>` would go stale and
    /// `create_branch` would base the local branch on HEAD instead of the fork
    /// tip — producing a sibling commit rejected with `RejectNonFastForward`.
    /// A fresh day (branch not yet on the fork) matches nothing: zero updates,
    /// no error. Fetching every `sigmacatch/*` branch (all pending-PR branches,
    /// not just today's) also feeds `pending_regression_rule_ids()` so the
    /// skip set covers data from PRs still open on other days. The fetch is
    /// best-effort: a network failure is logged (`warn!`) and swallowed so the
    /// run degrades to a worktree-only skip set instead of aborting at startup.
    pub fn switch_to_working_branch(&mut self) -> Result<()> {
        let branch_name = self.working_branch.clone().ok_or_else(|| {
            anyhow::anyhow!(
                "No working branch configured — call with_working_branch() before switching"
            )
        })?;
        let git_dir = self.repo_path.join(".git");
        if !self.offline {
            self.fetch_sigmacatch_branches(&git_dir)?;
        }
        create_branch(&git_dir, &branch_name)?;
        crate::plumbing::checkout_main_branch(&git_dir, &self.repo_path)?;
        Ok(())
    }

    /// Fetch every `sigmacatch/*` branch from origin with a single glob
    /// refspec, so their remote tracking refs are current before `create_branch`
    /// bases on them and before `pending_regression_rule_ids()` scans them.
    /// No-op (zero updates) when no such branch exists on the fork yet.
    ///
    /// This is a **best-effort** fetch: a network failure (transient outage,
    /// rate limit, no token) is logged as a `warn!` and swallowed. The run then
    /// degrades gracefully — the skip set is built only from the checked-out
    /// worktree (main) instead of the worktree ∪ pending branches, so an
    /// already-captured PR *could* be re-captured, but the run still proceeds
    /// and completes rather than aborting at startup. The push-rollback guard
    /// still protects against a sibling-commit push (`RejectNonFastForward`).
    fn fetch_sigmacatch_branches(&self, git_dir: &Path) -> Result<()> {
        let remote_url = crate::plumbing::read_remote_url_from_config(git_dir, "origin")?;
        let opts = crate::plumbing::fetch_options_for_sigmacatch_namespace();
        let outcome = match self.transport {
            GitTransport::Http => {
                let http_client = AuthHttpClient::new(self.token.clone())?;
                crate::plumbing::fetch_remote(&http_client, git_dir, &remote_url, &opts)
            }
            GitTransport::Ssh => {
                let ssh_url = https_to_ssh_url(&remote_url).unwrap_or_else(|| remote_url.clone());
                let ssh_cmd =
                    crate::transport::build_ssh_shell_command(self.ssh_key_path.as_deref());
                crate::plumbing::fetch_remote_ssh(git_dir, &ssh_url, ssh_cmd.as_str(), &opts)
            }
        };
        if let Err(e) = outcome {
            warn!(
                "Failed to fetch sigmacatch/* branches from origin ({}): \
                 the skip set will only cover the checked-out worktree. \
                 Re-runs on this repo can still resolve pending-PR data; consider \
                 retrying or checking network/token. Error: {}",
                sanitize_url(&remote_url),
                e
            );
        }
        Ok(())
    }

    /// Collect the rule ids that already have regression data on any remote
    /// `sigmacatch/*` branch (pending PRs not yet merged into main), without
    /// touching the working tree.
    /// Rule ids committed on remote `sigmacatch/*` branches, used to skip rules
    /// awaiting merge. Walks each branch's `regression_data/` tree for files
    /// whose stem is a `Uuid` (the generator commits `<rule_id>.json` +
    /// `<rule_id>.evtx` + `info.yml` as one atomic commit). Rules whose EVTX is
    /// broken (empty export) are excluded so they get re-captured. Best-effort
    /// offline: only the locally fetched refs are scanned.
    pub fn pending_regression_rule_ids(&self) -> Result<Vec<Uuid>> {
        let git_dir = self.repo_path.join(".git");
        let branches = crate::plumbing::list_sigmacatch_remote_refs(&git_dir)?;
        if branches.is_empty() {
            return Ok(Vec::new());
        }
        let odb = crate::plumbing::open_odb(&git_dir);
        let mut valid: HashSet<Uuid> = HashSet::new();
        let mut broken: HashSet<Uuid> = HashSet::new();
        for (refname, oid) in branches {
            let obj = odb
                .read(&oid)
                .map_err(|e| anyhow::anyhow!("Failed to read remote ref '{}': {}", refname, e))?;
            let commit = grit_lib::objects::parse_commit(&obj.data)
                .map_err(|e| anyhow::anyhow!("Failed to parse commit '{}': {}", refname, e))?;
            let tree_obj = odb
                .read(&commit.tree)
                .map_err(|e| anyhow::anyhow!("Failed to read tree of '{}': {}", refname, e))?;
            let entries = grit_lib::objects::parse_tree(&tree_obj.data)
                .map_err(|e| anyhow::anyhow!("Failed to parse tree of '{}': {}", refname, e))?;
            for entry in entries {
                if entry.mode == 0o040000 && entry.name.as_slice() == b"regression_data" {
                    collect_tree_rule_ids(&odb, entry.oid, &mut valid, &mut broken)?;
                }
            }
        }
        // Broken data (e.g. empty EVTX) must not skip the rule: re-capture it.
        let ids: HashSet<Uuid> = valid.difference(&broken).copied().collect();
        info!(
            "{} rule ids found in pending sigmacatch/* branches ({} with broken data)",
            ids.len(),
            broken.len()
        );
        Ok(ids.into_iter().collect())
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

    /// Object id the working branch currently points at locally.
    /// Returns an error if the branch ref is missing or its oid is malformed.
    pub fn working_branch_oid(&self) -> Result<ObjectId> {
        let branch = self
            .working_branch
            .as_deref()
            .ok_or_else(|| anyhow::anyhow!("No working branch configured"))?;
        let git_dir = self.repo_path.join(".git");
        let local_ref = format!("refs/heads/{}", branch);
        let oid_str = crate::plumbing::read_loose_or_packed_ref(&git_dir, &local_ref)
            .ok_or_else(|| anyhow::anyhow!("Working branch '{}' not found locally", branch))?;
        ObjectId::from_hex(&oid_str)
            .map_err(|e| anyhow::anyhow!("Invalid OID for branch '{}': {}", branch, e))
    }

    /// Roll the working branch ref back to `oid` after a push failure that left
    /// an orphaned local commit behind, so the local branch tip stays consistent
    /// with the remote (no dangling commits). The worktree is left untouched;
    /// the next `checkout_main_branch` reconciles it against the restored tip.
    pub fn reset_working_branch_to_commit(&self, oid: ObjectId) -> Result<()> {
        let branch = self
            .working_branch
            .as_deref()
            .ok_or_else(|| anyhow::anyhow!("No working branch configured"))?;
        let git_dir = self.repo_path.join(".git");
        let local_ref = format!("refs/heads/{}", branch);
        crate::plumbing::refs::map_grit(grit_lib::refs::write_ref(&git_dir, &local_ref, &oid))?;
        info!(
            "Reset working branch '{}' back to {} after a failed push",
            branch, oid
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

    /// Commit a set of files with a single message (add + commit only, no push).
    ///
    /// Invalid paths (traversal, NUL) are filtered out via `valid_commit_paths`;
    /// when nothing valid remains the commit is skipped with an `info!` log.
    pub fn git_commit_files(&self, files: Vec<String>, message: String) -> Result<()> {
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
            git_commit(
                &git_dir,
                &self.repo_path,
                message.as_str(),
                name,
                addr,
                self.signing_key.as_deref(),
            )?;
            info!("Committed {} file(s)", valid.len());
        }

        Ok(())
    }

    /// Commit regression data rule by rule, then push once at the end.
    ///
    /// Each `(rule_id, files)` pair becomes its own commit with a rule-specific
    /// message (`test: add regression data for rule {id}`). Empty/fully-invalid
    /// file lists are skipped (a no-op `git_commit` would bail with
    /// "Nothing to commit"). On a push failure the local branch is rolled back
    /// to its pre-batch tip so an orphaned local commit cannot diverge from the
    /// remote (which would cause `RejectNonFastForward` on the next run); the
    /// generated files stay on disk and are reconciled by the next startup.
    /// When contrib is disabled, commits stay local and no push is attempted.
    pub fn upload_rule_batches(&self, batches: Vec<(Uuid, Vec<String>)>) -> Result<()> {
        let pre_oid = self.working_branch_oid()?;
        let mut committed = 0;

        for (rule_id, files) in &batches {
            if files.is_empty() {
                info!("Skipping empty batch for rule {}", rule_id);
                continue;
            }
            let message = format!("🧪 test: add regression data for rule {}", rule_id);
            if let Err(e) = self.git_commit_files(files.clone(), message) {
                warn!(
                    "Commit failed for rule {} after {} commit(s): {} — \
                     rolling local branch back to pre-batch tip {}",
                    rule_id, committed, e, pre_oid
                );
                let _ = self.reset_working_branch_to_commit(pre_oid);
                return Err(e);
            }
            committed += 1;
        }

        if committed == 0 {
            info!("Nothing to commit — skipping push");
            return Ok(());
        }

        if !self.contrib {
            info!(
                "Contrib disabled — {} commit(s) kept local (no push)",
                committed
            );
            return Ok(());
        }

        if let Err(e) = self.push() {
            warn!(
                "Push failed after {} commit(s): {} — rolling local branch back to pre-batch tip {}",
                committed, e, pre_oid
            );
            self.reset_working_branch_to_commit(pre_oid)?;
            return Err(e);
        }

        info!(
            "Pushed {} commit(s) for {} rule(s)",
            committed,
            batches.len()
        );
        Ok(())
    }

    /// Push the working branch to origin. No-op (logged) when contrib is
    /// disabled.
    pub fn push(&self) -> Result<()> {
        if !self.contrib {
            info!("Contrib disabled — skipping push to remote (local commit only)");
            return Ok(());
        }

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
            signing_key: None,
            offline: false,
            contrib: false,
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

/// Recursively walk a git tree in memory and collect `<uuid>` data filenames
/// under `regression_data/` (the generator's skip markers). Never touches the
/// working tree. `.evtx` blobs are parsed to validate they contain records.
fn collect_tree_rule_ids(
    odb: &grit_lib::odb::Odb,
    tree_oid: ObjectId,
    valid: &mut HashSet<Uuid>,
    broken: &mut HashSet<Uuid>,
) -> Result<()> {
    collect_tree_rule_ids_depth(odb, tree_oid, valid, broken, 0)
}

const MAX_REGRESSION_TREE_DEPTH: u32 = 32;

fn collect_tree_rule_ids_depth(
    odb: &grit_lib::odb::Odb,
    tree_oid: ObjectId,
    valid: &mut HashSet<Uuid>,
    broken: &mut HashSet<Uuid>,
    depth: u32,
) -> Result<()> {
    if depth > MAX_REGRESSION_TREE_DEPTH {
        warn!("regression_data tree exceeds depth limit at {:?}", tree_oid);
        return Ok(());
    }
    let obj = odb.read(&tree_oid)?;
    let entries = grit_lib::objects::parse_tree(&obj.data)?;
    for entry in entries {
        if entry.mode == 0o040000 {
            collect_tree_rule_ids_depth(odb, entry.oid, valid, broken, depth + 1)?;
        } else if matches!(entry.mode, 0o100644 | 0o100755) {
            let name = String::from_utf8_lossy(&entry.name);
            let stem = name.rsplit_once('.').map(|(s, _)| s).unwrap_or(&name);
            if let Ok(id) = Uuid::parse_str(stem) {
                if name.ends_with(".evtx") {
                    // Empty/undecodable EVTX blob = the empty-export bug: do not
                    // skip the rule so it is re-captured with valid data.
                    match odb.read(&entry.oid) {
                        Ok(blob) => match input_evtx::parse_evtx_bytes(&blob.data) {
                            Ok(events) if !events.is_empty() => {
                                valid.insert(id);
                            }
                            _ => {
                                warn!(
                                    "rule {} excluded from pending skip-set: broken EVTX '{}' (will be re-captured)",
                                    id, name
                                );
                                broken.insert(id);
                            }
                        },
                        Err(e) => {
                            warn!("failed to read EVTX blob '{}': {}", name, e);
                            broken.insert(id);
                        }
                    }
                } else {
                    valid.insert(id);
                }
            }
        }
    }
    Ok(())
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

    fn write_commit(odb: &grit_lib::odb::Odb, tree: ObjectId, parents: Vec<ObjectId>) -> ObjectId {
        let commit = CommitData {
            tree,
            parents,
            author: "t <t@example.com> 0 +0000".to_string(),
            committer: "t <t@example.com> 0 +0000".to_string(),
            message: "remote\n".to_string(),
            encoding: None,
            author_raw: Vec::new(),
            committer_raw: Vec::new(),
            raw_message: None,
        };
        let raw = grit_lib::objects::serialize_commit(&commit);
        odb.write(ObjectKind::Commit, &raw).unwrap()
    }

    /// Set up a committed repo whose remote tracking ref `sigmacatch/20260803`
    /// points at a commit with (`has_parent`) / (`has_rules`) characteristics.
    /// Returns a SigmaRepo configured on that working branch.
    fn setup_remote_branch(
        tmp: &tempfile::TempDir,
        has_parent: bool,
        has_rules: bool,
    ) -> SigmaRepo {
        make_committed_repo(tmp);
        let git_dir = tmp.path().join(".git");
        let odb = crate::plumbing::open_odb(&git_dir);
        let mut index = grit_lib::index::Index::new();
        if has_rules {
            std::fs::create_dir_all(tmp.path().join("rules")).unwrap();
            let f = tmp.path().join("rules/x.yml");
            std::fs::write(&f, "title: x\n").unwrap();
            crate::plumbing::add_file_to_index(&git_dir, &f, tmp.path(), &mut index).unwrap();
        } else {
            let f = tmp.path().join("a.txt");
            std::fs::write(&f, "a\n").unwrap();
            crate::plumbing::add_file_to_index(&git_dir, &f, tmp.path(), &mut index).unwrap();
        }
        let tree = write_tree_from_index(&odb, &index, "").unwrap();
        let parent = crate::plumbing::resolve_head(&git_dir).unwrap();
        let parents = if has_parent { vec![parent] } else { Vec::new() };
        let remote_oid = write_commit(&odb, tree, parents);
        let remote_ref = git_dir.join("refs/remotes/origin/sigmacatch/20260803");
        std::fs::create_dir_all(remote_ref.parent().unwrap()).unwrap();
        std::fs::write(&remote_ref, format!("{remote_oid}\n")).unwrap();

        let mut repo = SigmaRepo::new();
        repo.repo_path = tmp.path().to_path_buf();
        repo.working_branch = Some("sigmacatch/20260803".to_string());
        repo
    }

    #[test]
    fn test_check_remote_working_branch_absent_is_ok() {
        let tmp = tempfile::tempdir().unwrap();
        make_committed_repo(&tmp);
        let mut repo = SigmaRepo::new();
        repo.repo_path = tmp.path().to_path_buf();
        repo.working_branch = Some("sigmacatch/20260803".to_string());
        assert!(repo.check_remote_working_branch().is_ok());
    }

    #[test]
    fn test_check_remote_working_branch_valid_is_ok() {
        let tmp = tempfile::tempdir().unwrap();
        let repo = setup_remote_branch(&tmp, true, true);
        assert!(repo.check_remote_working_branch().is_ok());
    }

    #[test]
    fn test_check_remote_working_branch_orphan_rejected() {
        let tmp = tempfile::tempdir().unwrap();
        let repo = setup_remote_branch(&tmp, false, true);
        let err = repo.check_remote_working_branch().unwrap_err();
        assert!(
            err.to_string().to_lowercase().contains("parent"),
            "orphan commit must be rejected: {err}"
        );
    }

    #[test]
    fn test_check_remote_working_branch_missing_rules_rejected() {
        let tmp = tempfile::tempdir().unwrap();
        let repo = setup_remote_branch(&tmp, true, false);
        let err = repo.check_remote_working_branch().unwrap_err();
        assert!(
            err.to_string().to_lowercase().contains("rules"),
            "amputated tree must be rejected: {err}"
        );
    }

    /// `working_branch_oid` must reflect the local branch tip and
    /// `reset_working_branch_to_commit` must move it (rollback after a failed
    /// push).
    #[test]
    fn test_working_branch_oid_and_reset() {
        let tmp = tempfile::tempdir().unwrap();
        make_committed_repo(&tmp);
        let git_dir = tmp.path().join(".git");
        let head_oid = crate::plumbing::resolve_head(&git_dir).unwrap();

        crate::branch::create_branch(&git_dir, "sigmacatch/20260803").unwrap();
        let mut repo = SigmaRepo::new();
        repo.repo_path = tmp.path().to_path_buf();
        repo.working_branch = Some("sigmacatch/20260803".to_string());

        assert_eq!(
            repo.working_branch_oid().unwrap(),
            head_oid,
            "branch tip must match HEAD after creation"
        );

        let odb = crate::plumbing::open_odb(&git_dir);
        let empty_tree = write_tree_from_index(&odb, &grit_lib::index::Index::new(), "").unwrap();
        let other_oid = write_commit(&odb, empty_tree, vec![head_oid]);

        repo.reset_working_branch_to_commit(other_oid).unwrap();
        assert_eq!(
            repo.working_branch_oid().unwrap(),
            other_oid,
            "reset must move the local branch ref"
        );

        // Roll back to the original tip (simulating a failed-push rollback).
        repo.reset_working_branch_to_commit(head_oid).unwrap();
        assert_eq!(repo.working_branch_oid().unwrap(), head_oid);
    }

    /// A run with contrib disabled must still commit locally — only the push is
    /// gated. `upload_rule_batches` produces a commit per rule with the
    /// rule-specific message.
    #[test]
    fn test_upload_rule_batches_commits_locally_when_contrib_disabled() {
        let tmp = tempfile::tempdir().unwrap();
        make_committed_repo(&tmp);
        let git_dir = tmp.path().join(".git");
        crate::branch::create_branch(&git_dir, "sigmacatch/20260803").unwrap();

        let rel = "regression_data/rules/win/a.json";
        std::fs::create_dir_all(tmp.path().join("regression_data/rules/win")).unwrap();
        std::fs::write(tmp.path().join(rel), "{}").unwrap();

        let mut repo = SigmaRepo::new();
        repo.repo_path = tmp.path().to_path_buf();
        repo.working_branch = Some("sigmacatch/20260803".to_string());
        repo.set_info_user("testuser", "test@example.com");
        repo.contrib = false;

        let before = repo.working_branch_oid().unwrap();
        let rule_id = Uuid::new_v4();
        repo.upload_rule_batches(vec![(rule_id, vec![rel.to_string()])])
            .unwrap();
        let after = repo.working_branch_oid().unwrap();
        assert_ne!(
            before, after,
            "contrib-disabled run must still commit locally"
        );
    }

    /// Empty file lists must not produce a commit (`git_commit` would bail with
    /// "Nothing to commit" on an unchanged tree).
    #[test]
    fn test_upload_rule_batches_skips_empty_batches() {
        let tmp = tempfile::tempdir().unwrap();
        make_committed_repo(&tmp);
        let git_dir = tmp.path().join(".git");
        crate::branch::create_branch(&git_dir, "sigmacatch/20260803").unwrap();

        let mut repo = SigmaRepo::new();
        repo.repo_path = tmp.path().to_path_buf();
        repo.working_branch = Some("sigmacatch/20260803".to_string());
        repo.contrib = false;

        let before = repo.working_branch_oid().unwrap();
        let rule_id = Uuid::new_v4();
        repo.upload_rule_batches(vec![(rule_id, vec![])]).unwrap();
        let after = repo.working_branch_oid().unwrap();
        assert_eq!(before, after, "empty batches must not create a commit");
    }

    /// `push()` must no-op (Ok) when contrib is disabled — no working branch,
    /// no network needed.
    #[test]
    fn test_push_noop_when_contrib_disabled() {
        let mut repo = SigmaRepo::new();
        repo.contrib = false;
        assert!(repo.push().is_ok(), "contrib-disabled push must no-op");
    }

    #[test]
    fn test_set_git_operations_enables_contrib() {
        let mut repo = SigmaRepo::new();
        repo.set_git_operations(true, true);
        assert!(repo.contrib_enabled());
    }

    /// A commit failure mid-batch must roll the local branch back to its
    /// pre-batch tip so no orphaned commits remain. We stage two batches:
    /// the first commits a real file; the second references a path that resolves
    /// to no on-disk file, so `git_add` stages nothing and `git_commit` bails
    /// "Nothing to commit". The failure must roll back the first commit.
    #[test]
    fn test_upload_rule_batches_rolls_back_on_commit_failure() {
        let tmp = tempfile::tempdir().unwrap();
        make_committed_repo(&tmp);
        let git_dir = tmp.path().join(".git");
        crate::branch::create_branch(&git_dir, "sigmacatch/20260803").unwrap();

        let good = "regression_data/rules/win/good.json";
        std::fs::create_dir_all(tmp.path().join("regression_data/rules/win")).unwrap();
        std::fs::write(tmp.path().join(good), "{}").unwrap();
        // bad path: syntactically valid (no NUL/..) but absent on disk
        let bad = "regression_data/rules/win/missing.json".to_string();

        let mut repo = SigmaRepo::new();
        repo.repo_path = tmp.path().to_path_buf();
        repo.working_branch = Some("sigmacatch/20260803".to_string());
        repo.set_info_user("testuser", "test@example.com");
        repo.contrib = true;

        let before = repo.working_branch_oid().unwrap();
        let rule_a = Uuid::new_v4();
        let rule_b = Uuid::new_v4();
        let result = repo.upload_rule_batches(vec![
            (rule_a, vec![good.to_string()]),
            (rule_b, vec![bad.clone()]),
        ]);

        assert!(
            result.is_err(),
            "second batch must fail (Nothing to commit)"
        );
        let after = repo.working_branch_oid().unwrap();
        assert_eq!(
            before, after,
            "first commit must be rolled back on the second batch's failure"
        );
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

    /// Build a remote ref `sigmacatch/<date>` whose commit tree contains the
    /// given `regression_data` files, and return the `SigmaRepo` configured on
    /// the next working branch.
    fn setup_pending_branch(tmp: &tempfile::TempDir, rel_files: &[(&str, &[u8])]) -> SigmaRepo {
        make_committed_repo(tmp);
        let git_dir = tmp.path().join(".git");
        let odb = crate::plumbing::open_odb(&git_dir);
        for (rel, content) in rel_files {
            let path = tmp.path().join(rel);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(&path, content).unwrap();
        }
        let mut index = grit_lib::index::Index::new();
        crate::plumbing::add_directory_to_index(
            &git_dir,
            &tmp.path().join("regression_data"),
            tmp.path(),
            &mut index,
        )
        .unwrap();
        let tree = write_tree_from_index(&odb, &index, "").unwrap();
        let parent = crate::plumbing::resolve_head(&git_dir).unwrap();
        let remote_oid = write_commit(&odb, tree, vec![parent]);
        let remote_ref = git_dir.join("refs/remotes/origin/sigmacatch/20260807");
        std::fs::create_dir_all(remote_ref.parent().unwrap()).unwrap();
        std::fs::write(&remote_ref, format!("{remote_oid}\n")).unwrap();

        let mut repo = SigmaRepo::new();
        repo.repo_path = tmp.path().to_path_buf();
        repo.working_branch = Some("sigmacatch/20260808".to_string());
        repo
    }

    /// Rule ids committed on a pending-PR branch (not merged into main) must be
    /// returned, so a fresh VM's skip set covers them. Non-`<uuid>` files are
    /// ignored. Rules whose committed `.evtx` has no records (empty-export bug)
    /// are excluded so they are re-captured with valid data.
    #[test]
    fn test_pending_regression_rule_ids_from_remote_branch() {
        let tmp = tempfile::tempdir().unwrap();
        let id1 = Uuid::new_v4();
        let id2 = Uuid::new_v4();
        let id3 = Uuid::new_v4();
        let repo = setup_pending_branch(
            &tmp,
            &[
                (
                    &format!("regression_data/rules/win/a/{id1}.json"),
                    b"{}".as_slice(),
                ),
                (
                    &format!("regression_data/rules/win/a/{id1}.evtx"),
                    include_bytes!("../tests/fixtures/valid-single.evtx").as_slice(),
                ),
                (
                    "regression_data/rules/win/a/info.yml",
                    b"test: x\n".as_slice(),
                ),
                (
                    &format!("regression_data/rules/win/b/{id2}.json"),
                    b"{}".as_slice(),
                ),
                (
                    "regression_data/rules/win/b/info.yml",
                    b"test: x\n".as_slice(),
                ),
                (
                    "regression_data/rules/win/b/not-a-rule.txt",
                    b"x".as_slice(),
                ),
                (
                    &format!("regression_data/rules/win/c/{id3}.json"),
                    b"{}".as_slice(),
                ),
                (
                    &format!("regression_data/rules/win/c/{id3}.evtx"),
                    b"x".as_slice(),
                ),
                (
                    "regression_data/rules/win/c/info.yml",
                    b"test: x\n".as_slice(),
                ),
            ],
        );

        let mut ids = repo.pending_regression_rule_ids().unwrap();
        ids.sort();
        let mut expected = vec![id1, id2];
        expected.sort();
        assert_eq!(ids, expected);
    }

    /// No `sigmacatch/*` remote refs → empty skip source (fresh fork, fresh day).
    #[test]
    fn test_pending_regression_rule_ids_empty_without_branches() {
        let tmp = tempfile::tempdir().unwrap();
        make_committed_repo(&tmp);
        let mut repo = SigmaRepo::new();
        repo.repo_path = tmp.path().to_path_buf();
        repo.working_branch = Some("sigmacatch/20260808".to_string());

        assert!(
            repo.pending_regression_rule_ids().unwrap().is_empty(),
            "no remote sigmacatch/* branches must yield no pending ids"
        );
    }

    /// Two pending branches that share a rule id must dedupe (HashSet union).
    #[test]
    fn test_pending_regression_rule_ids_dedupes_across_branches() {
        let tmp = tempfile::tempdir().unwrap();
        let id = Uuid::new_v4();
        let rel = format!("regression_data/rules/win/a/{id}.json");
        setup_pending_branch(
            &tmp,
            &[
                (&rel, b"{}".as_slice()),
                ("regression_data/rules/win/a/info.yml", b"x".as_slice()),
            ],
        );

        let git_dir = tmp.path().join(".git");
        let first_ref = git_dir.join("refs/remotes/origin/sigmacatch/20260807");
        let oid = std::fs::read_to_string(&first_ref).unwrap();
        let second_ref = git_dir.join("refs/remotes/origin/sigmacatch/20260806");
        std::fs::create_dir_all(second_ref.parent().unwrap()).unwrap();
        std::fs::write(&second_ref, oid).unwrap();

        let mut repo = SigmaRepo::new();
        repo.repo_path = tmp.path().to_path_buf();
        repo.working_branch = Some("sigmacatch/20260808".to_string());

        let ids = repo.pending_regression_rule_ids().unwrap();
        assert_eq!(
            ids.len(),
            1,
            "shared rule id across branches must dedupe, got: {ids:?}"
        );
        assert!(ids.contains(&id));
    }
}
