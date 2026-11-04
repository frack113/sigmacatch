// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 sigmacatch contributors

//! Porcelain layer — high-level wrappers: clone, pull, push, add, commit.

use crate::repo::{RepoError, Result};
use std::path::Path;
use tracing::{info, warn};

use crate::repo::plumbing::{
    add_directory_to_index, add_file_to_index, add_tree_to_index, checkout_main_branch,
    commit_tree, connect_with_default_branch, fast_forward_branch, fetch_options_for_branches,
    fetch_options_for_shallow_clone, fetch_options_for_unshallow, fetch_remote, fetch_remote_on,
    init_repo, open_odb, read_remote_url_from_config, resolve_head, set_head_after_fetch,
    setup_sparse_checkout, symbolic_ref_target, write_index,
};
use crate::repo::transport::{build_ssh_shell_command, https_to_ssh_url};

/// Branch name (e.g. `master`) that HEAD currently points at, when HEAD is on
/// a symbolic ref. Returns `None` for a detached HEAD.
fn current_branch_name(git_dir: &Path) -> Result<Option<String>> {
    Ok(symbolic_ref_target(git_dir, "HEAD")?
        .and_then(|target| target.strip_prefix("refs/heads/").map(String::from)))
}

/// Clone a repository over SSH (full history).
pub(crate) fn git_clone(url: &str, dest: &Path, ssh_key_path: Option<&str>) -> Result<()> {
    let git_dir = dest.join(".git");
    if git_dir.exists() {
        info!("Repository already exists at {:?}, skipping clone", dest);
        return Ok(());
    }

    info!("Cloning via SSH into {:?}", dest);
    init_repo(&git_dir, dest, url)?;
    let ssh_mode = build_ssh_shell_command(ssh_key_path);
    let (mut conn, default_branch) = match connect_with_default_branch(url, &ssh_mode) {
        Ok(r) => r,
        Err(e) => {
            let _ = std::fs::remove_dir_all(&git_dir);
            return Err(e);
        }
    };
    info!("Remote default branch: {default_branch}");
    let opts = fetch_options_for_branches(&[default_branch.as_str()]);
    let (count, default_branch) = match fetch_remote_on(&git_dir, &mut *conn, &opts) {
        Ok(r) => r,
        Err(e) => {
            let _ = std::fs::remove_dir_all(&git_dir);
            return Err(e);
        }
    };
    if count == 0 {
        let _ = std::fs::remove_dir_all(&git_dir);
        return Err(RepoError::State(
            "No refs fetched from remote via SSH — empty or unreachable repository".to_string(),
        ));
    }

    set_head_after_fetch(&git_dir, default_branch.as_deref());

    checkout_main_branch(&git_dir, dest)?;

    crate::repo::plumbing::pack_loose_objects(&git_dir)?;

    Ok(())
}

/// Clone a repository using SSH transport with shallow clone and optional sparse checkout.
pub(crate) fn git_clone_shallow(
    url: &str,
    dest: &Path,
    ssh_key_path: Option<&str>,
    sparse_checkout: bool,
) -> Result<()> {
    let git_dir = dest.join(".git");
    if git_dir.exists() {
        info!("Repository already exists at {:?}, skipping clone", dest);
        return Ok(());
    }

    info!(
        "Cloning via SSH into {:?} (shallow, sparse={})",
        dest, sparse_checkout
    );
    init_repo(&git_dir, dest, url)?;

    // Configure sparse checkout before fetch if requested
    if sparse_checkout {
        setup_sparse_checkout(&git_dir)?;
    }

    let ssh_mode = build_ssh_shell_command(ssh_key_path);
    let (mut conn, default_branch) = match connect_with_default_branch(url, &ssh_mode) {
        Ok(r) => r,
        Err(e) => {
            let _ = std::fs::remove_dir_all(&git_dir);
            return Err(e);
        }
    };
    info!("Remote default branch: {default_branch}");
    let opts = fetch_options_for_shallow_clone(&[default_branch.as_str()]);
    let (count, default_branch) = match fetch_remote_on(&git_dir, &mut *conn, &opts) {
        Ok(r) => r,
        Err(e) => {
            let _ = std::fs::remove_dir_all(&git_dir);
            return Err(e);
        }
    };
    if count == 0 {
        let _ = std::fs::remove_dir_all(&git_dir);
        return Err(RepoError::State(
            "No refs fetched from remote via SSH — empty or unreachable repository".to_string(),
        ));
    }

    set_head_after_fetch(&git_dir, default_branch.as_deref());

    checkout_main_branch(&git_dir, dest)?;

    crate::repo::plumbing::pack_loose_objects(&git_dir)?;

    Ok(())
}

/// Unshallow a shallow repository over SSH (fetch full history).
/// Used before push when repo was cloned with shallow_clone=true.
pub(crate) fn git_unshallow(git_dir: &Path, ssh_key_path: Option<&str>) -> Result<()> {
    let remote_url = read_remote_url_from_config(git_dir, "origin")?;
    let ssh_url = https_to_ssh_url(&remote_url).unwrap_or(remote_url);
    let ssh_mode = build_ssh_shell_command(ssh_key_path);
    let branch = current_branch_name(git_dir)?
        .ok_or_else(|| RepoError::State("Cannot unshallow — HEAD is detached".to_string()))?;
    let opts = fetch_options_for_unshallow(&[branch.as_str()]);

    fetch_remote(git_dir, &ssh_url, &ssh_mode, &opts)?;
    crate::repo::plumbing::pack_loose_objects(git_dir)?;

    let work_tree = git_dir
        .parent()
        .ok_or_else(|| RepoError::State("Cannot determine worktree from git_dir".to_string()))?;
    checkout_main_branch(git_dir, work_tree)?;

    Ok(())
}

/// Fetch from origin over SSH and fast-forward the current branch.
///
/// Only the current branch is fetched (narrow refspec) — the default branch
/// after `switch_to_tracking_branch`, never the wildcard `+refs/heads/*`.
pub(crate) fn git_pull(git_dir: &Path, ssh_key_path: Option<&str>) -> Result<()> {
    let remote_url = read_remote_url_from_config(git_dir, "origin")?;
    let ssh_url = https_to_ssh_url(&remote_url).unwrap_or(remote_url);
    let ssh_mode = build_ssh_shell_command(ssh_key_path);
    let branch = current_branch_name(git_dir)?
        .ok_or_else(|| RepoError::State("Cannot pull — HEAD is detached".to_string()))?;
    let opts = fetch_options_for_branches(&[branch.as_str()]);

    fetch_remote(git_dir, &ssh_url, &ssh_mode, &opts)?;
    fast_forward_branch(git_dir)?;

    crate::repo::plumbing::pack_loose_objects(git_dir)?;

    // Re-checkout worktree to reflect any changes from fast-forward
    let work_tree = git_dir
        .parent()
        .ok_or_else(|| RepoError::State("Cannot determine worktree from git_dir".to_string()))?;
    checkout_main_branch(git_dir, work_tree)?;
    Ok(())
}

/// Stage files under `paths` (relative to `work_tree`) into the git index.
pub(crate) fn git_add(git_dir: &Path, work_tree: &Path, paths: &[&str]) -> Result<()> {
    let mut index = grit_lib::index::Index::new();
    for path in paths {
        let full_path = work_tree.join(path);
        if !full_path.exists() {
            warn!("Path does not exist, skipping: {:?}", full_path);
            continue;
        }
        if full_path.is_dir() {
            add_directory_to_index(git_dir, &full_path, work_tree, &mut index)?;
        } else if full_path.is_file() {
            add_file_to_index(git_dir, &full_path, work_tree, &mut index)?;
        }
    }
    write_index(git_dir, &mut index)?;
    Ok(())
}

/// Commit whatever is currently staged in the index.
/// Must be called after `git_add`.
/// Merges the parent commit's tree with staged changes so existing
/// files are preserved in the new commit (not just the staged ones).
pub(crate) fn git_commit(
    git_dir: &Path,
    _work_tree: &Path,
    msg: &str,
    author: &str,
    email: &str,
    signing_key: Option<&Path>,
) -> Result<()> {
    let index_path = git_dir.join("index");
    if !index_path.exists() {
        return Err(RepoError::State(
            "No index to commit — call git_add first".to_string(),
        ));
    }
    let odb = open_odb(git_dir);

    let staged_index = grit_lib::index::Index::load(&index_path)
        .map_err(|e| RepoError::Grit(format!("Failed to load index: {}", e)))?;

    let parent_oid = resolve_head(git_dir)?;
    let parent_obj = odb
        .read(&parent_oid)
        .map_err(|e| RepoError::Grit(format!("Failed to read HEAD commit: {}", e)))?;
    let parent_commit = grit_lib::objects::parse_commit(&parent_obj.data)
        .map_err(|e| RepoError::Grit(format!("Failed to parse HEAD commit: {}", e)))?;

    // Add the full parent (HEAD) tree at stage 0, then overlay the staged
    // entries with `add_or_replace` so staged blob content wins. There is no
    // staged-paths filtering — that was the site of a prior tree-amputation
    // bug (inverted condition).
    let mut merged_index = grit_lib::index::Index::new();
    add_tree_to_index(&odb, parent_commit.tree, "", &mut merged_index)?;
    for entry in staged_index.entries() {
        merged_index.add_or_replace(grit_lib::index::IndexEntry { ..entry.clone() });
    }

    let tree_oid = grit_lib::index::write_tree::write_tree_from_index(&odb, &merged_index, "")
        .map_err(|e| RepoError::Grit(format!("Failed to write tree: {}", e)))?;

    // Nothing changed relative to HEAD — skip creating an empty commit.
    if tree_oid == parent_commit.tree {
        return Err(RepoError::Grit(
            "Nothing to commit — the staged changes match the current HEAD tree".to_string(),
        ));
    }

    commit_tree(git_dir, &odb, tree_oid, msg, author, email, signing_key)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::repo::plumbing::init::init_repo;
    use grit_lib::objects::{CommitData, ObjectKind};

    /// Minimal repo: one commit on `main`, HEAD symbolic, origin in config.
    fn setup_repo(tmp: &std::path::Path) -> (std::path::PathBuf, std::path::PathBuf, String) {
        let git_dir = tmp.join(".git");
        init_repo(&git_dir, tmp, "https://example.com/sigma.git").unwrap();

        let commit = CommitData {
            tree: grit_lib::objects::ObjectId::from_hex("4b825dc642cb6eb9a060e54bf8d69288fbee4904")
                .unwrap(),
            parents: Vec::new(),
            author: "test <t@example.com> 0 +0000".to_string(),
            committer: "test <t@example.com> 0 +0000".to_string(),
            message: "initial\n".to_string(),
            encoding: None,
            author_raw: Vec::new(),
            committer_raw: Vec::new(),
            raw_message: None,
            extra_headers: Vec::new(),
        };
        let odb = open_odb(&git_dir);
        let raw = grit_lib::objects::serialize_commit(&commit);
        let commit_oid = odb.write(ObjectKind::Commit, &raw).unwrap();
        std::fs::create_dir_all(git_dir.join("refs/heads")).unwrap();
        std::fs::write(git_dir.join("refs/heads/main"), format!("{commit_oid}\n")).unwrap();
        std::fs::write(git_dir.join("HEAD"), b"ref: refs/heads/main\n").unwrap();

        (git_dir, tmp.to_path_buf(), commit_oid.to_string())
    }

    #[test]
    fn current_branch_name_symbolic_and_detached() {
        let tmp = tempfile::tempdir().unwrap();
        let (git_dir, _, oid) = setup_repo(tmp.path());

        assert_eq!(
            current_branch_name(&git_dir).unwrap().as_deref(),
            Some("main")
        );

        std::fs::write(git_dir.join("HEAD"), format!("{oid}\n")).unwrap();
        assert_eq!(current_branch_name(&git_dir).unwrap(), None);
    }

    #[test]
    fn git_pull_without_origin_is_actionable_error() {
        let tmp = tempfile::tempdir().unwrap();
        let git_dir = tmp.path().join(".git");
        // HEAD only — no config, hence no origin remote.
        std::fs::create_dir_all(&git_dir).unwrap();
        std::fs::write(git_dir.join("HEAD"), b"ref: refs/heads/main\n").unwrap();

        let err = git_pull(&git_dir, None).unwrap_err().to_string();
        assert!(err.contains("origin"), "unexpected error: {err}");
    }

    #[test]
    fn git_pull_detached_head_is_rejected() {
        let tmp = tempfile::tempdir().unwrap();
        let (git_dir, _, oid) = setup_repo(tmp.path());
        std::fs::write(git_dir.join("HEAD"), format!("{oid}\n")).unwrap();

        let err = git_pull(&git_dir, None).unwrap_err().to_string();
        assert!(err.contains("detached"), "unexpected error: {err}");
    }

    /// A pre-existing `.git` short-circuits the SSH clone without touching ssh.
    #[test]
    fn git_clone_skips_when_git_dir_exists() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(tmp.path().join(".git")).unwrap();

        git_clone("git@github.com:u/r.git", tmp.path(), None).unwrap();
    }

    /// A failed fetch must remove the half-initialized `.git`: otherwise the
    /// next run short-circuits on "Repository already exists" and works on a
    /// repository with no refs. Shallow is the default path, so pin it there.
    #[test]
    fn git_clone_shallow_removes_git_dir_when_fetch_fails() {
        let _guard = crate::repo::tests::ENV_LOCK.lock().unwrap();
        let tmp = tempfile::tempdir().unwrap();
        let dest = tmp.path().join("sigma");

        // A nonexistent ssh binary fails immediately — no real process, no network.
        unsafe { std::env::set_var("GIT_SSH", "/nonexistent/ssh") };
        let result = git_clone_shallow("git@github.com:u/r.git", &dest, None, true);
        unsafe { std::env::remove_var("GIT_SSH") };

        let err = result.unwrap_err().to_string();
        assert!(!err.is_empty(), "a failed fetch must surface an error");
        assert!(
            !dest.join(".git").exists(),
            "half-initialized .git must be removed after a failed fetch"
        );
    }

    #[test]
    fn git_add_missing_path_is_skipped_but_index_written() {
        let tmp = tempfile::tempdir().unwrap();
        let (git_dir, work_tree, _) = setup_repo(tmp.path());

        git_add(&git_dir, &work_tree, &["does-not-exist.txt"]).unwrap();
        assert!(
            git_dir.join("index").exists(),
            "git_add must still write the (empty) index"
        );
    }

    #[test]
    fn git_commit_without_index_is_state_error() {
        let tmp = tempfile::tempdir().unwrap();
        let (git_dir, work_tree, _) = setup_repo(tmp.path());

        let err = git_commit(&git_dir, &work_tree, "m", "a", "e@example.com", None)
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("No index to commit"),
            "unexpected error: {err}"
        );
    }
}
