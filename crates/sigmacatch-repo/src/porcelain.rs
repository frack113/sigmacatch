// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 sigmacatch contributors

//! Porcelain layer — high-level wrappers: clone, pull, push, add, commit.

use anyhow::Result;
use std::path::Path;
use tracing::{info, warn};

use crate::plumbing::{
    add_directory_to_index, add_file_to_index, add_tree_to_index, checkout_main_branch,
    commit_tree, fast_forward_branch, fetch_options_for_branches, fetch_remote, fetch_remote_ssh,
    init_repo, open_odb, read_remote_url_from_config, resolve_head, set_head_after_fetch,
    symbolic_ref_target, write_index,
};
use crate::transport::{build_ssh_shell_command, https_to_ssh_url, AuthHttpClient};

/// Default branches fetched on clone. Sigmacatch only ever uses the default
/// branch; `main` is the alternative in case `master` is not the default.
const DEFAULT_BRANCHES: &[&str] = &["master", "main"];

/// Branch name (e.g. `master`) that HEAD currently points at, when HEAD is on
/// a symbolic ref. Returns `None` for a detached HEAD.
fn current_branch_name(git_dir: &Path) -> Result<Option<String>> {
    Ok(symbolic_ref_target(git_dir, "HEAD")?
        .and_then(|target| target.strip_prefix("refs/heads/").map(String::from)))
}

/// Clone a repository using token auth.
/// Wraps `clone_repo` by creating an `AuthHttpClient` from token.
pub(crate) fn git_clone(url: &str, dest: &Path, token: Option<&str>) -> Result<()> {
    let http_client = AuthHttpClient::new(token.map(|s| zeroize::Zeroizing::new(s.to_string())))?;
    crate::plumbing::clone_repo(&http_client, url, dest)
}

/// Clone a repository using SSH transport.
pub(crate) fn git_clone_ssh(url: &str, dest: &Path, ssh_key_path: Option<&str>) -> Result<()> {
    let git_dir = dest.join(".git");
    if git_dir.exists() {
        info!("Repository already exists at {:?}, skipping clone", dest);
        return Ok(());
    }

    info!("Cloning via SSH into {:?}", dest);
    init_repo(&git_dir, dest, url)?;
    let opts = fetch_options_for_branches(DEFAULT_BRANCHES);
    let ssh_mode = build_ssh_shell_command(ssh_key_path);
    let (count, default_branch) = match fetch_remote_ssh(&git_dir, url, &ssh_mode, &opts) {
        Ok(r) => r,
        Err(e) => {
            let _ = std::fs::remove_dir_all(&git_dir);
            return Err(e);
        }
    };
    if count == 0 {
        let _ = std::fs::remove_dir_all(&git_dir);
        anyhow::bail!("No refs fetched from remote via SSH — empty or unreachable repository");
    }

    set_head_after_fetch(&git_dir, default_branch.as_deref());

    checkout_main_branch(&git_dir, dest)?;

    crate::plumbing::pack_loose_objects(&git_dir)?;

    Ok(())
}

/// Fetch from origin and fast-forward the current branch.
///
/// Only the current branch is fetched (narrow refspec) — the default branch
/// after `switch_to_tracking_branch`, never the wildcard `+refs/heads/*`.
pub(crate) fn git_pull(git_dir: &Path, token: Option<&str>) -> Result<()> {
    let http_client = AuthHttpClient::new(token.map(|s| zeroize::Zeroizing::new(s.to_string())))?;
    let remote_url = read_remote_url_from_config(git_dir, "origin")?;
    let branch = current_branch_name(git_dir)?
        .ok_or_else(|| anyhow::anyhow!("Cannot pull — HEAD is detached"))?;
    let opts = fetch_options_for_branches(&[branch.as_str()]);

    fetch_remote(&http_client, git_dir, &remote_url, &opts)?;
    fast_forward_branch(git_dir)?;

    crate::plumbing::pack_loose_objects(git_dir)?;

    // Re-checkout worktree to reflect any changes from fast-forward
    let work_tree = git_dir
        .parent()
        .ok_or_else(|| anyhow::anyhow!("Cannot determine worktree from git_dir"))?;
    checkout_main_branch(git_dir, work_tree)?;
    Ok(())
}

/// Fetch from origin via SSH and fast-forward the current branch.
pub(crate) fn git_pull_ssh(git_dir: &Path, ssh_key_path: Option<&str>) -> Result<()> {
    let remote_url = read_remote_url_from_config(git_dir, "origin")?;
    let ssh_url = https_to_ssh_url(&remote_url).unwrap_or(remote_url);
    let ssh_mode = build_ssh_shell_command(ssh_key_path);
    let branch = current_branch_name(git_dir)?
        .ok_or_else(|| anyhow::anyhow!("Cannot pull — HEAD is detached"))?;
    let opts = fetch_options_for_branches(&[branch.as_str()]);

    fetch_remote_ssh(git_dir, &ssh_url, &ssh_mode, &opts)?;
    fast_forward_branch(git_dir)?;

    crate::plumbing::pack_loose_objects(git_dir)?;

    // Re-checkout worktree to reflect any changes from fast-forward
    let work_tree = git_dir
        .parent()
        .ok_or_else(|| anyhow::anyhow!("Cannot determine worktree from git_dir"))?;
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
    write_index(git_dir, &index)?;
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
        anyhow::bail!("No index to commit — call git_add first");
    }
    let odb = open_odb(git_dir);

    let staged_index = grit_lib::index::Index::load(&index_path)
        .map_err(|e| anyhow::anyhow!("Failed to load index: {}", e))?;

    // Merge parent tree entries + staged changes into a single tree
    let parent_oid = resolve_head(git_dir)?;
    let parent_obj = odb
        .read(&parent_oid)
        .map_err(|e| anyhow::anyhow!("Failed to read HEAD commit: {}", e))?;
    let parent_commit = grit_lib::objects::parse_commit(&parent_obj.data)
        .map_err(|e| anyhow::anyhow!("Failed to parse HEAD commit: {}", e))?;

    // Merge the full parent (HEAD) tree under the staged entries. The parent
    // tree is added at stage 0 unconditionally; staged entries are then overlaid
    // with `add_or_replace`, so the staged blob content wins. There is no
    // staged-paths filtering step — that was the site of a prior tree-amputation
    // bug (inverted condition) and is no longer needed.
    let mut merged_index = grit_lib::index::Index::new();
    add_tree_to_index(&odb, parent_commit.tree, "", &mut merged_index)?;
    for entry in &staged_index.entries {
        merged_index.add_or_replace(grit_lib::index::IndexEntry { ..entry.clone() });
    }

    let tree_oid = grit_lib::write_tree::write_tree_from_index(&odb, &merged_index, "")
        .map_err(|e| anyhow::anyhow!("Failed to write tree: {}", e))?;

    // Nothing changed relative to HEAD — skip creating an empty commit.
    if tree_oid == parent_commit.tree {
        anyhow::bail!("Nothing to commit — the staged changes match the current HEAD tree");
    }

    commit_tree(git_dir, &odb, tree_oid, msg, author, email, signing_key)
}
