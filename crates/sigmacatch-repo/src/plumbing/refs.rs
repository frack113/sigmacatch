// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 sigmacatch contributors

//! Reference and HEAD management: resolution, HEAD switching, remote tracking,
//! and fast-forward updates — all delegated to `grit_lib::refs` (loose/packed/
//! reftable, atomic lock writes, reflogs).

use anyhow::{Context, Result};
use grit_lib::objects::ObjectId;
use grit_lib::refs;
use std::path::Path;
use tracing::{info, warn};

/// Bridge grit-lib's `error::Error` into `anyhow::Error` (no blanket `From` exists).
pub(crate) fn map_grit<T>(r: std::result::Result<T, grit_lib::error::Error>) -> Result<T> {
    r.map_err(|e| anyhow::anyhow!("{}", e))
}

/// Resolve a ref name (or `"HEAD"`) to its object id, following symbolic refs.
pub(crate) fn resolve_head(git_dir: &Path) -> Result<ObjectId> {
    map_grit(refs::resolve_ref(git_dir, "HEAD"))
}

/// List every remote tracking ref under `refs/remotes/origin/sigmacatch/`
/// (loose + packed, deduplicated, sorted) — the pending-PR branches on the fork.
pub(crate) fn list_sigmacatch_remote_refs(git_dir: &Path) -> Result<Vec<(String, ObjectId)>> {
    map_grit(refs::list_refs(git_dir, "refs/remotes/origin/sigmacatch/"))
}

/// Resolve a ref name to its oid, returning `None` when absent (packed or loose).
/// Mirrors grit-lib's `resolve_ref` but as an `Option` for callers that treat a
/// missing ref as a valid "first run" case.
pub fn read_loose_or_packed_ref(git_dir: &Path, ref_name: &str) -> Option<String> {
    refs::resolve_ref(git_dir, ref_name)
        .ok()
        .map(|oid| oid.to_string())
}

/// Read a symbolic ref's target (e.g. HEAD -> "refs/heads/main"), or `None` for a
/// direct/detached ref.
pub(crate) fn symbolic_ref_target(git_dir: &Path, refname: &str) -> Result<Option<String>> {
    map_grit(refs::read_symbolic_ref(git_dir, refname))
}

/// Parse remote URL from `.git/config` for a given remote name.
pub(crate) fn read_remote_url_from_config(git_dir: &Path, remote: &str) -> Result<String> {
    let config_path = git_dir.join("config");
    let content = std::fs::read_to_string(&config_path).with_context(|| {
        format!(
            "cannot read git config at {} (expected remote '{}')",
            config_path.display(),
            remote
        )
    })?;
    let target = format!("[remote \"{}\"]", remote);
    let mut in_remote = false;
    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with('[') {
            in_remote = trimmed == target;
        } else if in_remote && let Some(url) = trimmed.strip_prefix("url = ") {
            return Ok(url.to_string());
        }
    }
    anyhow::bail!(
        "Remote '{}' not found in git config at {:?}",
        remote,
        config_path
    )
}

/// Configure HEAD and create the local tracking ref after a fetch (HTTP and SSH).
/// Resolves the default branch from `refs/remotes/origin/<branch>`, falling back
/// to `main`/`master`.
pub(crate) fn set_head_after_fetch(git_dir: &Path, default_branch: Option<&str>) {
    let candidates: Vec<String> = default_branch
        .map(|b| vec![b.to_string()])
        .unwrap_or_else(|| vec!["main".to_string(), "master".to_string()]);

    let head_file = git_dir.join("HEAD");
    for branch in &candidates {
        let remote_ref = format!("refs/remotes/origin/{}", branch);
        if let Some(oid_str) = read_loose_or_packed_ref(git_dir, &remote_ref) {
            let local_ref = format!("refs/heads/{}", branch);
            if let Err(e) = refs::write_symbolic_ref(git_dir, "HEAD", &local_ref) {
                warn!("Failed to set HEAD symbolic ref: {}", e);
                return;
            }
            let oid = match ObjectId::from_hex(&oid_str) {
                Ok(o) => o,
                Err(e) => {
                    warn!("Invalid OID for '{}': {}", remote_ref, e);
                    return;
                }
            };
            let _ = refs::write_ref(git_dir, &local_ref, &oid);
            info!(
                "HEAD set to {} (→ {})",
                local_ref,
                &oid_str[..12.min(oid_str.len())]
            );
            return;
        }
    }
    if !head_file.exists() {
        warn!("No default branch found — HEAD not set");
    }
}

/// After a fetch, fast-forward the local branch under HEAD to its remote
/// tracking ref (`refs/remotes/origin/<branch>`).
pub(crate) fn fast_forward_branch(git_dir: &Path) -> Result<()> {
    let remote_branch = match symbolic_ref_target(git_dir, "HEAD")? {
        Some(target) => {
            let stripped = target.strip_prefix("refs/heads/").unwrap_or(&target);
            stripped.to_string()
        }
        None => {
            warn!("Detached HEAD — cannot fast-forward");
            return Ok(());
        }
    };
    let remote_ref = format!("refs/remotes/origin/{}", remote_branch);
    let Some(remote_oid) = read_loose_or_packed_ref(git_dir, &remote_ref) else {
        warn!(
            "Remote tracking ref '{}' not found — cannot fast-forward",
            remote_ref
        );
        return Ok(());
    };
    let local_ref = format!("refs/heads/{}", remote_branch);
    let oid = ObjectId::from_hex(&remote_oid)
        .map_err(|e| anyhow::anyhow!("Invalid OID for '{}': {}", remote_ref, e))?;
    map_grit(refs::write_ref(git_dir, &local_ref, &oid))?;
    info!(
        "Fast-forwarded '{}' to {}",
        remote_branch,
        &remote_oid[..12.min(remote_oid.len())]
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::read_remote_url_from_config;

    #[test]
    fn missing_config_yields_actionable_error() {
        let tmp = tempfile::tempdir().unwrap();
        let git_dir = tmp.path().join(".git");
        std::fs::create_dir_all(&git_dir).unwrap();

        let err = read_remote_url_from_config(&git_dir, "origin")
            .unwrap_err()
            .to_string()
            .to_lowercase();
        assert!(err.contains("git config"), "unexpected error: {err}");
        assert!(err.contains("origin"), "unexpected error: {err}");
    }
}
