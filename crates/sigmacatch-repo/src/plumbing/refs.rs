// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 sigmacatch contributors

//! Reference and HEAD management: loose/packed refs, HEAD resolution,
//! remote tracking, and fast-forward updates.

use anyhow::Result;
use grit_lib::objects::ObjectId;
use std::path::Path;
use tracing::{info, warn};

fn read_packed_ref(git_dir: &Path, ref_name: &str) -> Option<String> {
    let packed_path = git_dir.join("packed-refs");
    let content = std::fs::read_to_string(packed_path).ok()?;
    for line in content.lines() {
        let line = line.trim();
        if line.starts_with('#') || line.starts_with('^') || line.is_empty() {
            continue;
        }
        if let Some((oid, name)) = line.split_once(' ') {
            if name == ref_name {
                return Some(oid.to_string());
            }
        }
    }
    None
}

pub fn read_loose_or_packed_ref(git_dir: &Path, ref_name: &str) -> Option<String> {
    let loose_path = git_dir.join(ref_name);
    match std::fs::read_to_string(&loose_path) {
        Ok(content) => {
            let trimmed = content.trim().to_string();
            if trimmed.is_empty() {
                None
            } else {
                Some(trimmed)
            }
        }
        Err(_) => read_packed_ref(git_dir, ref_name),
    }
}

pub(crate) fn resolve_head(git_dir: &Path) -> Result<ObjectId> {
    let head_path = git_dir.join("HEAD");
    let content = std::fs::read_to_string(&head_path)?;
    let content = content.trim();
    if let Some(ref_str) = content.strip_prefix("ref: ") {
        let ref_path_str = ref_str.trim();
        let full_ref = format!(
            "refs/heads/{}",
            ref_path_str.trim_start_matches("refs/heads/")
        );
        if let Some(oid_str) = read_loose_or_packed_ref(git_dir, &full_ref) {
            return ObjectId::from_hex(&oid_str)
                .map_err(|e| anyhow::anyhow!("Invalid OID '{}': {}", oid_str, e));
        }
        anyhow::bail!(
            "Cannot resolve HEAD ref '{}' — branch not found locally",
            ref_path_str
        );
    } else {
        ObjectId::from_hex(content.trim())
            .map_err(|e| anyhow::anyhow!("Invalid detached HEAD OID '{}': {}", content, e))
    }
}

/// Parse remote URL from `.git/config` for a given remote name.
pub(crate) fn read_remote_url_from_config(git_dir: &Path, remote: &str) -> Result<String> {
    let config_path = git_dir.join("config");
    let content = std::fs::read_to_string(&config_path)?;
    let target = format!("[remote \"{}\"]", remote);
    let mut in_remote = false;
    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with('[') {
            in_remote = trimmed == target;
        } else if in_remote {
            if let Some(url) = trimmed.strip_prefix("url = ") {
                return Ok(url.to_string());
            }
        }
    }
    anyhow::bail!(
        "Remote '{}' not found in git config at {:?}",
        remote,
        config_path
    )
}

/// Resolve a default branch name from remote tracking refs.
/// Tries `origin/<branch_name>` first, then falls back to `origin/main` / `origin/master`.
fn resolve_default_head(git_dir: &Path, default_branch: Option<&str>) -> Option<(String, String)> {
    if let Some(branch_name) = default_branch {
        let remote_ref = format!("refs/remotes/origin/{}", branch_name);
        if let Some(oid_str) = read_loose_or_packed_ref(git_dir, &remote_ref) {
            return Some((format!("refs/heads/{}", branch_name), oid_str));
        }
    }
    for fallback in &["main", "master"] {
        let remote_ref = format!("refs/remotes/origin/{}", fallback);
        if let Some(oid_str) = read_loose_or_packed_ref(git_dir, &remote_ref) {
            return Some((format!("refs/heads/{}", fallback), oid_str));
        }
    }
    None
}

/// Configure HEAD and create local tracking ref after a fetch (both HTTP and SSH).
pub(crate) fn set_head_after_fetch(git_dir: &Path, default_branch: Option<&str>) {
    let head_file = git_dir.join("HEAD");
    if let Some((local_ref, oid_str)) = resolve_default_head(git_dir, default_branch) {
        let head_content = format!("ref: {}\n", local_ref);
        std::fs::write(git_dir.join("HEAD"), &head_content).ok();
        let loose_path = git_dir.join(&local_ref);
        if let Some(parent) = loose_path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        let _ = std::fs::write(&loose_path, format!("{}\n", oid_str));
        info!(
            "HEAD set to {} (→ {})",
            local_ref,
            &oid_str[..12.min(oid_str.len())]
        );
    } else if !head_file.exists() {
        warn!("No default branch found — HEAD not set");
    }
}

/// After a fetch, update the local branch ref to match its remote tracking ref.
pub(crate) fn fast_forward_branch(git_dir: &Path) -> Result<()> {
    let head_content = std::fs::read_to_string(git_dir.join("HEAD"))?;
    let head_content = head_content.trim();

    let Some(ref_str) = head_content.strip_prefix("ref: ") else {
        warn!("Detached HEAD — cannot fast-forward");
        return Ok(());
    };

    let ref_name = ref_str.trim();
    let branch_name = ref_name.strip_prefix("refs/heads/").unwrap_or(ref_name);

    let remote_ref = format!("refs/remotes/origin/{}", branch_name);
    let Some(remote_oid) = read_loose_or_packed_ref(git_dir, &remote_ref) else {
        warn!(
            "Remote tracking ref '{}' not found — cannot fast-forward",
            remote_ref
        );
        return Ok(());
    };

    let local_path = git_dir.join(ref_name);
    std::fs::write(&local_path, format!("{}\n", remote_oid))?;
    info!(
        "Fast-forwarded '{}' to {}",
        branch_name,
        &remote_oid[..12.min(remote_oid.len())]
    );
    Ok(())
}
