// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 sigmacatch contributors

use anyhow::Result;
use grit_lib::objects::ObjectId;
use std::path::Path;
use tracing::{info, warn};

use crate::git;

/// Branch naming convention: sigmacatch-contrib/YYYYMMDD_<author>
pub fn create_branch_name(author: &str) -> String {
    let date = chrono::Local::now().format("%Y%m%d");
    let sanitized = author
        .to_lowercase()
        .chars()
        .map(|c| if c.is_alphanumeric() { c } else { '-' })
        .collect::<String>();
    let prefix = format!("sigmacatch-contrib/{}", date);
    let branch = format!("{}/{}", prefix, sanitized);

    // Git max branch name length is 255 bytes
    if branch.len() > 255 {
        let ellipsis_bytes = "…".len();
        let available = 255 - prefix.len() - 1 - ellipsis_bytes;
        let truncated = if available < sanitized.len() {
            let safe_end = sanitized
                .char_indices()
                .take_while(|(i, _)| *i < available)
                .last()
                .map_or(0, |(i, _)| i);
            format!("{}…", &sanitized[..safe_end])
        } else {
            sanitized
        };
        format!("{}/{}", prefix, truncated)
    } else {
        branch
    }
}

/// Create a new branch from origin/master (or origin/main fallback).
/// If the branch already exists locally, switches to it without error.
pub fn create_branch(repo_path: &Path, branch_name: &str) -> Result<()> {
    let git_dir = repo_path.join(".git");
    git::create_branch(&git_dir, branch_name)
}

/// Push the current branch to the given remote using grit-lib HTTP.
/// Fetches remote state first, then pushes only if safe:
/// - New branch (remote doesn't exist) → normal push
/// - Local ahead of remote → normal push (fast-forward)
/// - Remote ahead or diverged → skip with warning (no force)
pub fn push_branch(repo_path: &Path, branch_name: &str, remote: &str) -> Result<()> {
    let git_dir = repo_path.join(".git");

    let token = std::env::var("GITHUB_TOKEN").ok();
    let http_client = git::AuthHttpClient::new(token);
    let repo = grit_lib::repo::Repository::open(&git_dir, None)?;

    let remote_url = read_remote_url(&git_dir, remote)?;

    // Verify HEAD matches the branch we intend to push
    let head_content = std::fs::read_to_string(git_dir.join("HEAD"))?;
    let expected_ref = format!("ref: refs/heads/{}\n", branch_name);
    if head_content != expected_ref {
        anyhow::bail!(
            "HEAD is not on branch '{}' (HEAD: {}). Refusing to push.",
            branch_name,
            head_content.trim()
        );
    }

    // Fetch the specific branch from remote
    let fetch_opts = grit_lib::transfer::FetchOptions {
        refspecs: vec![format!(
            "+refs/heads/{}:refs/remotes/{}/{}",
            branch_name, remote, branch_name
        )],
        ..Default::default()
    };
    let _fetch_outcome = grit_lib::transport::http::http_fetch(
        &http_client,
        &git_dir,
        &remote_url,
        &fetch_opts,
        &mut grit_lib::fetch::NoProgress,
    )
    .map_err(|e| anyhow::anyhow!("Failed to fetch branch '{}': {}", branch_name, e))?;

    // Check if remote tracking branch exists
    let remote_ref_path = git_dir
        .join("refs")
        .join("remotes")
        .join(remote)
        .join(branch_name);
    let remote_exists = remote_ref_path.exists();

    if !remote_exists {
        return git::push_branch(&http_client, &git_dir, &remote_url, branch_name);
    }

    // Read local HEAD OID
    let local_oid = git::resolve_head(&repo)?;

    // Read remote tracking OID
    let remote_oid_str = std::fs::read_to_string(&remote_ref_path)?
        .trim()
        .to_string();
    let remote_oid = ObjectId::from_hex(&remote_oid_str)
        .map_err(|e| anyhow::anyhow!("Invalid remote OID '{}': {}", remote_oid_str, e))?;

    if local_oid == remote_oid {
        info!("Branch '{}' is already up to date with remote", branch_name);
        return Ok(());
    }

    // Check if remote is ancestor of local (fast-forward possible)
    let is_ancestor = match grit_lib::merge_base::is_ancestor(&repo, remote_oid, local_oid) {
        Ok(v) => v,
        Err(e) => {
            warn!("Failed to check merge base: {}. Skipping push.", e);
            return Ok(());
        }
    };

    if is_ancestor {
        return git::push_branch(&http_client, &git_dir, &remote_url, branch_name);
    }

    // Remote is ahead or diverged → skip, no force
    let local_hex = local_oid.to_hex();
    let remote_hex = remote_oid.to_hex();
    warn!(
        "Branch '{}' has diverged from remote (local: {}, remote: {}). \
         Skipping push — merge or rebase manually before next run.",
        branch_name,
        &local_hex[..12.min(local_hex.len())],
        &remote_hex[..12.min(remote_hex.len())]
    );
    Ok(())
}

fn read_remote_url(git_dir: &Path, remote: &str) -> Result<String> {
    let config_path = git_dir.join("config");
    let content = std::fs::read_to_string(&config_path)?;
    let target_section = format!("[remote \"{}\"]", remote);
    let alt_section = format!("[remote {}]", remote);

    let mut in_section = false;
    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed == target_section || trimmed == alt_section {
            in_section = true;
        } else if in_section {
            if trimmed.starts_with('[') {
                in_section = false;
            } else if let Some((key, value)) = trimmed.split_once('=') {
                if key.trim() == "url" {
                    return Ok(value.trim().trim_matches('"').to_string());
                }
            }
        }
    }
    anyhow::bail!("No URL found for remote '{}' in config", remote)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_branch_name_normal() {
        let name = create_branch_name("testuser");
        assert!(name.starts_with("sigmacatch-contrib/"));
        assert!(name.contains("testuser"));
        assert!(name.len() <= 255);
    }

    #[test]
    fn test_create_branch_name_with_spaces() {
        let name = create_branch_name("John Doe");
        assert!(name.contains("john-doe"));
        assert!(name.len() <= 255);
    }

    #[test]
    fn test_create_branch_name_with_special_chars() {
        let name = create_branch_name("User@Domain!test");
        assert!(name.contains("user-domain-test"));
        assert!(!name.contains('@'));
        assert!(!name.contains('!'));
        assert!(name.len() <= 255);
    }

    #[test]
    fn test_create_branch_name_empty_author() {
        let name = create_branch_name("");
        assert!(name.starts_with("sigmacatch-contrib/"));
        assert!(name.len() <= 255);
    }

    #[test]
    fn test_create_branch_name_already_includes_date() {
        let name1 = create_branch_name("testuser");
        let name2 = create_branch_name("testuser");
        assert_eq!(name1, name2);
    }

    #[test]
    fn test_create_branch_name_truncation() {
        let long_name = "a".repeat(300);
        let name = create_branch_name(&long_name);
        assert!(
            name.len() <= 255,
            "branch name byte length {} should be <= 255",
            name.len()
        );
        assert!(name.contains("…"));
    }
}
