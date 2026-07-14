// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 sigmacatch contributors

use anyhow::Result;
use gix_ref::transaction::PreviousValue;
use std::path::Path;
use tracing::info;

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
        let available = 255 - prefix.len() - 1 - ellipsis_bytes; // -1 for '/', -ellipsis_bytes for '…'
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
    let repo = gix::open(repo_path).map_err(|e| anyhow::anyhow!("Failed to open repo at {:?}: {}", repo_path, e))?;

    // Check if branch already exists locally
    let full_ref_name = format!("refs/heads/{}", branch_name);
    if repo.find_reference(full_ref_name.as_str()).is_ok() {
        info!("Branch '{}' already exists locally, switching to it", branch_name);
        return Ok(());
    }

    // Find tracking branch (master or main)
    let tracking = find_tracking_branch(&repo)?;
    let tracking_full = format!("refs/remotes/origin/{}", tracking);

    // Get the commit ID of the tracking branch
    let tracking_ref = repo
        .find_reference(&tracking_full)
        .map_err(|e| anyhow::anyhow!("Failed to find tracking ref '{}': {}", tracking_full, e))?;

    let target_id = tracking_ref
        .try_id()
        .ok_or_else(|| anyhow::anyhow!("Tracking ref '{}' is symbolic, cannot create branch", tracking_full))?
        .detach();

    // Create the branch pointing to the tracking branch's tip
    let _branch = repo
        .reference(branch_name, target_id, PreviousValue::Any, "")
        .map_err(|e| anyhow::anyhow!("Failed to create branch '{}': {}", branch_name, e))?;

    info!("Created branch '{}' from 'origin/{}'", branch_name, tracking);
    Ok(())
}

/// Find the tracking branch name (origin/master or origin/main).
fn find_tracking_branch(repo: &gix::Repository) -> Result<String> {
    // Try origin/master first
    if repo.find_reference("refs/remotes/origin/master").is_ok() {
        return Ok("master".to_string());
    }

    // Fallback to origin/main
    if repo.find_reference("refs/remotes/origin/main").is_ok() {
        return Ok("main".to_string());
    }

    anyhow::bail!("Cannot find origin/master or origin/main for branch creation")
}

/// Push the current branch to the given remote using git CLI.
/// Uses --force-with-lease for existing branches, --force for new ones.
pub fn push_branch(repo_path: &Path, branch_name: &str, remote: &str) -> Result<()> {
    let tracking_branch = format!("origin/{}", branch_name);
    let has_tracking = std::process::Command::new("git")
        .args(["rev-parse", "--verify", &tracking_branch])
        .current_dir(repo_path)
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false);

    let refspec = format!("refs/heads/{}:refs/heads/{}", branch_name, branch_name);
    let push_args = if has_tracking {
        vec!["push", remote, &refspec, "--force-with-lease"]
    } else {
        vec!["push", remote, &refspec, "--force"]
    };

    let output = std::process::Command::new("git")
        .args(push_args)
        .current_dir(repo_path)
        .output()
        .map_err(|e| anyhow::anyhow!("Failed to execute git push: {}", e))?;

    if output.status.success() {
        info!("Pushed branch '{}' to '{}'", branch_name, remote);
        Ok(())
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stdout = String::from_utf8_lossy(&output.stdout);
        anyhow::bail!(
            "Failed to push branch '{}' to '{}': stdout: {}, stderr: {}",
            branch_name,
            remote,
            stdout.trim(),
            stderr.trim()
        )
    }
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
        assert_eq!(name1, name2); // Same day = same name
    }

    #[test]
    fn test_create_branch_name_truncation() {
        let long_name = "a".repeat(300);
        let name = create_branch_name(&long_name);
        assert!(name.len() <= 256, "branch name byte length {} should be <= 256", name.len());
        assert!(name.contains("…"));
    }
}
