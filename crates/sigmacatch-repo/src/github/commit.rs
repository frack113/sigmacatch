// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 sigmacatch contributors

use anyhow::Result;
use std::path::Path;
use tracing::{info, warn};

fn commit_identity(author: &str, email: &str) -> (String, String) {
    let name = if author.trim().is_empty() {
        "sigmacatch"
    } else {
        author
    };
    let addr = if email.trim().is_empty() {
        "sigmacatch@localhost"
    } else {
        email
    };
    (name.to_string(), addr.to_string())
}

pub fn commit_all_rules(
    repo_path: &Path,
    files: &[String],
    author: &str,
    email: &str,
) -> Result<()> {
    if files.is_empty() {
        info!("No files to commit");
        return Ok(());
    }

    let valid: Vec<&str> = files
        .iter()
        .filter(|f| {
            if f.contains('\0') || f.contains("..") {
                warn!("Skipping commit for invalid path: {}", f);
                false
            } else {
                true
            }
        })
        .map(|s| s.as_str())
        .collect();

    if valid.is_empty() {
        info!("No valid files to commit");
        return Ok(());
    }

    let git_dir = repo_path.join(".git");
    let (git_author, git_email) = commit_identity(author, email);

    crate::git_add(&git_dir, repo_path, &valid)?;

    let message = format!(
        "✨ feat(sigma): add regression data for {} file(s)",
        valid.len()
    );
    crate::git_commit(&git_dir, repo_path, &message, &git_author, &git_email)?;
    info!("Committed {} file(s) in batch", valid.len());
    Ok(())
}
