// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 sigmacatch contributors

use anyhow::Result;
use std::path::Path;
use tracing::{info, warn};

use crate::regression::format::validate_rule_id;

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

/// Batch-commit regression data. Falls back to individual commits on failure.
pub fn commit_all_rules(
    repo_path: &Path,
    rules: &[(String, String)],
    author: &str,
    email: &str,
) -> Result<()> {
    let valid: Vec<&(String, String)> = rules
        .iter()
        .filter(|(rid, _)| {
            if validate_rule_id(rid) {
                true
            } else {
                warn!("Skipping commit for invalid rule_id: {}", rid);
                false
            }
        })
        .collect();

    if valid.is_empty() {
        info!("No valid rules to commit");
        return Ok(());
    }

    let message = format!(
        "✨ feat(sigma): add regression data for {} rule(s)",
        valid.len()
    );
    let git_dir = repo_path.join(".git");
    let (git_author, git_email) = commit_identity(author, email);

    if let Err(e) = crate::git::git_add(&git_dir, repo_path, &["regression_data"]) {
        warn!(
            "Batch commit failed ({}). Falling back to individual commits.",
            e
        );
        return individual_commits(repo_path, &valid, &git_author, &git_email);
    }

    match crate::git::git_commit(&git_dir, repo_path, &message, &git_author, &git_email) {
        Ok(_) => {
            info!("Committed {} rules in batch", valid.len());
            Ok(())
        }
        Err(e) => {
            warn!(
                "Batch commit failed ({}). Falling back to individual commits.",
                e
            );
            individual_commits(repo_path, &valid, &git_author, &git_email)
        }
    }
}

fn individual_commits(
    repo_path: &Path,
    rules: &[&(String, String)],
    git_author: &str,
    git_email: &str,
) -> Result<()> {
    let mut successes = 0u32;
    let mut failures = 0u32;

    for (rule_id, reg_dir) in rules {
        let git_dir = repo_path.join(".git");
        let msg = format!("✨ feat(sigma): add regression data for {}", rule_id);

        if let Err(e) = crate::git::git_add(&git_dir, repo_path, &[reg_dir.as_str()]) {
            warn!("git_add failed for '{}': {}", rule_id, e);
            failures += 1;
            continue;
        }

        match crate::git::git_commit(&git_dir, repo_path, &msg, git_author, git_email) {
            Ok(_) => {
                info!("Committed {} (fallback)", rule_id);
                successes += 1;
            }
            Err(e) => {
                warn!("Failed to commit '{}': {}", rule_id, e);
                failures += 1;
            }
        }
    }

    if successes == 0 && !rules.is_empty() {
        anyhow::bail!("All {} individual commits failed", rules.len());
    }
    if failures > 0 {
        warn!(
            "{} individual commits succeeded, {} failed",
            successes, failures
        );
    }
    Ok(())
}
