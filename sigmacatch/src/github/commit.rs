// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 sigmacatch contributors

use anyhow::Result;
use std::path::Path;
use tracing::{info, warn};

use crate::regression::triplet::validate_rule_id;

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

/// Commit regression data and updated rule YAML files, one commit per rule.
/// The commit message is `✨ feat(sigma): add {rule_id} regression data`.
/// Falls back to a single batch commit if every per-rule commit fails.
pub fn commit_all_rules(
    repo_path: &Path,
    rules: &[(String, String, Option<String>)],
    author: &str,
    email: &str,
) -> Result<()> {
    let valid: Vec<&(String, String, Option<String>)> = rules
        .iter()
        .filter(|(rid, _, _)| {
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

    let git_dir = repo_path.join(".git");
    let (git_author, git_email) = commit_identity(author, email);

    let mut successes = 0u32;
    let mut failures = 0u32;

    for (rule_id, reg_dir, rule_yaml) in &valid {
        let msg = format!("✨ feat(sigma): add {} regression data", rule_id);

        let mut paths: Vec<&str> = vec![reg_dir.as_str()];
        if let Some(yaml) = rule_yaml.as_ref() {
            paths.push(yaml.as_str());
        }
        if let Err(e) = crate::repo::git_add(&git_dir, repo_path, &paths) {
            warn!("git_add failed for '{}': {}", rule_id, e);
            failures += 1;
            continue;
        }

        match crate::repo::git_commit(&git_dir, repo_path, &msg, &git_author, &git_email) {
            Ok(_) => {
                info!("Committed {}", rule_id);
                successes += 1;
            }
            Err(e) => {
                warn!("Failed to commit '{}': {}", rule_id, e);
                failures += 1;
            }
        }
    }

    if successes == 0 && !valid.is_empty() {
        warn!(
            "All {} per-rule commits failed — falling back to batch commit",
            valid.len()
        );
        return batch_commit(repo_path, &valid, &git_author, &git_email);
    }
    if failures > 0 {
        warn!(
            "{} per-rule commits succeeded, {} failed",
            successes, failures
        );
    }
    Ok(())
}

/// Single commit for all rules (fallback path only).
fn batch_commit(
    repo_path: &Path,
    rules: &[&(String, String, Option<String>)],
    git_author: &str,
    git_email: &str,
) -> Result<()> {
    let git_dir = repo_path.join(".git");
    let message = format!(
        "✨ feat(sigma): add regression data for {} rule(s)",
        rules.len()
    );

    let mut staged_paths: Vec<&str> = Vec::new();
    for (_, reg_dir, rule_yaml) in rules {
        staged_paths.push(reg_dir.as_str());
        if let Some(yaml) = rule_yaml.as_ref() {
            staged_paths.push(yaml.as_str());
        }
    }
    crate::repo::git_add(&git_dir, repo_path, &staged_paths)?;
    crate::repo::git_commit(&git_dir, repo_path, &message, git_author, git_email)?;
    info!("Committed {} rules in batch (fallback)", rules.len());
    Ok(())
}
