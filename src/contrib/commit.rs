// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 sigmacatch contributors

use anyhow::Result;
use std::path::Path;
use tracing::{info, warn};

use crate::regression::format::validate_rule_id;

/// Commit all rules in a single batch using grit-lib.
/// Falls back to individual commits if batch commit fails.
///
/// `rules` is a list of `(rule_id, reg_rel_path)` pairs where `reg_rel_path`
/// is the path relative to the repo root (e.g. `regression_data/windows/process_creation/lsass`).
pub fn commit_all_rules(
    repo_path: &Path,
    rules: &[(String, String)],
    author: &str,
    email: &str,
) -> Result<()> {
    let valid_rules: Vec<(&str, &str)> = rules
        .iter()
        .filter_map(|(rid, path)| {
            if validate_rule_id(rid) {
                Some((rid.as_str(), path.as_str()))
            } else {
                warn!("Skipping commit for invalid rule_id: {}", rid);
                None
            }
        })
        .collect();

    if valid_rules.is_empty() {
        info!("No valid rules to commit");
        return Ok(());
    }

    let message = format!(
        "✨ feat(sigma): add regression data for {} rule(s)",
        valid_rules.len()
    );

    let git_dir = repo_path.join(".git");
    let git_author = if author.is_empty() {
        "sigmacatch"
    } else {
        author
    };
    let git_email = if email.is_empty() {
        "sigmacatch@localhost"
    } else {
        email
    };

    match crate::git::stage_and_commit_dir(
        &git_dir,
        repo_path,
        "regression_data",
        &message,
        git_author,
        git_email,
    ) {
        Ok(_) => {
            info!("Committed {} rules in batch", valid_rules.len());
            Ok(())
        }
        Err(be) => {
            warn!(
                "Batch commit failed ({}). Falling back to individual commits.",
                be
            );
            individual_commits(repo_path, &valid_rules, author, email)
        }
    }
}

fn individual_commits(
    repo_path: &Path,
    rules: &[(&str, &str)],
    author: &str,
    email: &str,
) -> Result<()> {
    let git_author = if author.is_empty() {
        "sigmacatch"
    } else {
        author
    };
    let git_email = if email.is_empty() {
        "sigmacatch@localhost"
    } else {
        email
    };

    let mut successes = 0u32;
    let mut failures = 0u32;
    for (rule_id, reg_dir) in rules {
        let git_dir = repo_path.join(".git");
        let msg = format!("✨ feat(sigma): add regression data for {}", rule_id);
        match crate::git::commit_single_dir(
            &git_dir, repo_path, reg_dir, &msg, git_author, git_email,
        ) {
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
