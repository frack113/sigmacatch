// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 sigmacatch contributors

use anyhow::Result;
use std::path::Path;
use tracing::{info, warn};

use crate::regression::format::validate_rule_id;

fn git_env(author: &str, email: &str) -> [(&'static str, String); 2] {
    let name = if author.is_empty() {
        "sigmacatch".to_string()
    } else {
        author.to_string()
    };
    let mail = if email.is_empty() {
        "sigmacatch@localhost".to_string()
    } else {
        email.to_string()
    };
    [("GIT_AUTHOR_NAME", name), ("GIT_AUTHOR_EMAIL", mail)]
}

/// Commit all rules in a single batch.
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
        "feat(sigma): add regression data for {} rule(s)",
        valid_rules.len()
    );

    let status = std::process::Command::new("git")
        .args(["add", "-A"])
        .current_dir(repo_path)
        .envs(git_env(author, email))
        .status()
        .map_err(|e| anyhow::anyhow!("Failed to git add in {:?}: {}", repo_path, e))?;

    if !status.success() {
        anyhow::bail!("git add failed in {:?}", repo_path);
    }

    let output = std::process::Command::new("git")
        .args(["commit", "-m", &message])
        .current_dir(repo_path)
        .envs(git_env(author, email))
        .output()
        .map_err(|e| anyhow::anyhow!("Failed to git commit: {}", e))?;

    if output.status.success() {
        info!("Committed {} rules in batch", valid_rules.len());
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stdout = String::from_utf8_lossy(&output.stdout);
        if stderr.contains("nothing to commit") || stdout.contains("nothing to commit") {
            info!("No changes to commit in batch");
        } else {
            warn!(
                "Batch commit failed: stdout: {}, stderr: {}. Falling back to individual commits.",
                stdout.trim(),
                stderr.trim()
            );
            // Unstage everything (preserves working tree including YAML modifications)
            let _ = std::process::Command::new("git")
                .args(["reset", "HEAD"])
                .current_dir(repo_path)
                .envs(git_env(author, email))
                .output();
            // Fall back to individual commits
            for (rule_id, reg_dir) in &valid_rules {
                let status = std::process::Command::new("git")
                    .args(["add", "-A", reg_dir])
                    .current_dir(repo_path)
                    .envs(git_env(author, email))
                    .status()
                    .map_err(|e| anyhow::anyhow!("Failed to git add '{}': {}", reg_dir, e))?;
                if !status.success() {
                    warn!("git add failed for '{}', skipping commit", reg_dir);
                    continue;
                }
                let msg = format!("feat(sigma): add regression data for {}", rule_id);
                let out = std::process::Command::new("git")
                    .args(["commit", "-m", &msg])
                    .current_dir(repo_path)
                    .envs(git_env(author, email))
                    .output()
                    .map_err(|e| anyhow::anyhow!("Failed to git commit: {}", e))?;
                if out.status.success() {
                    info!("Committed {} (fallback)", rule_id);
                } else {
                    let estderr = String::from_utf8_lossy(&out.stderr);
                    warn!("git commit failed for '{}': {}", rule_id, estderr.trim());
                }
            }
        }
    }

    Ok(())
}
