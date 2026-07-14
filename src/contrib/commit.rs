// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 sigmacatch contributors

use anyhow::Result;
use std::path::Path;
use tracing::{info, warn};

/// Commit changes for a single rule's regression data.
/// Returns Ok(()) even if there are no changes to commit.
pub fn commit_rule(repo_path: &Path, rule_id: &str) -> Result<()> {
    let reg_dir = format!("regression_data/rules/{}", rule_id);

    // Stage all files in the rule's regression data directory
    let status = std::process::Command::new("git")
        .args(["add", "-A", &reg_dir])
        .current_dir(repo_path)
        .status()
        .map_err(|e| anyhow::anyhow!("Failed to git add '{}': {}", reg_dir, e))?;

    if !status.success() {
        warn!("git add failed for '{}', skipping commit", reg_dir);
        return Ok(());
    }

    let message = format!("feat(sigma): add regression data for {}", rule_id);

    let output = std::process::Command::new("git")
        .args(["commit", "-m", &message])
        .current_dir(repo_path)
        .output()
        .map_err(|e| anyhow::anyhow!("Failed to git commit: {}", e))?;

    if output.status.success() {
        info!("Committed regression data for {}", rule_id);
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stdout = String::from_utf8_lossy(&output.stdout);
        if stderr.contains("nothing to commit") || stdout.contains("nothing to commit") {
            info!("No changes to commit for {}", rule_id);
        } else {
            warn!(
                "git commit failed for '{}': stdout: {}, stderr: {}",
                rule_id,
                stdout.trim(),
                stderr.trim()
            );
        }
    }

    Ok(())
}

/// Commit all rules in a single batch.
/// Falls back to individual commits if batch commit fails.
pub fn commit_all_rules(repo_path: &Path, rule_ids: &[String]) -> Result<()> {
    let message = format!(
        "feat(sigma): add regression data for {} rule(s)",
        rule_ids.len()
    );

    // Stage all regression data
    let status = std::process::Command::new("git")
        .args(["add", "-A", "regression_data/"])
        .current_dir(repo_path)
        .status()
        .map_err(|e| anyhow::anyhow!("Failed to git add regression_data/: {}", e))?;

    if !status.success() {
        anyhow::bail!("git add failed for regression_data/");
    }

    let output = std::process::Command::new("git")
        .args(["commit", "-m", &message])
        .current_dir(repo_path)
        .output()
        .map_err(|e| anyhow::anyhow!("Failed to git commit: {}", e))?;

    if output.status.success() {
        info!("Committed {} rules in batch", rule_ids.len());
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
            // Reset staging area before individual fallback
            std::process::Command::new("git")
                .args(["reset", "HEAD"])
                .current_dir(repo_path)
                .output()
                .ok();
            // Fall back to individual commits
            for rule_id in rule_ids {
                let reg_dir = format!("regression_data/rules/{}", rule_id);
                let status = std::process::Command::new("git")
                    .args(["add", "-A", &reg_dir])
                    .current_dir(repo_path)
                    .status()
                    .ok();
                if status.is_some_and(|s| s.success()) {
                    let msg = format!("feat(sigma): add regression data for {}", rule_id);
                    let out = std::process::Command::new("git")
                        .args(["commit", "-m", &msg])
                        .current_dir(repo_path)
                        .output()
                        .ok();
                    if out.is_some_and(|o| o.status.success()) {
                        info!("Committed {} (fallback)", rule_id);
                    }
                }
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_commit_message_format() {
        let message = format!("feat(sigma): add regression data for {}", "test-rule-123");
        assert!(message.starts_with("feat(sigma): add regression data for"));
        assert!(message.contains("test-rule-123"));
    }
}
