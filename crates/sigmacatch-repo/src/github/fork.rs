// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 sigmacatch contributors

use anyhow::Result;
use reqwest::{Client, StatusCode};
use std::process::Command;
use tracing::{info, warn};

#[derive(Debug, Clone)]
pub struct ForkConfig {
    pub fork_url: String,
    pub branch_name: String,
}

impl ForkConfig {
    pub fn new(fork_url: String, branch_name: String) -> Self {
        Self {
            fork_url,
            branch_name,
        }
    }
}

#[derive(Debug, Clone)]
pub enum ForkSshResult {
    Exists,
    NotFound,
    SshError(String),
}

pub fn check_fork_exists_ssh(username: &str) -> ForkSshResult {
    let ssh_remote = format!("git@github.com:{}/sigma.git", username);
    let output = Command::new("git")
        .arg("ls-remote")
        .arg(&ssh_remote)
        .arg("HEAD")
        .output();
    match output {
        Ok(out) => {
            if out.status.success() && !out.stdout.is_empty() {
                ForkSshResult::Exists
            } else {
                let stderr = String::from_utf8_lossy(&out.stderr);
                warn!(
                    "SSH fork check failed for '{}': {} — fork likely does not exist.",
                    username,
                    stderr.trim()
                );
                ForkSshResult::NotFound
            }
        }
        Err(e) => {
            warn!(
                "SSH fork check failed for '{}': cannot execute `git ls-remote` — {}",
                username, e
            );
            ForkSshResult::SshError(
                "Cannot execute `git ls-remote` (ensure git is installed and on PATH).".to_string(),
            )
        }
    }
}

pub async fn check_fork_exists(username: &str) -> Result<bool> {
    let url = format!("https://github.com/{}/sigma", username);
    let client = Client::builder()
        .redirect(reqwest::redirect::Policy::limited(5))
        .timeout(std::time::Duration::from_secs(10))
        .build()?;

    match client.head(&url).send().await {
        Ok(resp) => {
            let status = resp.status();
            if status == StatusCode::TOO_MANY_REQUESTS || status == StatusCode::FORBIDDEN {
                warn!(
                    "GitHub rate-limited while checking fork (HTTP {}). Assuming fork exists to avoid false negative.",
                    status.as_u16()
                );
                return Ok(true);
            }
            Ok(status.is_success())
        }
        Err(e) => {
            if e.status() == Some(StatusCode::TOO_MANY_REQUESTS)
                || e.status() == Some(StatusCode::FORBIDDEN)
            {
                warn!("GitHub rate-limited while checking fork. Assuming fork exists.");
                return Ok(true);
            }
            anyhow::bail!(
                "Cannot reach GitHub to check fork at {}: {}. \
                 Verify network connectivity and try again.",
                url,
                e
            );
        }
    }
}

pub async fn detect_fork(username: &str, branch_name: &str) -> Result<ForkConfig> {
    if username.is_empty() {
        anyhow::bail!("Cannot detect fork: username is empty");
    }

    let fork_url = format!("https://github.com/{}/sigma", username);

    match check_fork_exists(username).await {
        Ok(exists) => {
            if exists {
                info!("Fork detected via HTTP: {}", fork_url);
                return Ok(ForkConfig::new(fork_url, branch_name.to_string()));
            }
        }
        Err(_) => {
            warn!("HTTP fork check failed, falling back to SSH detection");
        }
    }

    match check_fork_exists_ssh(username) {
        ForkSshResult::Exists => {
            info!("Fork detected via SSH: {}", fork_url);
            return Ok(ForkConfig::new(fork_url, branch_name.to_string()));
        }
        ForkSshResult::NotFound => {
            warn!("SSH fork check: fork '{}' not found on GitHub.", username);
        }
        ForkSshResult::SshError(reason) => {
            warn!(
                "SSH fork check failed for '{}': {} — cannot determine if fork exists.",
                username, reason
            );
        }
    }

    anyhow::bail!(
        "Fork {} not found. Create a fork at: https://github.com/SigmaHQ/sigma/fork",
        fork_url
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fork_config_new() {
        let config = ForkConfig::new(
            "https://github.com/testuser/sigma".to_string(),
            "sigmacatch-contrib/20260714_testuser".to_string(),
        );
        assert_eq!(config.fork_url, "https://github.com/testuser/sigma");
        assert_eq!(config.branch_name, "sigmacatch-contrib/20260714_testuser");
    }

    #[test]
    fn test_detect_fork_empty_username() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let result = rt.block_on(detect_fork("", "sigmacatch-contrib/20260714_test"));
        assert!(result.is_err());
    }
}
