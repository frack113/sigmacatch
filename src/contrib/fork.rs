// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 sigmacatch contributors

use anyhow::Result;
use reqwest::Client;
use tracing::{info, warn};

#[derive(Debug, Clone)]
pub struct ForkConfig {
    pub fork_url: String,
    pub is_fork: bool,
    pub fallback_url: String,
    pub branch_name: String,
}

impl ForkConfig {
    pub fn new(fork_url: String, is_fork: bool, branch_name: String) -> Self {
        Self {
            fork_url,
            is_fork,
            fallback_url: crate::sigma::loader::SIGMA_REPO_URL.to_string(),
            branch_name,
        }
    }
}

/// Check if a GitHub fork exists via HTTP HEAD request.
/// Returns true if the fork URL responds with 2xx or 3xx.
pub async fn check_fork_exists(username: &str) -> Result<bool> {
    let url = format!("https://github.com/{}/sigma", username);
    let client = Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(std::time::Duration::from_secs(10))
        .build()?;

    match client.head(&url).send().await {
        Ok(resp) => {
            let status = resp.status();
            Ok(status.is_success() || status.is_redirection())
        }
        Err(e) => {
            warn!("Failed to check fork existence: {}", e);
            Ok(false)
        }
    }
}

/// Detect fork for a given username.
/// Returns ForkConfig with fork_url set if fork exists, or fallback to SigmaHQ.
pub async fn detect_fork(username: &str, branch_name: &str) -> Result<ForkConfig> {
    if username.is_empty() {
        anyhow::bail!("Cannot detect fork: username is empty");
    }

    let fork_url = format!("https://github.com/{}/sigma", username);
    let exists = check_fork_exists(username).await?;

    if exists {
        info!("Fork detected: {}", fork_url);
        Ok(ForkConfig::new(fork_url, true, branch_name.to_string()))
    } else {
        warn!(
            "Fork {} not found. Falling back to SigmaHQ/sigma.",
            fork_url
        );
        Ok(ForkConfig::new(
            crate::sigma::loader::SIGMA_REPO_URL.to_string(),
            false,
            branch_name.to_string(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fork_config_new_with_fork() {
        let config = ForkConfig::new(
            "https://github.com/testuser/sigma.git".to_string(),
            true,
            "sigmacatch-contrib/20260714_testuser".to_string(),
        );
        assert!(config.is_fork);
        assert_eq!(
            config.fork_url,
            "https://github.com/testuser/sigma.git"
        );
        assert_eq!(config.fallback_url, crate::sigma::loader::SIGMA_REPO_URL);
        assert_eq!(
            config.branch_name,
            "sigmacatch-contrib/20260714_testuser"
        );
    }

    #[test]
    fn test_fork_config_new_without_fork() {
        let config = ForkConfig::new(
            "https://github.com/SigmaHQ/sigma.git".to_string(),
            false,
            "sigmacatch-contrib/20260714_testuser".to_string(),
        );
        assert!(!config.is_fork);
        assert_eq!(config.fork_url, crate::sigma::loader::SIGMA_REPO_URL);
        assert_eq!(
            config.branch_name,
            "sigmacatch-contrib/20260714_testuser"
        );
    }

    #[test]
    fn test_detect_fork_empty_username() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let result = rt.block_on(detect_fork("", "sigmacatch-contrib/20260714_test"));
        assert!(result.is_err());
    }
}
