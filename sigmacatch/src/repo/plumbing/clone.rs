// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 sigmacatch contributors

//! Full clone: init + fetch + set HEAD + checkout worktree.

use crate::repo::{RepoError, Result};
use grit_lib::transport::http::HttpClient;
use std::path::Path;
use tracing::info;

use crate::repo::plumbing::checkout::checkout_main_branch;
use crate::repo::plumbing::fetch::{
    fetch_options_for_branches, fetch_options_for_shallow_clone, fetch_remote,
};
use crate::repo::plumbing::init::init_repo;
use crate::repo::plumbing::refs::set_head_after_fetch;

/// Default branches fetched on clone. Sigmacatch only ever uses the default
/// branch; `main` is the alternative in case `master` is not the default.
const DEFAULT_BRANCHES: &[&str] = &["master", "main"];

/// Full clone: init + fetch + set HEAD + checkout worktree.
pub fn clone_repo(http_client: &dyn HttpClient, url: &str, dest: &Path) -> Result<()> {
    clone_repo_inner(http_client, url, dest, false, false)
}

/// Shallow clone with optional sparse checkout.
pub fn clone_repo_shallow(
    http_client: &dyn HttpClient,
    url: &str,
    dest: &Path,
    sparse_checkout: bool,
) -> Result<()> {
    clone_repo_inner(http_client, url, dest, true, sparse_checkout)
}

fn clone_repo_inner(
    http_client: &dyn HttpClient,
    url: &str,
    dest: &Path,
    shallow: bool,
    sparse_checkout: bool,
) -> Result<()> {
    let git_dir = dest.join(".git");
    if git_dir.exists() {
        info!("Repository already exists at {:?}, skipping clone", dest);
        return Ok(());
    }

    info!(
        "Cloning into {:?} (shallow={}, sparse={})",
        dest, shallow, sparse_checkout
    );
    init_repo(&git_dir, dest, url)?;

    // Configure sparse checkout before fetch if requested
    if sparse_checkout {
        setup_sparse_checkout(&git_dir)?;
    }

    let opts = if shallow {
        fetch_options_for_shallow_clone(DEFAULT_BRANCHES)
    } else {
        fetch_options_for_branches(DEFAULT_BRANCHES)
    };
    let (count, default_branch) = match fetch_remote(http_client, &git_dir, url, &opts) {
        Ok(r) => r,
        Err(e) => {
            let _ = std::fs::remove_dir_all(&git_dir);
            return Err(e);
        }
    };
    if count == 0 {
        let _ = std::fs::remove_dir_all(&git_dir);
        return Err(RepoError::State(
            "No refs fetched from remote — empty or unreachable repository".to_string(),
        ));
    }

    set_head_after_fetch(&git_dir, default_branch.as_deref());

    checkout_main_branch(&git_dir, dest)?;

    crate::repo::plumbing::pack_loose_objects(&git_dir)?;

    Ok(())
}

/// Set up cone-mode sparse checkout for rules/, rules-emerging-threats/, regression_data/
pub(crate) fn setup_sparse_checkout(git_dir: &Path) -> Result<()> {
    use grit_lib::sparse_checkout::build_expanded_cone_sparse_checkout_lines;

    let dirs = vec![
        "rules".to_string(),
        "rules-emerging-threats".to_string(),
        "regression_data".to_string(),
    ];
    let lines = build_expanded_cone_sparse_checkout_lines(&dirs);

    let sparse_dir = git_dir.join("info");
    std::fs::create_dir_all(&sparse_dir)?;
    let sparse_file = sparse_dir.join("sparse-checkout");
    std::fs::write(&sparse_file, lines.join("\n"))?;

    // Enable sparse checkout in config
    let config_file = git_dir.join("config");
    let mut config = if config_file.exists() {
        std::fs::read_to_string(&config_file)?
    } else {
        String::new()
    };
    if !config.contains("core.sparseCheckout") {
        config.push_str("\n[core]\n");
        config.push_str("    sparseCheckout = true\n");
        config.push_str("    sparseCheckoutCone = true\n");
        std::fs::write(&config_file, config)?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    struct FailClient;

    impl HttpClient for FailClient {
        fn get(&self, _url: &str, _git_protocol: Option<&str>) -> grit_lib::error::Result<Vec<u8>> {
            Err(grit_lib::error::Error::Message(
                "no network in tests".into(),
            ))
        }

        fn post(
            &self,
            _url: &str,
            _content_type: &str,
            _accept: &str,
            _body: &[u8],
            _git_protocol: Option<&str>,
        ) -> grit_lib::error::Result<Vec<u8>> {
            Err(grit_lib::error::Error::Message(
                "no network in tests".into(),
            ))
        }
    }

    /// A pre-existing `.git` short-circuits the clone without touching the remote.
    #[test]
    fn clone_repo_skips_when_git_dir_exists() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(tmp.path().join(".git")).unwrap();

        clone_repo(&FailClient, "https://example.com/sigma.git", tmp.path()).unwrap();
    }

    /// A failed fetch must remove the half-initialized `.git` so the next run
    /// starts clean instead of hitting the "already exists" short-circuit.
    #[test]
    fn clone_repo_cleans_up_on_fetch_error() {
        let tmp = tempfile::tempdir().unwrap();
        let dest = tmp.path();
        let git_dir = dest.join(".git");

        let err = clone_repo(&FailClient, "https://example.com/sigma.git", dest)
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("no network in tests"),
            "unexpected error: {err}"
        );
        assert!(
            !git_dir.exists(),
            "half-initialized .git must be removed after a failed fetch"
        );
    }
}
