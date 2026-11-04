// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 sigmacatch contributors

//! Worktree helpers shared by the SSH clone path.
//!
//! The clone itself lives in `porcelain::git_clone*`: it initializes the
//! repository, fetches over SSH through grit-lib, then checks out the worktree.
//! Only the sparse-checkout configuration is raw plumbing.

use crate::repo::Result;
use std::path::Path;

/// Set up cone-mode sparse checkout for rules/, rules-emerging-threats/, regression_data/
pub(crate) fn setup_sparse_checkout(git_dir: &Path) -> Result<()> {
    use grit_lib::index::sparse_checkout::build_expanded_cone_sparse_checkout_lines;

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
    // Guard on the flags actually written below: a git config spells the key
    // as `sparseCheckout` inside a `[core]` section, never `core.sparseCheckout`.
    if !config.contains("sparseCheckout = true") {
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

    /// Only the three rule directories are materialized, and the config gains
    /// both cone-mode flags — without them git falls back to a full worktree.
    #[test]
    fn setup_sparse_checkout_writes_cone_config() {
        let tmp = tempfile::tempdir().unwrap();
        let git_dir = tmp.path().join(".git");
        std::fs::create_dir_all(&git_dir).unwrap();

        setup_sparse_checkout(&git_dir).unwrap();

        let sparse = std::fs::read_to_string(git_dir.join("info/sparse-checkout")).unwrap();
        for dir in ["rules", "rules-emerging-threats", "regression_data"] {
            assert!(sparse.contains(dir), "missing {dir} in:\n{sparse}");
        }
        assert!(!sparse.contains("docs"), "sparse set must stay narrow");

        let config = std::fs::read_to_string(git_dir.join("config")).unwrap();
        assert!(config.contains("sparseCheckout = true"), "got:\n{config}");
        assert!(
            config.contains("sparseCheckoutCone = true"),
            "got:\n{config}"
        );
    }

    /// A pre-existing config must be appended to, not clobbered, and a second
    /// call must not duplicate the `[core]` block.
    #[test]
    fn setup_sparse_checkout_preserves_config_and_is_idempotent() {
        let tmp = tempfile::tempdir().unwrap();
        let git_dir = tmp.path().join(".git");
        std::fs::create_dir_all(&git_dir).unwrap();
        std::fs::write(git_dir.join("config"), "[remote \"origin\"]\n\turl = x\n").unwrap();

        setup_sparse_checkout(&git_dir).unwrap();
        setup_sparse_checkout(&git_dir).unwrap();

        let config = std::fs::read_to_string(git_dir.join("config")).unwrap();
        assert!(config.starts_with("[remote \"origin\"]"), "got:\n{config}");
        assert_eq!(
            config.matches("sparseCheckout = true").count(),
            1,
            "second call must not duplicate the [core] block, got:\n{config}"
        );
    }
}
