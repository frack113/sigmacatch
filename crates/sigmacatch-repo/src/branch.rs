// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 sigmacatch contributors

//! Branch and HEAD management: validation, creation, switching.
//!
//! All ref mutations go through `grit_lib::refs` (atomic lock writes, packed +
//! loose + reftable). Creating/switching a branch is therefore two native calls
//! rather than hand-rolled file/path handling.

use anyhow::Result;
use grit_lib::refs;
use std::path::Path;
use tracing::info;

use crate::plumbing::refs::{map_grit, read_loose_or_packed_ref, resolve_head};

fn validate_branch_name(name: &str) -> Result<()> {
    if name.is_empty() {
        anyhow::bail!("branch name must not be empty");
    }
    for c in ['\0', '\n', '\r', '\\', '~', '^', ':', '?', '*', '['] {
        if name.contains(c) {
            anyhow::bail!("branch name contains invalid character {:?}: {:?}", c, name);
        }
    }
    if name.starts_with('/') || name.ends_with('/') || name.contains("//") {
        anyhow::bail!("branch name has invalid '/' placement: {:?}", name);
    }
    for component in name.split('/') {
        if component.is_empty() || component == "." || component == ".." {
            anyhow::bail!(
                "branch name component cannot be empty, '.' or '..': {:?}",
                name
            );
        }
        if component.ends_with(".lock") {
            anyhow::bail!("branch name component cannot end with '.lock': {:?}", name);
        }
    }
    Ok(())
}

/// Create a new branch from the current HEAD and switch to it.
/// If the branch already exists locally, `write_ref` atomically replaces it
/// from the current HEAD, so a stale/dirty local branch (e.g. from a previous
/// run whose push failed) cannot diverge from the freshly pulled upstream.
pub(crate) fn create_branch(git_dir: &Path, branch_name: &str) -> Result<()> {
    validate_branch_name(branch_name)?;
    let full_ref_name = format!("refs/heads/{}", branch_name);
    let head_oid = resolve_head(git_dir)?;
    map_grit(refs::write_ref(git_dir, &full_ref_name, &head_oid))?;
    switch_head(git_dir, branch_name)?;
    info!(
        "Created and switched to branch '{}' from HEAD ({})",
        branch_name, head_oid
    );
    Ok(())
}

/// Switch HEAD to an existing local branch (symbolic ref).
pub(crate) fn switch_head(git_dir: &Path, branch_name: &str) -> Result<()> {
    validate_branch_name(branch_name)?;
    let local_ref = format!("refs/heads/{}", branch_name);
    if read_loose_or_packed_ref(git_dir, &local_ref).is_none() {
        anyhow::bail!(
            "Cannot switch to branch '{}' — ref '{}' not found locally",
            branch_name,
            local_ref
        );
    }
    map_grit(refs::write_symbolic_ref(git_dir, "HEAD", &local_ref))?;
    info!("Switched HEAD to branch '{}'", branch_name);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::plumbing::refs::symbolic_ref_target;

    #[test]
    fn test_validate_branch_name_valid() {
        assert!(validate_branch_name("sigmacatch/20250701").is_ok());
        assert!(validate_branch_name("feature/test").is_ok());
        assert!(validate_branch_name("a").is_ok());
    }

    #[test]
    fn test_validate_branch_name_empty() {
        let err = validate_branch_name("").unwrap_err();
        assert!(err.to_string().to_lowercase().contains("empty"));
    }

    #[test]
    fn test_validate_branch_name_null_char() {
        let err = validate_branch_name("foo\x00bar").unwrap_err();
        assert!(err.to_string().to_lowercase().contains("invalid character"));
    }

    #[test]
    fn test_validate_branch_name_newline() {
        let err = validate_branch_name("foo\nbar").unwrap_err();
        assert!(err.to_string().to_lowercase().contains("invalid character"));
    }

    #[test]
    fn test_validate_branch_name_backslash() {
        let err = validate_branch_name("foo\\bar").unwrap_err();
        assert!(err.to_string().to_lowercase().contains("invalid character"));
    }

    #[test]
    fn test_validate_branch_name_tilde() {
        let err = validate_branch_name("foo^bar").unwrap_err();
        assert!(err.to_string().to_lowercase().contains("invalid character"));
    }

    #[test]
    fn test_validate_branch_name_colon() {
        let err = validate_branch_name("foo:bar").unwrap_err();
        assert!(err.to_string().to_lowercase().contains("invalid character"));
    }

    #[test]
    fn test_validate_branch_name_question_mark() {
        let err = validate_branch_name("foo?bar").unwrap_err();
        assert!(err.to_string().to_lowercase().contains("invalid character"));
    }

    #[test]
    fn test_validate_branch_name_star() {
        let err = validate_branch_name("foo*bar").unwrap_err();
        assert!(err.to_string().to_lowercase().contains("invalid character"));
    }

    #[test]
    fn test_validate_branch_name_brackets() {
        let err = validate_branch_name("foo[bar").unwrap_err();
        assert!(err.to_string().to_lowercase().contains("invalid character"));
    }

    #[test]
    fn test_validate_branch_name_empty_components() {
        assert!(validate_branch_name("foo//bar").is_err());
    }

    #[test]
    fn test_validate_branch_name_dot_components() {
        assert!(validate_branch_name("foo/bar/.").is_err());
        assert!(validate_branch_name("foo/../bar").is_err());
    }

    #[test]
    fn test_validate_branch_name_lock_suffix() {
        let err = validate_branch_name("foo/bar.lock").unwrap_err();
        assert!(err.to_string().to_lowercase().contains(".lock"));
    }

    #[test]
    fn test_validate_branch_name_leading_slash() {
        let err = validate_branch_name("/foo/bar").unwrap_err();
        assert!(err
            .to_string()
            .to_lowercase()
            .contains("invalid '/' placement"));
    }

    #[test]
    fn test_validate_branch_name_trailing_slash() {
        let err = validate_branch_name("foo/bar/").unwrap_err();
        assert!(err
            .to_string()
            .to_lowercase()
            .contains("invalid '/' placement"));
    }

    // `symbolic_ref_target` is exercised indirectly via commit_tree/branch tests
    // elsewhere; here we assert the resolution fallback used by `switch_head`.
    #[test]
    fn test_switch_head_missing_branch_errors() {
        let tmp = tempfile::tempdir().unwrap();
        let git_dir = tmp.path().join(".git");
        crate::plumbing::init::init_repo(&git_dir, tmp.path(), "https://example.com/sigma.git")
            .unwrap();
        // HEAD points at refs/heads/main (symbolic) but the ref doesn't exist yet.
        let err = switch_head(&git_dir, "sigmacatch/me").unwrap_err();
        assert!(err.to_string().to_lowercase().contains("not found"));
        // sanity: symbolic ref resolves to the target.
        let target = symbolic_ref_target(&git_dir, "HEAD").unwrap();
        assert_eq!(target.as_deref(), Some("refs/heads/main"));
    }
}
