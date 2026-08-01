// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 sigmacatch contributors

//! Branch and HEAD management: validation, creation, switching.

use anyhow::Result;
use std::path::Path;
use tracing::info;

use crate::plumbing::refs::{read_loose_or_packed_ref, resolve_head};

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
/// If the branch already exists locally, it is deleted and recreated from the
/// current HEAD so that a stale/dirty local branch (e.g. from a previous run
/// whose push failed) cannot diverge from the freshly pulled upstream.
pub(crate) fn create_branch(git_dir: &Path, branch_name: &str) -> Result<()> {
    validate_branch_name(branch_name)?;
    let full_ref_name = format!("refs/heads/{}", branch_name);
    let ref_path = git_dir.join(&full_ref_name);

    let head_oid = resolve_head(git_dir)?;

    if ref_path.exists() {
        info!(
            "Branch '{}' already exists locally, recreating from HEAD ({})",
            branch_name, head_oid
        );
        std::fs::remove_file(&ref_path)?;
    }

    if let Some(parent) = ref_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(&ref_path, format!("{}\n", head_oid))?;
    switch_head(git_dir, branch_name)?;

    info!(
        "Created and switched to branch '{}' from HEAD ({})",
        branch_name, head_oid
    );
    Ok(())
}

/// Switch HEAD to an existing local branch.
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
    std::fs::write(git_dir.join("HEAD"), format!("ref: {}\n", local_ref))?;
    info!("Switched HEAD to branch '{}'", branch_name);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_branch_name_valid() {
        assert!(validate_branch_name("sigmacatch-contrib/20250701").is_ok());
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
}
