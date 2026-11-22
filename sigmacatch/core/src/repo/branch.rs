// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 sigmacatch contributors

//! Branch and HEAD management: validation, creation, switching.
//!
//! All ref mutations go through grit-lib's ref store (atomic lock writes, packed +
//! loose + reftable).

use crate::repo::{RepoError, Result};
use grit_lib::refs::RawRefLookup;
use std::path::Path;
use tracing::info;

use crate::repo::plumbing::refs::{
    map_grit, read_loose_or_packed_ref, read_raw_ref_lookup, resolve_head, write_direct_ref,
    write_symbolic_ref,
};
use grit_lib::refs::store::{FilesRefStore, RefNameRef, RefStore};
use std::sync::Arc;

fn open_store(git_dir: &Path) -> Result<Arc<dyn RefStore>> {
    let store = map_grit(FilesRefStore::from_git_dir(git_dir))?;
    Ok(Arc::new(store))
}

fn validate_branch_name(name: &str) -> Result<()> {
    if name.is_empty() {
        return Err(RepoError::InvalidRef(
            "branch name must not be empty".to_string(),
        ));
    }
    for c in ['\0', '\n', '\r', '\\', '~', '^', ':', '?', '*', '['] {
        if name.contains(c) {
            return Err(RepoError::InvalidRef(format!(
                "branch name contains invalid character {:?}: {:?}",
                c, name
            )));
        }
    }
    if name.starts_with('/') || name.ends_with('/') || name.contains("//") {
        return Err(RepoError::InvalidRef(format!(
            "branch name has invalid '/' placement: {:?}",
            name
        )));
    }
    for component in name.split('/') {
        if component.is_empty() || component == "." || component == ".." {
            return Err(RepoError::InvalidRef(format!(
                "branch name component cannot be empty, '.' or '..': {:?}",
                name
            )));
        }
        if component.ends_with(".lock") {
            return Err(RepoError::InvalidRef(format!(
                "branch name component cannot end with '.lock': {:?}",
                name
            )));
        }
    }
    Ok(())
}

/// Create the working branch and switch to it.
///
/// The base is the remote tracking ref `refs/remotes/origin/<branch>` when it
/// exists (the branch was already pushed to the fork, e.g. a same-day re-run),
/// falling back to HEAD (master after pull) for a fresh branch. Basing on the
/// remote ref makes a new commit a fast-forward; basing on HEAD would create a
/// sibling commit and the push would be rejected with `RejectNonFastForward`.
/// If the branch already exists locally, the ref is atomically replaced from the
/// chosen base, so a stale/dirty local branch cannot diverge.
pub(crate) fn create_branch(git_dir: &Path, branch_name: &str) -> Result<()> {
    validate_branch_name(branch_name)?;
    let full_ref_name = format!("refs/heads/{}", branch_name);
    let remote_ref = format!("refs/remotes/origin/{}", branch_name);

    let (base_oid, base_desc) = match read_raw_ref_lookup(git_dir, &remote_ref) {
        // The branch exists on the fork (same-day re-run): base on it so the
        // next commit is a fast-forward. A present-but-unresolvable ref must
        // fail loudly rather than silently fall back to HEAD.
        Ok(RawRefLookup::Exists) => {
            let store = open_store(git_dir)?;
            let oid =
                map_grit(store.resolve(RefNameRef::from_trusted(&remote_ref))).map_err(|e| {
                    RepoError::Grit(format!(
                        "Remote tracking ref '{}' exists but cannot be resolved: {}. \
                     Delete the branch on GitHub and re-run.",
                        remote_ref, e
                    ))
                })?;
            (oid, format!("remote tracking ref '{}'", remote_ref))
        }
        Ok(_) => (resolve_head(git_dir)?, "HEAD".to_string()),
        Err(e) => {
            return Err(RepoError::Grit(format!(
                "Failed to read remote tracking ref '{}': {}",
                remote_ref, e
            )));
        }
    };

    write_direct_ref(git_dir, &full_ref_name, &base_oid)?;
    switch_head(git_dir, branch_name)?;
    info!(
        "Created and switched to branch '{}' from {} ({})",
        branch_name, base_desc, base_oid
    );
    Ok(())
}

/// Switch HEAD to an existing local branch (symbolic ref).
pub(crate) fn switch_head(git_dir: &Path, branch_name: &str) -> Result<()> {
    validate_branch_name(branch_name)?;
    let local_ref = format!("refs/heads/{}", branch_name);
    if read_loose_or_packed_ref(git_dir, &local_ref).is_none() {
        return Err(RepoError::State(format!(
            "Cannot switch to branch '{}' — ref '{}' not found locally",
            branch_name, local_ref
        )));
    }
    write_symbolic_ref(git_dir, "HEAD", &local_ref)?;
    info!("Switched HEAD to branch '{}'", branch_name);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::repo::plumbing::read_loose_or_packed_ref;
    use crate::repo::plumbing::refs::symbolic_ref_target;
    use grit_lib::index::Index;
    use grit_lib::index::write_tree::write_tree_from_index;
    use grit_lib::objects::{CommitData, ObjectId, ObjectKind};

    fn init_with_commit(tmp: &tempfile::TempDir) -> (std::path::PathBuf, ObjectId) {
        let git_dir = tmp.path().join(".git");
        crate::repo::plumbing::init::init_repo(
            &git_dir,
            tmp.path(),
            "https://example.com/sigma.git",
        )
        .unwrap();
        let odb = crate::repo::plumbing::open_odb(&git_dir);
        let tree = write_tree_from_index(&odb, &Index::new(), "").unwrap();
        let commit = CommitData {
            tree,
            parents: Vec::new(),
            author: "t <t@example.com> 0 +0000".to_string(),
            committer: "t <t@example.com> 0 +0000".to_string(),
            message: "init\n".to_string(),
            encoding: None,
            author_raw: Vec::new(),
            committer_raw: Vec::new(),
            raw_message: None,
            extra_headers: Vec::new(),
        };
        let raw = grit_lib::objects::serialize_commit(&commit);
        let head_oid = odb.write(ObjectKind::Commit, &raw).unwrap();
        std::fs::create_dir_all(git_dir.join("refs/heads")).unwrap();
        std::fs::write(git_dir.join("refs/heads/main"), format!("{head_oid}\n")).unwrap();
        std::fs::write(git_dir.join("HEAD"), b"ref: refs/heads/main\n").unwrap();
        (git_dir, head_oid)
    }

    fn make_commit(git_dir: &std::path::Path, parents: Vec<ObjectId>, message: &str) -> ObjectId {
        let odb = crate::repo::plumbing::open_odb(git_dir);
        let tree = write_tree_from_index(&odb, &Index::new(), "").unwrap();
        let commit = CommitData {
            tree,
            parents,
            author: "t <t@example.com> 0 +0000".to_string(),
            committer: "t <t@example.com> 0 +0000".to_string(),
            message: message.to_string(),
            encoding: None,
            author_raw: Vec::new(),
            committer_raw: Vec::new(),
            raw_message: None,
            extra_headers: Vec::new(),
        };
        let raw = grit_lib::objects::serialize_commit(&commit);
        odb.write(ObjectKind::Commit, &raw).unwrap()
    }

    #[test]
    fn test_create_branch_bases_on_remote_tracking_ref() {
        let tmp = tempfile::tempdir().unwrap();
        let (git_dir, head_oid) = init_with_commit(&tmp);
        let remote_oid = make_commit(&git_dir, vec![head_oid], "remote run\n");
        let remote_ref = git_dir.join("refs/remotes/origin/sigmacatch/20260803");
        std::fs::create_dir_all(remote_ref.parent().unwrap()).unwrap();
        std::fs::write(&remote_ref, format!("{remote_oid}\n")).unwrap();

        create_branch(&git_dir, "sigmacatch/20260803").unwrap();

        let local = read_loose_or_packed_ref(&git_dir, "refs/heads/sigmacatch/20260803").unwrap();
        assert_eq!(
            local,
            remote_oid.to_string(),
            "local branch must be based on the remote tracking ref"
        );
    }

    #[test]
    fn test_create_branch_bases_on_head_without_remote_tracking_ref() {
        let tmp = tempfile::tempdir().unwrap();
        let (git_dir, head_oid) = init_with_commit(&tmp);

        create_branch(&git_dir, "sigmacatch/20260803").unwrap();

        let local = read_loose_or_packed_ref(&git_dir, "refs/heads/sigmacatch/20260803").unwrap();
        assert_eq!(local, head_oid.to_string());
    }

    #[test]
    fn test_create_branch_rejects_invalid_remote_oid() {
        let tmp = tempfile::tempdir().unwrap();
        let (git_dir, _) = init_with_commit(&tmp);
        let remote_ref = git_dir.join("refs/remotes/origin/sigmacatch/20260803");
        std::fs::create_dir_all(remote_ref.parent().unwrap()).unwrap();
        std::fs::write(&remote_ref, "not-a-valid-oid\n").unwrap();

        let err = create_branch(&git_dir, "sigmacatch/20260803").unwrap_err();
        assert!(
            err.to_string()
                .to_lowercase()
                .contains("failed to read remote tracking ref"),
            "corrupt remote ref must fail loudly: {err}"
        );
    }

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
    fn test_validate_branch_name_invalid_chars() {
        let err = validate_branch_name("foo\x00bar").unwrap_err();
        assert!(err.to_string().to_lowercase().contains("invalid character"));
        assert!(validate_branch_name("foo\nbar").is_err());
        assert!(validate_branch_name("foo\\bar").is_err());
        assert!(validate_branch_name("foo^bar").is_err());
        assert!(validate_branch_name("foo:bar").is_err());
        assert!(validate_branch_name("foo?bar").is_err());
        assert!(validate_branch_name("foo*bar").is_err());
        assert!(validate_branch_name("foo[bar").is_err());
    }

    #[test]
    fn test_validate_branch_name_components() {
        assert!(validate_branch_name("foo//bar").is_err());
        assert!(validate_branch_name("foo/bar/.").is_err());
        assert!(validate_branch_name("foo/../bar").is_err());
        let err = validate_branch_name("foo/bar.lock").unwrap_err();
        assert!(err.to_string().to_lowercase().contains(".lock"));
        let err = validate_branch_name("/foo/bar").unwrap_err();
        assert!(
            err.to_string()
                .to_lowercase()
                .contains("invalid '/' placement")
        );
        let err = validate_branch_name("foo/bar/").unwrap_err();
        assert!(
            err.to_string()
                .to_lowercase()
                .contains("invalid '/' placement")
        );
    }

    #[test]
    fn test_switch_head_missing_branch_errors() {
        let tmp = tempfile::tempdir().unwrap();
        let git_dir = tmp.path().join(".git");
        crate::repo::plumbing::init::init_repo(
            &git_dir,
            tmp.path(),
            "https://example.com/sigma.git",
        )
        .unwrap();
        let err = switch_head(&git_dir, "sigmacatch/me").unwrap_err();
        assert!(err.to_string().to_lowercase().contains("not found"));
        let target = symbolic_ref_target(&git_dir, "HEAD").unwrap();
        assert_eq!(target.as_deref(), Some("refs/heads/main"));
    }
}
