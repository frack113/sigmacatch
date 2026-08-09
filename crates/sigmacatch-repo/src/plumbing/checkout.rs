// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 sigmacatch contributors

//! Working-tree checkout from a commit tree.

use anyhow::Result;
use grit_lib::objects::ObjectId;
use grit_lib::odb::Odb;
use std::collections::HashSet;
use std::path::Path;
use tracing::{info, warn};

use crate::plumbing::refs::read_loose_or_packed_ref;

pub(crate) fn open_odb(git_dir: &Path) -> Odb {
    Odb::new(&git_dir.join("objects")).with_config_git_dir(git_dir.to_path_buf())
}

/// Check out the HEAD commit's tree into `work_tree`, then reconcile the
/// worktree so it is an exact mirror of the checked-out commit: any file
/// present on disk but absent from the tree is removed. `.git` is never
/// touched. Reconciliation makes the on-disk state deterministic across runs —
/// stale files from a previous run whose push failed cannot accumulate and
/// skew the skip-set (`existing info.yml` reads) on later runs.
pub(crate) fn checkout_main_branch(git_dir: &Path, work_tree: &Path) -> Result<()> {
    let head_path = git_dir.join("HEAD");
    let head_content = std::fs::read_to_string(&head_path)?;
    let head_ref = head_content.trim().to_string();

    let oid_str = if let Some(ref_str) = head_ref.strip_prefix("ref: ") {
        let ref_name = ref_str.trim();
        read_loose_or_packed_ref(git_dir, ref_name).ok_or_else(|| {
            anyhow::anyhow!(
                "Cannot resolve HEAD ref '{}' — branch not found locally",
                ref_name
            )
        })?
    } else {
        head_ref.clone()
    };

    let head_oid = ObjectId::from_hex(&oid_str)
        .map_err(|e| anyhow::anyhow!("Invalid HEAD OID '{}': {}", oid_str, e))?;

    let odb = open_odb(git_dir);
    let commit_obj = odb
        .read(&head_oid)
        .map_err(|e| anyhow::anyhow!("Failed to read HEAD commit {}: {}", head_oid, e))?;
    let commit = grit_lib::objects::parse_commit(&commit_obj.data)
        .map_err(|e| anyhow::anyhow!("Failed to parse HEAD commit: {}", e))?;

    checkout_tree(&odb, commit.tree, work_tree, "")?;
    reconcile_worktree(&odb, commit.tree, work_tree)?;
    info!("Checked out working tree at {:?}", work_tree);
    Ok(())
}

fn checkout_tree(odb: &Odb, tree_oid: ObjectId, base_path: &Path, prefix: &str) -> Result<()> {
    let obj = odb
        .read(&tree_oid)
        .map_err(|e| anyhow::anyhow!("Failed to read tree {}: {}", tree_oid, e))?;
    let entries = grit_lib::objects::parse_tree(&obj.data)
        .map_err(|e| anyhow::anyhow!("Failed to parse tree: {}", e))?;

    for entry in entries {
        let entry_name = match std::str::from_utf8(&entry.name) {
            Ok(s) => s.to_string(),
            Err(e) => {
                warn!("Skipping tree entry with invalid UTF-8 name: {}", e);
                continue;
            }
        };
        let rel_path = if prefix.is_empty() {
            entry_name.clone()
        } else {
            format!("{}/{}", prefix, entry_name)
        };
        if rel_path.contains("..") || rel_path.starts_with('/') {
            anyhow::bail!("Path traversal detected in tree entry: '{}'", rel_path);
        }
        let full_path = base_path.join(&rel_path);

        let full_path = crate::plumbing::long_path::long_path(&full_path);
        if entry.mode == 0o040000 {
            std::fs::create_dir_all(&full_path)?;
            checkout_tree(odb, entry.oid, base_path, &rel_path)?;
        } else if entry.mode == 0o120000 {
            let blob = odb
                .read(&entry.oid)
                .map_err(|e| anyhow::anyhow!("Failed to read symlink blob: {}", e))?;
            let target = String::from_utf8_lossy(&blob.data);
            #[cfg(unix)]
            std::os::unix::fs::symlink(target.as_ref(), &full_path)?;
            #[cfg(not(unix))]
            std::fs::write(&full_path, target.as_ref())?;
        } else {
            if let Some(parent) = full_path.parent() {
                std::fs::create_dir_all(parent)?;
            }
            let blob = odb
                .read(&entry.oid)
                .map_err(|e| anyhow::anyhow!("Failed to read blob {}: {}", entry.oid, e))?;
            std::fs::write(&full_path, &blob.data)?;
            if cfg!(unix) {
                set_executable(&full_path, entry.mode)?;
            }
        }
    }
    Ok(())
}

/// Collect every blob path reachable from `tree_oid` as forward-slash separated
/// relative paths (directories are recursed, not recorded).
fn collect_tree_paths(
    odb: &Odb,
    tree_oid: ObjectId,
    prefix: &str,
    out: &mut HashSet<String>,
) -> Result<()> {
    let obj = odb
        .read(&tree_oid)
        .map_err(|e| anyhow::anyhow!("Failed to read tree {}: {}", tree_oid, e))?;
    let entries = grit_lib::objects::parse_tree(&obj.data)
        .map_err(|e| anyhow::anyhow!("Failed to parse tree: {}", e))?;
    for entry in entries {
        let name = match std::str::from_utf8(&entry.name) {
            Ok(s) => s.to_string(),
            Err(_) => continue,
        };
        let rel = if prefix.is_empty() {
            name
        } else {
            format!("{}/{}", prefix, name)
        };
        if entry.mode == 0o040000 {
            collect_tree_paths(odb, entry.oid, &rel, out)?;
        } else {
            out.insert(rel);
        }
    }
    Ok(())
}

/// Remove files present in `work_tree` but absent from the commit tree, so the
/// worktree mirrors the checked-out commit exactly. `.git` is skipped. Returns
/// true when this directory still contains tracked content.
fn remove_untracked(
    dir: &Path,
    prefix: &str,
    tracked: &HashSet<String>,
    removed: &mut usize,
) -> Result<bool> {
    let mut has_tracked = false;
    let mut child_dirs = Vec::new();
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let name = entry.file_name().to_string_lossy().to_string();
        if prefix.is_empty() && name == ".git" {
            continue;
        }
        let rel = if prefix.is_empty() {
            name.clone()
        } else {
            format!("{}/{}", prefix, name)
        };
        let file_type = entry.file_type()?;
        if file_type.is_dir() {
            child_dirs.push((rel, entry.path()));
        } else if tracked.contains(&rel) {
            has_tracked = true;
        } else {
            std::fs::remove_file(entry.path())?;
            *removed += 1;
        }
    }
    for (rel, path) in child_dirs {
        let keep = remove_untracked(&path, &rel, tracked, removed)?;
        if keep {
            has_tracked = true;
        } else if std::fs::read_dir(&path)?.next().is_none() {
            std::fs::remove_dir(&path)?;
        }
    }
    Ok(has_tracked)
}

fn reconcile_worktree(odb: &Odb, tree_oid: ObjectId, work_tree: &Path) -> Result<()> {
    let mut tracked = HashSet::new();
    collect_tree_paths(odb, tree_oid, "", &mut tracked)?;
    let mut removed = 0usize;
    remove_untracked(work_tree, "", &tracked, &mut removed)?;
    if removed > 0 {
        info!(
            "Reconciled worktree at {:?}: removed {} file(s) not in the checked-out tree",
            work_tree, removed
        );
    }
    Ok(())
}

#[cfg(unix)]
fn set_executable(path: &Path, mode: u32) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let metadata = std::fs::metadata(path)?;
    let mut perms = metadata.permissions();
    if mode == 0o100755 {
        perms.set_mode(0o100755);
    } else {
        perms.set_mode(0o100644);
    }
    std::fs::set_permissions(path, perms)?;
    Ok(())
}

#[cfg(not(unix))]
fn set_executable(_path: &Path, _mode: u32) -> Result<()> {
    Ok(())
}

#[cfg(unix)]
pub(crate) fn is_exec_file(metadata: &std::fs::Metadata) -> bool {
    use std::os::unix::fs::PermissionsExt;
    metadata.permissions().mode() & 0o111 != 0
}

#[cfg(not(unix))]
pub(crate) fn is_exec_file(_metadata: &std::fs::Metadata) -> bool {
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use grit_lib::index::Index;
    use grit_lib::objects::{CommitData, ObjectKind};
    use grit_lib::write_tree::write_tree_from_index;

    /// Init a repo whose HEAD commit contains `rules/a.yml` and `keep.txt`.
    fn build_committed_repo(tmp: &tempfile::TempDir) {
        let git_dir = tmp.path().join(".git");
        crate::plumbing::init::init_repo(&git_dir, tmp.path(), "https://example.com/sigma.git")
            .unwrap();
        std::fs::create_dir_all(tmp.path().join("rules")).unwrap();
        std::fs::write(tmp.path().join("rules/a.yml"), "title: a\n").unwrap();
        std::fs::write(tmp.path().join("keep.txt"), "keep\n").unwrap();
        let odb = open_odb(&git_dir);
        let mut index = Index::new();
        crate::plumbing::add_file_to_index(
            &git_dir,
            &tmp.path().join("rules/a.yml"),
            tmp.path(),
            &mut index,
        )
        .unwrap();
        crate::plumbing::add_file_to_index(
            &git_dir,
            &tmp.path().join("keep.txt"),
            tmp.path(),
            &mut index,
        )
        .unwrap();
        let tree = write_tree_from_index(&odb, &index, "").unwrap();
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
        };
        let raw = grit_lib::objects::serialize_commit(&commit);
        let cid = odb.write(ObjectKind::Commit, &raw).unwrap();
        std::fs::create_dir_all(git_dir.join("refs/heads")).unwrap();
        std::fs::write(git_dir.join("refs/heads/main"), format!("{cid}\n")).unwrap();
        std::fs::write(git_dir.join("HEAD"), b"ref: refs/heads/main\n").unwrap();
    }

    /// The worktree must mirror the checked-out tree exactly: stale files from
    /// a previous run (never pushed) are deleted, tracked files survive, and
    /// `.git` is never touched.
    #[test]
    fn test_checkout_reconciles_stale_files() {
        let tmp = tempfile::tempdir().unwrap();
        build_committed_repo(&tmp);
        let git_dir = tmp.path().join(".git");
        std::fs::write(tmp.path().join("stale.txt"), "stale\n").unwrap();
        std::fs::create_dir_all(tmp.path().join("stale_dir")).unwrap();
        std::fs::write(tmp.path().join("stale_dir/x.txt"), "x\n").unwrap();

        checkout_main_branch(&git_dir, tmp.path()).unwrap();

        assert!(tmp.path().join("rules/a.yml").exists());
        assert!(tmp.path().join("keep.txt").exists());
        assert!(
            !tmp.path().join("stale.txt").exists(),
            "stale file must be removed"
        );
        assert!(
            !tmp.path().join("stale_dir").exists(),
            "empty stale dir must be removed"
        );
        assert!(git_dir.exists(), ".git must never be touched");
    }

    /// Reconciliation is a no-op on a clean mirror.
    #[test]
    fn test_checkout_clean_mirror_stays_intact() {
        let tmp = tempfile::tempdir().unwrap();
        build_committed_repo(&tmp);
        let git_dir = tmp.path().join(".git");
        checkout_main_branch(&git_dir, tmp.path()).unwrap();
        checkout_main_branch(&git_dir, tmp.path()).unwrap();
        assert!(tmp.path().join("rules/a.yml").exists());
        assert!(tmp.path().join("keep.txt").exists());
    }
}
