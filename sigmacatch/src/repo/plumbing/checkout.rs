// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 sigmacatch contributors

//! Working-tree checkout from a commit tree.

use crate::repo::{RepoError, Result};
use grit_lib::objects::ObjectId;
use grit_lib::objects::odb::Odb;
use std::collections::HashSet;
use std::path::Path;
use tracing::{info, warn};

use crate::repo::plumbing::refs::read_loose_or_packed_ref;

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
            RepoError::State(format!(
                "Cannot resolve HEAD ref '{}' — branch not found locally",
                ref_name
            ))
        })?
    } else {
        head_ref
    };

    let head_oid = ObjectId::from_hex(&oid_str)
        .map_err(|e| RepoError::Grit(format!("Invalid HEAD OID '{}': {}", oid_str, e)))?;

    let odb = open_odb(git_dir);
    let commit_obj = odb
        .read(&head_oid)
        .map_err(|e| RepoError::Grit(format!("Failed to read HEAD commit {}: {}", head_oid, e)))?;
    let commit = grit_lib::objects::parse_commit(&commit_obj.data)
        .map_err(|e| RepoError::Grit(format!("Failed to parse HEAD commit: {}", e)))?;

    checkout_tree(&odb, commit.tree, work_tree, "")?;
    reconcile_worktree(&odb, commit.tree, work_tree)?;
    info!("Checked out working tree at {:?}", work_tree);
    Ok(())
}

fn checkout_tree(odb: &Odb, tree_oid: ObjectId, base_path: &Path, prefix: &str) -> Result<()> {
    let obj = odb
        .read(&tree_oid)
        .map_err(|e| RepoError::Grit(format!("Failed to read tree {}: {}", tree_oid, e)))?;
    let entries = grit_lib::objects::parse_tree(&obj.data)
        .map_err(|e| RepoError::Grit(format!("Failed to parse tree: {}", e)))?;

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
            return Err(RepoError::Grit(format!(
                "Path traversal detected in tree entry: '{}'",
                rel_path
            )));
        }
        let full_path = base_path.join(&rel_path);

        let full_path = crate::repo::plumbing::long_path::long_path(&full_path);
        if entry.mode == 0o040000 {
            std::fs::create_dir_all(&full_path)?;
            checkout_tree(odb, entry.oid, base_path, &rel_path)?;
        } else if entry.mode == 0o120000 {
            let blob = odb
                .read(&entry.oid)
                .map_err(|e| RepoError::Grit(format!("Failed to read symlink blob: {}", e)))?;
            let target = String::from_utf8_lossy(&blob.data);
            #[cfg(unix)]
            std::os::unix::fs::symlink(target.as_ref(), &full_path)?;
            #[cfg(not(unix))]
            std::fs::write(&full_path, target.as_ref())?;
        } else {
            if let Some(parent) = full_path.parent() {
                std::fs::create_dir_all(parent)?;
            }
            let blob = odb.read(&entry.oid).map_err(|e| {
                RepoError::Grit(format!("Failed to read blob {}: {}", entry.oid, e))
            })?;
            // Re-checkouts mostly find the file already in place: skip the
            // write (create + truncate + write) when the bytes already match.
            let up_to_date = std::fs::read(&full_path).is_ok_and(|on_disk| on_disk == blob.data);
            if !up_to_date {
                std::fs::write(&full_path, &blob.data)?;
            }
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
        .map_err(|e| RepoError::Grit(format!("Failed to read tree {}: {}", tree_oid, e)))?;
    let entries = grit_lib::objects::parse_tree(&obj.data)
        .map_err(|e| RepoError::Grit(format!("Failed to parse tree: {}", e)))?;
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
    let wanted = if mode == 0o100755 { 0o755 } else { 0o644 };
    // Only touch the inode when the permission bits actually differ.
    if perms.mode() & 0o7777 != wanted {
        perms.set_mode(wanted);
        std::fs::set_permissions(path, perms)?;
    }
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
    use grit_lib::index::write_tree::write_tree_from_index;
    use grit_lib::objects::{CommitData, ObjectKind};

    /// Init a repo whose HEAD commit contains `rules/a.yml` and `keep.txt`.
    fn build_committed_repo(tmp: &tempfile::TempDir) {
        let git_dir = tmp.path().join(".git");
        crate::repo::plumbing::init::init_repo(
            &git_dir,
            tmp.path(),
            "https://example.com/sigma.git",
        )
        .unwrap();
        std::fs::create_dir_all(tmp.path().join("rules")).unwrap();
        std::fs::write(tmp.path().join("rules/a.yml"), "title: a\n").unwrap();
        std::fs::write(tmp.path().join("keep.txt"), "keep\n").unwrap();
        let odb = open_odb(&git_dir);
        let mut index = Index::new();
        crate::repo::plumbing::add_file_to_index(
            &git_dir,
            &tmp.path().join("rules/a.yml"),
            tmp.path(),
            &mut index,
        )
        .unwrap();
        crate::repo::plumbing::add_file_to_index(
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
            extra_headers: Vec::new(),
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

    /// A re-checkout leaves an up-to-date file untouched (same inode content,
    /// same mtime) and restores a modified one.
    #[test]
    fn test_recheckout_skips_unchanged_and_restores_modified() {
        let tmp = tempfile::tempdir().unwrap();
        build_committed_repo(&tmp);
        let git_dir = tmp.path().join(".git");
        checkout_main_branch(&git_dir, tmp.path()).unwrap();

        let keep = tmp.path().join("keep.txt");
        let a = tmp.path().join("rules/a.yml");
        // Age the files, so an unwanted rewrite would show in the mtime.
        let old = std::time::SystemTime::now() - std::time::Duration::from_secs(3600);
        for path in [&keep, &a] {
            std::fs::File::options()
                .write(true)
                .open(path)
                .unwrap()
                .set_modified(old)
                .unwrap();
        }
        std::fs::write(&a, "title: locally edited\n").unwrap();
        std::fs::File::options()
            .write(true)
            .open(&a)
            .unwrap()
            .set_modified(old)
            .unwrap();

        checkout_main_branch(&git_dir, tmp.path()).unwrap();

        assert_eq!(std::fs::read_to_string(&keep).unwrap(), "keep\n");
        assert_eq!(
            std::fs::metadata(&keep).unwrap().modified().unwrap(),
            old,
            "an up-to-date file must not be rewritten"
        );
        assert_eq!(
            std::fs::read_to_string(&a).unwrap(),
            "title: a\n",
            "a modified file must be restored from the tree"
        );
    }

    /// A tracked file whose permission bits drifted is put back to 0644.
    #[cfg(unix)]
    #[test]
    fn test_recheckout_fixes_drifted_permissions() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = tempfile::tempdir().unwrap();
        build_committed_repo(&tmp);
        let git_dir = tmp.path().join(".git");
        checkout_main_branch(&git_dir, tmp.path()).unwrap();
        let keep = tmp.path().join("keep.txt");
        std::fs::set_permissions(&keep, std::fs::Permissions::from_mode(0o755)).unwrap();

        checkout_main_branch(&git_dir, tmp.path()).unwrap();

        let mode = std::fs::metadata(&keep).unwrap().permissions().mode() & 0o7777;
        assert_eq!(mode, 0o644);
    }

    /// On a nested tree, a re-checkout over a dirty worktree (edited, deleted
    /// and stray files) ends with exactly the committed bytes and paths.
    #[test]
    fn test_recheckout_mirrors_nested_tree_exactly() {
        let tmp = tempfile::tempdir().unwrap();
        let git_dir = tmp.path().join(".git");
        crate::repo::plumbing::init::init_repo(&git_dir, tmp.path(), "https://example.com/s.git")
            .unwrap();
        let odb = open_odb(&git_dir);
        let mut index = Index::new();
        let mut expected = std::collections::BTreeMap::new();
        for i in 0..120 {
            let rel = format!("d{}/e{}/f{i}.yml", i % 5, i % 7);
            let body = format!("title: rule {i}\n{}", "x".repeat(i * 7));
            let full = tmp.path().join(&rel);
            std::fs::create_dir_all(full.parent().unwrap()).unwrap();
            std::fs::write(&full, &body).unwrap();
            crate::repo::plumbing::add_file_to_index(&git_dir, &full, tmp.path(), &mut index)
                .unwrap();
            expected.insert(rel, body);
        }
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
            extra_headers: Vec::new(),
        };
        let cid = odb
            .write(
                ObjectKind::Commit,
                &grit_lib::objects::serialize_commit(&commit),
            )
            .unwrap();
        std::fs::create_dir_all(git_dir.join("refs/heads")).unwrap();
        std::fs::write(git_dir.join("refs/heads/main"), format!("{cid}\n")).unwrap();
        std::fs::write(git_dir.join("HEAD"), b"ref: refs/heads/main\n").unwrap();

        // Dirty the worktree: edit some files, delete some, add strays.
        for (n, rel) in expected.keys().enumerate() {
            match n % 4 {
                0 => std::fs::write(tmp.path().join(rel), "edited").unwrap(),
                1 => std::fs::remove_file(tmp.path().join(rel)).unwrap(),
                _ => {}
            }
        }
        std::fs::write(tmp.path().join("d0/stray.txt"), "stray").unwrap();

        checkout_main_branch(&git_dir, tmp.path()).unwrap();

        fn collect(dir: &Path, root: &Path, out: &mut std::collections::BTreeMap<String, String>) {
            for entry in std::fs::read_dir(dir).unwrap() {
                let entry = entry.unwrap();
                if entry.file_name() == ".git" {
                    continue;
                }
                let path = entry.path();
                if path.is_dir() {
                    collect(&path, root, out);
                } else {
                    let rel = path
                        .strip_prefix(root)
                        .unwrap()
                        .to_string_lossy()
                        .replace('\\', "/");
                    out.insert(rel, std::fs::read_to_string(&path).unwrap());
                }
            }
        }
        let mut on_disk = std::collections::BTreeMap::new();
        collect(tmp.path(), tmp.path(), &mut on_disk);
        assert_eq!(on_disk, expected);
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
