// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 sigmacatch contributors

//! Index construction: stage files, directories, and parent-tree entries.

use crate::repo::{RepoError, Result};
use grit_lib::objects::ObjectId;
use grit_lib::objects::odb::Odb;
use std::path::Path;
use tracing::warn;

use crate::repo::plumbing::checkout::{is_exec_file, open_odb};
use crate::repo::plumbing::refs::resolve_head;

/// Look up the file mode recorded in the parent (HEAD) tree for `rel_path`
/// (forward-slash separated). Returns `None` if the path does not exist in HEAD.
fn lookup_parent_mode(git_dir: &Path, rel_path: &str) -> Option<u32> {
    let odb = open_odb(git_dir);
    let head_oid = resolve_head(git_dir).ok()?;
    let head_obj = odb.read(&head_oid).ok()?;
    let commit = grit_lib::objects::parse_commit(&head_obj.data).ok()?;
    let mut tree_oid = commit.tree;
    let mut prefix = String::new();
    for component in rel_path.split('/') {
        let obj = odb.read(&tree_oid).ok()?;
        let entries = grit_lib::objects::parse_tree(&obj.data).ok()?;
        let entry = entries.into_iter().find(|e| {
            std::str::from_utf8(&e.name)
                .map(|n| n == component)
                .unwrap_or(false)
        })?;
        if prefix.is_empty() {
            prefix = component.to_string();
        } else {
            prefix = format!("{}/{}", prefix, component);
        }
        if prefix == rel_path {
            return Some(entry.mode);
        }
        if entry.mode == 0o040000 {
            tree_oid = entry.oid;
        } else {
            return None;
        }
    }
    None
}

/// Recursively copy every entry of `tree_oid` into `index` at stage 0,
/// prefix-prefixed by `prefix`.
///
/// This is the primitive used by `git_commit` to merge the **full** HEAD
/// tree under the staged entries. Unlike a filtered variant, it has no
/// branch on `staged_paths`, so there is no inversion-prone condition to get
/// wrong — staged paths are simply overlaid afterwards by `add_or_replace`.
pub(crate) fn add_tree_to_index(
    odb: &Odb,
    tree_oid: ObjectId,
    prefix: &str,
    index: &mut grit_lib::index::Index,
) -> Result<()> {
    let obj = odb
        .read(&tree_oid)
        .map_err(|e| RepoError::Grit(format!("Failed to read tree {}: {}", tree_oid, e)))?;
    let entries = grit_lib::objects::parse_tree(&obj.data)
        .map_err(|e| RepoError::Grit(format!("Failed to parse tree: {}", e)))?;
    for entry in entries {
        let Ok(name) = std::str::from_utf8(&entry.name) else {
            warn!("Skipping tree entry with invalid UTF-8 name");
            continue;
        };
        let rel_path = if prefix.is_empty() {
            name.to_string()
        } else {
            format!("{}/{}", prefix, name)
        };
        if entry.mode == 0o040000 {
            add_tree_to_index(odb, entry.oid, &rel_path, index)?;
        } else {
            let mode = match entry.mode {
                0o100755 => 0o100755,
                0o120000 => 0o120000,
                _ => 0o100644,
            };
            let path_bytes = rel_path.as_bytes().to_vec();
            index.add_or_replace(grit_lib::index::IndexEntry {
                ctime_sec: 0,
                ctime_nsec: 0,
                mtime_sec: 0,
                mtime_nsec: 0,
                dev: 0,
                ino: 0,
                mode,
                uid: 0,
                gid: 0,
                size: 0,
                oid: entry.oid,
                flags: (path_bytes.len().min(0xfff)) as u16,
                flags_extended: None,
                path: path_bytes,
                base_index_pos: 0,
            });
        }
    }
    Ok(())
}

/// Why [`patch_tree`] could not build the tree.
pub(crate) enum PatchTreeError {
    /// A staged path collides with an entry of the other kind (a file where a
    /// directory is, or the reverse), or a name is not valid UTF-8: the caller
    /// falls back to the full-index merge, which defines the behaviour there.
    Unsupported,
    /// Reading or writing an object failed.
    Repo(RepoError),
}

impl From<RepoError> for PatchTreeError {
    fn from(e: RepoError) -> Self {
        Self::Repo(e)
    }
}

/// Build the tree that results from overlaying `staged` entries (sorted by
/// path, stage 0, forward-slash paths) on `base`, rewriting only the trees
/// along the staged paths and reusing every other subtree by id.
///
/// Gives the same tree id as loading the whole `base` tree into an index,
/// overlaying `staged` with `add_or_replace` and calling
/// `write_tree_from_index`, without reading or rewriting the untouched
/// directories.
pub(crate) fn patch_tree(
    odb: &Odb,
    base: Option<ObjectId>,
    staged: &[&grit_lib::index::IndexEntry],
    prefix_len: usize,
) -> std::result::Result<ObjectId, PatchTreeError> {
    use grit_lib::objects::{ObjectKind, TreeEntry, serialize_tree, tree_entry_cmp};

    let mut entries: Vec<TreeEntry> = match base {
        Some(oid) => {
            let obj = odb
                .read(&oid)
                .map_err(|e| RepoError::Grit(format!("Failed to read tree {}: {}", oid, e)))?;
            grit_lib::objects::parse_tree(&obj.data)
                .map_err(|e| RepoError::Grit(format!("Failed to parse tree: {}", e)))?
        }
        None => Vec::new(),
    };

    let mut i = 0;
    while i < staged.len() {
        let rest = &staged[i].path[prefix_len..];
        match rest.iter().position(|&b| b == b'/') {
            None => {
                // A file at this level.
                if rest.is_empty() || std::str::from_utf8(rest).is_err() {
                    return Err(PatchTreeError::Unsupported);
                }
                let mode = staged[i].mode;
                match entries.iter().position(|e| e.name == rest) {
                    Some(pos) => {
                        if entries[pos].mode == 0o040000 {
                            return Err(PatchTreeError::Unsupported);
                        }
                        entries[pos].mode = mode;
                        entries[pos].oid = staged[i].oid;
                    }
                    None => entries.push(TreeEntry {
                        mode,
                        name: rest.to_vec(),
                        oid: staged[i].oid,
                    }),
                }
                i += 1;
            }
            Some(sep) => {
                // A directory: take every staged path below it.
                let name = &rest[..sep];
                if name.is_empty() || std::str::from_utf8(name).is_err() {
                    return Err(PatchTreeError::Unsupported);
                }
                let dir_prefix = &staged[i].path[..prefix_len + sep + 1];
                let mut j = i;
                while j < staged.len() && staged[j].path.starts_with(dir_prefix) {
                    j += 1;
                }
                let existing = entries.iter().position(|e| e.name == name);
                let child_base = match existing {
                    Some(pos) if entries[pos].mode == 0o040000 => Some(entries[pos].oid),
                    Some(_) => return Err(PatchTreeError::Unsupported),
                    None => None,
                };
                let child = patch_tree(odb, child_base, &staged[i..j], prefix_len + sep + 1)?;
                match existing {
                    Some(pos) => entries[pos].oid = child,
                    None => entries.push(TreeEntry {
                        mode: 0o040000,
                        name: name.to_vec(),
                        oid: child,
                    }),
                }
                i = j;
            }
        }
    }

    entries.sort_by(|a, b| tree_entry_cmp(&a.name, a.mode, &b.name, b.mode));
    odb.write(ObjectKind::Tree, &serialize_tree(&entries))
        .map_err(|e| PatchTreeError::Repo(RepoError::Grit(format!("Failed to write tree: {e}"))))
}

pub(crate) fn write_index(git_dir: &Path, index: &mut grit_lib::index::Index) -> Result<()> {
    let index_path = git_dir.join("index");
    if let Some(parent) = index_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    index
        .write(&index_path)
        .map_err(|e| RepoError::Grit(format!("Failed to write index: {}", e)))?;
    Ok(())
}

pub(crate) fn add_file_to_index(
    git_dir: &Path,
    file_path: &Path,
    base: &Path,
    index: &mut grit_lib::index::Index,
) -> Result<()> {
    let odb = open_odb(git_dir);
    let file_path = crate::repo::plumbing::long_path::long_path(file_path);
    let base = crate::repo::plumbing::long_path::long_path(base);
    let contents = std::fs::read(&file_path)?;
    let blob_oid = odb
        .write(grit_lib::objects::ObjectKind::Blob, &contents)
        .map_err(|e| RepoError::Grit(format!("Failed to write blob: {}", e)))?;

    let metadata = file_path.metadata()?;
    let is_exec = is_exec_file(&metadata);
    let mut mode = if is_exec { 0o100755 } else { 0o100644 };

    let rel = file_path
        .strip_prefix(&base)
        .map_err(|_| RepoError::Grit("Path not under base".to_string()))?;
    let path_str = rel.to_string_lossy().replace('\\', "/");
    let path_bytes = path_str.as_bytes().to_vec();

    // Preserve the parent-tree mode: on Windows (non-unix) is_exec_file is
    // always false, so a path upstream stores at 100755 (e.g. .evtx files)
    // would otherwise be re-staged as 100644 and produce spurious mode diffs.
    if let Some(parent_mode) = lookup_parent_mode(git_dir, &path_str) {
        mode = parent_mode;
    }
    #[cfg(unix)]
    let entry = {
        use std::os::unix::fs::MetadataExt;
        grit_lib::index::IndexEntry {
            ctime_sec: 0,
            ctime_nsec: 0,
            mtime_sec: 0,
            mtime_nsec: 0,
            dev: metadata.dev() as u32,
            ino: metadata.ino() as u32,
            mode,
            uid: metadata.uid(),
            gid: metadata.gid(),
            size: metadata.len() as u32,
            oid: blob_oid,
            flags: (path_bytes.len().min(0xfff)) as u16,
            flags_extended: None,
            path: path_bytes,
            base_index_pos: 0,
        }
    };
    #[cfg(not(unix))]
    let entry = grit_lib::index::IndexEntry {
        ctime_sec: 0,
        ctime_nsec: 0,
        mtime_sec: 0,
        mtime_nsec: 0,
        dev: 0,
        ino: 0,
        mode,
        uid: 0,
        gid: 0,
        size: 0,
        oid: blob_oid,
        flags: (path_bytes.len().min(0xfff)) as u16,
        flags_extended: None,
        path: path_bytes,
        base_index_pos: 0,
    };
    index.add_or_replace(entry);
    Ok(())
}

pub(crate) fn add_directory_to_index(
    git_dir: &Path,
    dir: &Path,
    base: &Path,
    index: &mut grit_lib::index::Index,
) -> Result<()> {
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        if path == git_dir || path.starts_with(git_dir) {
            continue;
        }
        let file_type = entry.file_type()?;
        if file_type.is_symlink() {
            continue;
        }
        if file_type.is_dir() {
            add_directory_to_index(git_dir, &path, base, index)?;
        } else if file_type.is_file() {
            add_file_to_index(git_dir, &path, base, index)?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::repo::plumbing::init::init_repo;
    use crate::repo::porcelain::{git_add, git_commit};
    use grit_lib::objects::ObjectKind;

    /// Create an initial commit containing `rel_path` (content `content`) on
    /// branch `main`, so HEAD resolves for subsequent `git_commit` calls.
    fn make_initial_commit(
        git_dir: &Path,
        work_tree: &Path,
        rel_path: &str,
        content: &str,
    ) -> Result<()> {
        let file = work_tree.join(rel_path);
        if let Some(parent) = file.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(&file, content)?;

        let odb = open_odb(git_dir);
        let mut index = grit_lib::index::Index::new();
        add_file_to_index(git_dir, &file, work_tree, &mut index)?;
        let tree_oid = crate::repo::plumbing::refs::map_grit(
            grit_lib::index::write_tree::write_tree_from_index(&odb, &index, ""),
        )?;

        let commit = grit_lib::objects::CommitData {
            tree: tree_oid,
            parents: vec![],
            author: "test <test@example.com> 0 +0000".to_string(),
            committer: "test <test@example.com> 0 +0000".to_string(),
            message: "initial commit\n".to_string(),
            encoding: None,
            author_raw: Vec::new(),
            committer_raw: Vec::new(),
            raw_message: None,
            extra_headers: Vec::new(),
        };
        let raw = grit_lib::objects::serialize_commit(&commit);
        let commit_oid =
            crate::repo::plumbing::refs::map_grit(odb.write(ObjectKind::Commit, &raw))?;
        std::fs::create_dir_all(git_dir.join("refs/heads"))?;
        std::fs::write(git_dir.join("refs/heads/main"), format!("{}\n", commit_oid))?;
        std::fs::write(git_dir.join("HEAD"), b"ref: refs/heads/main\n")?;
        Ok(())
    }

    /// Walk a tree and collect all blob paths, so a test can assert which files
    /// ended up in a commit.
    fn collect_tree_paths(
        odb: &Odb,
        tree_oid: grit_lib::objects::ObjectId,
        prefix: &str,
        out: &mut Vec<String>,
    ) -> Result<()> {
        let obj = crate::repo::plumbing::refs::map_grit(odb.read(&tree_oid))?;
        let entries =
            crate::repo::plumbing::refs::map_grit(grit_lib::objects::parse_tree(&obj.data))?;
        for entry in entries {
            let name = std::str::from_utf8(&entry.name).unwrap().to_string();
            let rel = if prefix.is_empty() {
                name
            } else {
                format!("{}/{}", prefix, name)
            };
            if entry.mode == 0o040000 {
                collect_tree_paths(odb, entry.oid, &rel, out)?;
            } else {
                out.push(rel);
            }
        }
        Ok(())
    }

    /// Regression test for the commit-tree amputation bug: staging new
    /// regression files must NOT drop every other file already in the parent
    /// tree. The merged commit must contain the parent files AND the staged ones.
    #[test]
    fn test_commit_preserves_parent_tree() {
        let tmp = tempfile::tempdir().unwrap();
        let work_tree = tmp.path().to_path_buf();
        let git_dir = work_tree.join(".git");
        init_repo(&git_dir, &work_tree, "https://example.com/repo.git").unwrap();

        // Parent commit contains a rules file.
        let existing = "rules/windows/builtin.yml";
        make_initial_commit(&git_dir, &work_tree, existing, "title: Test\n").unwrap();

        // Stage a new regression file (the real sigmacatch flow).
        let new_file = "regression_data/rules/1234/info.yml";
        let new_path = work_tree.join(new_file);
        std::fs::create_dir_all(new_path.parent().unwrap()).unwrap();
        std::fs::write(&new_path, "id: 1234\n").unwrap();
        git_add(&git_dir, &work_tree, &[new_file]).unwrap();
        git_commit(
            &git_dir,
            &work_tree,
            "test: add regression data",
            "test",
            "test@example.com",
            None,
        )
        .unwrap();

        let odb = open_odb(&git_dir);
        let head_oid = resolve_head(&git_dir).unwrap();
        let head_obj = odb.read(&head_oid).unwrap();
        let head_commit = grit_lib::objects::parse_commit(&head_obj.data).unwrap();
        let mut paths = Vec::new();
        collect_tree_paths(&odb, head_commit.tree, "", &mut paths).unwrap();

        assert!(
            paths.contains(&existing.to_string()),
            "parent file dropped from committed tree: {paths:?}"
        );
        assert!(
            paths.contains(&new_file.to_string()),
            "staged file missing from committed tree: {paths:?}"
        );
        assert_eq!(
            paths.len(),
            2,
            "committed tree should contain exactly the parent + staged files: {paths:?}"
        );
    }

    fn staged_entry(
        odb: &Odb,
        path: &str,
        content: &str,
        mode: u32,
    ) -> grit_lib::index::IndexEntry {
        let oid = odb
            .write(ObjectKind::Blob, content.as_bytes())
            .expect("blob written");
        let path_bytes = path.as_bytes().to_vec();
        grit_lib::index::IndexEntry {
            ctime_sec: 0,
            ctime_nsec: 0,
            mtime_sec: 0,
            mtime_nsec: 0,
            dev: 0,
            ino: 0,
            mode,
            uid: 0,
            gid: 0,
            size: 0,
            oid,
            flags: (path_bytes.len().min(0xfff)) as u16,
            flags_extended: None,
            path: path_bytes,
            base_index_pos: 0,
        }
    }

    /// `patch_tree` yields the same tree id as the full merge (HEAD tree into an
    /// index, staged entries overlaid, `write_tree_from_index`) over many
    /// layouts, including names that sort around a directory (`a`, `a-b`,
    /// `a.txt`, `a/x`, `a0`), new directories, replaced files, mode changes
    /// and multi-level paths.
    #[test]
    fn test_patch_tree_matches_full_index_merge() {
        let tmp = tempfile::tempdir().unwrap();
        let git_dir = tmp.path().join(".git");
        init_repo(&git_dir, tmp.path(), "https://example.com/s.git").unwrap();
        let odb = open_odb(&git_dir);

        let base_paths = [
            "a-b",
            "a.txt",
            "a/x",
            "a/y/z.yml",
            "a0",
            "b/c/d/e.txt",
            "b/c/f.txt",
            "top.md",
            "rules/windows/p/one.yml",
            "rules/windows/p/two.yml",
            "rules/linux/q.yml",
        ];
        let mut base_index = grit_lib::index::Index::new();
        for (n, path) in base_paths.iter().enumerate() {
            let mode = if n % 4 == 0 { 0o100755 } else { 0o100644 };
            base_index.add_or_replace(staged_entry(&odb, path, &format!("base {n}"), mode));
        }
        let base_tree =
            grit_lib::index::write_tree::write_tree_from_index(&odb, &base_index, "").unwrap();

        let candidates = [
            "a-b",
            "a.txt",
            "a/x",
            "a/new.yml",
            "a/y/z.yml",
            "a/y/w/deep.yml",
            "a0",
            "a1",
            "b/c/d/e.txt",
            "b/c/d/g.txt",
            "b/h.txt",
            "top.md",
            "zz/new/dir/f.evtx",
            "rules/windows/p/one.yml",
            "rules/windows/p/three.yml",
            "rules/windows/r/info.yml",
            "rules/linux/q.yml",
            "rules/macos/m.yml",
            "regression_data/rules/windows/p/i.yml",
        ];
        let mut seed: u64 = 0x9E37_79B9_7F4A_7C15;
        for round in 0..200 {
            let mut staged: Vec<grit_lib::index::IndexEntry> = Vec::new();
            for path in &candidates {
                seed = seed
                    .wrapping_mul(6364136223846793005)
                    .wrapping_add(1442695040888963407);
                if matches!((seed >> 33) % 3, 0) {
                    let mode = if matches!((seed >> 40) % 5, 0) {
                        0o100755
                    } else {
                        0o100644
                    };
                    staged.push(staged_entry(
                        &odb,
                        path,
                        &format!("staged {round} {path}"),
                        mode,
                    ));
                }
            }
            if staged.is_empty() {
                continue;
            }

            let mut merged = grit_lib::index::Index::new();
            add_tree_to_index(&odb, base_tree, "", &mut merged).unwrap();
            for entry in &staged {
                merged.add_or_replace(entry.clone());
            }
            let expected =
                grit_lib::index::write_tree::write_tree_from_index(&odb, &merged, "").unwrap();

            let mut sorted: Vec<&grit_lib::index::IndexEntry> = staged.iter().collect();
            sorted.sort_by(|a, b| a.path.cmp(&b.path));
            let got = match patch_tree(&odb, Some(base_tree), &sorted, 0) {
                Ok(oid) => oid,
                Err(_) => panic!("patch_tree must support this layout (round {round})"),
            };
            assert_eq!(got, expected, "tree id differs in round {round}");
        }
    }

    /// A staged file where HEAD has a directory is not handled by the patch
    /// path: it reports `Unsupported` so the caller falls back.
    #[test]
    fn test_patch_tree_reports_file_directory_collision() {
        let tmp = tempfile::tempdir().unwrap();
        let git_dir = tmp.path().join(".git");
        init_repo(&git_dir, tmp.path(), "https://example.com/s.git").unwrap();
        let odb = open_odb(&git_dir);
        let mut base_index = grit_lib::index::Index::new();
        base_index.add_or_replace(staged_entry(&odb, "d/f.txt", "x", 0o100644));
        let base_tree =
            grit_lib::index::write_tree::write_tree_from_index(&odb, &base_index, "").unwrap();
        let staged = [staged_entry(&odb, "d", "now a file", 0o100644)];
        let refs: Vec<&grit_lib::index::IndexEntry> = staged.iter().collect();
        assert!(matches!(
            patch_tree(&odb, Some(base_tree), &refs, 0),
            Err(PatchTreeError::Unsupported)
        ));
    }
}
