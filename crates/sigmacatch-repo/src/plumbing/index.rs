// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 sigmacatch contributors

//! Index construction: stage files, directories, and parent-tree entries.

use anyhow::Result;
use grit_lib::objects::ObjectId;
use grit_lib::odb::Odb;
use std::path::Path;
use tracing::warn;

use crate::plumbing::checkout::{is_exec_file, open_odb};
use crate::plumbing::refs::resolve_head;

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

pub(crate) fn add_tree_to_index(
    odb: &Odb,
    tree_oid: ObjectId,
    prefix: &str,
    index: &mut grit_lib::index::Index,
) -> Result<()> {
    let obj = odb
        .read(&tree_oid)
        .map_err(|e| anyhow::anyhow!("Failed to read tree {}: {}", tree_oid, e))?;
    let entries = grit_lib::objects::parse_tree(&obj.data)
        .map_err(|e| anyhow::anyhow!("Failed to parse tree: {}", e))?;
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

pub(crate) fn write_index(git_dir: &Path, index: &grit_lib::index::Index) -> Result<()> {
    let index_path = git_dir.join("index");
    if let Some(parent) = index_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    index
        .write(&index_path)
        .map_err(|e| anyhow::anyhow!("Failed to write index: {}", e))?;
    Ok(())
}

pub(crate) fn add_file_to_index(
    git_dir: &Path,
    file_path: &Path,
    base: &Path,
    index: &mut grit_lib::index::Index,
) -> Result<()> {
    let odb = open_odb(git_dir);
    let contents = std::fs::read(file_path)?;
    let blob_oid = odb
        .write(grit_lib::objects::ObjectKind::Blob, &contents)
        .map_err(|e| anyhow::anyhow!("Failed to write blob: {}", e))?;

    let metadata = file_path.metadata()?;
    let is_exec = is_exec_file(&metadata);
    let mut mode = if is_exec { 0o100755 } else { 0o100644 };

    let rel = file_path
        .strip_prefix(base)
        .map_err(|_| anyhow::anyhow!("Path not under base"))?;
    let path_str = rel.to_string_lossy().replace('\\', "/");
    let path_bytes = path_str.as_bytes().to_vec();

    // Preserve the mode recorded in the parent tree for this path. On Windows
    // (non-unix) is_exec_file is always false, so a path that upstream stores
    // at mode 100755 (e.g. .evtx files checked into SigmaHQ) would otherwise be
    // re-staged as 100644 and produce spurious mode-change diffs. Reuse the
    // parent mode when the path already exists in HEAD.
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
