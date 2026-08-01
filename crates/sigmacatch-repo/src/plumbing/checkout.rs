// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 sigmacatch contributors

//! Working-tree checkout from a commit tree.

use anyhow::Result;
use grit_lib::objects::ObjectId;
use grit_lib::odb::Odb;
use std::path::Path;
use tracing::{info, warn};

use crate::plumbing::refs::read_loose_or_packed_ref;

pub(crate) fn open_odb(git_dir: &Path) -> Odb {
    Odb::new(&git_dir.join("objects")).with_config_git_dir(git_dir.to_path_buf())
}

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
