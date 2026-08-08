// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 sigmacatch contributors

//! Commit object creation.

use anyhow::Result;
use grit_lib::objects::{ObjectId, ObjectKind};
use grit_lib::odb::Odb;
use grit_lib::refs;
use std::path::Path;
use tracing::info;

use crate::plumbing::refs::{map_grit, resolve_head, symbolic_ref_target};

/// Write a new commit object pointing at `tree_oid` with HEAD as its parent,
/// then advance the ref currently pointed to by HEAD (or detach HEAD if it is
/// detached). Uses grit-lib's `refs` module for ref/HEAD writes.
pub(crate) fn commit_tree(
    git_dir: &Path,
    odb: &Odb,
    tree_oid: ObjectId,
    message: &str,
    author: &str,
    email: &str,
) -> Result<()> {
    let parent_oid = resolve_head(git_dir)?;
    let now = chrono::Utc::now().timestamp();
    let author_line = format!("{} <{}> {} +0000", author, email, now);
    let committer_line = author_line.clone();

    let commit = grit_lib::objects::CommitData {
        tree: tree_oid,
        parents: vec![parent_oid],
        author: author_line,
        committer: committer_line,
        message: format!("{}\n", message.trim_end_matches('\n')),
        encoding: None,
        author_raw: Vec::new(),
        committer_raw: Vec::new(),
        raw_message: None,
    };

    let raw = grit_lib::objects::serialize_commit(&commit);
    let commit_oid = odb
        .write(ObjectKind::Commit, &raw)
        .map_err(|e| anyhow::anyhow!("Failed to write commit object: {}", e))?;

    match symbolic_ref_target(git_dir, "HEAD")? {
        Some(ref_name) => {
            map_grit(refs::write_ref(git_dir, &ref_name, &commit_oid))?;
            info!(
                "Committed {} to {}: {}",
                commit_oid,
                ref_name,
                message.trim()
            );
        }
        None => {
            map_grit(refs::write_ref(git_dir, "HEAD", &commit_oid))?;
            info!(
                "Committed {} to detached HEAD: {}",
                commit_oid,
                message.trim()
            );
        }
    }

    Ok(())
}
