// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 sigmacatch contributors

//! Commit object creation.

use anyhow::Result;
use grit_lib::objects::ObjectId;
use grit_lib::odb::Odb;
use std::path::Path;
use tracing::info;

use crate::plumbing::refs::resolve_head;

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
        .write(grit_lib::objects::ObjectKind::Commit, &raw)
        .map_err(|e| anyhow::anyhow!("Failed to write commit object: {}", e))?;

    let head_path = git_dir.join("HEAD");
    let head_content = std::fs::read_to_string(&head_path)?;
    let head_ref = head_content
        .trim()
        .strip_prefix("ref: ")
        .map(|s| s.trim().to_string());

    if let Some(ref_name) = head_ref {
        let full_path = git_dir.join(&ref_name);
        std::fs::write(&full_path, format!("{}\n", commit_oid))?;
        info!(
            "Committed {} to {}: {}",
            commit_oid,
            ref_name,
            message.trim()
        );
    } else {
        std::fs::write(&head_path, format!("{}\n", commit_oid))?;
        info!(
            "Committed {} to detached HEAD: {}",
            commit_oid,
            message.trim()
        );
    }

    Ok(())
}
