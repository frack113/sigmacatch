// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 sigmacatch contributors

//! Full clone: init + fetch + set HEAD + checkout worktree.

use anyhow::Result;
use grit_lib::transport::http::HttpClient;
use std::path::Path;
use tracing::info;

use crate::plumbing::checkout::checkout_main_branch;
use crate::plumbing::fetch::fetch_remote;
use crate::plumbing::init::init_repo;
use crate::plumbing::refs::set_head_after_fetch;

/// Full clone: init + fetch + set HEAD + checkout worktree.
pub fn clone_repo(http_client: &dyn HttpClient, url: &str, dest: &Path) -> Result<()> {
    let git_dir = dest.join(".git");
    if git_dir.exists() {
        info!("Repository already exists at {:?}, skipping clone", dest);
        return Ok(());
    }

    info!("Cloning into {:?}", dest);
    init_repo(&git_dir, dest, url)?;
    let (count, default_branch) = match fetch_remote(http_client, &git_dir, url) {
        Ok(r) => r,
        Err(e) => {
            let _ = std::fs::remove_dir_all(&git_dir);
            return Err(e);
        }
    };
    if count == 0 {
        let _ = std::fs::remove_dir_all(&git_dir);
        anyhow::bail!("No refs fetched from remote — empty or unreachable repository");
    }

    set_head_after_fetch(&git_dir, default_branch.as_deref());

    checkout_main_branch(&git_dir, dest)?;
    Ok(())
}
