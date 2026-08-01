// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 sigmacatch contributors

//! Fetch from remote via smart HTTP or SSH.

use anyhow::Result;
use grit_lib::fetch::NoProgress;
use grit_lib::transfer::{FetchOptions, TagMode};
use grit_lib::transport::http::{http_fetch, HttpClient};
use grit_lib::transport::{ConnectOptions, SshTransport, Transport};
use std::path::Path;
use tracing::info;

use crate::transport::sanitize_url;

/// Fetch from remote via smart HTTP.
pub fn fetch_remote(
    http_client: &dyn HttpClient,
    git_dir: &Path,
    repo_url: &str,
) -> Result<(usize, Option<String>)> {
    info!("Fetching from {}", sanitize_url(repo_url));
    let opts = FetchOptions {
        refspecs: vec!["+refs/heads/*:refs/remotes/origin/*".to_string()],
        tags: TagMode::None,
        depth: Some(1),
        ..Default::default()
    };
    let outcome = http_fetch(http_client, git_dir, repo_url, &opts, &mut NoProgress)?;
    let count = outcome.updates.len();
    info!(
        "Fetched {} ref updates (default branch: {})",
        count,
        outcome.default_branch.as_deref().unwrap_or("unknown")
    );
    Ok((count, outcome.default_branch))
}

/// Fetch from remote via SSH.
pub fn fetch_remote_ssh(
    git_dir: &Path,
    repo_url: &str,
    ssh_shell_cmd: &str,
) -> Result<(usize, Option<String>)> {
    info!("Fetching via SSH from {}", repo_url);
    let transport = if ssh_shell_cmd.is_empty() {
        SshTransport::new()
    } else {
        SshTransport::with_shell_command(ssh_shell_cmd)
    };
    let mut conn = transport.connect(
        repo_url,
        grit_lib::transport::Service::UploadPack,
        &ConnectOptions::default(),
    )?;
    let opts = FetchOptions {
        refspecs: vec!["+refs/heads/*:refs/remotes/origin/*".to_string()],
        tags: TagMode::None,
        depth: Some(1),
        ..Default::default()
    };
    let outcome = grit_lib::fetch::fetch_remote(git_dir, &mut *conn, &opts, &mut NoProgress)?;
    let count = outcome.updates.len();
    info!(
        "Fetched {} ref updates via SSH (default branch: {})",
        count,
        outcome.default_branch.as_deref().unwrap_or("unknown")
    );
    Ok((count, outcome.default_branch))
}
