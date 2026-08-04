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

/// Fetch options shared by the HTTP and SSH fetch paths (clone + pull).
///
/// Full history (no `depth`). A shallow (`depth = 1`) fetch leaves the local
/// ODB without the ancestors of the fetched tips, so a push whose remote
/// advanced after the clone cannot build its pack: the want-walk crosses the
/// shallow boundary and fails with `object not found: <parent oid>` (case of
/// `f321ac84b7cb0c1e688bb1a6415d0bf73d767d1d` on 2026-08-03).
fn fetch_options() -> FetchOptions {
    FetchOptions {
        refspecs: vec!["+refs/heads/*:refs/remotes/origin/*".to_string()],
        tags: TagMode::None,
        ..Default::default()
    }
}

/// Fetch from remote via smart HTTP.
pub fn fetch_remote(
    http_client: &dyn HttpClient,
    git_dir: &Path,
    repo_url: &str,
) -> Result<(usize, Option<String>)> {
    info!("Fetching from {}", sanitize_url(repo_url));
    let opts = fetch_options();
    let outcome = http_fetch(http_client, git_dir, repo_url, &opts, &mut NoProgress)?;
    let count = outcome.updates.len();
    info!(
        "Fetched {} ref updates (default branch: {})",
        count,
        outcome.default_branch.as_deref().unwrap_or("unknown")
    );
    Ok((count, outcome.default_branch))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A shallow (`depth = 1`) fetch must never be used: the local ODB would
    /// miss every ancestor of the fetched tips, which breaks the push pack walk
    /// (`object not found: <parent>`) as soon as the remote advances mid-run.
    #[test]
    fn test_fetch_options_are_full_history() {
        let opts = fetch_options();
        assert!(
            opts.depth.is_none(),
            "fetch must be full-history, not shallow"
        );
        assert!(opts
            .refspecs
            .iter()
            .any(|r| r == "+refs/heads/*:refs/remotes/origin/*"));
        assert_eq!(opts.tags, TagMode::None);
    }
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
    let opts = fetch_options();
    let outcome = grit_lib::fetch::fetch_remote(git_dir, &mut *conn, &opts, &mut NoProgress)?;
    let count = outcome.updates.len();
    info!(
        "Fetched {} ref updates via SSH (default branch: {})",
        count,
        outcome.default_branch.as_deref().unwrap_or("unknown")
    );
    Ok((count, outcome.default_branch))
}
