// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 sigmacatch contributors

//! Fetch from remote via smart HTTP or SSH.

use anyhow::Result;
use grit_lib::fetch::Progress;
use grit_lib::transfer::{FetchOptions, TagMode};
use grit_lib::transport::http::{HttpClient, http_fetch};
use grit_lib::transport::{ConnectOptions, SshCommand, SshTransport, Transport};
use std::path::Path;
use tracing::info;

use crate::transport::{SshMode, sanitize_url};

/// Forward the remote's side-band progress lines (channel 2) to the log so a
/// first clone's long download isn't silent. The server's messages are
/// `\r`-delimited counters (`Enumerating objects`, `Compressing objects`, …).
struct LogProgress;

impl Progress for LogProgress {
    fn message(&mut self, bytes: &[u8]) {
        let text = String::from_utf8_lossy(bytes);
        for line in text.split('\r') {
            let line = line.trim();
            if !line.is_empty() {
                info!("remote: {}", line);
            }
        }
    }
}

/// Fetch options for a specific set of branches.
///
/// Full history (no `depth`). A shallow (`depth = 1`) fetch leaves the local
/// ODB without the ancestors of the fetched tips, so a push whose remote
/// advanced after the clone cannot build its pack: the want-walk crosses the
/// shallow boundary and fails with `object not found: <parent oid>` (case of
/// `f321ac84b7cb0c1e688bb1a6415d0bf73d767d1d` on 2026-08-03).
///
/// The refspec is narrow (`+refs/heads/{branch}:refs/remotes/origin/{branch}`
/// per branch) instead of `+refs/heads/*`. Sigmacatch only ever reads the
/// default branch (plus the `sigmacatch/<date>` working branch on the fork),
/// so downloading every remote branch wastes bandwidth and time. With protocol
/// v2 the server turns these refspecs into `ref-prefix` lines and does not even
/// advertise the other branches.
pub(crate) fn fetch_options_for_branches(branches: &[&str]) -> FetchOptions {
    let refspecs = branches
        .iter()
        .map(|b| format!("+refs/heads/{}:refs/remotes/origin/{}", b, b))
        .collect();
    FetchOptions {
        refspecs,
        tags: TagMode::None,
        ..Default::default()
    }
}

/// Fetch options for the whole `sigmacatch/*` namespace (every pending-PR
/// working branch on the fork).
///
/// A single glob refspec (`+refs/heads/sigmacatch/*:refs/remotes/origin/sigmacatch/*`)
/// replaces the per-branch refspecs: it is still narrow (never `+refs/heads/*`),
/// and with protocol v2 the server turns it into a `ref-prefix` line cut at the
/// first `*` (`refs/heads/sigmacatch/`) so only those branches are advertised.
/// Full history (no `depth`) — same invariant as `fetch_options_for_branches`.
pub(crate) fn fetch_options_for_sigmacatch_namespace() -> FetchOptions {
    FetchOptions {
        refspecs: vec!["+refs/heads/sigmacatch/*:refs/remotes/origin/sigmacatch/*".to_string()],
        tags: TagMode::None,
        ..Default::default()
    }
}

/// Fetch from remote via smart HTTP.
pub fn fetch_remote(
    http_client: &dyn HttpClient,
    git_dir: &Path,
    repo_url: &str,
    opts: &FetchOptions,
) -> Result<(usize, Option<String>)> {
    info!("Fetching from {}", sanitize_url(repo_url));
    let outcome = http_fetch(http_client, git_dir, repo_url, opts, &mut LogProgress)?;
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
    ssh_mode: &SshMode,
    opts: &FetchOptions,
) -> Result<(usize, Option<String>)> {
    info!("Fetching via SSH from {}", repo_url);
    let transport = match ssh_mode {
        SshMode::Default => SshTransport::new(),
        SshMode::ShellCommand(cmd) => SshTransport {
            ssh_command: SshCommand::ShellCommand(cmd.clone().into()),
        },
        SshMode::Program(args) => SshTransport {
            ssh_command: SshCommand::Program(args[0].clone()),
        },
    };
    let mut conn = transport.connect(
        repo_url,
        grit_lib::transport::Service::UploadPack,
        &ConnectOptions::default(),
    )?;
    let outcome = grit_lib::fetch::fetch_remote(git_dir, &mut *conn, opts, &mut LogProgress)?;
    let count = outcome.updates.len();
    info!(
        "Fetched {} ref updates via SSH (default branch: {})",
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
        let opts = fetch_options_for_branches(&["master", "main"]);
        assert!(
            opts.depth.is_none(),
            "fetch must be full-history, not shallow"
        );
        assert!(opts.refspecs.iter().all(|r| !r.contains("refs/heads/*")));
        assert_eq!(opts.tags, TagMode::None);
    }

    /// The narrow refspec must map exactly the requested branches, never the
    /// wildcard `+refs/heads/*` that downloads every remote branch.
    #[test]
    fn test_fetch_options_for_branches_builds_narrow_refspecs() {
        let opts = fetch_options_for_branches(&["master", "main"]);
        assert_eq!(
            opts.refspecs,
            vec![
                "+refs/heads/master:refs/remotes/origin/master",
                "+refs/heads/main:refs/remotes/origin/main",
            ]
        );
    }

    /// The sigmacatch namespace fetch must use one glob refspec scoped to
    /// `sigmacatch/*` (never the full `+refs/heads/*`) and stay full-history.
    #[test]
    fn test_fetch_options_for_sigmacatch_namespace() {
        let opts = fetch_options_for_sigmacatch_namespace();
        assert_eq!(
            opts.refspecs,
            vec!["+refs/heads/sigmacatch/*:refs/remotes/origin/sigmacatch/*".to_string()]
        );
        assert!(opts.depth.is_none(), "namespace fetch must be full-history");
        assert_eq!(opts.tags, TagMode::None);
        assert!(
            opts.refspecs.iter().all(|r| !r.contains("refs/heads/*:")),
            "must never fetch the full refs/heads/* namespace"
        );
    }
}
