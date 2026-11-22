// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 sigmacatch contributors

//! Fetch from remote over SSH (grit-lib 0.5.31+ public API: `Repository` + `Remote`).

use crate::repo::{RepoError, Result};
use grit_lib::prelude::RepositoryOptions;
use grit_lib::progress::CancelToken;
use grit_lib::remote::fetch::Progress;
use grit_lib::remote::transfer::{FetchDepth, FetchOptions, TagMode};
use grit_lib::remote::{ListRefsOptions, Remote};
use grit_lib::repo::Repository;
use std::path::Path;
use tracing::info;

use super::refs::map_grit;

/// Forward the remote's side-band progress lines (channel 2) to the log.
struct LogProgress;

impl grit_lib::progress::ProgressSink for LogProgress {}

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

fn open_repo(git_dir: &Path) -> Result<Repository> {
    map_grit(Repository::open(git_dir, &RepositoryOptions::default()))
}

/// Fetch options for a specific set of branches (full history, narrow refspecs).
pub(crate) fn fetch_options_for_branches(branches: &[&str]) -> FetchOptions {
    let mut opts = FetchOptions::new();
    opts.refspecs = branches
        .iter()
        .map(|b| format!("+refs/heads/{}:refs/remotes/origin/{}", b, b))
        .collect();
    opts.tags = TagMode::None;
    opts
}

/// Fetch options for the whole `sigmacatch/*` namespace (full history).
pub(crate) fn fetch_options_for_sigmacatch_namespace() -> FetchOptions {
    let mut opts = FetchOptions::new();
    opts.refspecs = vec!["+refs/heads/sigmacatch/*:refs/remotes/origin/sigmacatch/*".to_string()];
    opts.tags = TagMode::None;
    opts
}

/// Fetch options for shallow clone (depth=1).
pub(crate) fn fetch_options_for_shallow_clone(branches: &[&str]) -> FetchOptions {
    let mut opts = FetchOptions::new();
    opts.refspecs = branches
        .iter()
        .map(|b| format!("+refs/heads/{}:refs/remotes/origin/{}", b, b))
        .collect();
    opts.tags = TagMode::None;
    opts.fetch_depth = FetchDepth::depth(1);
    opts
}

/// Fetch options for unshallow (fetch full history).
pub(crate) fn fetch_options_for_unshallow(branches: &[&str]) -> FetchOptions {
    let mut opts = FetchOptions::new();
    opts.refspecs = branches
        .iter()
        .map(|b| format!("+refs/heads/{}:refs/remotes/origin/{}", b, b))
        .collect();
    opts.tags = TagMode::None;
    opts.fetch_depth = Some(FetchDepth::Unshallow);
    opts
}

/// Discover the remote's default branch (HEAD symref target) via `list_refs`.
pub fn discover_default_branch(repo_url: &str) -> Result<String> {
    let remote = map_grit(Remote::from_url(repo_url))?;
    let opts = ListRefsOptions {
        symrefs: true,
        ..Default::default()
    };
    let refs = map_grit(remote.list_refs(None, &opts, None))?;
    for r in &refs {
        if r.name == "HEAD"
            && let Some(target) = &r.symref_target
            && let Some(branch) = target.strip_prefix("refs/heads/")
        {
            return Ok(branch.to_string());
        }
    }
    Err(RepoError::State(format!(
        "Remote {repo_url} advertised no HEAD branch — cannot determine its default branch"
    )))
}

/// Fetch from remote using the public `Repository` + `Remote` API.
///
/// Returns `(update_count, default_branch)`.
pub fn fetch_remote(
    git_dir: &Path,
    repo_url: &str,
    _ssh_mode: &crate::repo::transport::SshMode,
    opts: &FetchOptions,
) -> Result<(usize, Option<String>)> {
    info!("Fetching via SSH from {}", repo_url);
    let repo = open_repo(git_dir)?;
    let remote = map_grit(Remote::from_url(repo_url))?;
    let mut progress = LogProgress;
    let cancel = CancelToken::never();
    let outcome = map_grit(remote.fetch(&repo, opts.clone(), &mut progress, &cancel, None))?;
    let count = outcome.updates.len();
    info!(
        "Fetched {} ref updates via SSH (default branch: {})",
        count,
        outcome.default_branch.as_deref().unwrap_or("unknown")
    );
    Ok((count, outcome.default_branch))
}

/// Discover default branch and fetch it with narrow refspecs.
///
/// Returns `(update_count, default_branch)`. Replaces the former
/// `connect_with_default_branch` + `fetch_remote_on` single-handshake pattern
/// with the public `Repository`/`Remote` API (two operations).
pub fn discover_and_fetch(
    git_dir: &Path,
    repo_url: &str,
    ssh_mode: &crate::repo::transport::SshMode,
    opts_for_branch: impl FnOnce(&str) -> FetchOptions,
) -> Result<(usize, String)> {
    let default_branch = discover_default_branch(repo_url)?;
    let opts = opts_for_branch(&default_branch);
    let (count, outcome_branch) = fetch_remote(git_dir, repo_url, ssh_mode, &opts)?;
    Ok((count, outcome_branch.unwrap_or(default_branch)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use grit_lib::remote::transfer::TagMode;

    #[test]
    fn test_fetch_options_are_full_history() {
        let opts = fetch_options_for_branches(&["master", "main"]);
        assert!(
            opts.fetch_depth.is_none(),
            "fetch must be full-history, not shallow"
        );
        assert!(opts.refspecs.iter().all(|r| !r.contains("refs/heads/*")));
        assert_eq!(opts.tags, TagMode::None);
    }

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

    #[test]
    fn test_fetch_options_for_sigmacatch_namespace() {
        let opts = fetch_options_for_sigmacatch_namespace();
        assert_eq!(
            opts.refspecs,
            vec!["+refs/heads/sigmacatch/*:refs/remotes/origin/sigmacatch/*".to_string()]
        );
        assert!(
            opts.fetch_depth.is_none(),
            "namespace fetch must be full-history"
        );
        assert_eq!(opts.tags, TagMode::None);
        assert!(opts.refspecs.iter().all(|r| !r.contains("refs/heads/*:")));
    }

    #[test]
    fn log_progress_survives_crlf_and_invalid_utf8() {
        let mut progress = LogProgress;
        progress.message(b"Enumerating objects: 42\rCompressing objects\r\r");
        progress.message(b"bad \xff\xfe bytes\r");
        progress.message(b"\r");
        progress.message(b"");
    }
}
