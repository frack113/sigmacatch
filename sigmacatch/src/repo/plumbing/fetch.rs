// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 sigmacatch contributors

//! Fetch from remote over SSH.

use crate::repo::{RepoError, Result};
use grit_lib::progress::{NeverCancel, ProgressSink};
use grit_lib::remote::fetch::Progress;
use grit_lib::remote::transfer::{FetchDepth, FetchOptions, TagMode};
use std::path::Path;
use tracing::info;

use super::refs::map_grit;
use grit_lib::remote::transport::{ConnectOptions, Connection, SshTransport, Transport};

use crate::repo::transport::SshMode;

/// Forward the remote's side-band progress lines (channel 2) to the log so a
/// first clone's long download isn't silent. The server's messages are
/// `\r`-delimited counters (`Enumerating objects`, `Compressing objects`, …).
struct LogProgress;

impl ProgressSink for LogProgress {}

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

/// Fetch options for shallow clone (depth=1).
/// Used for initial clone when `git.shallow_clone = true`.
pub(crate) fn fetch_options_for_shallow_clone(branches: &[&str]) -> FetchOptions {
    let refspecs = branches
        .iter()
        .map(|b| format!("+refs/heads/{}:refs/remotes/origin/{}", b, b))
        .collect();
    FetchOptions {
        refspecs,
        tags: TagMode::None,
        fetch_depth: FetchDepth::depth(1),
        ..Default::default()
    }
}

/// Fetch options for unshallow (fetch full history).
/// Used before push when repo was cloned shallow.
pub(crate) fn fetch_options_for_unshallow(branches: &[&str]) -> FetchOptions {
    let refspecs = branches
        .iter()
        .map(|b| format!("+refs/heads/{}:refs/remotes/origin/{}", b, b))
        .collect();
    FetchOptions {
        refspecs,
        tags: TagMode::None,
        fetch_depth: Some(FetchDepth::Unshallow),
        ..Default::default()
    }
}

/// Connect to the remote over SSH and return a live connection positioned
/// just past the ref advertisement.
pub fn connect_ssh(repo_url: &str, ssh_mode: &SshMode) -> Result<Box<dyn Connection>> {
    let SshMode::Program(args) = ssh_mode;
    let transport = SshTransport::with_program(args[0].clone());
    map_grit(transport.connect(
        repo_url,
        grit_lib::remote::transport::Service::UploadPack,
        &ConnectOptions::default(),
    ))
}

/// Connect to the remote over SSH and report the branch its `HEAD` symref
/// points at — the branch a clone must check out.
///
/// The connection is returned so the caller can fetch through it: the
/// advertisement was already read on connect, and a second handshake would be
/// wasted. The remote's advertised default branch is authoritative: grit-lib
/// resolves explicit fetch refspecs strictly, so requesting a branch the
/// remote does not have fails the whole fetch with `SourceNotFound`.
pub fn connect_with_default_branch(
    repo_url: &str,
    ssh_mode: &SshMode,
) -> Result<(Box<dyn Connection>, String)> {
    let conn = connect_ssh(repo_url, ssh_mode)?;
    let head = conn.head_symref().map(str::to_string);
    match head {
        Some(sym) if sym.starts_with("refs/heads/") => {
            Ok((conn, sym.strip_prefix("refs/heads/").unwrap().to_string()))
        }
        _ => Err(RepoError::State(format!(
            "Remote {repo_url} advertised no HEAD branch — cannot determine its default branch"
        ))),
    }
}

/// Fetch from a live SSH connection whose advertisement was already read.
pub fn fetch_remote_on(
    git_dir: &Path,
    conn: &mut dyn Connection,
    opts: &FetchOptions,
) -> Result<(usize, Option<String>)> {
    let mut opts = opts.clone();
    let outcome = map_grit(grit_lib::remote::fetch::fetch_remote(
        git_dir,
        conn,
        &mut opts,
        &mut LogProgress,
        &NeverCancel,
    ))?;
    let count = outcome.updates.len();
    info!(
        "Fetched {} ref updates via SSH (default branch: {})",
        count,
        outcome.default_branch.as_deref().unwrap_or("unknown")
    );
    Ok((count, outcome.default_branch))
}

/// Fetch from remote over SSH (connects, then fetches).
pub fn fetch_remote(
    git_dir: &Path,
    repo_url: &str,
    ssh_mode: &SshMode,
    opts: &FetchOptions,
) -> Result<(usize, Option<String>)> {
    info!("Fetching via SSH from {}", repo_url);
    let mut conn = connect_ssh(repo_url, ssh_mode)?;
    fetch_remote_on(git_dir, &mut *conn, opts)
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
            opts.fetch_depth.is_none(),
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
        assert!(
            opts.fetch_depth.is_none(),
            "namespace fetch must be full-history"
        );
        assert_eq!(opts.tags, TagMode::None);
        assert!(
            opts.refspecs.iter().all(|r| !r.contains("refs/heads/*:")),
            "must never fetch the full refs/heads/* namespace"
        );
    }

    /// Side-band progress bytes are `\r`-delimited and may carry invalid UTF-8
    /// mid-transfer — the logging path must survive both without panicking.
    #[test]
    fn log_progress_survives_crlf_and_invalid_utf8() {
        let mut progress = LogProgress;
        progress.message(b"Enumerating objects: 42\rCompressing objects\r\r");
        progress.message(b"bad \xff\xfe bytes\r");
        progress.message(b"\r");
        progress.message(b"");
    }

    #[test]
    fn fetch_remote_fails_at_connect_with_missing_binary() {
        let tmp = tempfile::tempdir().unwrap();
        let git_dir = tmp.path().join(".git");
        crate::repo::plumbing::init::init_repo(
            &git_dir,
            tmp.path(),
            "git@github.com:SigmaHQ/sigma.git",
        )
        .unwrap();

        // A nonexistent ssh binary fails immediately — no real process, no network.
        let mode = SshMode::Program(vec![std::ffi::OsString::from("/nonexistent/ssh")]);
        let opts = fetch_options_for_branches(&["main"]);
        let err = fetch_remote(&git_dir, "git@github.com:u/r.git", &mode, &opts)
            .unwrap_err()
            .to_string();
        assert!(!err.is_empty());
    }

    /// Default-branch discovery fails at connect when the ssh binary is
    /// missing — the error must be actionable, not a refspec failure.
    #[test]
    fn connect_with_default_branch_fails_at_connect_with_missing_binary() {
        let mode = SshMode::Program(vec![std::ffi::OsString::from("/nonexistent/ssh")]);
        // `Ok` carries a `Box<dyn Connection>` that is not `Debug`, so no
        // `unwrap_err` — match instead.
        let err = match connect_with_default_branch("git@github.com:u/r.git", &mode) {
            Err(e) => e.to_string(),
            Ok(_) => panic!("expected a connect failure"),
        };
        assert!(!err.is_empty());
    }
}
