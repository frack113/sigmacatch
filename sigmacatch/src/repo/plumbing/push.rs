// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 sigmacatch contributors

//! Push local branches to remote via smart HTTP or SSH.

use super::refs::map_grit;
use crate::repo::{RepoError, Result};
use grit_lib::fetch::NoProgress;
use grit_lib::objects::ObjectId;
use grit_lib::transfer::PushOptions;
use grit_lib::transfer::PushRefSpec;
use grit_lib::transport::Transport;
use grit_lib::transport::http::HttpClient;
use grit_lib::transport::{SshCommand, SshTransport};
use std::path::Path;
use tracing::{info, warn};

use crate::repo::plumbing::refs::read_loose_or_packed_ref;
use crate::repo::transport::SshMode;

/// Describe a rejection reason in user-friendly text.
fn describe_push_rejection(status: &grit_lib::push_report::PushRefStatus) -> String {
    match status {
        grit_lib::push_report::PushRefStatus::RejectNonFastForward => {
            "local branch has diverged — run `git pull` first or use `--force`".to_string()
        }
        grit_lib::push_report::PushRefStatus::RejectAlreadyExists => {
            "remote ref already exists — rename your branch or delete the remote ref".to_string()
        }
        grit_lib::push_report::PushRefStatus::RejectFetchFirst => {
            "remote has new commits not in your local branch — run `git pull` first".to_string()
        }
        grit_lib::push_report::PushRefStatus::RejectNeedsForce => {
            "remote requires `--force` (non-fast-forward) — update the remote branch first"
                .to_string()
        }
        grit_lib::push_report::PushRefStatus::RejectStale => {
            "force-with-lease stale — the remote ref changed unexpectedly".to_string()
        }
        grit_lib::push_report::PushRefStatus::RemoteRejected => {
            "remote rejected the update (hook or policy)".to_string()
        }
        grit_lib::push_report::PushRefStatus::AtomicPushFailed => {
            "atomic push failed — another ref in this push was rejected".to_string()
        }
        _ => format!("{:?}", status),
    }
}

/// Push a local branch to the remote via smart HTTP.
pub fn push_branch(
    http_client: &dyn HttpClient,
    git_dir: &Path,
    remote_url: &str,
    branch_name: &str,
) -> Result<()> {
    let ref_name = format!("refs/heads/{}", branch_name);
    let oid_str = read_loose_or_packed_ref(git_dir, &ref_name)
        .ok_or_else(|| RepoError::State(format!("Branch '{}' not found locally", branch_name)))?;
    let head_oid = ObjectId::from_hex(&oid_str).map_err(|e| {
        RepoError::InvalidRef(format!("Invalid OID for branch '{}': {}", branch_name, e))
    })?;
    let spec = PushRefSpec {
        src: Some(head_oid),
        dst: format!("refs/heads/{}", branch_name),
        force: false,
        delete: false,
        expected_old: None,
        expect_absent: false,
    };
    let opts = PushOptions {
        atomic: false,
        dry_run: false,
        push_options: Vec::new(),
    };
    let outcome = map_grit(grit_lib::push::push_http(
        http_client,
        git_dir,
        remote_url,
        &[spec],
        &opts,
        &mut NoProgress,
    ))?;
    if outcome.results.is_empty() {
        warn!("No refs were pushed");
    } else {
        for result in &outcome.results {
            if result.status.is_error() {
                return Err(RepoError::Grit(format!(
                    "Push of '{}' rejected by remote: {:?}. \
                     The remote branch has diverged (likely another machine or a prior \
                     partial push). Delete the branch on GitHub and re-run, or rename it.",
                    branch_name, result.status
                )));
            }
        }
        info!("Pushed branch '{}'", branch_name);
    }
    Ok(())
}

/// Push via SSH.
pub fn push_branch_ssh(
    git_dir: &Path,
    remote_url: &str,
    branch_name: &str,
    ssh_mode: &SshMode,
) -> Result<()> {
    let ref_name = format!("refs/heads/{}", branch_name);
    let oid_str = read_loose_or_packed_ref(git_dir, &ref_name)
        .ok_or_else(|| RepoError::State(format!("Branch '{}' not found locally", branch_name)))?;
    let head_oid = ObjectId::from_hex(&oid_str).map_err(|e| {
        RepoError::InvalidRef(format!("Invalid OID for branch '{}': {}", branch_name, e))
    })?;
    let spec = PushRefSpec {
        src: Some(head_oid),
        dst: format!("refs/heads/{}", branch_name),
        force: false,
        delete: false,
        expected_old: None,
        expect_absent: false,
    };
    let opts = PushOptions {
        atomic: false,
        dry_run: false,
        push_options: Vec::new(),
    };
    let transport = match ssh_mode {
        SshMode::Default => SshTransport::new(),
        SshMode::ShellCommand(cmd) => SshTransport {
            ssh_command: SshCommand::ShellCommand(cmd.clone().into()),
        },
        SshMode::Program(args) => SshTransport {
            ssh_command: SshCommand::Program(args[0].clone()),
        },
    };
    let mut conn = map_grit(transport.connect(
        remote_url,
        grit_lib::transport::Service::ReceivePack,
        &grit_lib::transport::ConnectOptions::default(),
    ))?;
    let outcome = map_grit(grit_lib::push::push_remote(
        git_dir,
        &mut *conn,
        &[spec],
        &opts,
        &mut NoProgress,
    ))?;
    if outcome.results.is_empty() {
        warn!("No refs were pushed via SSH");
    } else {
        for result in &outcome.results {
            if result.status.is_error() {
                let reason = describe_push_rejection(&result.status);
                let remote_msg = result
                    .message
                    .as_deref()
                    .map(|m| format!(" ({})", m))
                    .unwrap_or_default();
                let action_hint = if matches!(
                    result.status,
                    grit_lib::push_report::PushRefStatus::RejectFetchFirst
                        | grit_lib::push_report::PushRefStatus::RejectNonFastForward
                ) {
                    "Delete the branch on GitHub and re-run, or rename it."
                } else {
                    &reason
                };
                return Err(RepoError::Grit(format!(
                    "Push of '{}' rejected by remote via SSH: {:?}{}.\n    \
                     Fix: {}",
                    branch_name, result.status, remote_msg, action_hint
                )));
            }
        }
        info!("Pushed branch '{}' via SSH", branch_name);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::repo::plumbing::init::init_repo;
    use grit_lib::objects::{CommitData, ObjectKind};

    /// HttpClient whose every request fails fast — keeps tests off the network
    /// while still exercising the pre-push validation and call sites.
    struct FailClient;

    impl HttpClient for FailClient {
        fn get(&self, _url: &str, _git_protocol: Option<&str>) -> grit_lib::error::Result<Vec<u8>> {
            Err(grit_lib::error::Error::Message(
                "no network in tests".into(),
            ))
        }

        fn post(
            &self,
            _url: &str,
            _content_type: &str,
            _accept: &str,
            _body: &[u8],
            _git_protocol: Option<&str>,
        ) -> grit_lib::error::Result<Vec<u8>> {
            Err(grit_lib::error::Error::Message(
                "no network in tests".into(),
            ))
        }
    }

    /// Minimal repo with one commit on `branch`, HEAD symbolic.
    fn setup_repo(tmp: &std::path::Path, branch: &str) -> std::path::PathBuf {
        let git_dir = tmp.join(".git");
        init_repo(&git_dir, tmp, "https://example.com/sigma.git").unwrap();

        let commit = CommitData {
            tree: grit_lib::objects::ObjectId::from_hex("4b825dc642cb6eb9a060e54bf8d69288fbee4904")
                .unwrap(),
            parents: Vec::new(),
            author: "test <t@example.com> 0 +0000".to_string(),
            committer: "test <t@example.com> 0 +0000".to_string(),
            message: "initial\n".to_string(),
            encoding: None,
            author_raw: Vec::new(),
            committer_raw: Vec::new(),
            raw_message: None,
        };
        let odb = crate::repo::plumbing::checkout::open_odb(&git_dir);
        let raw = grit_lib::objects::serialize_commit(&commit);
        let commit_oid = odb.write(ObjectKind::Commit, &raw).unwrap();
        let ref_path = git_dir.join("refs").join("heads").join(branch);
        if let Some(parent) = ref_path.parent() {
            std::fs::create_dir_all(parent).unwrap();
        }
        std::fs::write(&ref_path, format!("{commit_oid}\n")).unwrap();
        std::fs::write(git_dir.join("HEAD"), format!("ref: refs/heads/{branch}\n")).unwrap();
        git_dir
    }

    #[test]
    fn describe_push_rejection_covers_every_status() {
        use grit_lib::push_report::PushRefStatus as S;
        assert!(describe_push_rejection(&S::RejectNonFastForward).contains("git pull"));
        assert!(describe_push_rejection(&S::RejectAlreadyExists).contains("already exists"));
        assert!(describe_push_rejection(&S::RejectFetchFirst).contains("git pull"));
        assert!(describe_push_rejection(&S::RejectNeedsForce).contains("--force"));
        assert!(describe_push_rejection(&S::RejectStale).contains("stale"));
        assert!(describe_push_rejection(&S::RemoteRejected).contains("rejected"));
        assert!(describe_push_rejection(&S::AtomicPushFailed).contains("atomic"));
        // Wildcard arm: non-rejection statuses fall back to the debug name.
        assert_eq!(describe_push_rejection(&S::Ok), "Ok");
        assert_eq!(describe_push_rejection(&S::UpToDate), "UpToDate");
    }

    #[test]
    fn push_branch_missing_local_branch_is_state_error() {
        let tmp = tempfile::tempdir().unwrap();
        let git_dir = setup_repo(tmp.path(), "main");

        let err = push_branch(
            &FailClient,
            &git_dir,
            "https://example.com/sigma.git",
            "feature",
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("not found locally"), "unexpected error: {err}");
    }

    #[test]
    fn push_branch_valid_branch_reaches_transport() {
        let tmp = tempfile::tempdir().unwrap();
        let git_dir = setup_repo(tmp.path(), "main");

        let err = push_branch(
            &FailClient,
            &git_dir,
            "https://example.com/sigma.git",
            "main",
        )
        .unwrap_err()
        .to_string();
        // The FailClient's error surfaces through map_grit.
        assert!(
            err.contains("no network in tests"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn push_branch_ssh_missing_local_branch_is_state_error() {
        let tmp = tempfile::tempdir().unwrap();
        let git_dir = setup_repo(tmp.path(), "main");
        let mode = SshMode::Program(vec![std::ffi::OsString::from("/nonexistent/ssh")]);

        let err = push_branch_ssh(&git_dir, "git@github.com:u/r.git", "feature", &mode)
            .unwrap_err()
            .to_string();
        assert!(err.contains("not found locally"), "unexpected error: {err}");
    }

    #[test]
    fn push_branch_ssh_valid_branch_fails_at_connect() {
        let tmp = tempfile::tempdir().unwrap();
        let git_dir = setup_repo(tmp.path(), "main");
        // A nonexistent ssh binary fails immediately — no real process, no network.
        let mode = SshMode::Program(vec![std::ffi::OsString::from("/nonexistent/ssh")]);

        let err = push_branch_ssh(&git_dir, "git@github.com:u/r.git", "main", &mode)
            .unwrap_err()
            .to_string();
        assert!(
            !err.contains("not found locally"),
            "unexpected error: {err}"
        );
        assert!(!err.contains("Invalid OID"), "unexpected error: {err}");
    }
}
