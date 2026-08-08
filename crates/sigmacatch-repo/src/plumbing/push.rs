// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 sigmacatch contributors

//! Push local branches to remote via smart HTTP or SSH.

use anyhow::Result;
use grit_lib::fetch::NoProgress;
use grit_lib::objects::ObjectId;
use grit_lib::transfer::PushOptions;
use grit_lib::transfer::PushRefSpec;
use grit_lib::transport::http::HttpClient;
use grit_lib::transport::Transport;
use grit_lib::transport::{SshCommand, SshTransport};
use std::path::Path;
use tracing::{info, warn};

use crate::plumbing::refs::read_loose_or_packed_ref;
use crate::transport::SshMode;

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
        .ok_or_else(|| anyhow::anyhow!("Branch '{}' not found locally", branch_name))?;
    let head_oid = ObjectId::from_hex(&oid_str)
        .map_err(|e| anyhow::anyhow!("Invalid OID for branch '{}': {}", branch_name, e))?;
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
    let outcome = grit_lib::push::push_http(
        http_client,
        git_dir,
        remote_url,
        &[spec],
        &opts,
        &mut NoProgress,
    )?;
    if outcome.results.is_empty() {
        warn!("No refs were pushed");
    } else {
        for result in &outcome.results {
            if result.status.is_error() {
                anyhow::bail!(
                    "Push of '{}' rejected by remote: {:?}. \
                     The remote branch has diverged (likely another machine or a prior \
                     partial push). Delete the branch on GitHub and re-run, or rename it.",
                    branch_name,
                    result.status
                );
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
        .ok_or_else(|| anyhow::anyhow!("Branch '{}' not found locally", branch_name))?;
    let head_oid = ObjectId::from_hex(&oid_str)
        .map_err(|e| anyhow::anyhow!("Invalid OID for branch '{}': {}", branch_name, e))?;
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
    let mut conn = transport.connect(
        remote_url,
        grit_lib::transport::Service::ReceivePack,
        &grit_lib::transport::ConnectOptions::default(),
    )?;
    let outcome =
        grit_lib::push::push_remote(git_dir, &mut *conn, &[spec], &opts, &mut NoProgress)?;
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
                anyhow::bail!(
                    "Push of '{}' rejected by remote via SSH: {:?}{}.\n    \
                     Fix: {}",
                    branch_name,
                    result.status,
                    remote_msg,
                    action_hint
                );
            }
        }
        info!("Pushed branch '{}' via SSH", branch_name);
    }
    Ok(())
}
