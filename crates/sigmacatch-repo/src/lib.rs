// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 sigmacatch contributors

//! Git operations via grit-lib (pure Rust Git reimplementation).
//!
//! Architecture:
//!   Transport    → `AuthHttpClient` (HttpClient trait) for HTTPS auth
//!   Plumbing     → Raw git ops: Odb, Index, commit, checkout, refs (`plumbing/`)
//!   Porcelain    → High-level wrappers: clone, pull, push, add, commit (`porcelain.rs`)
//!   Branch       → Branch and HEAD management (`branch.rs`)
//!   SigmaRepo    → High-level sigma repository manager — the single entry point
//!   github       → GitHub fork detection + git commit workflow

pub mod github;

pub(crate) mod branch;
pub(crate) mod plumbing;
pub(crate) mod porcelain;
pub(crate) mod sigma_repo;
pub(crate) mod transport;

pub use crate::branch::{create_branch, switch_head};
pub use crate::plumbing::clone::clone_repo;
pub use crate::plumbing::fetch::{fetch_remote, fetch_remote_ssh};
pub use crate::plumbing::init::init_repo;
pub use crate::plumbing::push::{push_branch, push_branch_ssh};
pub use crate::plumbing::refs::read_loose_or_packed_ref;
pub use crate::porcelain::{
    create_branch_name, git_add, git_clone, git_clone_ssh, git_commit, git_pull, git_pull_ssh,
    git_push, git_push_ssh, push,
};
pub use crate::sigma_repo::SigmaRepo;
pub use crate::transport::{https_to_ssh_url, AuthHttpClient, GitTransport};

/// Default SigmaHQ repository URL.
pub const DEFAULT_SIGMA_REPO_URL: &str = "https://github.com/SigmaHQ/sigma.git";
