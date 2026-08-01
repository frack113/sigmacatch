// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 sigmacatch contributors

//! Plumbing layer — raw git operations on top of grit-lib.
//!
//! Mirrors the architecture documented in the crate root:
//!   Plumbing → Raw git ops: Odb, Index, commit, checkout, refs

pub(crate) mod checkout;
pub(crate) mod clone;
pub(crate) mod commit;
pub(crate) mod fetch;
pub(crate) mod index;
pub(crate) mod init;
pub(crate) mod push;
pub(crate) mod refs;

pub(crate) use checkout::{checkout_main_branch, open_odb};
pub(crate) use clone::clone_repo;
pub(crate) use commit::commit_tree;
pub(crate) use fetch::{fetch_remote, fetch_remote_ssh};
pub(crate) use index::{add_directory_to_index, add_file_to_index, add_tree_to_index, write_index};
pub(crate) use init::init_repo;
pub(crate) use push::{push_branch, push_branch_ssh};
pub(crate) use refs::{
    fast_forward_branch, read_loose_or_packed_ref, read_remote_url_from_config, resolve_head,
    set_head_after_fetch,
};
