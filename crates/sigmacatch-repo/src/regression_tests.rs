// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 sigmacatch contributors

//! Offline regression tests for real-world bugs.

use std::path::PathBuf;

use crate::plumbing::{add_file_to_index, init_repo, open_odb};
use grit_lib::objects::{CommitData, ObjectId, ObjectKind, serialize_commit};
use grit_lib::transfer::{PackBuildOptions, build_pack};
use grit_lib::write_tree::write_tree_from_index;

/// Minimal in-memory repo helper: init + commit with explicit parents.
struct TestRepo {
    git_dir: PathBuf,
    work_tree: PathBuf,
}

impl TestRepo {
    fn init(tmp: &tempfile::TempDir) -> Self {
        let git_dir = tmp.path().join(".git");
        init_repo(&git_dir, tmp.path(), "https://example.com/sigma.git").unwrap();
        Self {
            git_dir,
            work_tree: tmp.path().to_path_buf(),
        }
    }

    /// Write + stage one file and commit it with the given parents.
    fn commit(&self, name: &str, content: &str, parents: Vec<ObjectId>) -> ObjectId {
        let file = self.work_tree.join(name);
        std::fs::write(&file, content).unwrap();
        let odb = open_odb(&self.git_dir);
        let mut index = grit_lib::index::Index::new();
        add_file_to_index(&self.git_dir, &file, &self.work_tree, &mut index).unwrap();
        let tree = write_tree_from_index(&odb, &index, "").unwrap();
        let commit = CommitData {
            tree,
            parents,
            author: "t <t@example.com> 0 +0000".to_string(),
            committer: "t <t@example.com> 0 +0000".to_string(),
            message: format!("commit {name}\n"),
            encoding: None,
            author_raw: Vec::new(),
            committer_raw: Vec::new(),
            raw_message: None,
        };
        let raw = serialize_commit(&commit);
        odb.write(ObjectKind::Commit, &raw).unwrap()
    }

    /// Build the pack for a push of `wants` with remote `haves` — the exact
    /// operation grit runs in `push_branch`/`push_branch_ssh`.
    fn build_pack(&self, wants: &[ObjectId], haves: &[ObjectId]) -> anyhow::Result<Vec<u8>> {
        let odb = open_odb(&self.git_dir);
        build_pack(&odb, wants, haves, &PackBuildOptions::default()).map_err(Into::into)
    }
}

/// Regression test for the 2026-08-03 push failure
/// (`object not found: f321ac84b7cb0c1e688bb1a6415d0bf73d767d1d`).
///
/// A shallow (`depth = 1`) clone leaves the local ODB with the fetched tip but
/// without its ancestors. When the remote advances mid-run the push want-walk
/// crosses that boundary and `build_pack` errors on the missing parent. Full
/// history fetches (no `depth`) never hit this.
#[test]
fn test_shallow_boundary_breaks_push_pack_build() {
    let tmp = tempfile::tempdir().unwrap();
    let repo = TestRepo::init(&tmp);

    // Normal local history.
    let b = repo.commit("b.txt", "b\n", vec![]);
    let a = repo.commit("a.txt", "a\n", vec![b]);

    // Simulate the shallow fetch: a tip whose parent was never fetched (the
    // depth-1 boundary). `f321ac84...` is the real parent that was missing in
    // the 2026-08-03 push.
    let missing_parent = ObjectId::from_hex("f321ac84b7cb0c1e688bb1a6415d0bf73d767d1d").unwrap();
    let shallow_tip = repo.commit("tip.txt", "tip\n", vec![missing_parent]);

    // The commit sigmacatch actually pushes.
    let c = repo.commit("c.txt", "c\n", vec![shallow_tip]);

    // Remote haves do not cover the missing parent.
    let err = repo.build_pack(&[c], &[a]).unwrap_err();
    assert!(
        format!("{err:#}").contains("f321ac84b7cb0c1e688bb1a6415d0bf73d767d1d"),
        "expected a missing-parent error, got: {err:#}"
    );
}

/// The same push with a full history (every ancestor present) always builds a
/// valid pack.
#[test]
fn test_full_history_push_pack_build_succeeds() {
    let tmp = tempfile::tempdir().unwrap();
    let repo = TestRepo::init(&tmp);

    let b = repo.commit("b.txt", "b\n", vec![]);
    let a = repo.commit("a.txt", "a\n", vec![b]);
    let tip = repo.commit("tip.txt", "tip\n", vec![a]);
    let c = repo.commit("c.txt", "c\n", vec![tip]);

    let pack = repo.build_pack(&[c], &[a]).unwrap();
    assert!(pack.starts_with(b"PACK"));
    assert!(pack.len() > 32);
}
