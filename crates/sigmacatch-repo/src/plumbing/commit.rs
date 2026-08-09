// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 sigmacatch contributors

//! Commit object creation.

use anyhow::Result;
use grit_lib::objects::{ObjectId, ObjectKind};
use grit_lib::odb::Odb;
use grit_lib::refs;
use std::path::Path;
use tracing::info;

use crate::plumbing::refs::{map_grit, resolve_head, symbolic_ref_target};

/// Write a new commit object pointing at `tree_oid` with HEAD as its parent,
/// then advance the ref currently pointed to by HEAD (or detach HEAD if it is
/// detached). Uses grit-lib's `refs` module for ref/HEAD writes.
///
/// When `signing_key` is `Some`, the commit is signed with that ed25519
/// OpenSSH key and the `gpgsig` header is inserted, exactly like
/// `git commit -S` with `gpg.format = ssh`. The signature is computed over the
/// commit bytes *without* the `gpgsig` header (git's convention), so GitHub
/// shows the commit as "Verified". The unsigned path produces byte-identical
/// output to `grit_lib::objects::serialize_commit` (headers, blank line,
/// message).
pub(crate) fn commit_tree(
    git_dir: &Path,
    odb: &Odb,
    tree_oid: ObjectId,
    message: &str,
    author: &str,
    email: &str,
    signing_key: Option<&Path>,
) -> Result<()> {
    let parent_oid = resolve_head(git_dir)?;
    let now = chrono::Utc::now().timestamp();
    let author_line = format!("{} <{}> {} +0000", author, email, now);
    let committer_line = author_line.clone();
    let message = format!("{}\n", message.trim_end_matches('\n'));

    let mut raw = Vec::with_capacity(64 + author_line.len() + committer_line.len() + message.len());
    raw.extend_from_slice(format!("tree {}\n", tree_oid).as_bytes());
    raw.extend_from_slice(format!("parent {}\n", parent_oid).as_bytes());
    raw.extend_from_slice(format!("author {}\n", author_line).as_bytes());
    raw.extend_from_slice(format!("committer {}\n", committer_line).as_bytes());
    raw.push(b'\n');
    raw.extend_from_slice(message.as_bytes());

    let raw = match signing_key {
        Some(key_path) => crate::signing::insert_signature(raw, key_path)?,
        None => raw,
    };

    let commit_oid = odb
        .write(ObjectKind::Commit, &raw)
        .map_err(|e| anyhow::anyhow!("Failed to write commit object: {}", e))?;

    match symbolic_ref_target(git_dir, "HEAD")? {
        Some(ref_name) => {
            map_grit(refs::write_ref(git_dir, &ref_name, &commit_oid))?;
            info!(
                "Committed {} to {}: {}",
                commit_oid,
                ref_name,
                message.trim()
            );
        }
        None => {
            map_grit(refs::write_ref(git_dir, "HEAD", &commit_oid))?;
            info!(
                "Committed {} to detached HEAD: {}",
                commit_oid,
                message.trim()
            );
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::plumbing::{init_repo, open_odb, write_index};
    use grit_lib::objects::{CommitData, ObjectKind};
    use grit_lib::write_tree::write_tree_from_index;
    use std::os::unix::fs::PermissionsExt;
    use std::process::Command;

    /// The test ed25519 OpenSSH private key from the `ssh-key` crate docs.
    const TEST_KEY: &str = r#"-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACCzPq7zfqLffKoBDe/eo04kH2XxtSmk9D7RQyf1xUqrYgAAAJgAIAxdACAM
XQAAAAtzc2gtZWQyNTUxOQAAACCzPq7zfqLffKoBDe/eo04kH2XxtSmk9D7RQyf1xUqrYg
AAAEC2BsIi0QwW2uFscKTUUXNHLsYX4FxlaSDSblbAj7WR7bM+rvN+ot98qgEN796jTiQf
ZfG1KaT0PtFDJ/XFSqtiAAAAEHVzZXJAZXhhbXBsZS5jb20BAgMEBQ==
-----END OPENSSH PRIVATE KEY-----
"#;

    /// Set up a minimal repo with an initial unsigned commit on `main`.
    fn setup_repo(tmp: &std::path::Path) -> (std::path::PathBuf, std::path::PathBuf) {
        let git_dir = tmp.join(".git");
        init_repo(&git_dir, tmp, "https://example.com/sigma.git").unwrap();

        std::fs::write(tmp.join("README.md"), "# test\n").unwrap();
        let odb = open_odb(&git_dir);
        let mut index = grit_lib::index::Index::new();
        crate::plumbing::add_file_to_index(&git_dir, &tmp.join("README.md"), tmp, &mut index)
            .unwrap();
        let tree = write_tree_from_index(&odb, &index, "").unwrap();
        let commit = CommitData {
            tree,
            parents: Vec::new(),
            author: "test <t@example.com> 0 +0000".to_string(),
            committer: "test <t@example.com> 0 +0000".to_string(),
            message: "initial\n".to_string(),
            encoding: None,
            author_raw: Vec::new(),
            committer_raw: Vec::new(),
            raw_message: None,
        };
        let raw = grit_lib::objects::serialize_commit(&commit);
        let commit_oid = odb.write(ObjectKind::Commit, &raw).unwrap();
        // Write the ref so resolve_head works in subsequent commits.
        std::fs::create_dir_all(git_dir.join("refs/heads")).unwrap();
        std::fs::write(git_dir.join("refs/heads/main"), format!("{}\n", commit_oid)).unwrap();
        std::fs::write(git_dir.join("HEAD"), b"ref: refs/heads/main\n").unwrap();

        (git_dir, tmp.to_path_buf())
    }

    /// Write an ed25519 key to `dir/id_ed25519` and its public key to
    /// `dir/allowed_signers`, configure the repo's `gpg.ssh.allowedSignersFile`
    /// and `user.signingkey`, and return the private key path.
    fn write_test_key(git_dir: &std::path::Path, dir: &std::path::Path) -> std::path::PathBuf {
        let path = dir.join("id_ed25519");
        std::fs::write(&path, TEST_KEY).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        let pub_key = Command::new("ssh-keygen")
            .args(["-y", "-f", path.to_str().unwrap()])
            .output()
            .expect("ssh-keygen must be available");
        assert!(
            pub_key.status.success(),
            "ssh-keygen failed: {}",
            String::from_utf8_lossy(&pub_key.stderr)
        );
        let pub_key_str = String::from_utf8(pub_key.stdout).unwrap();
        let allowed = dir.join("allowed_signers");
        std::fs::write(&allowed, pub_key_str).unwrap();
        // Configure git to use SSH signing with this key.
        let mut config = std::fs::read_to_string(git_dir.join("config")).unwrap();
        config.push_str(&format!(
            "\
[gpg]
\tformat = ssh
[user]
\tsigningkey = {}\n\
[gpg \"ssh\"]\
\tallowedSignersFile = {}\n",
            path.to_str().unwrap(),
            allowed.to_str().unwrap()
        ));
        std::fs::write(git_dir.join("config"), config).unwrap();
        path
    }

    /// Run `git cat-file commit HEAD` and return the raw commit object text.
    fn git_cat_file(repo_dir: &std::path::Path) -> String {
        let out = Command::new("git")
            .args(["cat-file", "commit", "HEAD"])
            .current_dir(repo_dir)
            .output()
            .expect("git must be available");
        assert!(
            out.status.success(),
            "git cat-file failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        String::from_utf8(out.stdout).unwrap()
    }

    /// A commit signed with our pure-Rust SSH signing must be accepted by real
    /// git as a "Good SSH signature". This is the ground-truth check: if git
    /// rejects it, the header layout or signed payload is wrong.
    #[test]
    #[ignore = "requires git binary on PATH"]
    fn test_signed_commit_accepted_by_real_git() {
        let tmp = tempfile::tempdir().unwrap();
        let (git_dir, work_tree) = setup_repo(tmp.path());
        let key = write_test_key(&git_dir, tmp.path());

        std::fs::write(work_tree.join("new.txt"), "hello\n").unwrap();
        let mut index = grit_lib::index::Index::new();
        crate::plumbing::add_file_to_index(
            &git_dir,
            &work_tree.join("new.txt"),
            &work_tree,
            &mut index,
        )
        .unwrap();
        write_index(&git_dir, &index).unwrap();

        let odb = open_odb(&git_dir);
        let tree = write_tree_from_index(&odb, &index, "").unwrap();
        commit_tree(
            &git_dir,
            &odb,
            tree,
            "test: signed commit",
            "testuser",
            "test@example.com",
            Some(&key),
        )
        .unwrap();

        // Verify with real git: the commit must have a "Good" SSH signature.
        // Note: exit code may be 1 due to allowedSignersFile warnings, and the
        // verification result goes to stderr, so we check stderr for "Good".
        let out = Command::new("git")
            .args(["verify-commit", "HEAD"])
            .current_dir(&work_tree)
            .output()
            .expect("git must be available");
        let output = String::from_utf8(out.stderr).unwrap();
        assert!(
            output.contains("Good") && output.contains("git") && output.contains("ED25519"),
            "real git must accept the signature, got stderr:\n{}",
            output
        );

        // Also verify the raw object contains the gpgsig header in the right place.
        let cat = git_cat_file(&work_tree);
        assert!(
            cat.contains("gpgsig "),
            "commit object must contain the gpgsig header, got:\n{cat}"
        );
        // The header must appear between the committer line and the blank line.
        let committer_line = "committer testuser <test@example.com> ";
        let committer_idx = cat.find(committer_line).expect("missing committer line");
        let blank_line_idx = cat.find("\n\n").expect("missing blank line");
        let gpgsig_idx = cat.find("gpgsig ").expect("missing gpgsig header");
        assert!(
            gpgsig_idx > committer_idx,
            "gpgsig must appear after the committer line"
        );
        assert!(
            gpgsig_idx < blank_line_idx,
            "gpgsig must appear before the blank line"
        );
    }

    /// The unsigned commit object must be byte-identical to grit's
    /// serialize_commit output (no gpgsig header, same header layout).
    #[test]
    fn test_unsigned_commit_matches_serialize_commit() {
        let tmp = tempfile::tempdir().unwrap();
        let (git_dir, _) = setup_repo(tmp.path());
        let odb = open_odb(&git_dir);

        let mut index = grit_lib::index::Index::new();
        crate::plumbing::add_file_to_index(
            &git_dir,
            &tmp.path().join("README.md"),
            tmp.path(),
            &mut index,
        )
        .unwrap();
        write_index(&git_dir, &index).unwrap();
        let tree = write_tree_from_index(&odb, &index, "").unwrap();

        // Capture grit's output for comparison.
        let parent_oid = resolve_head(&git_dir).unwrap();
        let now = chrono::Utc::now().timestamp();
        let author_line = "testuser <test@example.com> ".to_string() + &now.to_string();
        let commit_data = CommitData {
            tree,
            parents: vec![parent_oid],
            author: author_line.clone(),
            committer: author_line.clone(),
            message: "test: unsigned commit\n".to_string(),
            encoding: None,
            author_raw: Vec::new(),
            committer_raw: Vec::new(),
            raw_message: None,
        };
        let grit_raw = grit_lib::objects::serialize_commit(&commit_data);

        // Build our raw bytes the same way commit_tree does.
        let mut raw = Vec::new();
        raw.extend_from_slice(format!("tree {}\n", tree).as_bytes());
        raw.extend_from_slice(format!("parent {}\n", parent_oid).as_bytes());
        raw.extend_from_slice(format!("author {}\n", author_line).as_bytes());
        raw.extend_from_slice(format!("committer {}\n", author_line).as_bytes());
        raw.push(b'\n');
        raw.extend_from_slice(b"test: unsigned commit\n");

        assert_eq!(
            grit_raw, raw,
            "unsigned commit bytes must match grit's serialize_commit exactly"
        );
    }
}
