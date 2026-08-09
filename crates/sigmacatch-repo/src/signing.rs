// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 sigmacatch contributors

//! SSH commit signing in pure Rust (no external `ssh`/`ssh-keygen` binary).
//!
//! The `ssh-key` crate implements OpenSSH's `sshsig` (PROTOCOL.sshsig), the
//! exact format `ssh-keygen -Y sign -n git -f <key>` produces. Git stores that
//! armored signature in the commit's `gpgsig` header and GitHub verifies it —
//! so a commit signed here carries the same "Verified" badge as one signed by
//! git itself.

use anyhow::{Context, Result};
use ssh_key::{HashAlg, LineEnding, PrivateKey, SshSig};
use std::path::Path;

/// Namespace git uses when signing objects (`ssh-keygen -Y sign -n git`).
const GIT_SIGNING_NAMESPACE: &str = "git";

/// Hash algorithm git uses for SSH commit signatures (SHA-512).
const GIT_SIGNING_HASH: HashAlg = HashAlg::Sha512;

/// Header git writes the signature into (SHA-1 object format).
const GPG_SIG_HEADER: &str = "gpgsig";

/// Sign `payload` with the ed25519 OpenSSH private key at `key_path`,
/// returning the armored SSH signature blob (PEM, LF line endings, trailing
/// newline) — exactly what `ssh-keygen -Y sign` would write to its `.sig`
/// file.
pub fn sign_commit(payload: &[u8], key_path: &Path) -> Result<Vec<u8>> {
    let private_key = PrivateKey::read_openssh_file(key_path)
        .with_context(|| format!("Failed to load signing key {:?}", key_path))?;
    let sig: SshSig = private_key
        .sign(GIT_SIGNING_NAMESPACE, GIT_SIGNING_HASH, payload)
        .context("Failed to sign commit")?;
    let pem = sig
        .to_pem(LineEnding::LF)
        .context("Failed to serialize SSH signature")?;
    Ok(pem.into_bytes())
}

/// Take a raw commit object (`tree/parent/author/committer` headers, blank
/// line, message) and return the same object with the `gpgsig` header inserted
/// between the last header line and the blank line.
///
/// Mirrors git's `add_header_signature`: the signature is computed over the
/// commit *without* the `gpgsig` header (the caller passes those exact bytes),
/// then each armored signature line is folded into the header block with a
/// single leading space, exactly as git/git log expects.
pub fn insert_signature(raw: Vec<u8>, key_path: &Path) -> Result<Vec<u8>> {
    let armored = sign_commit(&raw, key_path)?;

    // Find the blank line separating headers from the message (first "\n\n"),
    // and insert the header right before it — i.e. between the newline ending
    // the committer line and the blank line's second newline.
    let inspos = raw
        .windows(2)
        .position(|w| w == b"\n\n")
        .map(|p| p + 1)
        .unwrap_or(raw.len());

    let armored_str = String::from_utf8(armored).context("SSH signature is not valid UTF-8")?;
    let mut lines: Vec<&str> = armored_str.split('\n').collect();
    if lines.last() == Some(&"") {
        lines.pop();
    }

    let mut out = Vec::with_capacity(raw.len() + armored_str.len() + GPG_SIG_HEADER.len() + 8);
    out.extend_from_slice(&raw[..inspos]);
    for (i, line) in lines.iter().enumerate() {
        if i == 0 {
            out.extend_from_slice(GPG_SIG_HEADER.as_bytes());
            out.push(b' ');
        } else {
            out.push(b' ');
        }
        out.extend_from_slice(line.as_bytes());
        out.push(b'\n');
    }
    out.extend_from_slice(&raw[inspos..]);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ssh_key::PublicKey;

    /// Private key from ssh-key's own docs; its public key:
    /// `ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAILM+rvN+ot98qgEN796jTiQfZfG1KaT0PtFDJ/XFSqti`
    const TEST_KEY: &str = r#"-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACCzPq7zfqLffKoBDe/eo04kH2XxtSmk9D7RQyf1xUqrYgAAAJgAIAxdACAM
XQAAAAtzc2gtZWQyNTUxOQAAACCzPq7zfqLffKoBDe/eo04kH2XxtSmk9D7RQyf1xUqrYg
AAAEC2BsIi0QwW2uFscKTUUXNHLsYX4FxlaSDSblbAj7WR7bM+rvN+ot98qgEN796jTiQf
ZfG1KaT0PtFDJ/XFSqtiAAAAEHVzZXJAZXhhbXBsZS5jb20BAgMEBQ==
-----END OPENSSH PRIVATE KEY-----
"#;

    fn write_test_key(dir: &std::path::Path) -> std::path::PathBuf {
        let path = dir.join("id_ed25519");
        std::fs::write(&path, TEST_KEY).unwrap();
        path
    }

    /// The produced signature must verify against the matching public key
    /// (`PrivateKey::sign` output is an SshSig over the exact payload).
    #[test]
    fn test_signature_verifies_with_public_key() {
        let tmp = tempfile::tempdir().unwrap();
        let key = write_test_key(tmp.path());
        let payload = b"tree 4b825dc642cb6eb9a060e54bf8d69288fbee4904\nparent abcd\n";

        let armored = sign_commit(payload, &key).unwrap();
        let sig: SshSig = std::str::from_utf8(&armored).unwrap().parse().unwrap();

        let private_key = PrivateKey::read_openssh_file(&key).unwrap();
        let public_key = private_key.public_key();
        assert!(PublicKey::verify(public_key, "git", payload, &sig).is_ok());
    }

    /// The armored blob must look exactly like `ssh-keygen -Y sign` output.
    #[test]
    fn test_signature_is_armored_ssh_signature() {
        let tmp = tempfile::tempdir().unwrap();
        let key = write_test_key(tmp.path());
        let armored = sign_commit(b"payload", &key).unwrap();
        let text = String::from_utf8(armored).unwrap();
        assert!(
            text.starts_with("-----BEGIN SSH SIGNATURE-----\n"),
            "must be SSH-signature armor, got: {text:?}"
        );
        assert!(
            text.ends_with("-----END SSH SIGNATURE-----\n"),
            "armor must end with the END marker, got: {text:?}"
        );
    }

    /// `insert_signature` must fold the armor into a `gpgsig` header block
    /// exactly between the last header line and the blank line, leaving the
    /// message untouched.
    #[test]
    fn test_insert_signature_layout() {
        let tmp = tempfile::tempdir().unwrap();
        let key = write_test_key(tmp.path());
        let raw = b"tree abc123\nparent def456\nauthor t <t@example.com> 0 +0000\ncommitter t <t@example.com> 0 +0000\n\nmessage\n";

        let signed = insert_signature(raw.to_vec(), &key).unwrap();
        let text = String::from_utf8(signed).unwrap();
        assert!(
            text.starts_with(
                "tree abc123\nparent def456\nauthor t <t@example.com> 0 +0000\ncommitter t <t@example.com> 0 +0000\ngpgsig -----BEGIN SSH SIGNATURE-----\n"
            ),
            "header must follow the committer line: {text:?}"
        );
        assert!(
            text.contains("\n -----END SSH SIGNATURE-----\n\nmessage\n"),
            "continuation lines must be space-indented and message preserved: {text:?}"
        );
    }

    /// Every continuation line must be indented with a single space (git's
    /// convention), and no line may be indented with two spaces.
    #[test]
    fn test_insert_signature_continuation_indentation() {
        let tmp = tempfile::tempdir().unwrap();
        let key = write_test_key(tmp.path());
        let raw = b"tree abc\n\nmsg\n";
        let signed = insert_signature(raw.to_vec(), &key).unwrap();
        let text = String::from_utf8(signed).unwrap();

        let lines: Vec<&str> = text.split('\n').collect();
        let header_start = lines.iter().position(|l| l.starts_with("gpgsig ")).unwrap();
        let mut prev_indented = true;
        for line in &lines[header_start + 1..] {
            if line.starts_with(' ') {
                assert!(
                    !line.starts_with("  "),
                    "continuation must have exactly one space: {line:?}"
                );
                prev_indented = true;
            } else {
                assert!(
                    line.is_empty(),
                    "unindented non-blank line must not appear inside the header: {line:?}"
                );
                break;
            }
        }
        assert!(prev_indented, "continuation lines must be present");
    }
}
