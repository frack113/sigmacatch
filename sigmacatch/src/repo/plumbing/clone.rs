// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 sigmacatch contributors

//! Full clone: init + fetch + set HEAD + checkout worktree.

use crate::repo::{RepoError, Result};
use grit_lib::transport::http::HttpClient;
use std::path::{Path, PathBuf};
use std::process::Command;
use tracing::{info, warn};

use crate::repo::plumbing::checkout::checkout_main_branch;
use crate::repo::plumbing::fetch::{
    fetch_options_for_branches, fetch_options_for_shallow_clone, fetch_remote,
};
use crate::repo::plumbing::init::init_repo;
use crate::repo::plumbing::refs::set_head_after_fetch;

/// Default branches fetched on clone. Sigmacatch only ever uses the default
/// branch; `main` is the alternative in case `master` is not the default.
const DEFAULT_BRANCHES: &[&str] = &["master", "main"];

/// Default HTTP timeout for clone operations (seconds).
const DEFAULT_HTTP_TIMEOUT: u64 = 120;

/// Full clone: init + fetch + set HEAD + checkout worktree.
pub fn clone_repo(http_client: &dyn HttpClient, url: &str, dest: &Path) -> Result<()> {
    clone_repo_inner(
        http_client,
        url,
        dest,
        false,
        false,
        false,
        DEFAULT_HTTP_TIMEOUT,
    )
}

/// Shallow clone with optional sparse checkout.
pub fn clone_repo_shallow(
    http_client: &dyn HttpClient,
    url: &str,
    dest: &Path,
    sparse_checkout: bool,
) -> Result<()> {
    clone_repo_inner(
        http_client,
        url,
        dest,
        true,
        sparse_checkout,
        false,
        DEFAULT_HTTP_TIMEOUT,
    )
}

/// Partial clone with blobless filter (--filter=blob:none) + shallow depth=1.
/// Uses `git` CLI for initial clone since grit-lib doesn't yet support --filter.
pub fn clone_repo_partial(
    http_client: &dyn HttpClient,
    url: &str,
    dest: &Path,
    sparse_checkout: bool,
) -> Result<()> {
    clone_repo_inner(
        http_client,
        url,
        dest,
        true,
        sparse_checkout,
        true,
        DEFAULT_HTTP_TIMEOUT,
    )
}

fn clone_repo_inner(
    http_client: &dyn HttpClient,
    url: &str,
    dest: &Path,
    shallow: bool,
    sparse_checkout: bool,
    partial_clone: bool,
    http_timeout: u64,
) -> Result<()> {
    let git_dir = dest.join(".git");
    if git_dir.exists() {
        info!("Repository already exists at {:?}, skipping clone", dest);
        return Ok(());
    }

    info!(
        "Cloning into {:?} (shallow={}, sparse={}, partial={})",
        dest, shallow, sparse_checkout, partial_clone
    );

    if partial_clone {
        // Use git CLI for partial clone with --filter=blob:none --depth=1
        // grit-lib doesn't yet support --filter in FetchOptions
        clone_via_git_cli(
            http_client,
            url,
            dest,
            shallow,
            sparse_checkout,
            http_timeout,
        )?;
    } else {
        let git_dir = dest.join(".git");
        init_repo(&git_dir, dest, url)?;

        // Configure sparse checkout before fetch if requested
        if sparse_checkout {
            setup_sparse_checkout(&git_dir)?;
        }

        let opts = if shallow {
            fetch_options_for_shallow_clone(DEFAULT_BRANCHES)
        } else {
            fetch_options_for_branches(DEFAULT_BRANCHES)
        };
        let (count, default_branch) = match fetch_remote(http_client, &git_dir, url, &opts) {
            Ok(r) => r,
            Err(e) => {
                let _ = std::fs::remove_dir_all(&git_dir);
                return Err(e);
            }
        };
        if count == 0 {
            let _ = std::fs::remove_dir_all(&git_dir);
            return Err(RepoError::State(
                "No refs fetched from remote — empty or unreachable repository".to_string(),
            ));
        }

        set_head_after_fetch(&git_dir, default_branch.as_deref());

        checkout_main_branch(&git_dir, dest)?;

        crate::repo::plumbing::pack_loose_objects(&git_dir)?;
    }

    Ok(())
}

/// Clone using `git` CLI with --filter=blob:none --depth=1 for partial clone.
/// Falls back to shallow clone via grit-lib if git CLI is not available.
fn clone_via_git_cli(
    http_client: &dyn HttpClient,
    url: &str,
    dest: &Path,
    shallow: bool,
    sparse_checkout: bool,
    _http_timeout: u64,
) -> Result<()> {
    // Try to find git executable
    let Some(git_exe) = find_git_executable() else {
        warn!("git executable not found in PATH, falling back to shallow clone via grit-lib");
        return clone_repo_inner_impl(http_client, url, dest, true, false);
    };

    let mut cmd = Command::new(git_exe);
    cmd.arg("clone");
    cmd.arg("--filter=blob:none");
    if shallow {
        cmd.arg("--depth=1");
    }
    cmd.arg("--single-branch");
    cmd.arg("--branch=master");
    cmd.arg(url);
    cmd.arg(dest);

    info!(
        "Cloning via git CLI: {}",
        cmd.get_args()
            .map(|s| s.to_string_lossy())
            .collect::<Vec<_>>()
            .join(" ")
    );

    let output = cmd.output().map_err(RepoError::Io)?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        warn!(
            "git clone failed, falling back to shallow clone: {}",
            stderr.trim()
        );
        let _ = std::fs::remove_dir_all(dest);
        return clone_repo_inner_impl(http_client, url, dest, true, false);
    }

    // Configure sparse checkout if requested
    if sparse_checkout {
        let git_dir = dest.join(".git");
        setup_sparse_checkout(&git_dir)?;

        // Need to re-checkout to apply sparse patterns
        let git_dir = dest.join(".git");
        checkout_main_branch(&git_dir, dest)?;
    }

    // Pack loose objects for performance
    let git_dir = dest.join(".git");
    crate::repo::plumbing::pack_loose_objects(&git_dir)?;

    Ok(())
}

/// Find git executable in common Windows locations
fn find_git_executable() -> Option<PathBuf> {
    // Check common locations
    let candidates = vec![
        PathBuf::from(r"C:\Program Files\Git\bin\git.exe"),
        PathBuf::from(r"C:\Program Files (x86)\Git\bin\git.exe"),
        PathBuf::from(r"C:\Windows\System32\OpenSSH\git.exe"),
    ];

    for candidate in candidates {
        if candidate.exists() {
            return Some(candidate);
        }
    }

    // Try PATH
    if let Ok(output) = Command::new("where").arg("git").output()
        && output.status.success()
        && let Some(exe) = first_executable_path(&output.stdout)
    {
        return Some(exe);
    }

    None
}

/// Extract the first usable path from `where git` output.
///
/// `where` prints one path per line, so the contract is: return the first
/// non-empty trimmed line, or `None` when there is none. Returning `None` is
/// what lets the caller fall back to the grit-lib path; returning an empty path
/// would instead fail opaquely inside `Command::new`. The invariant is pinned by
/// the `first_executable_path_*` tests below.
fn first_executable_path(stdout: &[u8]) -> Option<PathBuf> {
    String::from_utf8_lossy(stdout)
        .lines()
        .map(str::trim)
        .find(|line| !line.is_empty())
        .map(PathBuf::from)
}

/// Internal implementation shared by both clone paths
fn clone_repo_inner_impl(
    http_client: &dyn HttpClient,
    url: &str,
    dest: &Path,
    shallow: bool,
    sparse_checkout: bool,
) -> Result<()> {
    let git_dir = dest.join(".git");
    if git_dir.exists() {
        info!("Repository already exists at {:?}, skipping clone", dest);
        return Ok(());
    }

    info!(
        "Cloning into {:?} (shallow={}, sparse={})",
        dest, shallow, sparse_checkout
    );
    init_repo(&git_dir, dest, url)?;

    // Configure sparse checkout before fetch if requested
    if sparse_checkout {
        setup_sparse_checkout(&git_dir)?;
    }

    let opts = if shallow {
        fetch_options_for_shallow_clone(DEFAULT_BRANCHES)
    } else {
        fetch_options_for_branches(DEFAULT_BRANCHES)
    };
    let (count, default_branch) = match fetch_remote(http_client, &git_dir, url, &opts) {
        Ok(r) => r,
        Err(e) => {
            let _ = std::fs::remove_dir_all(dest);
            return Err(e);
        }
    };
    if count == 0 {
        let _ = std::fs::remove_dir_all(&git_dir);
        return Err(RepoError::State(
            "No refs fetched from remote — empty or unreachable repository".to_string(),
        ));
    }

    set_head_after_fetch(&git_dir, default_branch.as_deref());

    checkout_main_branch(&git_dir, dest)?;

    crate::repo::plumbing::pack_loose_objects(&git_dir)?;

    Ok(())
}

/// Set up cone-mode sparse checkout for rules/, rules-emerging-threats/, regression_data/
pub(crate) fn setup_sparse_checkout(git_dir: &Path) -> Result<()> {
    use grit_lib::sparse_checkout::build_expanded_cone_sparse_checkout_lines;

    let dirs = vec![
        "rules".to_string(),
        "rules-emerging-threats".to_string(),
        "regression_data".to_string(),
    ];
    let lines = build_expanded_cone_sparse_checkout_lines(&dirs);

    let sparse_dir = git_dir.join("info");
    std::fs::create_dir_all(&sparse_dir)?;
    let sparse_file = sparse_dir.join("sparse-checkout");
    std::fs::write(&sparse_file, lines.join("\n"))?;

    // Enable sparse checkout in config
    let config_file = git_dir.join("config");
    let mut config = if config_file.exists() {
        std::fs::read_to_string(&config_file)?
    } else {
        String::new()
    };
    if !config.contains("core.sparseCheckout") {
        config.push_str("\n[core]\n");
        config.push_str("    sparseCheckout = true\n");
        config.push_str("    sparseCheckoutCone = true\n");
        std::fs::write(&config_file, config)?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

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

    /// A pre-existing `.git` short-circuits the clone without touching the remote.
    #[test]
    fn clone_repo_skips_when_git_dir_exists() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(tmp.path().join(".git")).unwrap();

        clone_repo(&FailClient, "https://example.com/sigma.git", tmp.path()).unwrap();
    }

    /// A failed fetch must remove the half-initialized `.git` so the next run
    /// starts clean instead of hitting the "already exists" short-circuit.
    #[test]
    fn clone_repo_cleans_up_on_fetch_error() {
        let tmp = tempfile::tempdir().unwrap();
        let dest = tmp.path();
        let git_dir = dest.join(".git");

        let err = clone_repo(&FailClient, "https://example.com/sigma.git", dest)
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("no network in tests"),
            "unexpected error: {err}"
        );
        assert!(
            !git_dir.exists(),
            "half-initialized .git must be removed after a failed fetch"
        );
    }

    /// `where git` can print several paths; the first usable one wins.
    #[test]
    fn first_executable_path_takes_first_non_empty_line() {
        let out = b"C:\\Program Files\\Git\\bin\\git.exe\r\nC:\\other\\git.exe\r\n";
        assert_eq!(
            first_executable_path(out),
            Some(PathBuf::from(r"C:\Program Files\Git\bin\git.exe"))
        );
    }

    /// A leading blank line must not yield an empty path: `Command::new("")`
    /// would fail opaquely instead of letting the caller fall back.
    #[test]
    fn first_executable_path_skips_leading_blank_lines() {
        let out = b"\r\n   \r\nC:\\Program Files\\Git\\bin\\git.exe\r\n";
        assert_eq!(
            first_executable_path(out),
            Some(PathBuf::from(r"C:\Program Files\Git\bin\git.exe"))
        );
    }

    /// Blank output means "git not found" — the caller must be able to fall
    /// back, so this must stay `None` rather than an empty path.
    #[test]
    fn first_executable_path_returns_none_when_blank() {
        assert_eq!(first_executable_path(b""), None);
        assert_eq!(first_executable_path(b"\r\n \r\n"), None);
    }
}
