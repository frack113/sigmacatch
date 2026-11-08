// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 sigmacatch contributors

//! Transport layer: SSH with key-based auth only.
//!
//! Sigmacatch never handles GitHub credentials. Clone, fetch and push all go
//! through the system `ssh` binary (SSH agent, or `git.ssh_key_path` wired via
//! `~/.ssh/config`), so there is no token to configure, store or leak.

use tracing::{debug, info};

/// Hide credentials embedded in a URL before logging it.
pub(crate) fn sanitize_url(url: &str) -> String {
    if let Some(at_pos) = url.find('@')
        && let Some(scheme_end) = url[..at_pos].find("://")
    {
        let prefix = &url[..scheme_end + 3];
        return format!("{}<redacted>@{}", prefix, &url[at_pos + 1..]);
    }
    url.to_string()
}

/// Convert an HTTPS GitHub URL to SSH format.
/// e.g. `https://github.com/user/repo.git` → `git@github.com:user/repo.git`
///
/// Kept for repositories cloned before the SSH-only switch: their `.git/config`
/// still carries an HTTPS `origin`, and every transport path converts it on
/// read. Returns `None` if the URL is not a valid GitHub HTTPS URL, contains
/// path traversal, or contains characters that would allow SSH command
/// injection.
pub fn https_to_ssh_url(url: &str) -> Option<String> {
    let rest = url.strip_prefix("https://github.com/")?;
    if rest.contains("..") || rest.contains([' ', '\t', '\n', '\r']) {
        return None;
    }
    // Allow one or two '/' for user/repo or org/subgroup/repo patterns
    let slash_count = rest.split('/').count() - 1;
    if !(1..=2).contains(&slash_count) {
        return None;
    }
    let repo = rest.strip_suffix(".git").unwrap_or(rest);
    // Reject if the repo name contains shell-special characters
    if repo.chars().any(|c| {
        [
            '\'', '"', '$', '`', '\\', '!', '&', '|', ';', '(', ')', '{', '}', '[', ']', '<', '>',
            '#',
        ]
        .contains(&c)
    }) {
        return None;
    }
    Some(format!("git@github.com:{}.git", repo))
}

/// How the caller should construct the SSH transport.
/// Direct exec only — no shell dependency. Host-key verification is disabled
/// via `~/.ssh/config` written by `ensure_ssh_host_config`.
#[derive(Clone, Debug)]
pub(crate) enum SshMode {
    /// Direct `ssh` binary execution.
    Program(#[allow(dead_code)] Vec<std::ffi::OsString>),
}

/// Build the SSH transport mode from environment and optional SSH key path.
/// Direct exec (`Program`) everywhere — the key is wired via `~/.ssh/config`
/// (`ensure_ssh_host_config`). `GIT_SSH_COMMAND` is unsupported (required `sh -c`).
pub(crate) fn build_ssh_shell_command(_ssh_key_path: Option<&str>) -> SshMode {
    if let Ok(cmd) = std::env::var("GIT_SSH")
        && !cmd.is_empty()
    {
        debug!("Using GIT_SSH from environment");
        return SshMode::Program(vec![cmd.into()]);
    }
    if let Ok(cmd) = std::env::var("GIT_SSH_COMMAND")
        && !cmd.is_empty()
    {
        debug!("Ignoring GIT_SSH_COMMAND (shell command lines not supported)");
    }
    // Direct binary execution — no OS-resolving dependency. The `ssh` binary is
    // provided by the runtime environment: OpenSSH on Linux/macOS, the Windows
    // OpenSSH client (shipped since Windows 10) or Git for Windows on Windows.
    SshMode::Program(vec![std::ffi::OsString::from("ssh")])
}

/// Ensure `~/.ssh/config` disables host-key verification and points to the
/// SSH private key.
///
/// `ssh.exe` on Windows prompts for host-key confirmation by default when the
/// host is not in `known_hosts`. In a headless / CI context this prompt blocks
/// the process. Writing a `~/.ssh/config` with `StrictHostKeyChecking no`
/// suppresses the prompt without requiring a POSIX shell (unlike
/// `GIT_SSH_COMMAND`).
///
/// On Windows, `UserKnownHostsFile` is set to `NUL` (not `/dev/null`) so that
/// the known-hosts file is discarded without causing a permission error.
///
/// The function is idempotent: if the config already contains the required
/// directives it returns `Ok(())` immediately.
pub fn ensure_ssh_host_config(ssh_key_path: Option<&str>) -> crate::repo::Result<()> {
    let home = std::env::var("USERPROFILE")
        .or_else(|_| std::env::var("HOME"))
        .unwrap_or_default();
    let ssh_dir = std::path::Path::new(&home).join(".ssh");
    let config_path = ssh_dir.join("config");

    let known_hosts_directive = if cfg!(windows) {
        "UserKnownHostsFile NUL"
    } else {
        "UserKnownHostsFile /dev/null"
    };

    if config_path.exists() {
        let content = std::fs::read_to_string(&config_path)?;
        if content.contains("StrictHostKeyChecking no") && content.contains(known_hosts_directive) {
            // If a key was previously configured, keep it; otherwise the caller
            // needs a fresh write below.
            if let Some(key) = ssh_key_path {
                if content.contains(&format!("IdentityFile {}", key)) {
                    return Ok(());
                }
            } else if !content.contains("IdentityFile") {
                return Ok(());
            }
        }
    }

    std::fs::create_dir_all(&ssh_dir)?;
    let mut content = String::new();
    if config_path.exists() {
        content = std::fs::read_to_string(&config_path)?;
        if !content.ends_with('\n') {
            content.push('\n');
        }
    }
    content.push_str("Host *\n");
    content.push_str("    StrictHostKeyChecking no\n");
    content.push_str(&format!("    {known_hosts_directive}\n"));
    if let Some(key) = ssh_key_path {
        content.push_str(&format!("    IdentityFile {key}\n"));
    }
    let tmp_path = ssh_dir.join("config.tmp");
    std::fs::write(&tmp_path, &content)?;
    std::fs::rename(&tmp_path, &config_path)?;
    let key_suffix = if let Some(key) = ssh_key_path {
        format!(", IdentityFile {key}")
    } else {
        String::new()
    };
    info!(
        "Wrote SSH host-config to {:?} (StrictHostKeyChecking no, {}{})",
        config_path, known_hosts_directive, key_suffix
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sanitize_url_with_at() {
        let url = "https://user:token@github.com/foo/bar.git";
        let result = sanitize_url(url);
        assert_eq!(result, "https://<redacted>@github.com/foo/bar.git");
    }

    #[test]
    fn test_sanitize_url_without_at() {
        let url = "https://github.com/foo/bar.git";
        let result = sanitize_url(url);
        assert_eq!(result, url);
    }

    #[test]
    fn test_sanitize_url_empty() {
        let result = sanitize_url("");
        assert_eq!(result, "");
    }

    #[test]
    fn test_https_to_ssh_url_accepts_user_repo() {
        assert_eq!(
            https_to_ssh_url("https://github.com/user/repo.git").as_deref(),
            Some("git@github.com:user/repo.git")
        );
        // The `.git` suffix is normalized away and re-added.
        assert_eq!(
            https_to_ssh_url("https://github.com/user/repo").as_deref(),
            Some("git@github.com:user/repo.git")
        );
    }

    #[test]
    fn test_https_to_ssh_url_accepts_subgroup() {
        assert_eq!(
            https_to_ssh_url("https://github.com/org/subgroup/repo.git").as_deref(),
            Some("git@github.com:org/subgroup/repo.git")
        );
    }

    #[test]
    fn test_https_to_ssh_url_rejects_non_github() {
        assert_eq!(https_to_ssh_url("https://gitlab.com/user/repo.git"), None);
        assert_eq!(https_to_ssh_url("http://github.com/user/repo.git"), None);
        assert_eq!(https_to_ssh_url("github.com/user/repo.git"), None);
    }

    #[test]
    fn test_https_to_ssh_url_rejects_bad_slash_counts() {
        // 0 slashes: not user/repo
        assert_eq!(https_to_ssh_url("https://github.com/repo"), None);
        // 3+ slashes: deeper nesting is not a valid repo path
        assert_eq!(https_to_ssh_url("https://github.com/a/b/c/d"), None);
    }

    #[test]
    fn test_https_to_ssh_url_rejects_traversal_and_whitespace() {
        assert_eq!(https_to_ssh_url("https://github.com/user/../etc"), None);
        assert_eq!(https_to_ssh_url("https://github.com/user/re po.git"), None);
        assert_eq!(https_to_ssh_url("https://github.com/user/repo\t.git"), None);
        assert_eq!(
            https_to_ssh_url("https://github.com/user/repo\r\n.git"),
            None
        );
    }

    #[test]
    fn test_https_to_ssh_url_rejects_shell_metacharacters() {
        for ch in ['\'', '"', '$', '`', '\\', '!', '&', '|', ';', '(', ')', '#'] {
            let url = format!("https://github.com/user/re{ch}po.git");
            assert_eq!(
                https_to_ssh_url(&url),
                None,
                "must reject {ch:?} in {url:?}"
            );
        }
    }

    // Shared with the porcelain tests: Rust test threads share one environment,
    // so every test that mutates `GIT_SSH`/`HOME` takes this lock.
    use crate::repo::tests::ENV_LOCK;

    #[test]
    fn test_build_ssh_shell_command_unix_is_program() {
        let _guard = ENV_LOCK.lock().unwrap();
        unsafe {
            std::env::remove_var("GIT_SSH");
            std::env::remove_var("GIT_SSH_COMMAND");
        }
        let mode = build_ssh_shell_command(None);
        assert!(
            matches!(mode, SshMode::Program(_)),
            "Unix must use direct Program, not sh -c: {mode:?}"
        );
    }

    #[test]
    fn test_build_ssh_shell_command_git_ssh_override() {
        let _guard = ENV_LOCK.lock().unwrap();
        unsafe {
            std::env::set_var("GIT_SSH", "/usr/bin/fake-ssh");
        }
        let mode = build_ssh_shell_command(Some("/some/key"));
        match &mode {
            SshMode::Program(args) => {
                assert_eq!(args, &vec![std::ffi::OsString::from("/usr/bin/fake-ssh")]);
            }
        }
        unsafe { std::env::remove_var("GIT_SSH") };
    }

    #[test]
    fn test_ensure_ssh_host_config_writes_and_is_idempotent() {
        let _guard = ENV_LOCK.lock().unwrap();
        let tmp = tempfile::tempdir().unwrap();
        unsafe {
            std::env::set_var("USERPROFILE", tmp.path());
            std::env::set_var("HOME", tmp.path());
        }

        let config = tmp.path().join(".ssh").join("config");
        ensure_ssh_host_config(None).unwrap();
        assert!(config.exists(), "fresh home must gain a .ssh/config");
        let first = std::fs::read_to_string(&config).unwrap();
        assert!(first.contains("StrictHostKeyChecking no"), "got:\n{first}");
        #[cfg(not(windows))]
        assert!(
            first.contains("UserKnownHostsFile /dev/null"),
            "got:\n{first}"
        );
        #[cfg(windows)]
        assert!(first.contains("UserKnownHostsFile NUL"), "got:\n{first}");

        // Idempotent: a second call with the same arguments rewrites nothing.
        ensure_ssh_host_config(None).unwrap();
        assert_eq!(
            std::fs::read_to_string(&config).unwrap(),
            first,
            "idempotent call must not rewrite the config"
        );

        // A new key path forces a rewrite that carries the IdentityFile.
        let key = tmp.path().join("id_ed25519");
        std::fs::write(&key, b"key").unwrap();
        ensure_ssh_host_config(Some(key.to_str().unwrap())).unwrap();
        let with_key = std::fs::read_to_string(&config).unwrap();
        assert!(
            with_key.contains(&format!("IdentityFile {}", key.display())),
            "got:\n{with_key}"
        );
        // And now that call is idempotent too.
        ensure_ssh_host_config(Some(key.to_str().unwrap())).unwrap();
        assert_eq!(std::fs::read_to_string(&config).unwrap(), with_key);
    }

    #[test]
    fn test_ensure_ssh_host_config_preserves_existing_content() {
        let _guard = ENV_LOCK.lock().unwrap();
        let tmp = tempfile::tempdir().unwrap();
        unsafe {
            std::env::set_var("USERPROFILE", tmp.path());
            std::env::set_var("HOME", tmp.path());
        }

        let ssh_dir = tmp.path().join(".ssh");
        std::fs::create_dir_all(&ssh_dir).unwrap();
        let config = ssh_dir.join("config");
        // A pre-existing config without the required directives must be
        // preserved (appended to), not clobbered.
        std::fs::write(&config, "Host github.com\n    Port 22\n").unwrap();
        ensure_ssh_host_config(None).unwrap();
        let content = std::fs::read_to_string(&config).unwrap();
        assert!(
            content.starts_with("Host github.com\n    Port 22"),
            "got:\n{content}"
        );
        assert!(
            content.contains("StrictHostKeyChecking no"),
            "got:\n{content}"
        );
    }
}
