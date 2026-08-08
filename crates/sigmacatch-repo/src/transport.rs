// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 sigmacatch contributors

//! Transport layer: HTTPS with token auth (`AuthHttpClient`) and SSH with
//! key-based auth. Also carries the shared URL-sanitization and SSH-command
//! helpers used by the plumbing and porcelain layers.

use anyhow::Result;
use std::sync::Mutex;
use tracing::{debug, info};
use zeroize::Zeroizing;

/// Git transport protocol for clone/fetch/push operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum GitTransport {
    /// HTTPS with token auth (default).
    #[default]
    Http,
    /// SSH with key-based auth.
    Ssh,
}

impl std::fmt::Display for GitTransport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            GitTransport::Http => write!(f, "http"),
            GitTransport::Ssh => write!(f, "ssh"),
        }
    }
}

pub(crate) fn sanitize_url(url: &str) -> String {
    if let Some(at_pos) = url.find('@') {
        if let Some(scheme_end) = url[..at_pos].find("://") {
            let prefix = &url[..scheme_end + 3];
            return format!("{}<redacted>@{}", prefix, &url[at_pos + 1..]);
        }
    }
    url.to_string()
}

/// Convert an HTTPS GitHub URL to SSH format.
/// e.g. `https://github.com/user/repo.git` → `git@github.com:user/repo.git`
///
/// Returns `None` if the URL is not a valid GitHub HTTPS URL, contains path traversal,
/// or contains characters that would allow SSH command injection.
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

/// Resolve the full path to the `ssh` executable, falling back to a bare name.
///
/// This is needed because the process PATH may differ from the user's interactive
/// shell PATH (e.g. when launched by a service or from a non-interactive context).
///
/// On Windows, common locations are checked:
/// - `C:\Windows\System32\OpenSSH\ssh.exe` (Windows OpenSSH client)
/// - `%ProgramFiles%\Git\usr\bin\ssh.exe` (Git for Windows)
///
/// On Unix, `which ssh` is used when available.
/// If none of these resolve, the caller receives `"ssh"` and the OS PATH lookup
/// is attempted (may still fail if PATH is too narrow).
#[cfg(windows)]
fn resolve_ssh_path() -> String {
    // First try the OS resolver (works on both Windows and Unix when PATH is set)
    let mut cmd = std::process::Command::new("which");
    cmd.arg("ssh").stdin(std::process::Stdio::null());
    if let Ok(output) = cmd.output() {
        if output.status.success() {
            let path = String::from_utf8_lossy(&output.stdout).trim().to_string();
            if !path.is_empty() {
                return path;
            }
        }
    }

    // Windows-specific fallbacks
    #[cfg(windows)]
    {
        let program_files =
            std::env::var("ProgramFiles").unwrap_or_else(|_| "C:\\Program Files".to_string());
        let program_files_x86 = std::env::var("ProgramFiles(x86)")
            .unwrap_or_else(|_| "C:\\Program Files (x86)".to_string());
        let candidates: Vec<std::path::PathBuf> = vec![
            std::path::PathBuf::from(r"C:\Windows\System32\OpenSSH\ssh.exe"),
            std::path::PathBuf::from(r"C:\Windows\Sysnative\OpenSSH\ssh.exe"),
            std::path::Path::new(&program_files)
                .join("Git")
                .join("usr")
                .join("bin")
                .join("ssh.exe"),
            std::path::Path::new(&program_files_x86)
                .join("Git")
                .join("usr")
                .join("bin")
                .join("ssh.exe"),
        ]
        .into_iter()
        .filter(|p| p.exists())
        .collect();

        if let Some(path) = candidates.into_iter().next() {
            return path.to_string_lossy().to_string();
        }
    }

    // Nothing resolved — return bare name, hope for the best
    "ssh".to_string()
}

/// How the caller should construct the SSH transport.
#[derive(Clone, Debug)]
pub(crate) enum SshMode {
    /// Use grit-lib's default: resolve from environment (`GIT_SSH_COMMAND`, `GIT_SSH`, `ssh`).
    #[allow(dead_code)]
    Default,
    /// Use `SshCommand::ShellCommand` — runs via `sh -c`. Requires a POSIX shell.
    #[allow(dead_code)]
    ShellCommand(String),
    /// Use `SshCommand::Program` — direct exec, no shell. Works on Windows.
    /// The vector holds the full argv: `["ssh.exe", "-i", "/path/to/key"]`.
    Program(Vec<std::ffi::OsString>),
}

/// Build the SSH transport mode from environment and optional SSH key path.
///
/// Priority: `GIT_SSH` env > resolved `ssh` path from PATH / common locations.
/// Environment variables take precedence so the user can override config at runtime
/// (e.g. for testing different keys or proxies).
///
/// On Unix, returns `ShellCommand("ssh -o StrictHostKeyChecking=no")` so the host-key
/// prompt is skipped in headless mode.
///
/// On Windows, returns `Program([ssh.exe, -i, key_path])`. Host-key verification is
/// disabled by writing `~/.ssh/config` with `StrictHostKeyChecking no` (see
/// `ensure_ssh_host_config`). `GIT_SSH_COMMAND` is unsupported on Windows because
/// grit-lib runs it via `sh -c` which requires a POSIX shell.
pub(crate) fn build_ssh_shell_command(ssh_key_path: Option<&str>) -> SshMode {
    if let Ok(cmd) = std::env::var("GIT_SSH") {
        if !cmd.is_empty() {
            debug!("Using GIT_SSH from environment");
            return SshMode::Program(vec![cmd.into()]);
        }
    }
    if let Ok(cmd) = std::env::var("GIT_SSH_COMMAND") {
        if !cmd.is_empty() {
            debug!(
                "Ignoring GIT_SSH_COMMAND (shell command lines are not supported without sh); \
                 use GIT_SSH or ~/.ssh/config instead"
            );
        }
    }
    #[cfg(windows)]
    {
        let ssh_bin = resolve_ssh_path();
        // SshCommand::Program only accepts the binary path; -i and key path
        // cannot be passed as args. The key is wired via IdentityFile in
        // ~/.ssh/config by ensure_ssh_host_config() instead.
        debug!("Resolved ssh path on Windows: {}", ssh_bin,);
        return SshMode::Program(vec![ssh_bin.into()]);
    }
    #[cfg(not(windows))]
    {
        let mut cmd = "ssh -o StrictHostKeyChecking=no".to_string();
        if let Some(key) = ssh_key_path {
            cmd.push_str(&format!(" -i {}", shell_escape(key)));
        }
        SshMode::ShellCommand(cmd)
    }
}

/// Escape a path for safe inclusion in a shell command string.
#[cfg(not(windows))]
fn shell_escape(s: &str) -> String {
    format!("'{}'", s.replace('\\', "\\\\").replace('\'', "'\\''"))
}

/// HTTP client implementing grit-lib's `HttpClient` trait with GitHub token auth.
pub struct AuthHttpClient {
    client: reqwest::blocking::Client,
    token: Mutex<Option<Zeroizing<String>>>,
}

impl AuthHttpClient {
    pub fn new(token: Option<Zeroizing<String>>) -> Result<Self> {
        let client = reqwest::blocking::Client::builder()
            .user_agent("sigmacatch/0.3.0")
            .timeout(std::time::Duration::from_secs(120))
            .connect_timeout(std::time::Duration::from_secs(30))
            .redirect(reqwest::redirect::Policy::limited(10))
            .build()?;
        Ok(Self {
            client,
            token: Mutex::new(token),
        })
    }

    fn add_auth(&self, url: &str) -> String {
        let token = self.token.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(t) = token.as_deref() {
            if url.starts_with("https://") {
                if let Some(rest) = url.strip_prefix("https://") {
                    return format!("https://x-access-token:{t}@{rest}");
                }
            }
        }
        url.to_string()
    }
}

impl grit_lib::transport::http::HttpClient for AuthHttpClient {
    /// Negotiate git protocol v2 for every HTTP request.
    ///
    /// grit's `http_fetch` passes `client.git_protocol_header()` into the
    /// `info/refs` discovery GET. Without an override it sends `None`, so the
    /// server (GitHub) falls back to a v0/v1 advertisement that enumerates
    /// *every* remote ref — wasteful here, and it defeats the `ref-prefix`
    /// narrowing that the narrow refspecs rely on under v2. Requesting v2
    /// makes grit issue a scoped `command=ls-refs` with `ref-prefix` lines
    /// derived from the refspecs, and use the v2 pack-negotiation path. With
    /// the Sigma repo (very large), this materially cuts clone/fetch time.
    fn git_protocol_header(&self) -> Option<&str> {
        Some("version=2")
    }

    fn get(&self, url: &str, git_protocol: Option<&str>) -> grit_lib::error::Result<Vec<u8>> {
        let auth_url = self.add_auth(url);
        debug!(
            "[HTTP GET] {} (protocol={:?})",
            sanitize_url(&auth_url),
            git_protocol
        );
        let mut req = self.client.get(&auth_url);
        if let Some(proto) = git_protocol {
            req = req.header("Git-Protocol", proto);
        }
        let resp = req
            .send()
            .map_err(|e| grit_lib::error::Error::Message(e.to_string()))?;
        let status = resp.status();
        debug!("[HTTP GET] {} → {}", sanitize_url(&auth_url), status);
        if !status.is_success() {
            return Err(grit_lib::error::Error::Message(format!(
                "HTTP GET {}: {}",
                status, url
            )));
        }
        resp.bytes()
            .map(|b| b.to_vec())
            .map_err(|e| grit_lib::error::Error::Message(e.to_string()))
    }

    fn post(
        &self,
        url: &str,
        content_type: &str,
        accept: &str,
        body: &[u8],
        git_protocol: Option<&str>,
    ) -> grit_lib::error::Result<Vec<u8>> {
        let auth_url = self.add_auth(url);
        debug!(
            "[HTTP POST] {} body={}B content_type={} accept={} protocol={:?}",
            sanitize_url(&auth_url),
            body.len(),
            content_type,
            accept,
            git_protocol
        );
        let mut req = self
            .client
            .post(&auth_url)
            .header("Content-Type", content_type)
            .header("Accept", accept);
        if let Some(proto) = git_protocol {
            req = req.header("Git-Protocol", proto);
        }
        let resp = req
            .body(body.to_vec())
            .send()
            .map_err(|e| grit_lib::error::Error::Message(e.to_string()))?;
        let status = resp.status();
        debug!("[HTTP POST] {} → {}", sanitize_url(&auth_url), status);
        if !status.is_success() {
            return Err(grit_lib::error::Error::Message(format!(
                "HTTP POST {}: {}",
                status, url
            )));
        }
        resp.bytes()
            .map(|b| b.to_vec())
            .map_err(|e| grit_lib::error::Error::Message(e.to_string()))
    }
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
pub fn ensure_ssh_host_config(ssh_key_path: Option<&str>) -> Result<()> {
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
    std::fs::write(&config_path, content)?;
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
    use grit_lib::transport::http::HttpClient;

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

    /// Protocol v2 must be advertised on every HTTP request — without it GitHub
    /// serves a v0/v1 full advertisement, which (a) enumerates every remote ref
    /// and (b) defeats the `ref-prefix` narrowing our narrow refspecs depend on,
    /// making clones of the large Sigma repo needlessly slow.
    #[test]
    fn test_git_protocol_header_negotiates_v2() {
        let client = AuthHttpClient::new(None).unwrap();
        assert_eq!(client.git_protocol_header(), Some("version=2"));
    }
}
