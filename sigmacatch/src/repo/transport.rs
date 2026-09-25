// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 sigmacatch contributors

//! Transport layer: HTTPS with token auth (`AuthHttpClient`) and SSH with
//! key-based auth. Also carries the shared URL-sanitization and SSH-command
//! helpers used by the plumbing and porcelain layers.

use crate::repo::{RepoError, Result};
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
    if let Ok(output) = cmd.output()
        && output.status.success()
    {
        let path = String::from_utf8_lossy(&output.stdout).trim().to_string();
        if !path.is_empty() {
            return path;
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
    #[expect(
        dead_code,
        reason = "variant kept for API completeness; no caller selects it yet"
    )]
    Default,
    /// Use `SshCommand::ShellCommand` — runs via `sh -c`. Requires a POSIX shell.
    /// Constructed only by non-Windows callers: dead under the `windows` target,
    /// alive otherwise — hence the target-gated expectation.
    #[cfg_attr(
        windows,
        expect(dead_code, reason = "no Windows caller constructs the sh -c transport")
    )]
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
        debug!(
            "Ignoring GIT_SSH_COMMAND (shell command lines are not supported without sh); \
                 use GIT_SSH or ~/.ssh/config instead"
        );
    }
    #[cfg(windows)]
    {
        let ssh_bin = resolve_ssh_path();
        // SshCommand::Program only accepts the binary path; -i and key path
        // cannot be passed as args. The key is wired via IdentityFile in
        // ~/.ssh/config by ensure_ssh_host_config() instead.
        debug!("Resolved ssh path on Windows: {}", ssh_bin,);
        SshMode::Program(vec![ssh_bin.into()])
    }
    #[cfg(not(windows))]
    {
        let mut cmd = "ssh -o StrictHostKeyChecking=no".to_string();
        if let Some(key) = _ssh_key_path {
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
/// Not `Sync` — constructed inside a single `spawn_blocking` closure and never
/// shared across threads. Restoring `Mutex` would be needed if concurrent use
/// is introduced in the future.
pub struct AuthHttpClient {
    client: reqwest::blocking::Client,
    token: Option<Zeroizing<String>>,
}

impl AuthHttpClient {
    /// Create with default timeouts (backward compatible)
    pub fn new(token: Option<Zeroizing<String>>) -> Result<Self> {
        Self::with_timeouts(token, 120, 30)
    }

    /// Create with custom timeouts
    pub fn with_timeouts(
        token: Option<Zeroizing<String>>,
        http_timeout_secs: u64,
        connect_timeout_secs: u64,
    ) -> Result<Self> {
        let client = reqwest::blocking::Client::builder()
            .user_agent("sigmacatch/0.3.0")
            .timeout(std::time::Duration::from_secs(http_timeout_secs))
            .connect_timeout(std::time::Duration::from_secs(connect_timeout_secs))
            .redirect(reqwest::redirect::Policy::limited(10))
            .build()
            .map_err(|e| RepoError::Transport(format!("http client build: {e}")))?;
        Ok(Self { client, token })
    }

    fn add_auth(&self, url: &str) -> String {
        if let Some(t) = self.token.as_deref()
            && url.starts_with("https://")
            && let Some(rest) = url.strip_prefix("https://")
        {
            return format!("https://x-access-token:{t}@{rest}");
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

    #[test]
    fn test_transport_display() {
        assert_eq!(GitTransport::Http.to_string(), "http");
        assert_eq!(GitTransport::Ssh.to_string(), "ssh");
        assert_eq!(GitTransport::default(), GitTransport::Http);
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

    /// Serde round-trip keeps the lowercase wire format used in `config.yaml`.
    #[test]
    fn test_transport_serde_round_trip() {
        let ssh: GitTransport = serde_yaml::from_str("ssh").unwrap();
        assert_eq!(ssh, GitTransport::Ssh);
        let http: GitTransport = serde_yaml::from_str("http").unwrap();
        assert_eq!(http, GitTransport::Http);
    }

    #[test]
    fn test_add_auth_prefixes_token_on_https_only() {
        let no_token = AuthHttpClient::new(None).unwrap();
        assert_eq!(
            no_token.add_auth("https://github.com/u/r.git/info/refs"),
            "https://github.com/u/r.git/info/refs"
        );

        let token = AuthHttpClient::new(Some(Zeroizing::new("tok123".to_string()))).unwrap();
        assert_eq!(
            token.add_auth("https://github.com/u/r.git/info/refs"),
            "https://x-access-token:tok123@github.com/u/r.git/info/refs"
        );
        // Non-HTTPS URLs are never rewritten.
        assert_eq!(
            token.add_auth("http://localhost:4000/u/r.git"),
            "http://localhost:4000/u/r.git"
        );
    }

    /// Serializes every test that mutates process environment variables
    /// (`GIT_SSH`, `HOME`, …): Rust test threads share one environment.
    static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    #[test]
    fn test_build_ssh_shell_command_default_unix() {
        let _guard = ENV_LOCK.lock().unwrap();
        unsafe {
            std::env::remove_var("GIT_SSH");
            std::env::remove_var("GIT_SSH_COMMAND");
        }
        let mode = build_ssh_shell_command(None);
        #[cfg(not(windows))]
        {
            match &mode {
                SshMode::ShellCommand(cmd) => {
                    assert_eq!(cmd, "ssh -o StrictHostKeyChecking=no")
                }
                other => panic!("expected ShellCommand, got {other:?}"),
            }
        }
        #[cfg(windows)]
        {
            assert!(matches!(mode, SshMode::Program(_)));
        }
    }

    #[test]
    #[cfg(not(windows))]
    fn test_build_ssh_shell_command_escapes_key_path() {
        let _guard = ENV_LOCK.lock().unwrap();
        unsafe { std::env::remove_var("GIT_SSH") };
        let mode = build_ssh_shell_command(Some("/tmp/a b/c's key"));
        match &mode {
            SshMode::ShellCommand(cmd) => {
                assert_eq!(
                    cmd,
                    "ssh -o StrictHostKeyChecking=no -i '/tmp/a b/c'\\''s key'"
                )
            }
            other => panic!("expected ShellCommand, got {other:?}"),
        }
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
            other => panic!("expected Program, got {other:?}"),
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

    #[test]
    #[cfg(not(windows))]
    fn test_shell_escape() {
        assert_eq!(shell_escape("/tmp/key"), "'/tmp/key'");
        assert_eq!(shell_escape("/a b/c"), "'/a b/c'");
        assert_eq!(shell_escape("/a'b/c"), "'/a'\\''b/c'");
        assert_eq!(shell_escape("/a\\b/c"), "'/a\\\\b/c'");
    }
}
