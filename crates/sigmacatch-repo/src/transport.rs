// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 sigmacatch contributors

//! Transport layer: HTTPS with token auth (`AuthHttpClient`) and SSH with
//! key-based auth. Also carries the shared URL-sanitization and SSH-command
//! helpers used by the plumbing and porcelain layers.

use anyhow::Result;
use std::sync::Mutex;
use tracing::debug;

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
    // Reject path traversal and suspicious characters
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

/// Escape a string for safe use as an argument inside a shell-quoted segment.
fn shell_quote_arg(arg: &str) -> String {
    if arg.is_empty() {
        return String::new();
    }
    if !arg
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.' | '/' | ':' | ',' | '~'))
    {
        let escaped = arg.replace('\'', "'\\''");
        return format!("'{}'", escaped);
    }
    arg.to_string()
}

/// Build the SSH shell command string from config or environment.
///
/// Priority: `GIT_SSH_COMMAND` env > `GIT_SSH` env > `ssh_key_path` in config > default `ssh`.
/// Environment variables take precedence so the user can override config at runtime without
/// modifying `config.yaml` (e.g. for testing different keys or proxies).
/// Returns an empty string when no custom command is configured (use default `ssh`).
pub(crate) fn build_ssh_shell_command(ssh_key_path: Option<&str>) -> String {
    if let Ok(cmd) = std::env::var("GIT_SSH_COMMAND") {
        if !cmd.is_empty() {
            debug!("Using GIT_SSH_COMMAND from environment");
            return cmd;
        }
    }
    if let Ok(cmd) = std::env::var("GIT_SSH") {
        if !cmd.is_empty() {
            debug!("Using GIT_SSH from environment");
            return cmd;
        }
    }
    if let Some(key_path) = ssh_key_path {
        if !key_path.is_empty() {
            let quoted = shell_quote_arg(key_path);
            let cmd = format!("ssh -i {quoted}");
            debug!("Constructed SSH command with key path: {cmd}");
            return cmd;
        }
    }
    String::new()
}

/// HTTP client implementing grit-lib's `HttpClient` trait with GitHub token auth.
pub struct AuthHttpClient {
    client: reqwest::blocking::Client,
    token: Mutex<Option<String>>,
}

impl AuthHttpClient {
    pub fn new(token: Option<String>) -> Result<Self> {
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
        if let Some(ref t) = *token {
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
