// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 sigmacatch contributors

//! Git operations via grit-lib (pure Rust Git reimplementation).
//!
//! Architecture:
//!   Transport    → AuthHttpClient (HttpClient trait) for HTTPS auth
//!   Plumbing     → Raw git ops: Odb, Index, commit, checkout, refs
//!   Porcelain    → High-level wrappers: clone, pull, push, add, commit

use anyhow::Result;
use grit_lib::fetch::NoProgress;
use grit_lib::objects::ObjectId;
use grit_lib::odb::Odb;
use grit_lib::transfer::{FetchOptions, PushOptions, PushRefSpec};
use grit_lib::transport::http::{http_fetch, HttpClient};
use grit_lib::write_tree::write_tree_from_index;
#[cfg(unix)]
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::Path;
use std::sync::Mutex;
use tracing::{debug, info, warn};

// ═══════════════════════════════════════════════════════════════════════════════
// Transport: AuthHttpClient
// ═══════════════════════════════════════════════════════════════════════════════

fn sanitize_url(url: &str) -> String {
    if let Some(at_pos) = url.find('@') {
        if let Some(scheme_end) = url[..at_pos].find("://") {
            let prefix = &url[..scheme_end + 3];
            return format!("{}<redacted>@{}", prefix, &url[at_pos + 1..]);
        }
    }
    url.to_string()
}

pub struct AuthHttpClient {
    client: reqwest::blocking::Client,
    token: Mutex<Option<String>>,
}

impl AuthHttpClient {
    pub fn new(token: Option<String>) -> Result<Self> {
        let client = reqwest::blocking::Client::builder()
            .user_agent("sigmacatch/0.2.0")
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
                    let encoded: String = t
                        .bytes()
                        .map(|b| match b {
                            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                                (b as char).to_string()
                            }
                            _ => format!("%{:02X}", b),
                        })
                        .collect();
                    return format!("https://x-access-token:{}@{}", encoded, rest);
                }
            }
        }
        url.to_string()
    }
}

impl HttpClient for AuthHttpClient {
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

// ═══════════════════════════════════════════════════════════════════════════════
// Plumbing — low-level git operations
// ═══════════════════════════════════════════════════════════════════════════════

fn open_odb(git_dir: &Path) -> Odb {
    Odb::new(&git_dir.join("objects")).with_config_git_dir(git_dir.to_path_buf())
}

pub(crate) fn git_config_escape(value: &str) -> String {
    if value.contains('"') || value.contains('\\') || value.contains('\n') || value.contains('\r') {
        let escaped = value
            .replace('\\', "\\\\")
            .replace('"', "\\\"")
            .replace('\n', "\\n")
            .replace('\r', "\\r");
        format!("\"{}\"", escaped)
    } else if value.contains(' ') || value.contains('\t') {
        format!("\"{}\"", value)
    } else {
        value.to_string()
    }
}

/// Initialize a bare `.git` directory with config and HEAD.
pub fn init_repo(git_dir: &Path, _work_tree: &Path, remote_url: &str) -> Result<()> {
    std::fs::create_dir_all(git_dir.join("objects").join("pack"))?;
    std::fs::create_dir_all(git_dir.join("refs").join("heads"))?;
    std::fs::create_dir_all(git_dir.join("refs").join("tags"))?;

    let escaped_url = git_config_escape(remote_url);
    let config = format!(
        "\
[core]
\trepositoryformatversion = 0
\tfilemode = true
\tbare = false
\tlogallrefupdates = true
[remote \"origin\"]
\turl = {}
\tfetch = +refs/heads/*:refs/remotes/origin/*
[user]
\tname = sigmacatch
\temail = sigmacatch@localhost
",
        escaped_url
    );
    std::fs::write(git_dir.join("config"), config)?;
    std::fs::write(git_dir.join("description"), b"SigmaHQ rules repository\n")?;

    // HEAD must exist before any grit-lib operation
    std::fs::write(git_dir.join("HEAD"), b"ref: refs/heads/main\n")?;

    info!("Initialized git repository");
    Ok(())
}

/// Fetch from remote via smart HTTP.
pub fn fetch_remote(
    http_client: &dyn HttpClient,
    git_dir: &Path,
    repo_url: &str,
) -> Result<(usize, Option<String>)> {
    info!("Fetching from {}", sanitize_url(repo_url));
    let opts = FetchOptions {
        refspecs: vec!["+refs/heads/*:refs/remotes/origin/*".to_string()],
        tags: grit_lib::transfer::TagMode::None,
        depth: Some(1),
        ..Default::default()
    };
    let outcome = http_fetch(http_client, git_dir, repo_url, &opts, &mut NoProgress)?;
    let count = outcome.updates.len();
    info!(
        "Fetched {} ref updates (default branch: {})",
        count,
        outcome.default_branch.as_deref().unwrap_or("unknown")
    );
    Ok((count, outcome.default_branch))
}

/// Full clone: init + fetch + set HEAD + checkout worktree.
pub fn clone_repo(http_client: &dyn HttpClient, url: &str, dest: &Path) -> Result<()> {
    let git_dir = dest.join(".git");
    if git_dir.exists() {
        info!("Repository already exists at {:?}, skipping clone", dest);
        return Ok(());
    }

    info!("Cloning into {:?}", dest);
    init_repo(&git_dir, dest, url)?;
    let (count, default_branch) = match fetch_remote(http_client, &git_dir, url) {
        Ok(r) => r,
        Err(e) => {
            let _ = std::fs::remove_dir_all(&git_dir);
            return Err(e);
        }
    };
    if count == 0 {
        let _ = std::fs::remove_dir_all(&git_dir);
        anyhow::bail!("No refs fetched from remote — empty or unreachable repository");
    }

    if let Some(branch_name) = &default_branch {
        let remote_ref = format!("refs/remotes/origin/{}", branch_name);
        let local_ref = format!("refs/heads/{}", branch_name);
        if let Some(oid_str) = read_loose_or_packed_ref(&git_dir, &remote_ref) {
            let head_content = format!("ref: {}\n", local_ref);
            std::fs::write(git_dir.join("HEAD"), &head_content)?;
            let loose_path = git_dir.join(&local_ref);
            if let Some(parent) = loose_path.parent() {
                std::fs::create_dir_all(parent)?;
            }
            std::fs::write(&loose_path, format!("{}\n", oid_str))?;
            info!(
                "HEAD set to {} (→ {})",
                local_ref,
                &oid_str[..12.min(oid_str.len())]
            );
        } else {
            warn!(
                "Default branch '{}' not found in remote tracking refs",
                branch_name
            );
        }
    } else {
        let head_file = git_dir.join("HEAD");
        if !head_file.exists() {
            if let Some(oid_str) = read_loose_or_packed_ref(&git_dir, "refs/remotes/origin/main") {
                std::fs::write(&head_file, format!("{}\n", oid_str))?;
                info!(
                    "HEAD set to detached {} (fallback)",
                    &oid_str[..12.min(oid_str.len())]
                );
            } else if let Some(oid_str) =
                read_loose_or_packed_ref(&git_dir, "refs/remotes/origin/master")
            {
                std::fs::write(&head_file, format!("{}\n", oid_str))?;
                info!(
                    "HEAD set to detached {} (fallback master)",
                    &oid_str[..12.min(oid_str.len())]
                );
            } else {
                warn!("No default branch found — HEAD not set");
            }
        }
    }

    checkout_main_branch(&git_dir, dest)?;
    Ok(())
}

/// Push a local branch to the remote via smart HTTP.
pub fn push_branch(
    http_client: &dyn HttpClient,
    git_dir: &Path,
    remote_url: &str,
    branch_name: &str,
) -> Result<()> {
    let ref_name = format!("refs/heads/{}", branch_name);
    let oid_str = read_loose_or_packed_ref(git_dir, &ref_name)
        .ok_or_else(|| anyhow::anyhow!("Branch '{}' not found locally", branch_name))?;
    let head_oid = ObjectId::from_hex(&oid_str)
        .map_err(|e| anyhow::anyhow!("Invalid OID for branch '{}': {}", branch_name, e))?;
    let spec = PushRefSpec {
        src: Some(head_oid),
        dst: format!("refs/heads/{}", branch_name),
        force: false,
        delete: false,
        expected_old: None,
        expect_absent: false,
    };
    let opts = PushOptions {
        atomic: false,
        dry_run: false,
        push_options: Vec::new(),
    };
    let outcome = grit_lib::push::push_http(
        http_client,
        git_dir,
        remote_url,
        &[spec],
        &opts,
        &mut NoProgress,
    )?;
    if outcome.results.is_empty() {
        warn!("No refs were pushed");
    } else {
        info!("Pushed branch '{}'", branch_name);
    }
    Ok(())
}

// ── Refs ─────────────────────────────────────────────────────────────────────

fn read_packed_ref(git_dir: &Path, ref_name: &str) -> Option<String> {
    let packed_path = git_dir.join("packed-refs");
    let content = std::fs::read_to_string(packed_path).ok()?;
    for line in content.lines() {
        let line = line.trim();
        if line.starts_with('#') || line.starts_with('^') || line.is_empty() {
            continue;
        }
        if let Some((oid, name)) = line.split_once(' ') {
            if name == ref_name {
                return Some(oid.to_string());
            }
        }
    }
    None
}

pub fn read_loose_or_packed_ref(git_dir: &Path, ref_name: &str) -> Option<String> {
    let loose_path = git_dir.join(ref_name);
    match std::fs::read_to_string(&loose_path) {
        Ok(content) => {
            let trimmed = content.trim().to_string();
            if trimmed.is_empty() {
                None
            } else {
                Some(trimmed)
            }
        }
        Err(_) => read_packed_ref(git_dir, ref_name),
    }
}

pub(crate) fn resolve_head(git_dir: &Path) -> Result<ObjectId> {
    let head_path = git_dir.join("HEAD");
    let content = std::fs::read_to_string(&head_path)?;
    let content = content.trim();
    if let Some(ref_str) = content.strip_prefix("ref: ") {
        let ref_path_str = ref_str.trim();
        let full_ref = format!(
            "refs/heads/{}",
            ref_path_str.trim_start_matches("refs/heads/")
        );
        if let Some(oid_str) = read_loose_or_packed_ref(git_dir, &full_ref) {
            return ObjectId::from_hex(&oid_str)
                .map_err(|e| anyhow::anyhow!("Invalid OID '{}': {}", oid_str, e));
        }
        anyhow::bail!(
            "Cannot resolve HEAD ref '{}' — branch not found locally",
            ref_path_str
        );
    } else {
        ObjectId::from_hex(content.trim())
            .map_err(|e| anyhow::anyhow!("Invalid detached HEAD OID '{}': {}", content, e))
    }
}

/// Parse remote URL from `.git/config` for a given remote name.
fn read_remote_url_from_config(git_dir: &Path, remote: &str) -> Result<String> {
    let config_path = git_dir.join("config");
    let content = std::fs::read_to_string(&config_path)?;
    let target = format!("[remote \"{}\"]", remote);
    let mut in_remote = false;
    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with('[') {
            in_remote = trimmed == target;
        } else if in_remote {
            if let Some(url) = trimmed.strip_prefix("url = ") {
                return Ok(url.to_string());
            }
        }
    }
    anyhow::bail!(
        "Remote '{}' not found in git config at {:?}",
        remote,
        config_path
    )
}

// ── Checkout ─────────────────────────────────────────────────────────────────

fn checkout_main_branch(git_dir: &Path, work_tree: &Path) -> Result<()> {
    let head_path = git_dir.join("HEAD");
    let head_content = std::fs::read_to_string(&head_path)?;
    let head_ref = head_content.trim().to_string();

    let oid_str = if let Some(ref_str) = head_ref.strip_prefix("ref: ") {
        let ref_name = ref_str.trim();
        read_loose_or_packed_ref(git_dir, ref_name).ok_or_else(|| {
            anyhow::anyhow!(
                "Cannot resolve HEAD ref '{}' — branch not found locally",
                ref_name
            )
        })?
    } else {
        head_ref.clone()
    };

    let head_oid = ObjectId::from_hex(&oid_str)
        .map_err(|e| anyhow::anyhow!("Invalid HEAD OID '{}': {}", oid_str, e))?;

    let odb = open_odb(git_dir);
    let commit_obj = odb
        .read(&head_oid)
        .map_err(|e| anyhow::anyhow!("Failed to read HEAD commit {}: {}", head_oid, e))?;
    let commit = grit_lib::objects::parse_commit(&commit_obj.data)
        .map_err(|e| anyhow::anyhow!("Failed to parse HEAD commit: {}", e))?;

    checkout_tree(&odb, commit.tree, work_tree, "")?;
    info!("Checked out working tree at {:?}", work_tree);
    Ok(())
}

fn checkout_tree(odb: &Odb, tree_oid: ObjectId, base_path: &Path, prefix: &str) -> Result<()> {
    let obj = odb
        .read(&tree_oid)
        .map_err(|e| anyhow::anyhow!("Failed to read tree {}: {}", tree_oid, e))?;
    let entries = grit_lib::objects::parse_tree(&obj.data)
        .map_err(|e| anyhow::anyhow!("Failed to parse tree: {}", e))?;

    for entry in entries {
        let entry_name = match std::str::from_utf8(&entry.name) {
            Ok(s) => s.to_string(),
            Err(e) => {
                warn!("Skipping tree entry with invalid UTF-8 name: {}", e);
                continue;
            }
        };
        let rel_path = if prefix.is_empty() {
            entry_name.clone()
        } else {
            format!("{}/{}", prefix, entry_name)
        };
        if rel_path.contains("..") || rel_path.starts_with('/') {
            anyhow::bail!("Path traversal detected in tree entry: '{}'", rel_path);
        }
        let full_path = base_path.join(&rel_path);

        if entry.mode == 0o040000 {
            std::fs::create_dir_all(&full_path)?;
            checkout_tree(odb, entry.oid, base_path, &rel_path)?;
        } else if entry.mode == 0o120000 {
            let blob = odb
                .read(&entry.oid)
                .map_err(|e| anyhow::anyhow!("Failed to read symlink blob: {}", e))?;
            let target = String::from_utf8_lossy(&blob.data);
            #[cfg(unix)]
            std::os::unix::fs::symlink(target.as_ref(), &full_path)?;
            #[cfg(not(unix))]
            std::fs::write(&full_path, target.as_ref())?;
        } else {
            if let Some(parent) = full_path.parent() {
                std::fs::create_dir_all(parent)?;
            }
            let blob = odb
                .read(&entry.oid)
                .map_err(|e| anyhow::anyhow!("Failed to read blob {}: {}", entry.oid, e))?;
            std::fs::write(&full_path, &blob.data)?;
            if cfg!(unix) {
                set_executable(&full_path, entry.mode)?;
            }
        }
    }
    Ok(())
}

#[cfg(unix)]
fn set_executable(path: &Path, mode: u32) -> Result<()> {
    let metadata = std::fs::metadata(path)?;
    let mut perms = metadata.permissions();
    if mode == 0o100755 {
        perms.set_mode(0o100755);
    } else {
        perms.set_mode(0o100644);
    }
    std::fs::set_permissions(path, perms)?;
    Ok(())
}

#[cfg(not(unix))]
fn set_executable(_path: &Path, _mode: u32) -> Result<()> {
    Ok(())
}

#[cfg(unix)]
fn is_exec_file(metadata: &std::fs::Metadata) -> bool {
    metadata.permissions().mode() & 0o111 != 0
}

#[cfg(not(unix))]
fn is_exec_file(_metadata: &std::fs::Metadata) -> bool {
    false
}

// ── Commit ───────────────────────────────────────────────────────────────────

fn commit_tree(
    git_dir: &Path,
    odb: &Odb,
    tree_oid: ObjectId,
    message: &str,
    author: &str,
    email: &str,
) -> Result<()> {
    let parent_oid = resolve_head(git_dir)?;
    let now = chrono::Utc::now().timestamp();
    let author_line = format!("{} <{}> {} +0000", author, email, now);
    let committer_line = author_line.clone();

    let commit = grit_lib::objects::CommitData {
        tree: tree_oid,
        parents: vec![parent_oid],
        author: author_line,
        committer: committer_line,
        message: format!("{}\n", message.trim_end_matches('\n')),
        encoding: None,
        author_raw: Vec::new(),
        committer_raw: Vec::new(),
        raw_message: None,
    };

    let raw = grit_lib::objects::serialize_commit(&commit);
    let commit_oid = odb
        .write(grit_lib::objects::ObjectKind::Commit, &raw)
        .map_err(|e| anyhow::anyhow!("Failed to write commit object: {}", e))?;

    let head_path = git_dir.join("HEAD");
    let head_content = std::fs::read_to_string(&head_path)?;
    let head_ref = head_content
        .trim()
        .strip_prefix("ref: ")
        .map(|s| s.trim().to_string());

    if let Some(ref_name) = head_ref {
        let full_path = git_dir.join(&ref_name);
        std::fs::write(&full_path, format!("{}\n", commit_oid))?;
        info!(
            "Committed {} to {}: {}",
            commit_oid,
            ref_name,
            message.trim()
        );
    } else {
        std::fs::write(&head_path, format!("{}\n", commit_oid))?;
        info!(
            "Committed {} to detached HEAD: {}",
            commit_oid,
            message.trim()
        );
    }

    Ok(())
}

// ── Index ────────────────────────────────────────────────────────────────────

fn add_tree_to_index(
    odb: &Odb,
    tree_oid: ObjectId,
    prefix: &str,
    index: &mut grit_lib::index::Index,
) -> Result<()> {
    let obj = odb
        .read(&tree_oid)
        .map_err(|e| anyhow::anyhow!("Failed to read tree {}: {}", tree_oid, e))?;
    let entries = grit_lib::objects::parse_tree(&obj.data)
        .map_err(|e| anyhow::anyhow!("Failed to parse tree: {}", e))?;
    for entry in entries {
        let Ok(name) = std::str::from_utf8(&entry.name) else {
            warn!("Skipping tree entry with invalid UTF-8 name");
            continue;
        };
        let rel_path = if prefix.is_empty() {
            name.to_string()
        } else {
            format!("{}/{}", prefix, name)
        };
        if entry.mode == 0o040000 {
            add_tree_to_index(odb, entry.oid, &rel_path, index)?;
        } else {
            let mode = match entry.mode {
                0o100755 => 0o100755,
                0o120000 => 0o120000,
                _ => 0o100644,
            };
            let path_bytes = rel_path.as_bytes().to_vec();
            index.add_or_replace(grit_lib::index::IndexEntry {
                ctime_sec: 0,
                ctime_nsec: 0,
                mtime_sec: 0,
                mtime_nsec: 0,
                dev: 0,
                ino: 0,
                mode,
                uid: 0,
                gid: 0,
                size: 0,
                oid: entry.oid,
                flags: (path_bytes.len().min(0xfff)) as u16,
                flags_extended: None,
                path: path_bytes,
                base_index_pos: 0,
            });
        }
    }
    Ok(())
}

fn write_index(git_dir: &Path, index: &grit_lib::index::Index) -> Result<()> {
    let index_path = git_dir.join("index");
    if let Some(parent) = index_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    index
        .write(&index_path)
        .map_err(|e| anyhow::anyhow!("Failed to write index: {}", e))?;
    Ok(())
}

fn add_directory_to_index(
    git_dir: &Path,
    dir: &Path,
    base: &Path,
    index: &mut grit_lib::index::Index,
) -> Result<()> {
    let odb = open_odb(git_dir);
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        if path == git_dir || path.starts_with(git_dir) {
            continue;
        }
        let file_type = entry.file_type()?;
        if file_type.is_symlink() {
            continue;
        }
        let rel = path
            .strip_prefix(base)
            .map_err(|_| anyhow::anyhow!("Path not under base"))?;

        if file_type.is_dir() {
            add_directory_to_index(git_dir, &path, base, index)?;
        } else if file_type.is_file() {
            let contents = std::fs::read(&path)?;
            let blob_oid = odb
                .write(grit_lib::objects::ObjectKind::Blob, &contents)
                .map_err(|e| {
                    anyhow::anyhow!(
                        "Failed to write blob {}: {}",
                        rel.to_string_lossy().replace('\\', "/"),
                        e
                    )
                })?;

            let metadata = path.metadata()?;
            let is_exec = is_exec_file(&metadata);
            let mode = if is_exec { 0o100755 } else { 0o100644 };

            let path_str = rel.to_string_lossy().replace('\\', "/");
            let path_bytes = path_str.as_bytes().to_vec();
            #[cfg(unix)]
            let entry = grit_lib::index::IndexEntry {
                ctime_sec: 0,
                ctime_nsec: 0,
                mtime_sec: 0,
                mtime_nsec: 0,
                dev: metadata.dev() as u32,
                ino: metadata.ino() as u32,
                mode,
                uid: metadata.uid(),
                gid: metadata.gid(),
                size: metadata.len() as u32,
                oid: blob_oid,
                flags: (path_bytes.len().min(0xfff)) as u16,
                flags_extended: None,
                path: path_bytes,
                base_index_pos: 0,
            };
            #[cfg(not(unix))]
            let entry = grit_lib::index::IndexEntry {
                ctime_sec: 0,
                ctime_nsec: 0,
                mtime_sec: 0,
                mtime_nsec: 0,
                dev: 0,
                ino: 0,
                mode,
                uid: 0,
                gid: 0,
                size: 0,
                oid: blob_oid,
                flags: (path_bytes.len().min(0xfff)) as u16,
                flags_extended: None,
                path: path_bytes,
                base_index_pos: 0,
            };
            index.add_or_replace(entry);
        }
    }
    Ok(())
}

// ── Ancestry ─────────────────────────────────────────────────────────────────

// ═══════════════════════════════════════════════════════════════════════════════
// Porcelain — high-level wrappers called by the rest of the app
// ═══════════════════════════════════════════════════════════════════════════════

/// Clone a repository using token auth.
/// Wraps `clone_repo` by creating an `AuthHttpClient` from token.
pub fn git_clone(url: &str, dest: &Path, token: Option<&str>) -> Result<()> {
    let http_client = AuthHttpClient::new(token.map(String::from))?;
    clone_repo(&http_client, url, dest)
}

/// Fetch from origin and fast-forward the current branch.
pub fn git_pull(git_dir: &Path, token: Option<&str>) -> Result<()> {
    let http_client = AuthHttpClient::new(token.map(String::from))?;
    let remote_url = read_remote_url_from_config(git_dir, "origin")?;

    fetch_remote(&http_client, git_dir, &remote_url)?;
    fast_forward_branch(git_dir)?;

    // Re-checkout worktree to reflect any changes from fast-forward
    let work_tree = git_dir
        .parent()
        .ok_or_else(|| anyhow::anyhow!("Cannot determine worktree from git_dir"))?;
    checkout_main_branch(git_dir, work_tree)?;
    Ok(())
}

/// Push a local branch to the named remote.
/// Verifies HEAD is on the expected branch before pushing.
pub fn git_push(repo_path: &Path, remote: &str, branch: &str, token: Option<&str>) -> Result<()> {
    let git_dir = repo_path.join(".git");

    let head_content = std::fs::read_to_string(git_dir.join("HEAD"))?;
    let expected_ref = format!("ref: refs/heads/{}\n", branch);
    if head_content != expected_ref {
        anyhow::bail!(
            "HEAD is not on branch '{}' (HEAD: {}). Refusing to push.",
            branch,
            head_content.trim()
        );
    }

    let http_client = AuthHttpClient::new(token.map(String::from))?;
    let remote_url = read_remote_url_from_config(&git_dir, remote)?;
    push_branch(&http_client, &git_dir, &remote_url, branch)
}

/// Stage files under `paths` (relative to `work_tree`) into the git index.
pub fn git_add(git_dir: &Path, work_tree: &Path, paths: &[&str]) -> Result<()> {
    let mut index = grit_lib::index::Index::new();
    for path in paths {
        let dir_path = work_tree.join(path);
        if dir_path.exists() {
            add_directory_to_index(git_dir, &dir_path, work_tree, &mut index)?;
        } else {
            warn!("Path does not exist, skipping: {:?}", dir_path);
        }
    }
    write_index(git_dir, &index)?;
    Ok(())
}

/// Commit whatever is currently staged in the index.
/// Must be called after `git_add`.
/// Merges the parent commit's tree with staged changes so existing
/// files are preserved in the new commit (not just the staged ones).
pub fn git_commit(
    git_dir: &Path,
    _work_tree: &Path,
    msg: &str,
    author: &str,
    email: &str,
) -> Result<()> {
    let index_path = git_dir.join("index");
    if !index_path.exists() {
        anyhow::bail!("No index to commit — call git_add first");
    }
    let odb = open_odb(git_dir);

    let staged_index = grit_lib::index::Index::load(&index_path)
        .map_err(|e| anyhow::anyhow!("Failed to load index: {}", e))?;

    // Merge parent tree entries + staged changes into a single tree
    let parent_oid = resolve_head(git_dir)?;
    let parent_obj = odb
        .read(&parent_oid)
        .map_err(|e| anyhow::anyhow!("Failed to read HEAD commit: {}", e))?;
    let parent_commit = grit_lib::objects::parse_commit(&parent_obj.data)
        .map_err(|e| anyhow::anyhow!("Failed to parse HEAD commit: {}", e))?;

    let mut merged_index = grit_lib::index::Index::new();
    add_tree_to_index(&odb, parent_commit.tree, "", &mut merged_index)?;
    for entry in &staged_index.entries {
        merged_index.add_or_replace(grit_lib::index::IndexEntry { ..entry.clone() });
    }

    let tree_oid = write_tree_from_index(&odb, &merged_index, "")
        .map_err(|e| anyhow::anyhow!("Failed to write tree: {}", e))?;
    commit_tree(git_dir, &odb, tree_oid, msg, author, email)
}

/// Generate a branch name for sigmacatch contribution branches.
pub fn create_branch_name() -> String {
    format!(
        "sigmacatch-contrib/{}",
        chrono::Local::now().format("%Y%m%d")
    )
}

// ═══════════════════════════════════════════════════════════════════════════════
// Branch and HEAD management
// ═══════════════════════════════════════════════════════════════════════════════

fn validate_branch_name(name: &str) -> Result<()> {
    if name.is_empty() {
        anyhow::bail!("branch name must not be empty");
    }
    for c in ['\0', '\n', '\r', '\\', '~', '^', ':', '?', '*', '['] {
        if name.contains(c) {
            anyhow::bail!("branch name contains invalid character {:?}: {:?}", c, name);
        }
    }
    if name.starts_with('/') || name.ends_with('/') || name.contains("//") {
        anyhow::bail!("branch name has invalid '/' placement: {:?}", name);
    }
    for component in name.split('/') {
        if component.is_empty() || component == "." || component == ".." {
            anyhow::bail!(
                "branch name component cannot be empty, '.' or '..': {:?}",
                name
            );
        }
        if component.ends_with(".lock") {
            anyhow::bail!("branch name component cannot end with '.lock': {:?}", name);
        }
    }
    Ok(())
}

/// Create a new branch from the current HEAD and switch to it.
pub fn create_branch(git_dir: &Path, branch_name: &str) -> Result<()> {
    validate_branch_name(branch_name)?;
    let full_ref_name = format!("refs/heads/{}", branch_name);
    let ref_path = git_dir.join(&full_ref_name);

    if ref_path.exists() {
        info!(
            "Branch '{}' already exists locally, switching to it",
            branch_name
        );
        switch_head(git_dir, branch_name)?;
        return Ok(());
    }

    let head_oid = resolve_head(git_dir)?;

    if let Some(parent) = ref_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(&ref_path, format!("{}\n", head_oid))?;
    switch_head(git_dir, branch_name)?;

    info!(
        "Created and switched to branch '{}' from HEAD ({})",
        branch_name, head_oid
    );
    Ok(())
}

/// Switch HEAD to an existing local branch.
pub fn switch_head(git_dir: &Path, branch_name: &str) -> Result<()> {
    validate_branch_name(branch_name)?;
    let local_ref = format!("refs/heads/{}", branch_name);
    if read_loose_or_packed_ref(git_dir, &local_ref).is_none() {
        anyhow::bail!(
            "Cannot switch to branch '{}' — ref '{}' not found locally",
            branch_name,
            local_ref
        );
    }
    std::fs::write(git_dir.join("HEAD"), format!("ref: {}\n", local_ref))?;
    info!("Switched HEAD to branch '{}'", branch_name);
    Ok(())
}

// ═══════════════════════════════════════════════════════════════════════════════
// Internal helpers
// ═══════════════════════════════════════════════════════════════════════════════

/// After a fetch, update the local branch ref to match its remote tracking ref.
fn fast_forward_branch(git_dir: &Path) -> Result<()> {
    let head_content = std::fs::read_to_string(git_dir.join("HEAD"))?;
    let head_content = head_content.trim();

    let Some(ref_str) = head_content.strip_prefix("ref: ") else {
        warn!("Detached HEAD — cannot fast-forward");
        return Ok(());
    };

    let ref_name = ref_str.trim();
    let branch_name = ref_name.strip_prefix("refs/heads/").unwrap_or(ref_name);

    let remote_ref = format!("refs/remotes/origin/{}", branch_name);
    let Some(remote_oid) = read_loose_or_packed_ref(git_dir, &remote_ref) else {
        warn!(
            "Remote tracking ref '{}' not found — cannot fast-forward",
            remote_ref
        );
        return Ok(());
    };

    let local_path = git_dir.join(ref_name);
    std::fs::write(&local_path, format!("{}\n", remote_oid))?;
    info!(
        "Fast-forwarded '{}' to {}",
        branch_name,
        &remote_oid[..12.min(remote_oid.len())]
    );
    Ok(())
}
