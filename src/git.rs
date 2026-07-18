// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 sigmacatch contributors

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

pub struct AuthHttpClient {
    client: reqwest::blocking::Client,
    token: Mutex<Option<String>>,
}

fn sanitize_url(url: &str) -> String {
    if let Some(at_pos) = url.find('@') {
        if let Some(scheme_end) = url[..at_pos].find("://") {
            let prefix = &url[..scheme_end + 3];
            return format!("{}<redacted>@{}", prefix, &url[at_pos + 1..]);
        }
    }
    url.to_string()
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

    // HEAD must exist before any Repository::open (grit-lib's fetch/push internals
    // open the repo and require HEAD to be present).
    std::fs::write(git_dir.join("HEAD"), b"ref: refs/heads/main\n")?;

    info!("Initialized git repository");
    Ok(())
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

pub fn fetch_remote(
    http_client: &dyn HttpClient,
    git_dir: &Path,
    repo_url: &str,
) -> Result<(usize, Option<String>)> {
    info!("Fetching from {}", sanitize_url(repo_url));
    let opts = FetchOptions {
        refspecs: vec!["+refs/heads/*:refs/remotes/origin/*".to_string()],
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
            let remote_ref = "refs/remotes/origin/main";
            if let Some(oid_str) = read_loose_or_packed_ref(&git_dir, remote_ref) {
                std::fs::write(&head_file, format!("{}\n", oid_str))?;
                info!(
                    "HEAD set to detached {} (fallback)",
                    &oid_str[..12.min(oid_str.len())]
                );
            } else {
                let remote_ref = "refs/remotes/origin/master";
                if let Some(oid_str) = read_loose_or_packed_ref(&git_dir, remote_ref) {
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
    }

    checkout_main_branch(&git_dir, dest)?;
    Ok(())
}

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

pub(crate) fn read_loose_or_packed_ref(git_dir: &Path, ref_name: &str) -> Option<String> {
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

fn open_odb(git_dir: &Path) -> Odb {
    Odb::new(&git_dir.join("objects")).with_config_git_dir(git_dir.to_path_buf())
}

/// Returns true if `ancestor` is reachable from `descendant` by walking commit
/// parents. Built on `Odb` directly to avoid `Repository::open` (which
/// `canonicalize()`s paths and breaks on Windows `\\?\` UNC prefixes).
pub fn is_ancestor(git_dir: &Path, ancestor: ObjectId, descendant: ObjectId) -> Result<bool> {
    if ancestor == descendant {
        return Ok(true);
    }
    let odb = open_odb(git_dir);
    let mut visited = std::collections::HashSet::new();
    let mut queue = std::collections::VecDeque::new();
    queue.push_back(descendant);
    while let Some(oid) = queue.pop_front() {
        if !visited.insert(oid) {
            continue;
        }
        if oid == ancestor {
            return Ok(true);
        }
        let obj = odb
            .read(&oid)
            .map_err(|e| anyhow::anyhow!("Failed to read commit {}: {}", oid, e))?;
        let commit = grit_lib::objects::parse_commit(&obj.data)
            .map_err(|e| anyhow::anyhow!("Failed to parse commit {}: {}", oid, e))?;
        for parent in commit.parents {
            queue.push_back(parent);
        }
    }
    Ok(false)
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
    use std::os::unix::fs::PermissionsExt;
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

fn validate_branch_name(name: &str) -> Result<()> {
    if name.is_empty() {
        anyhow::bail!("branch name must not be empty");
    }
    if name.contains('/')
        || name.contains('\\')
        || name.contains('\0')
        || name.contains('\n')
        || name.contains('\r')
    {
        anyhow::bail!("branch name contains invalid characters: {:?}", name);
    }
    if name == "." || name == ".." {
        anyhow::bail!("branch name cannot be '.' or '..'");
    }
    Ok(())
}

fn find_tracking_branch(git_dir: &Path) -> Result<String> {
    for candidate in &["master", "main"] {
        let ref_name = format!("refs/remotes/origin/{}", candidate);
        if read_loose_or_packed_ref(git_dir, &ref_name).is_some() {
            return Ok((*candidate).to_string());
        }
    }
    anyhow::bail!("Cannot find origin/master or origin/main for branch creation")
}

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

    let tracking = find_tracking_branch(git_dir)?;
    let remote_ref_name = format!("refs/remotes/origin/{}", tracking);
    let target_oid = read_loose_or_packed_ref(git_dir, &remote_ref_name).ok_or_else(|| {
        anyhow::anyhow!(
            "Remote tracking ref '{}' not found after fetch (not in loose refs or packed-refs)",
            remote_ref_name
        )
    })?;

    if let Some(parent) = ref_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(&ref_path, format!("{}\n", target_oid))?;
    switch_head(git_dir, branch_name)?;

    info!(
        "Created and switched to branch '{}' from 'origin/{}'",
        branch_name, tracking
    );
    Ok(())
}

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

pub fn stage_and_commit_dir(
    git_dir: &Path,
    work_tree: &Path,
    dir: &str,
    message: &str,
    author: &str,
    email: &str,
) -> Result<()> {
    let odb = open_odb(git_dir);
    let mut index = grit_lib::index::Index::new();
    let dir_path = work_tree.join(dir);
    if dir_path.exists() {
        add_directory_to_index(git_dir, &dir_path, work_tree, &mut index)?;
    }
    write_index(git_dir, &index).map_err(|e| anyhow::anyhow!("Failed to write index: {}", e))?;
    let tree_oid = write_tree_from_index(&odb, &index, "")
        .map_err(|e| anyhow::anyhow!("Failed to write tree: {}", e))?;
    commit_tree(git_dir, &odb, tree_oid, message, author, email)
}

pub fn commit_single_dir(
    git_dir: &Path,
    work_tree: &Path,
    dir_rel: &str,
    message: &str,
    author: &str,
    email: &str,
) -> Result<()> {
    let dir_path = work_tree.join(dir_rel);
    if !dir_path.exists() {
        return Err(anyhow::anyhow!("Directory does not exist: {:?}", dir_path));
    }

    let odb = open_odb(git_dir);
    let mut index = grit_lib::index::Index::new();
    add_directory_to_index(git_dir, &dir_path, work_tree, &mut index)?;

    write_index(git_dir, &index).map_err(|e| anyhow::anyhow!("Failed to write index: {}", e))?;

    let tree_oid = write_tree_from_index(&odb, &index, "")
        .map_err(|e| anyhow::anyhow!("Failed to write tree: {}", e))?;

    commit_tree(git_dir, &odb, tree_oid, message, author, email)
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
                .map_err(|e| anyhow::anyhow!("Failed to write blob {}: {}", rel.display(), e))?;

            let metadata = path.metadata()?;
            let is_exec = is_exec_file(&metadata);
            let mode = if is_exec { 0o100755 } else { 0o100644 };

            let path_bytes = rel.to_string_lossy().as_bytes().to_vec();
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

#[cfg(unix)]
fn is_exec_file(metadata: &std::fs::Metadata) -> bool {
    metadata.permissions().mode() & 0o111 != 0
}

#[cfg(not(unix))]
fn is_exec_file(_metadata: &std::fs::Metadata) -> bool {
    false
}
