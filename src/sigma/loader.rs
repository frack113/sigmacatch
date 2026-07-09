use anyhow::Result;
use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicBool;
use tracing::{info, warn};

#[cfg(unix)]
use std::os::unix::fs::MetadataExt;

const SIGMA_REPO_URL: &str = "https://github.com/SigmaHQ/sigma.git";

#[derive(Debug, Clone)]
pub struct SigmaRepo {
    pub path: PathBuf,
    offline: bool,
}

impl SigmaRepo {
    pub fn new(path: &Path) -> Self {
        Self {
            path: path.to_path_buf(),
            offline: false,
        }
    }

    pub fn with_offline(mut self, offline: bool) -> Self {
        self.offline = offline;
        self
    }

    pub async fn init(&self) -> Result<()> {
        // Clone is fatal (no rules = no pipeline). Pull is best-effort (stale rules > no rules).
        // This asymmetry is intentional: a fresh clone guarantees up-to-date rules,
        // while a failed pull falls back to existing rules rather than blocking the user.
        let repo_exists = if self.path.join(".git").exists() {
            gix::open(&self.path).is_ok()
        } else {
            false
        };

        if repo_exists {
            if self.offline {
                info!("Offline mode: using existing Sigma repository");
                return Ok(());
            }
            info!("Sigma repository exists, fetching latest...");
            if let Err(e) = self.pull().await {
                warn!(
                    "Failed to pull Sigma repository: {}. Continuing with existing rules.",
                    e
                );
            }
            return Ok(());
        }

        if self.path.join(".git").exists() && !repo_exists {
            warn!("Sigma repository at {:?} is corrupted (gix::open failed). Removing and re-cloning.", self.path);
            if let Err(e) = std::fs::remove_dir_all(&self.path) {
                warn!(
                    "Failed to remove corrupted repository: {}. Will attempt fresh clone.",
                    e
                );
            }
        }

        if self.offline {
            anyhow::bail!(
                "Offline mode enabled but no Sigma repository found at {:?}. \
                 Run without --offline first to clone the repository.",
                self.path
            );
        }

        self.clone_repo().await
    }

    async fn clone_repo(&self) -> Result<()> {
        info!("Cloning Sigma repository from {}...", SIGMA_REPO_URL);
        let url = SIGMA_REPO_URL.to_string();
        let path = self.path.clone();

        tokio::task::spawn_blocking(move || -> Result<()> {
            let mut prepare = gix::prepare_clone(url, &path)
                .map_err(|e| anyhow::anyhow!("Failed to prepare clone: {}", e))?;

            let (mut prepare_checkout, fetch_outcome) = prepare
                .fetch_then_checkout(gix::progress::Discard, &AtomicBool::new(false))
                .map_err(|e| anyhow::anyhow!("Failed to prepare clone: {}", e))?;

            if fetch_outcome.ref_map.mappings.is_empty() {
                return Err(anyhow::anyhow!(
                    "No refs fetched from remote (empty or unreachable)"
                ));
            }

            prepare_checkout
                .main_worktree(gix::progress::Discard, &AtomicBool::new(false))
                .map_err(|e| anyhow::anyhow!("Failed to checkout worktree: {}", e))?;

            Ok(())
        })
        .await
        .map_err(|e| {
            if e.is_panic() {
                let payload = e.into_panic();
                anyhow::anyhow!("Clone task panicked: {:?}", payload)
            } else {
                anyhow::anyhow!("Clone task failed: {}", e)
            }
        })??;

        info!("Sigma repository cloned to {:?}", self.path);
        Ok(())
    }

    async fn pull(&self) -> Result<()> {
        info!("Fetching Sigma repository from origin...");
        let path = self.path.clone();

        tokio::task::spawn_blocking(move || -> Result<()> {
            let repo = gix::open(&path)
                .map_err(|e| anyhow::anyhow!("Failed to open Sigma repository: {}", e))?;

            let remote = repo
                .find_remote("origin")
                .map_err(|e| anyhow::anyhow!("Failed to find remote 'origin': {}", e))?;

            let connection = remote
                .connect(gix::remote::Direction::Fetch)
                .map_err(|e| anyhow::anyhow!("Failed to connect to remote: {}", e))?;

            let mut extra_refspecs = Vec::new();
            let spec = gix::refspec::parse(
                "+refs/heads/*:refs/remotes/origin/*".as_ref(),
                gix::refspec::parse::Operation::Fetch,
            )
            .expect("hardcoded refspec is always valid");
            extra_refspecs.push(spec.into());

            let fetch_opts = gix::remote::ref_map::Options {
                prefix_from_spec_as_filter_on_remote: true,
                handshake_parameters: Vec::new(),
                extra_refspecs,
            };

            connection
                .prepare_fetch(gix::progress::Discard, fetch_opts)
                .map_err(|e| anyhow::anyhow!("Failed to prepare fetch: {}", e))?
                .receive(gix::progress::Discard, &AtomicBool::new(false))
                .map_err(|e| anyhow::anyhow!("Failed to receive pack: {}", e))?;

            info!("Fetch from origin complete");
            Ok(())
        })
        .await
        .map_err(|e| {
            if e.is_panic() {
                let payload = e.into_panic();
                anyhow::anyhow!("Pull task panicked: {:?}", payload)
            } else {
                anyhow::anyhow!("Pull task failed: {}", e)
            }
        })??;

        info!("Sigma repository pulled and reset to origin/master");
        Ok(())
    }
}

pub fn find_rules_dirs(root: &Path) -> Result<Vec<PathBuf>> {
    let mut dirs = Vec::new();
    let mut excluded = Vec::new();
    #[cfg(unix)]
    let mut visited_inodes = std::collections::HashSet::new();
    #[cfg(not(unix))]
    let mut visited_paths = std::collections::HashSet::new();
    if !root.exists() {
        warn!("Root directory does not exist: {:?}", root);
        return Ok(dirs);
    }

    let entries = std::fs::read_dir(root)?;
    for entry_result in entries {
        match entry_result {
            Ok(entry) => {
                let path = entry.path();
                if path.is_dir() {
                    #[cfg(unix)]
                    {
                        let inode = path.metadata().ok().map(|m| m.ino());
                        if let Some(id) = inode {
                            if !visited_inodes.insert(id) {
                                warn!("Skipping symlink cycle detected at: {:?}", path);
                                continue;
                            }
                        }
                    }
                    #[cfg(not(unix))]
                    {
                        let abs_path = std::fs::canonicalize(&path).ok();
                        if let Some(abs) = abs_path {
                            if !visited_paths.insert(abs) {
                                warn!("Skipping symlink cycle detected at: {:?}", path);
                                continue;
                            }
                        }
                    }
                    if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
                        if name == "rules" || name.starts_with("rules-") {
                            if name.starts_with("rules-compliance") {
                                excluded.push(name.to_string());
                                continue;
                            }
                            if name.starts_with("rules-") && !has_yml_files(&path, 0) {
                                continue;
                            }
                            info!("Found rules directory: {:?}", path);
                            dirs.push(path);
                        }
                    } else {
                        warn!("Skipping non-UTF8 directory name: {:?}", path);
                    }
                }
            }
            Err(e) => {
                warn!("Skipping entry due to error: {}", e);
            }
        }
    }

    if dirs.is_empty() {
        warn!("No 'rules*' directories found in {:?}", root);
    }
    if !excluded.is_empty() {
        info!("Excluded non-detection directories: {:?}", excluded);
    }

    Ok(dirs)
}

// Depth 8 is deliberately conservative: SigmaHQ rules-* dirs are shallow
// (max ~5 levels). The 64-depth limit in visit_dirs_inner handles the full
// file-system traversal; this is just a quick pre-check.
fn has_yml_files(dir: &Path, depth: u32) -> bool {
    if depth > 8 {
        return false;
    }
    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(e) => {
            warn!(
                "Cannot read directory {:?} while scanning for rules: {}",
                dir, e
            );
            return false;
        }
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            if has_yml_files(&path, depth + 1) {
                return true;
            }
        } else if let Some(ext) = path
            .extension()
            .and_then(|e| e.to_str())
            .map(|e| e.to_ascii_lowercase())
        {
            if ext == "yml" || ext == "yaml" {
                return true;
            }
        }
    }
    false
}
