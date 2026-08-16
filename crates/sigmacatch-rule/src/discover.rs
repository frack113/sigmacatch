// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 sigmacatch contributors

use anyhow::Result;
#[cfg(unix)]
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use tracing::{info, warn};

pub(crate) fn find_rules_dirs(root: &Path) -> Result<Vec<PathBuf>> {
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
                        if let Some(id) = inode
                            && !visited_inodes.insert(id)
                        {
                            warn!("Skipping symlink cycle detected at: {:?}", path);
                            continue;
                        }
                    }
                    #[cfg(not(unix))]
                    {
                        let abs_path = dunce::canonicalize(&path).ok();
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
            && (ext == "yml" || ext == "yaml")
        {
            return true;
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn make_rule_dir_with_file(tmp: &tempfile::TempDir, name: &str) {
        fs::create_dir(tmp.path().join(name)).unwrap();
        fs::write(tmp.path().join(name).join("rule.yml"), "test: value").unwrap();
    }

    #[test]
    fn test_find_rules_dirs_nonexistent_root() {
        let result = find_rules_dirs(Path::new("/nonexistent/path/12345"));
        assert!(result.unwrap().is_empty());
    }

    #[test]
    fn test_find_rules_dirs_empty_dir() {
        let tmp = tempfile::tempdir().unwrap();
        let result = find_rules_dirs(tmp.path()).unwrap();
        assert!(result.is_empty());
    }

    #[test]
    fn test_find_rules_dirs_discover_rules() {
        let tmp = tempfile::tempdir().unwrap();
        make_rule_dir_with_file(&tmp, "rules");
        let result = find_rules_dirs(tmp.path()).unwrap();
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].file_name().unwrap(), "rules");
    }

    #[test]
    fn test_find_rules_dirs_discover_rules_contrib() {
        let tmp = tempfile::tempdir().unwrap();
        make_rule_dir_with_file(&tmp, "rules-filestorage");
        let result = find_rules_dirs(tmp.path()).unwrap();
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].file_name().unwrap(), "rules-filestorage");
    }

    #[test]
    fn test_find_rules_dirs_excludes_rules_compliance() {
        let tmp = tempfile::tempdir().unwrap();
        make_rule_dir_with_file(&tmp, "rules-compliance");
        make_rule_dir_with_file(&tmp, "rules");
        let result = find_rules_dirs(tmp.path()).unwrap();
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].file_name().unwrap(), "rules");
    }

    #[test]
    fn test_find_rules_dirs_multiple_rules_dirs() {
        let tmp = tempfile::tempdir().unwrap();
        make_rule_dir_with_file(&tmp, "rules");
        make_rule_dir_with_file(&tmp, "rules-filestorage");
        make_rule_dir_with_file(&tmp, "rules-corporate");
        let result = find_rules_dirs(tmp.path()).unwrap();
        assert_eq!(result.len(), 3);
    }

    #[test]
    fn test_find_rules_dirs_empty_rules_prefix_not_discovered() {
        let tmp = tempfile::tempdir().unwrap();
        fs::create_dir(tmp.path().join("rules-empty")).unwrap();
        let result = find_rules_dirs(tmp.path()).unwrap();
        assert!(result.is_empty());
    }

    #[test]
    fn test_find_rules_dirs_nested_not_discovered() {
        let tmp = tempfile::tempdir().unwrap();
        let rules = tmp.path().join("rules");
        fs::create_dir_all(rules.join("nested")).unwrap();
        let result = find_rules_dirs(tmp.path()).unwrap();
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].file_name().unwrap(), "rules");
    }

    #[test]
    fn test_find_rules_dirs_nested_has_yml_discovered() {
        let tmp = tempfile::tempdir().unwrap();
        let rules = tmp.path().join("rules");
        fs::create_dir_all(&rules).unwrap();
        let nested = rules.join("nested");
        fs::create_dir(&nested).unwrap();
        fs::write(nested.join("rule.yml"), "test: true").unwrap();
        let result = find_rules_dirs(tmp.path()).unwrap();
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].file_name().unwrap(), "rules");
    }
}
