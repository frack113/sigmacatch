// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 sigmacatch contributors

use anyhow::{anyhow, Result};
use std::path::{Path, PathBuf};
use tracing::warn;

use crate::info::InfoYml;

/// Platform-agnostic regression data entry.
///
/// `info.yml` is the universal anchor. `data_path` is optional because
/// not all platforms produce binary event logs (EVTX is Windows-only).
/// `logtype` identifies the data format ("evtx", "json", etc.).
#[derive(Debug)]
pub struct RegressionInfo {
    pub info: InfoYml,
    pub info_path: PathBuf,
    pub data_path: Option<PathBuf>,
    pub rule_id: String,
    pub logtype: String,
}

/// Data file extensions to look for, in priority order.
const DATA_EXTENSIONS: &[&str] = &["evtx", "json"];

/// Load all regression entries from `regression_dir`.
///
/// Walks recursively for `info.yml` files, loads each one, and resolves
/// the associated data file (`{rule_id}.evtx`, `{rule_id}.json`, etc.).
pub fn load_all(regression_dir: &Path) -> Result<Vec<RegressionInfo>> {
    if !regression_dir.exists() {
        return Err(anyhow!(
            "Directory does not exist: {}",
            regression_dir.display()
        ));
    }

    let mut results = Vec::new();
    walk_recursive(regression_dir, &mut results, 0)?;
    results.sort_by(|a, b| a.info_path.cmp(&b.info_path));
    Ok(results)
}

fn walk_recursive(dir: &Path, results: &mut Vec<RegressionInfo>, depth: u32) -> Result<()> {
    if depth > 16 {
        warn!("walk_recursive: depth limit reached at {:?}", dir);
        return Ok(());
    }

    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return Ok(()),
    };

    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            walk_recursive(&path, results, depth + 1)?;
        } else if path.file_name().is_some_and(|n| n == "info.yml") {
            match load_one(&path) {
                Ok(info) => results.push(info),
                Err(e) => {
                    warn!("loader: skipping {}: {}", path.display(), e);
                }
            }
        }
    }

    Ok(())
}

fn load_one(info_path: &Path) -> Result<RegressionInfo> {
    let info = InfoYml::load(info_path)?;

    let rule_id = info
        .rule_metadata
        .first()
        .ok_or_else(|| anyhow!("No rule_metadata in {}", info_path.display()))?
        .id
        .clone();

    let logtype = info
        .regression_tests_info
        .first()
        .map(|t| t.test_type.clone())
        .unwrap_or_else(|| "unknown".to_string());

    let dir = info_path
        .parent()
        .ok_or_else(|| anyhow!("info.yml has no parent dir: {}", info_path.display()))?;

    let data_path = resolve_data_file(dir, &rule_id);

    Ok(RegressionInfo {
        info,
        info_path: info_path.to_path_buf(),
        data_path,
        rule_id,
        logtype,
    })
}

fn resolve_data_file(dir: &Path, rule_id: &str) -> Option<PathBuf> {
    for ext in DATA_EXTENSIONS {
        let candidate = dir.join(format!("{}.{}", rule_id, ext));
        if candidate.exists() {
            return Some(candidate);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn valid_info_yml(rule_id: &str) -> String {
        format!(
            "id: 00000000-0000-0000-0000-000000000000\n\
             description: N/A\n\
             date: 2024-01-01\n\
             author: test\n\
             rule_metadata:\n\
             \x20 - id: {}\n\
             \x20   title: Test\n\
             regression_tests_info: []\n",
            rule_id
        )
    }

    #[test]
    fn test_load_all_empty_dir() {
        let tmp = tempfile::tempdir().unwrap();
        let result = load_all(tmp.path()).unwrap();
        assert!(result.is_empty());
    }

    #[test]
    fn test_load_all_nonexistent_dir() {
        let result = load_all(Path::new("/nonexistent/path/xyz"));
        assert!(result.is_err());
    }

    #[test]
    fn test_load_all_with_evtx() {
        let tmp = tempfile::tempdir().unwrap();
        let rule_dir = tmp.path().join("my-rule");
        fs::create_dir(&rule_dir).unwrap();
        fs::write(rule_dir.join("info.yml"), valid_info_yml("my-rule")).unwrap();
        fs::write(rule_dir.join("my-rule.json"), "{}").unwrap();
        fs::write(rule_dir.join("my-rule.evtx"), "fake").unwrap();

        let results = load_all(tmp.path()).unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].rule_id, "my-rule");
        assert!(results[0].data_path.is_some());
        assert!(results[0]
            .data_path
            .as_ref()
            .unwrap()
            .to_string_lossy()
            .ends_with(".evtx"));
    }

    #[test]
    fn test_load_all_json_only() {
        let tmp = tempfile::tempdir().unwrap();
        let rule_dir = tmp.path().join("linux-rule");
        fs::create_dir(&rule_dir).unwrap();
        fs::write(rule_dir.join("info.yml"), valid_info_yml("linux-rule")).unwrap();
        fs::write(rule_dir.join("linux-rule.json"), "{}").unwrap();

        let results = load_all(tmp.path()).unwrap();
        assert_eq!(results.len(), 1);
        assert!(results[0].data_path.is_some());
        assert!(results[0]
            .data_path
            .as_ref()
            .unwrap()
            .to_string_lossy()
            .ends_with(".json"));
    }

    #[test]
    fn test_load_all_no_data_file() {
        let tmp = tempfile::tempdir().unwrap();
        let rule_dir = tmp.path().join("bare-rule");
        fs::create_dir(&rule_dir).unwrap();
        fs::write(rule_dir.join("info.yml"), valid_info_yml("bare-rule")).unwrap();

        let results = load_all(tmp.path()).unwrap();
        assert_eq!(results.len(), 1);
        assert!(results[0].data_path.is_none());
    }

    #[test]
    fn test_load_all_nested_dirs() {
        let tmp = tempfile::tempdir().unwrap();
        let deep = tmp.path().join("a").join("b").join("c");
        fs::create_dir_all(&deep).unwrap();
        fs::write(deep.join("info.yml"), valid_info_yml("deep-rule")).unwrap();
        fs::write(deep.join("deep-rule.evtx"), "fake").unwrap();

        let results = load_all(tmp.path()).unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].rule_id, "deep-rule");
    }

    #[test]
    fn test_load_all_sorted_by_path() {
        let tmp = tempfile::tempdir().unwrap();
        for name in &["z-rule", "a-rule", "m-rule"] {
            let d = tmp.path().join(name);
            fs::create_dir(&d).unwrap();
            fs::write(d.join("info.yml"), valid_info_yml(name)).unwrap();
        }

        let results = load_all(tmp.path()).unwrap();
        assert_eq!(results.len(), 3);
        let ids: Vec<_> = results.iter().map(|r| r.rule_id.as_str()).collect();
        assert_eq!(ids, vec!["a-rule", "m-rule", "z-rule"]);
    }

    #[test]
    fn test_load_all_invalid_info_yml_skipped() {
        let tmp = tempfile::tempdir().unwrap();
        let good = tmp.path().join("good-rule");
        fs::create_dir(&good).unwrap();
        fs::write(good.join("info.yml"), valid_info_yml("good-rule")).unwrap();

        let bad = tmp.path().join("bad-rule");
        fs::create_dir(&bad).unwrap();
        fs::write(bad.join("info.yml"), "not: valid: yaml: {{{{").unwrap();

        let results = load_all(tmp.path()).unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].rule_id, "good-rule");
    }
}
