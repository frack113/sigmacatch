pub mod format;
pub mod generator;
pub mod info_yml;

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use tracing::{info, warn};

#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(clippy::enum_variant_names)]
pub enum IncompleteReason {
    MissingJson,
    MissingEvtx,
    MissingJsonAndEvtx,
}

impl IncompleteReason {
    pub fn to_missing_fields(&self) -> Vec<&'static str> {
        match self {
            Self::MissingJson => vec!["json"],
            Self::MissingEvtx => vec!["evtx"],
            Self::MissingJsonAndEvtx => vec!["json", "evtx"],
        }
    }
}

#[derive(Debug, Default, Clone)]
pub struct SkipSet {
    pub(crate) rules: HashMap<String, PathBuf>,
    pub(crate) incomplete: Vec<(String, PathBuf, IncompleteReason)>,
    pub(crate) duplicates: HashMap<String, Vec<PathBuf>>,
}

impl SkipSet {
    pub fn into_rule_ids(self) -> HashSet<String> {
        let mut ids: HashSet<String> = self.rules.into_keys().collect();
        for (id, _, _) in self.incomplete {
            ids.insert(id);
        }
        ids
    }

    #[allow(dead_code)]
    pub fn is_empty(&self) -> bool {
        self.rules.is_empty() && self.incomplete.is_empty()
    }

    #[allow(dead_code)]
    pub fn incomplete_rule_ids(&self) -> impl Iterator<Item = &String> {
        self.incomplete.iter().map(|(id, _, _)| id)
    }
}

pub fn build_skip_set(dirs: &[(&str, &Path)], max_depth: u32) -> SkipSet {
    const DEFAULT_MAX_DEPTH: u32 = 64;
    let max_depth = if max_depth == 0 {
        DEFAULT_MAX_DEPTH
    } else {
        max_depth
    };

    if dirs.is_empty() {
        warn!("Skip set: no directories to scan");
        return SkipSet::default();
    }

    let mut skip = SkipSet::default();
    let mut seen_incomplete: HashSet<String> = HashSet::new();

    let mut sorted_dirs: Vec<_> = dirs.iter().collect();
    sorted_dirs.sort_by_key(|(label, _)| *label);

    for (label, dir) in sorted_dirs {
        if !dir.exists() {
            warn!("Skip set: directory not found: {:?}", dir);
            continue;
        }
        let Ok(entries) = std::fs::read_dir(dir) else {
            warn!("Skip set: permission denied: {:?}", dir);
            continue;
        };
        let mut entries_vec: Vec<_> = entries.filter_map(|e| e.ok()).collect();
        entries_vec.sort_by_key(|e| e.path());
        for entry in entries_vec {
            let path = entry.path();
            if path.is_dir() {
                collect_rule_ids_recursive(
                    &path,
                    &mut skip,
                    label,
                    1,
                    max_depth,
                    &mut seen_incomplete,
                );
            }
        }
    }

    info!(
        "Skip set: {} complete rules, {} incomplete, {} duplicates",
        skip.rules.len(),
        skip.incomplete.len(),
        skip.duplicates.len()
    );

    skip
}

fn collect_rule_ids_recursive(
    dir: &Path,
    skip: &mut SkipSet,
    label: &str,
    depth: u32,
    max_depth: u32,
    seen_incomplete: &mut HashSet<String>,
) {
    if depth > max_depth {
        return;
    }

    if let Some(name) = dir.file_name().and_then(|n| n.to_str()) {
        if name == "rules-compliance" || name == "rules_compliance" {
            return;
        }
    }

    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    let mut entries_vec: Vec<_> = entries.filter_map(|e| e.ok()).collect();
    entries_vec.sort_by_key(|e| e.path());
    for entry in entries_vec {
        let path = entry.path();
        if path.is_dir() {
            collect_rule_ids_recursive(&path, skip, label, depth + 1, max_depth, seen_incomplete);
        } else if path.file_name() == Some(std::ffi::OsStr::new("info.yml")) {
            handle_info_yml(&path, skip, label, seen_incomplete);
        }
    }
}

fn handle_info_yml(
    path: &Path,
    skip: &mut SkipSet,
    label: &str,
    seen_incomplete: &mut HashSet<String>,
) {
    let rule_id = match format::read_rule_id(path) {
        Ok(id) => id,
        Err(e) => {
            warn!("Skip set: failed to read rule_id from {:?}: {}", path, e);
            return;
        }
    };

    if !format::validate_rule_id(&rule_id) {
        warn!(
            "Skip set: invalid rule_id '{}' at {} (source: {})",
            rule_id,
            path.display(),
            label
        );
        return;
    }

    let Some(parent) = path.parent() else {
        return;
    };

    match format::validate_triplet(parent, &rule_id) {
        format::TripletStatus::Complete => {
            if let Some(existing_path) = skip.rules.get(&rule_id) {
                let entry = skip.duplicates.entry(rule_id.clone()).or_default();
                if entry.is_empty() {
                    entry.insert(0, existing_path.clone());
                }
                entry.push(path.to_path_buf());
                warn!(
                    "Skip set: duplicate rule '{}' using {:?}, also found at {:?} (source: {})",
                    rule_id, existing_path, path, label
                );
                return;
            }
            skip.incomplete.retain(|(id, _, _)| id != &rule_id);
            skip.rules.insert(rule_id, path.to_path_buf());
        }
        format::TripletStatus::Incomplete(reason) => {
            if !skip.rules.contains_key(&rule_id) {
                mark_incomplete(skip, &rule_id, path, reason, label, seen_incomplete);
            }
        }
    }
}

fn mark_incomplete(
    skip: &mut SkipSet,
    rule_id: &str,
    path: &Path,
    reason: IncompleteReason,
    label: &str,
    seen_incomplete: &mut HashSet<String>,
) {
    let missing = reason.to_missing_fields();
    if !seen_incomplete.insert(rule_id.to_string()) {
        warn!(
            "Skip set: also incomplete at {} (source: {}, missing: {})",
            path.display(),
            label,
            missing.join(", ")
        );
        return;
    }
    skip.incomplete
        .push((rule_id.to_string(), path.to_path_buf(), reason));
    warn!(
        "Skip set: incomplete regression for rule '{}' at {} (source: {}, missing: {})",
        rule_id,
        path.display(),
        label,
        missing.join(", ")
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::TempDir;

    #[test]
    fn test_build_skip_set_empty_dirs() {
        let result = build_skip_set(&[], 64);
        assert!(result.is_empty());
    }

    #[test]
    fn test_build_skip_set_nonexistent_dir() {
        let result = build_skip_set(&[("test", Path::new("/nonexistent/path/xyz"))], 64);
        assert!(result.is_empty());
    }

    #[test]
    fn test_build_skip_set_complete_triplet() {
        let tmp = TempDir::new().unwrap();
        let rule_dir = tmp.path().join("test-rule");
        std::fs::create_dir(&rule_dir).unwrap();
        std::fs::write(rule_dir.join("info.yml"), "id: test-id\ndescription: desc\ndate: 2024-01-01\nauthor: test\nrule_metadata:\n  - id: test-rule\n    title: Test\nregression_tests_info: []\n").unwrap();
        std::fs::write(rule_dir.join("test-rule.json"), "{}").unwrap();
        std::fs::write(rule_dir.join("test-rule.evtx"), "").unwrap();

        let result = build_skip_set(&[("test", tmp.path())], 64);
        assert_eq!(result.rules.len(), 1);
        assert!(result.incomplete.is_empty());
    }

    #[test]
    fn test_build_skip_set_missing_json() {
        let tmp = TempDir::new().unwrap();
        let rule_dir = tmp.path().join("test-rule");
        std::fs::create_dir(&rule_dir).unwrap();
        std::fs::write(rule_dir.join("info.yml"), "id: test-id\ndescription: desc\ndate: 2024-01-01\nauthor: test\nrule_metadata:\n  - id: test-rule\n    title: Test\nregression_tests_info: []\n").unwrap();
        std::fs::write(rule_dir.join("test-rule.evtx"), "").unwrap();

        let result = build_skip_set(&[("test", tmp.path())], 64);
        assert!(result.rules.is_empty());
        assert_eq!(result.incomplete.len(), 1);
    }

    #[test]
    fn test_build_skip_set_missing_evtx() {
        let tmp = TempDir::new().unwrap();
        let rule_dir = tmp.path().join("test-rule");
        std::fs::create_dir(&rule_dir).unwrap();
        std::fs::write(rule_dir.join("info.yml"), "id: test-id\ndescription: desc\ndate: 2024-01-01\nauthor: test\nrule_metadata:\n  - id: test-rule\n    title: Test\nregression_tests_info: []\n").unwrap();
        std::fs::write(rule_dir.join("test-rule.json"), "{}").unwrap();

        let result = build_skip_set(&[("test", tmp.path())], 64);
        assert!(result.rules.is_empty());
        assert_eq!(result.incomplete.len(), 1);
    }

    #[test]
    fn test_build_skip_set_max_depth() {
        let tmp = TempDir::new().unwrap();
        let deep = tmp
            .path()
            .join("a")
            .join("b")
            .join("c")
            .join("d")
            .join("e")
            .join("f")
            .join("g")
            .join("h")
            .join("i")
            .join("j");
        std::fs::create_dir_all(&deep).unwrap();
        let rule_dir = deep.join("test-rule");
        std::fs::create_dir(&rule_dir).unwrap();
        std::fs::write(
            rule_dir.join("info.yml"),
            "rule_metadata:\n  - id: test-rule\n    title: Test\n",
        )
        .unwrap();
        std::fs::write(rule_dir.join("test-rule.json"), "{}").unwrap();
        std::fs::write(rule_dir.join("test-rule.evtx"), "").unwrap();

        let result = build_skip_set(&[("test", tmp.path())], 3);
        assert!(result.rules.is_empty());
    }

    #[test]
    fn test_build_skip_set_rules_compliance_excluded() {
        let tmp = TempDir::new().unwrap();
        let compliance_dir = tmp.path().join("rules-compliance").join("test-rule");
        std::fs::create_dir_all(&compliance_dir).unwrap();
        std::fs::write(
            compliance_dir.join("info.yml"),
            "rule_metadata:\n  - id: compliance-rule\n    title: Compliance\n",
        )
        .unwrap();
        std::fs::write(compliance_dir.join("compliance-rule.json"), "{}").unwrap();
        std::fs::write(compliance_dir.join("compliance-rule.evtx"), "").unwrap();

        let result = build_skip_set(&[("test", tmp.path())], 64);
        assert!(!result.rules.contains_key("compliance-rule"));
    }

    #[test]
    fn test_build_skip_set_rules_compliance_underscore_excluded() {
        let tmp = TempDir::new().unwrap();
        let compliance_dir = tmp.path().join("rules_compliance").join("test-rule");
        std::fs::create_dir_all(&compliance_dir).unwrap();
        std::fs::write(
            compliance_dir.join("info.yml"),
            "rule_metadata:\n  - id: compliance-rule\n    title: Compliance\n",
        )
        .unwrap();
        std::fs::write(compliance_dir.join("compliance-rule.json"), "{}").unwrap();
        std::fs::write(compliance_dir.join("compliance-rule.evtx"), "").unwrap();

        let result = build_skip_set(&[("test", tmp.path())], 64);
        assert!(!result.rules.contains_key("compliance-rule"));
    }

    #[test]
    fn test_build_skip_set_invalid_rule_id() {
        let tmp = TempDir::new().unwrap();
        let rule_dir = tmp.path().join("test-rule");
        std::fs::create_dir(&rule_dir).unwrap();
        std::fs::write(rule_dir.join("info.yml"), "id: test-id\ndescription: desc\ndate: 2024-01-01\nauthor: test\nrule_metadata:\n  - id: INVALID_ID!\n    title: Invalid\nregression_tests_info: []\n").unwrap();
        std::fs::write(rule_dir.join("INVALID_ID!.json"), "{}").unwrap();
        std::fs::write(rule_dir.join("INVALID_ID!.evtx"), "").unwrap();

        let result = build_skip_set(&[("test", tmp.path())], 64);
        assert!(result.rules.is_empty());
    }

    #[test]
    fn test_build_skip_set_duplicate_rule_ids() {
        let tmp = TempDir::new().unwrap();

        let rule_dir1 = tmp.path().join("dir1").join("test-rule");
        std::fs::create_dir_all(&rule_dir1).unwrap();
        std::fs::write(rule_dir1.join("info.yml"), "id: test-id\ndescription: desc\ndate: 2024-01-01\nauthor: test\nrule_metadata:\n  - id: test-rule\n    title: Test\nregression_tests_info: []\n").unwrap();
        std::fs::write(rule_dir1.join("test-rule.json"), "{}").unwrap();
        std::fs::write(rule_dir1.join("test-rule.evtx"), "").unwrap();

        let rule_dir2 = tmp.path().join("dir2").join("test-rule");
        std::fs::create_dir_all(&rule_dir2).unwrap();
        std::fs::write(rule_dir2.join("info.yml"), "id: test-id\ndescription: desc\ndate: 2024-01-01\nauthor: test\nrule_metadata:\n  - id: test-rule\n    title: Test\nregression_tests_info: []\n").unwrap();
        std::fs::write(rule_dir2.join("test-rule.json"), "{}").unwrap();
        std::fs::write(rule_dir2.join("test-rule.evtx"), "").unwrap();

        let result = build_skip_set(&[("test", tmp.path())], 64);
        assert_eq!(result.rules.len(), 1);
        assert_eq!(result.duplicates.len(), 1);
    }

    #[test]
    fn test_parse_info_yml_bom() {
        let tmp = TempDir::new().unwrap();
        let info_path = tmp.path().join("info.yml");
        let mut file = std::fs::File::create(&info_path).unwrap();
        file.write_all(b"\xEF\xBB\xBFid: test-id\ndescription: desc\ndate: 2024-01-01\nauthor: test\nrule_metadata:\n  - id: bom-rule\n    title: BOM Test\nregression_tests_info: []\n").unwrap();
        drop(file);

        let result = format::read_rule_id(&info_path);
        assert_eq!(result.unwrap(), "bom-rule");
    }

    #[test]
    fn test_parse_info_yml_corrupted() {
        let tmp = TempDir::new().unwrap();
        let info_path = tmp.path().join("info.yml");
        std::fs::write(&info_path, "not: valid: yaml: {{{{").unwrap();

        assert!(format::read_rule_id(&info_path).is_err());
    }

    #[test]
    fn test_skip_set_into_rule_ids() {
        let mut skip = SkipSet::default();
        skip.rules
            .insert("rule-1".to_string(), PathBuf::from("/path1"));
        skip.rules
            .insert("rule-2".to_string(), PathBuf::from("/path2"));

        let ids = skip.into_rule_ids();
        assert_eq!(ids.len(), 2);
        assert!(ids.contains("rule-1"));
        assert!(ids.contains("rule-2"));
    }

    #[test]
    fn test_build_skip_set_complete_wins_over_incomplete() {
        let tmp = TempDir::new().unwrap();

        let dir_a = tmp.path().join("dir-a").join("test-rule");
        std::fs::create_dir_all(&dir_a).unwrap();
        std::fs::write(
            dir_a.join("info.yml"),
            "rule_metadata:\n  - id: test-rule\n    title: Test\n",
        )
        .unwrap();
        std::fs::write(dir_a.join("test-rule.evtx"), "").unwrap();

        let dir_b = tmp.path().join("dir-b").join("test-rule");
        std::fs::create_dir_all(&dir_b).unwrap();
        std::fs::write(
            dir_b.join("info.yml"),
            "rule_metadata:\n  - id: test-rule\n    title: Test\n",
        )
        .unwrap();
        std::fs::write(dir_b.join("test-rule.json"), "{}").unwrap();
        std::fs::write(dir_b.join("test-rule.evtx"), "").unwrap();

        let result = build_skip_set(
            &[
                ("a", &tmp.path().join("dir-a")),
                ("b", &tmp.path().join("dir-b")),
            ],
            64,
        );
        assert_eq!(result.rules.len(), 1);
        assert!(result.incomplete.is_empty());
    }

    #[test]
    fn test_build_skip_set_duplicate_three_way() {
        let tmp = TempDir::new().unwrap();

        for dir_name in &["dir-a", "dir-b", "dir-c"] {
            let rule_dir = tmp.path().join(dir_name).join("test-rule");
            std::fs::create_dir_all(&rule_dir).unwrap();
            std::fs::write(
                rule_dir.join("info.yml"),
                "rule_metadata:\n  - id: test-rule\n    title: Test\n",
            )
            .unwrap();
            std::fs::write(rule_dir.join("test-rule.json"), "{}").unwrap();
            std::fs::write(rule_dir.join("test-rule.evtx"), "").unwrap();
        }

        let result = build_skip_set(
            &[
                ("a", &tmp.path().join("dir-a")),
                ("b", &tmp.path().join("dir-b")),
                ("c", &tmp.path().join("dir-c")),
            ],
            64,
        );
        assert_eq!(result.rules.len(), 1);
        assert_eq!(result.duplicates.len(), 1);
        let dupes = result.duplicates.get("test-rule").unwrap();
        assert_eq!(dupes.len(), 3);
    }

    #[test]
    fn test_into_rule_ids_includes_incomplete() {
        let mut skip = SkipSet::default();
        skip.rules
            .insert("complete-rule".to_string(), PathBuf::from("/path1"));
        skip.incomplete.push((
            "incomplete-rule".to_string(),
            PathBuf::from("/path2"),
            IncompleteReason::MissingJson,
        ));

        let ids = skip.into_rule_ids();
        assert_eq!(ids.len(), 2);
        assert!(ids.contains("complete-rule"));
        assert!(ids.contains("incomplete-rule"));
    }

    #[test]
    fn test_build_skip_set_incomplete_not_in_rules() {
        let tmp = TempDir::new().unwrap();
        let rule_dir = tmp.path().join("test-rule");
        std::fs::create_dir(&rule_dir).unwrap();
        std::fs::write(
            rule_dir.join("info.yml"),
            "rule_metadata:\n  - id: test-rule\n    title: Test\n",
        )
        .unwrap();
        std::fs::write(rule_dir.join("test-rule.evtx"), "").unwrap();

        let result = build_skip_set(&[("test", tmp.path())], 64);
        assert!(result.rules.is_empty());
        assert_eq!(result.incomplete.len(), 1);
        let ids = result.clone().into_rule_ids();
        assert_eq!(ids.len(), 1);
        assert!(ids.contains("test-rule"));
    }

    #[test]
    fn test_folder_name_mismatch_still_accepted() {
        let tmp = TempDir::new().unwrap();
        let rule_dir = tmp.path().join("descriptive-slug-name");
        std::fs::create_dir(&rule_dir).unwrap();
        std::fs::write(
            rule_dir.join("info.yml"),
            "id: instance-id\nrule_metadata:\n  - id: actual-rule-uuid\n    title: Test\n",
        )
        .unwrap();
        std::fs::write(rule_dir.join("actual-rule-uuid.json"), "{}").unwrap();
        std::fs::write(rule_dir.join("actual-rule-uuid.evtx"), "").unwrap();

        let result = build_skip_set(&[("test", tmp.path())], 64);
        assert_eq!(
            result.rules.len(),
            1,
            "slug folder name should not prevent skip set entry"
        );
        assert!(result.rules.contains_key("actual-rule-uuid"));
    }
}
