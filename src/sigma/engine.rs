// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 sigmacatch contributors

use anyhow::Result;
use rsigma_eval::event::JsonEvent;
use rsigma_eval::Engine;
use rsigma_parser::{parse_sigma_yaml, LogSource};
use serde_json::Value;
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use tracing::{error, info, warn};

use crate::config::{MinLevel, MinStatus, SigmaFilterConfig};

const MAX_RULE_FILE_SIZE: u64 = 1_048_576;
const MAX_VISIT_DEPTH: u32 = 64;

pub struct SigmaEngine {
    engine: Engine,
    rules_count: usize,
    rule_paths: HashMap<String, PathBuf>,
    rule_descriptions: HashMap<String, String>,
    all_services: HashSet<String>,
    active_services: HashSet<String>,
    all_categories: HashSet<String>,
    active_categories: HashSet<String>,
    pre_filter_counts: HashMap<(u8, u8), usize>,
    pre_filter_total: usize,
    pre_filter_no_status: usize,
    pre_filter_no_level: usize,
}

impl std::fmt::Debug for SigmaEngine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SigmaEngine")
            .field("rules_count", &self.rules_count)
            .finish()
    }
}

impl Default for SigmaEngine {
    fn default() -> Self {
        let mut engine = Engine::new();
        engine.set_include_event(true);
        Self {
            engine,
            rules_count: 0,
            rule_paths: HashMap::new(),
            rule_descriptions: HashMap::new(),
            all_services: HashSet::new(),
            active_services: HashSet::new(),
            all_categories: HashSet::new(),
            active_categories: HashSet::new(),
            pre_filter_counts: HashMap::new(),
            pre_filter_total: 0,
            pre_filter_no_status: 0,
            pre_filter_no_level: 0,
        }
    }
}

impl SigmaEngine {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn load_rules_from_dirs(
        &mut self,
        dirs: &[&Path],
        skip_rules: &HashSet<String>,
        filter: &SigmaFilterConfig,
    ) -> Result<usize> {
        let mut total = 0;
        let mut reasons = SkipReasons::default();
        for dir in dirs {
            let (loaded, dir_reasons) = self.load_rules_from_dir(dir, skip_rules, filter);
            total += loaded;
            reasons.skip_set += dir_reasons.skip_set;
            reasons.non_windows += dir_reasons.non_windows;
            reasons.status += dir_reasons.status;
            reasons.level += dir_reasons.level;
            reasons.duplicate += dir_reasons.duplicate;
            reasons.other += dir_reasons.other;
        }
        self.rules_count = total;
        let total_skipped = reasons.total();
        if total == 0 {
            warn!(
                "No rules loaded — {} skipped (skip_set={}, non_windows={}, status={}, level={}, duplicate={}, other={})",
                total_skipped, reasons.skip_set, reasons.non_windows, reasons.status, reasons.level, reasons.duplicate, reasons.other
            );
        } else {
            info!(
                "Loaded {} rules ({} skipped: skip_set={}, non_windows={}, status={}, level={}, duplicate={}, other={})",
                total,
                total_skipped,
                reasons.skip_set,
                reasons.non_windows,
                reasons.status,
                reasons.level,
                reasons.duplicate,
                reasons.other
            );
        }
        Ok(total)
    }

    fn load_rules_from_dir(
        &mut self,
        dir: &Path,
        skip_rules: &HashSet<String>,
        filter: &SigmaFilterConfig,
    ) -> (usize, SkipReasons) {
        info!("Loading Sigma rules from {:?}", dir);
        let mut count = 0;
        let mut reasons = SkipReasons::default();
        let mut errors = Vec::new();

        if !dir.exists() {
            warn!("Rules directory does not exist: {:?}", dir);
            return (0, reasons);
        }

        self.visit_dirs(
            dir,
            &mut count,
            &mut reasons,
            &mut errors,
            skip_rules,
            filter,
        );

        info!(
            "Loaded {} rules from {:?} ({} errors, {} skip_set, {} non_windows, {} status, {} level, {} duplicate, {} other)",
            count,
            dir,
            errors.len(),
            reasons.skip_set,
            reasons.non_windows,
            reasons.status,
            reasons.level,
            reasons.duplicate,
            reasons.other
        );
        if !errors.is_empty() {
            for (path, err) in &errors {
                error!("Rule error: {:?} - {}", path, err);
            }
        }
        (count, reasons)
    }

    fn visit_dirs(
        &mut self,
        dir: &Path,
        count: &mut usize,
        reasons: &mut SkipReasons,
        errors: &mut Vec<(std::path::PathBuf, anyhow::Error)>,
        skip_rules: &HashSet<String>,
        filter: &SigmaFilterConfig,
    ) {
        self.visit_dirs_inner(dir, count, reasons, errors, skip_rules, filter, 0)
    }

    #[allow(clippy::too_many_arguments)]
    fn visit_dirs_inner(
        &mut self,
        dir: &Path,
        count: &mut usize,
        reasons: &mut SkipReasons,
        errors: &mut Vec<(std::path::PathBuf, anyhow::Error)>,
        skip_rules: &HashSet<String>,
        filter: &SigmaFilterConfig,
        depth: u32,
    ) {
        if depth > MAX_VISIT_DEPTH {
            warn!(
                "Max depth ({}) exceeded at {:?}, stopping recursion",
                MAX_VISIT_DEPTH, dir
            );
            return;
        }

        let entries = match std::fs::read_dir(dir) {
            Ok(e) => e,
            Err(e) => {
                warn!("Cannot read directory {:?}: {}", dir, e);
                return;
            }
        };

        let mut entries: Vec<_> = entries.filter_map(|e| e.ok()).collect();
        entries.sort_by_key(|e| e.path());

        for entry in entries {
            let path = entry.path();

            let file_name = match path.file_name().and_then(|n| n.to_str()) {
                Some(n) => n.to_string(),
                None => {
                    warn!("Non-UTF8 file name: {:?}", path.display());
                    continue;
                }
            };

            if file_name.starts_with('.') {
                continue;
            }

            if path.is_dir() {
                self.visit_dirs_inner(&path, count, reasons, errors, skip_rules, filter, depth + 1);
            } else if let Some(ext) = path
                .extension()
                .and_then(|e| e.to_str())
                .map(|e| e.to_ascii_lowercase())
            {
                if ext == "yml" || ext == "yaml" {
                    match self.load_rule_file(&path, skip_rules, filter) {
                        Ok((n, r)) => {
                            *count += n;
                            reasons.skip_set += r.skip_set;
                            reasons.non_windows += r.non_windows;
                            reasons.duplicate += r.duplicate;
                            reasons.other += r.other;
                        }
                        Err(LoadError::Error(e)) => {
                            warn!("Failed to load rule {:?}: {}", path, e);
                            errors.push((path, e));
                        }
                    }
                }
            } else if path.extension().is_some() {
                warn!("Non-UTF8 file extension: {:?}", path.display());
            }
        }
    }

    fn load_rule_file(
        &mut self,
        path: &Path,
        skip_rules: &HashSet<String>,
        filter: &SigmaFilterConfig,
    ) -> std::result::Result<(usize, SkipReasons), LoadError> {
        let mut reasons = SkipReasons::default();

        let metadata = std::fs::metadata(path).map_err(|e| LoadError::Error(e.into()))?;
        if metadata.len() > MAX_RULE_FILE_SIZE {
            warn!("Rule file too large (>1MB), skipping: {:?}", path);
            return Ok((0, reasons));
        }

        let content = std::fs::read_to_string(path).map_err(|e| LoadError::Error(e.into()))?;
        let mut collection = parse_sigma_yaml(&content).map_err(|e| LoadError::Error(e.into()))?;

        // NOTE: Skip counters are sequential — each retain is applied to the
        // collection as it exists after the previous filter. A rule filtered by
        // non_windows is never counted in status/level counters. The counters
        // reflect actual pipeline ordering, not independent totals.

        let before_non_windows = collection.rules.len();
        collection.rules.retain(|rule| {
            rule.logsource
                .product
                .as_deref()
                .map(|p| p == "windows")
                .unwrap_or(true)
        });
        reasons.non_windows += before_non_windows - collection.rules.len();

        for rule in &collection.rules {
            self.pre_filter_total += 1;
            match (rule.status.as_ref(), rule.level.as_ref()) {
                (Some(s), Some(l)) => {
                    let key = (MinStatus::from(s).ordinal(), MinLevel::from(l).ordinal());
                    *self.pre_filter_counts.entry(key).or_insert(0) += 1;
                }
                (None, _) => self.pre_filter_no_status += 1,
                (_, None) => self.pre_filter_no_level += 1,
            }
        }

        let before_status = collection.rules.len();
        collection.rules.retain(|rule| {
            rule.status
                .as_ref()
                .map(|s| filter.min_status.accepts(s))
                .unwrap_or(true)
        });
        reasons.status += before_status - collection.rules.len();

        let before_level = collection.rules.len();
        collection.rules.retain(|rule| {
            rule.level
                .as_ref()
                .map(|l| filter.min_level.accepts(l))
                .unwrap_or(true)
        });
        reasons.level += before_level - collection.rules.len();

        for rule in &collection.rules {
            if let Some(ref service) = rule.logsource.service {
                self.all_services.insert(service.clone());
            }
            if let Some(ref category) = rule.logsource.category {
                self.all_categories.insert(category.clone());
            }
        }

        let before_skip = collection.rules.len();
        collection
            .rules
            .retain(|rule| !rule.id.as_ref().is_some_and(|id| skip_rules.contains(id)));
        reasons.skip_set += before_skip - collection.rules.len();

        for rule in &collection.rules {
            if rule.id.is_none() {
                warn!("Rule without ID loaded from {:?}: {}", path, rule.title);
            }
            if let Some(ref service) = rule.logsource.service {
                self.active_services.insert(service.clone());
            }
            if let Some(ref category) = rule.logsource.category {
                self.active_categories.insert(category.clone());
            }
        }

        let before_duplicate = collection.rules.len();
        collection.rules.retain(|rule| {
            if let Some(ref id) = rule.id {
                if self.rule_paths.contains_key(id) {
                    warn!(
                        "Rule '{}' already mapped to {:?}, skipping duplicate from {:?}",
                        id, self.rule_paths[id], path
                    );
                    return false;
                }
            }
            true
        });
        reasons.duplicate += before_duplicate - collection.rules.len();

        if collection.rules.is_empty() {
            return Ok((0, reasons));
        }

        self.engine
            .add_collection(&collection)
            .map_err(|e| LoadError::Error(e.into()))?;

        for rule in &collection.rules {
            if let Some(ref id) = rule.id {
                self.rule_paths.insert(id.clone(), path.to_path_buf());
                if let Some(ref desc) = rule.description {
                    self.rule_descriptions.insert(id.clone(), desc.clone());
                }
            }
        }

        Ok((collection.rules.len(), reasons))
    }

    pub fn print_rule_table(&self, filter: &SigmaFilterConfig) {
        const STATUS_LABELS: [&str; 5] = ["unsup", "dep", "exp", "test", "stable"];
        const LEVEL_LABELS: [&str; 5] = ["informational", "low", "medium", "high", "critical"];

        let total = self.pre_filter_total;
        if total == 0 {
            eprintln!("⚠️  No rules loaded");
            return;
        }

        eprintln!("🔍 Checking {} rules…\n", total);

        eprint!("{:<20} │", "");
        for label in &STATUS_LABELS {
            eprint!(" {:^6} │", label);
        }
        eprintln!();

        eprint!("{}", "─".repeat(20));
        for _ in 0..5 {
            eprint!("┼{}", "─".repeat(8));
        }
        eprintln!();

        for (ri, level) in LEVEL_LABELS.iter().enumerate() {
            eprint!("{:<20} │", level);
            for si in 0..5 {
                let key = (si as u8, ri as u8);
                let count = self.pre_filter_counts.get(&key).copied().unwrap_or(0);
                eprint!(" {:>6} │", count);
            }
            eprintln!();
        }

        eprintln!();
        if self.pre_filter_no_status > 0 || self.pre_filter_no_level > 0 {
            eprintln!(
                "   ⚠️  {} rules missing status, {} rules missing level (counted as accepted)",
                self.pre_filter_no_status, self.pre_filter_no_level
            );
        }
        eprintln!(
            "⚙️  Filter: min_status={}, min_level={} → accepted {} rules",
            filter.min_status, filter.min_level, self.rules_count
        );
    }

    pub fn evaluate_event_with_logsource(
        &self,
        event: &Value,
        logsource: &LogSource,
    ) -> Vec<rsigma_eval::EvaluationResult> {
        let json_event = JsonEvent::borrow(event);
        self.engine.evaluate_with_logsource(&json_event, logsource)
    }

    pub fn rule_path(&self, rule_id: &str) -> Option<&PathBuf> {
        self.rule_paths.get(rule_id)
    }

    pub fn rule_description(&self, rule_id: &str) -> Option<&str> {
        self.rule_descriptions.get(rule_id).map(|s| s.as_str())
    }

    pub fn active_services(&self) -> &HashSet<String> {
        &self.active_services
    }

    pub fn all_services(&self) -> &HashSet<String> {
        &self.all_services
    }

    pub fn active_categories(&self) -> &HashSet<String> {
        &self.active_categories
    }

    pub fn all_categories(&self) -> &HashSet<String> {
        &self.all_categories
    }

    pub fn rules_count(&self) -> usize {
        self.rules_count
    }
}

enum LoadError {
    Error(anyhow::Error),
}

#[derive(Default)]
pub struct SkipReasons {
    pub skip_set: usize,
    pub non_windows: usize,
    pub status: usize,
    pub level: usize,
    pub duplicate: usize,
    pub other: usize,
}

impl SkipReasons {
    pub fn total(&self) -> usize {
        self.skip_set + self.non_windows + self.status + self.level + self.duplicate + self.other
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{Config, MinLevel, MinStatus, SigmaFilterConfig};
    use std::collections::HashSet;

    fn default_filter() -> SigmaFilterConfig {
        SigmaFilterConfig {
            min_status: MinStatus::Unsupported,
            min_level: MinLevel::Informational,
        }
    }

    fn windows_rule(id: &str, product: &str) -> String {
        format!(
            r#"title: Test Rule
id: {}
logsource:
    product: {}
    service: process
detection:
    selection:
        CommandLine|contains: 'test'
    condition: selection
"#,
            id, product
        )
    }

    fn no_product_rule(id: &str) -> String {
        format!(
            r#"title: Test Rule
id: {}
detection:
    selection:
        CommandLine|contains: 'test'
    condition: selection
"#,
            id
        )
    }

    #[test]
    fn test_windows_rule_loaded() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.yml");
        std::fs::write(&path, &windows_rule("test-001", "windows")).unwrap();

        let mut engine = SigmaEngine::new();
        let count = engine
            .load_rules_from_dirs(&[dir.path()], &HashSet::new(), &default_filter())
            .unwrap();

        assert_eq!(count, 1, "windows rule should be loaded");
    }

    #[test]
    fn test_linux_rule_filtered() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.yml");
        std::fs::write(&path, &windows_rule("test-002", "linux")).unwrap();

        let mut engine = SigmaEngine::new();
        let count = engine
            .load_rules_from_dirs(&[dir.path()], &HashSet::new(), &default_filter())
            .unwrap();

        assert_eq!(count, 0, "linux rule should be filtered out");
    }

    #[test]
    fn test_no_product_rule_loaded() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.yml");
        std::fs::write(&path, &no_product_rule("test-003")).unwrap();

        let mut engine = SigmaEngine::new();
        let count = engine
            .load_rules_from_dirs(&[dir.path()], &HashSet::new(), &default_filter())
            .unwrap();

        assert_eq!(count, 1, "rule without logsource.product should be loaded");
    }

    #[test]
    fn test_skip_set_filters_rule() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.yml");
        std::fs::write(&path, &windows_rule("test-004", "windows")).unwrap();

        let mut skip = HashSet::new();
        skip.insert("test-004".to_string());

        let mut engine = SigmaEngine::new();
        let count = engine
            .load_rules_from_dirs(&[dir.path()], &skip, &default_filter())
            .unwrap();

        assert_eq!(count, 0, "rule in skip set should be filtered");
    }

    #[test]
    fn test_file_too_large() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.yml");
        // Write a file larger than MAX_RULE_FILE_SIZE
        std::fs::write(&path, vec![b'x'; (MAX_RULE_FILE_SIZE + 1) as usize]).unwrap();

        let mut engine = SigmaEngine::new();
        let count = engine
            .load_rules_from_dirs(&[dir.path()], &HashSet::new(), &default_filter())
            .unwrap();

        assert_eq!(count, 0, "oversized file should be skipped");
    }

    #[test]
    fn test_hidden_files_skipped() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(".hidden.yml");
        std::fs::write(&path, &windows_rule("test-005", "windows")).unwrap();

        let mut engine = SigmaEngine::new();
        let count = engine
            .load_rules_from_dirs(&[dir.path()], &HashSet::new(), &default_filter())
            .unwrap();

        assert_eq!(count, 0, "hidden files should be skipped");
    }

    #[test]
    fn test_macos_rule_filtered() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.yml");
        std::fs::write(&path, &windows_rule("test-007", "macos")).unwrap();

        let mut engine = SigmaEngine::new();
        let count = engine
            .load_rules_from_dirs(&[dir.path()], &HashSet::new(), &default_filter())
            .unwrap();

        assert_eq!(count, 0, "macos rule should be filtered out");
    }

    fn rule_with_service(id: &str, service: &str) -> String {
        format!(
            r#"title: Test Rule
id: {}
logsource:
    product: windows
    service: {}
detection:
    selection:
        CommandLine|contains: 'test'
    condition: selection
"#,
            id, service
        )
    }

    fn rule_with_category(id: &str, service: &str, category: &str) -> String {
        format!(
            r#"title: Test Rule
id: {}
logsource:
    product: windows
    service: {}
    category: {}
detection:
    selection:
        CommandLine|contains: 'test'
    condition: selection
"#,
            id, service, category
        )
    }

    #[test]
    fn test_active_services_tracked() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.yml");
        std::fs::write(&path, &rule_with_service("test-svc-1", "sysmon")).unwrap();

        let mut engine = SigmaEngine::new();
        let count = engine
            .load_rules_from_dirs(&[dir.path()], &HashSet::new(), &default_filter())
            .unwrap();

        assert_eq!(count, 1);
        assert!(engine.active_services().contains("sysmon"));
        assert!(engine.all_services().contains("sysmon"));
        assert!(engine.active_categories().is_empty());
        assert!(engine.all_categories().is_empty());
    }

    #[test]
    fn test_skipped_rule_service_in_all_not_active() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.yml");
        std::fs::write(&path, &rule_with_service("test-svc-2", "powershell")).unwrap();

        let mut skip = HashSet::new();
        skip.insert("test-svc-2".to_string());

        let mut engine = SigmaEngine::new();
        let count = engine
            .load_rules_from_dirs(&[dir.path()], &skip, &default_filter())
            .unwrap();

        assert_eq!(count, 0);
        assert!(engine.all_services().contains("powershell"));
        assert!(!engine.active_services().contains("powershell"));
        assert!(engine.all_categories().is_empty());
        assert!(engine.active_categories().is_empty());
    }

    #[test]
    fn test_rule_without_service_no_tracking() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.yml");
        std::fs::write(&path, &no_product_rule("test-svc-3")).unwrap();

        let mut engine = SigmaEngine::new();
        let count = engine
            .load_rules_from_dirs(&[dir.path()], &HashSet::new(), &default_filter())
            .unwrap();

        assert_eq!(count, 1);
        assert!(engine.active_services().is_empty());
        assert!(engine.all_services().is_empty());
        assert!(engine.active_categories().is_empty());
        assert!(engine.all_categories().is_empty());
    }

    #[test]
    fn test_category_tracking_active() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.yml");
        std::fs::write(
            &path,
            &rule_with_category("test-cat-1", "sysmon", "process_creation"),
        )
        .unwrap();

        let mut engine = SigmaEngine::new();
        let count = engine
            .load_rules_from_dirs(&[dir.path()], &HashSet::new(), &default_filter())
            .unwrap();

        assert_eq!(count, 1);
        assert!(engine.active_services().contains("sysmon"));
        assert!(engine.all_services().contains("sysmon"));
        assert!(engine.active_categories().contains("process_creation"));
        assert!(engine.all_categories().contains("process_creation"));
    }

    #[test]
    fn test_category_tracking_skipped() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.yml");
        let _ = std::fs::write(
            &path,
            &rule_with_category("test-cat-2", "sysmon", "registry"),
        );

        let mut skip = HashSet::new();
        skip.insert("test-cat-2".to_string());

        let mut engine = SigmaEngine::new();
        let count = engine
            .load_rules_from_dirs(&[dir.path()], &skip, &default_filter())
            .unwrap();

        assert_eq!(count, 0);
        assert!(engine.all_services().contains("sysmon"));
        assert!(!engine.active_services().contains("sysmon"));
        assert!(engine.all_categories().contains("registry"));
        assert!(!engine.active_categories().contains("registry"));
    }

    #[test]
    fn test_linux_rule_not_in_all_services() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.yml");
        std::fs::write(&path, &windows_rule("test-linux-1", "linux")).unwrap();

        let mut engine = SigmaEngine::new();
        let count = engine
            .load_rules_from_dirs(&[dir.path()], &HashSet::new(), &default_filter())
            .unwrap();

        assert_eq!(count, 0);
        assert!(
            engine.all_services().is_empty(),
            "linux rules should not contribute to all_services"
        );
        assert!(
            engine.all_categories().is_empty(),
            "linux rules should not contribute to all_categories"
        );
    }

    #[test]
    fn test_uppercase_yml_extension() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.YML");
        std::fs::write(&path, &windows_rule("test-006", "windows")).unwrap();

        let mut engine = SigmaEngine::new();
        let count = engine
            .load_rules_from_dirs(&[dir.path()], &HashSet::new(), &default_filter())
            .unwrap();

        assert_eq!(count, 1, "uppercase .YML should be recognized");
    }

    fn rule_with_status(id: &str, status: &str) -> String {
        format!(
            r#"title: Test Rule
id: {}
status: {}
logsource:
    product: windows
    service: process
detection:
    selection:
        CommandLine|contains: 'test'
    condition: selection
"#,
            id, status
        )
    }

    fn rule_with_level(id: &str, level: &str) -> String {
        format!(
            r#"title: Test Rule
id: {}
level: {}
logsource:
    product: windows
    service: process
detection:
    selection:
        CommandLine|contains: 'test'
    condition: selection
"#,
            id, level
        )
    }

    fn rule_with_status_level(id: &str, status: &str, level: &str) -> String {
        format!(
            r#"title: Test Rule
id: {}
status: {}
level: {}
logsource:
    product: windows
    service: process
detection:
    selection:
        CommandLine|contains: 'test'
    condition: selection
"#,
            id, status, level
        )
    }

    #[test]
    fn test_status_experimental_accepted_by_default() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.yml");
        std::fs::write(&path, &rule_with_status("test-exp-1", "experimental")).unwrap();

        let mut engine = SigmaEngine::new();
        let count = engine
            .load_rules_from_dirs(&[dir.path()], &HashSet::new(), &default_filter())
            .unwrap();
        assert_eq!(
            count, 1,
            "experimental accepted when min_status=unsupported"
        );
    }

    #[test]
    fn test_status_test_accepted_by_default() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.yml");
        std::fs::write(&path, &rule_with_status("test-test-1", "test")).unwrap();

        let mut engine = SigmaEngine::new();
        let count = engine
            .load_rules_from_dirs(&[dir.path()], &HashSet::new(), &default_filter())
            .unwrap();
        assert_eq!(count, 1, "test accepted when min_status=unsupported");
    }

    #[test]
    fn test_status_stable_accepted_by_default() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.yml");
        std::fs::write(&path, &rule_with_status("test-stable-1", "stable")).unwrap();

        let mut engine = SigmaEngine::new();
        let count = engine
            .load_rules_from_dirs(&[dir.path()], &HashSet::new(), &default_filter())
            .unwrap();
        assert_eq!(count, 1, "stable accepted when min_status=unsupported");
    }

    #[test]
    fn test_status_experimental_rejected_when_min_test() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.yml");
        std::fs::write(&path, &rule_with_status("test-exp-2", "experimental")).unwrap();

        let filter = SigmaFilterConfig {
            min_status: MinStatus::Test,
            min_level: MinLevel::Informational,
        };
        let mut engine = SigmaEngine::new();
        let count = engine
            .load_rules_from_dirs(&[dir.path()], &HashSet::new(), &filter)
            .unwrap();
        assert_eq!(count, 0, "experimental rejected when min_status=test");
    }

    #[test]
    fn test_status_test_accepted_when_min_test() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.yml");
        std::fs::write(&path, &rule_with_status("test-test-2", "test")).unwrap();

        let filter = SigmaFilterConfig {
            min_status: MinStatus::Test,
            min_level: MinLevel::Informational,
        };
        let mut engine = SigmaEngine::new();
        let count = engine
            .load_rules_from_dirs(&[dir.path()], &HashSet::new(), &filter)
            .unwrap();
        assert_eq!(count, 1, "test accepted when min_status=test");
    }

    #[test]
    fn test_status_stable_accepted_when_min_stable() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.yml");
        std::fs::write(&path, &rule_with_status("test-stable-2", "stable")).unwrap();

        let filter = SigmaFilterConfig {
            min_status: MinStatus::Stable,
            min_level: MinLevel::Informational,
        };
        let mut engine = SigmaEngine::new();
        let count = engine
            .load_rules_from_dirs(&[dir.path()], &HashSet::new(), &filter)
            .unwrap();
        assert_eq!(count, 1, "stable accepted when min_status=stable");
    }

    #[test]
    fn test_status_test_rejected_when_min_stable() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.yml");
        std::fs::write(&path, &rule_with_status("test-test-3", "test")).unwrap();

        let filter = SigmaFilterConfig {
            min_status: MinStatus::Stable,
            min_level: MinLevel::Informational,
        };
        let mut engine = SigmaEngine::new();
        let count = engine
            .load_rules_from_dirs(&[dir.path()], &HashSet::new(), &filter)
            .unwrap();
        assert_eq!(count, 0, "test rejected when min_status=stable");
    }

    #[test]
    fn test_level_informational_accepted_by_default() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.yml");
        std::fs::write(&path, &rule_with_level("test-lvl-info", "informational")).unwrap();

        let mut engine = SigmaEngine::new();
        let count = engine
            .load_rules_from_dirs(&[dir.path()], &HashSet::new(), &default_filter())
            .unwrap();
        assert_eq!(
            count, 1,
            "informational accepted when min_level=informational"
        );
    }

    #[test]
    fn test_level_low_rejected_when_min_medium() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.yml");
        std::fs::write(&path, &rule_with_level("test-lvl-low", "low")).unwrap();

        let filter = SigmaFilterConfig {
            min_status: MinStatus::Unsupported,
            min_level: MinLevel::Medium,
        };
        let mut engine = SigmaEngine::new();
        let count = engine
            .load_rules_from_dirs(&[dir.path()], &HashSet::new(), &filter)
            .unwrap();
        assert_eq!(count, 0, "low rejected when min_level=medium");
    }

    #[test]
    fn test_level_medium_accepted_when_min_medium() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.yml");
        std::fs::write(&path, &rule_with_level("test-lvl-med", "medium")).unwrap();

        let filter = SigmaFilterConfig {
            min_status: MinStatus::Unsupported,
            min_level: MinLevel::Medium,
        };
        let mut engine = SigmaEngine::new();
        let count = engine
            .load_rules_from_dirs(&[dir.path()], &HashSet::new(), &filter)
            .unwrap();
        assert_eq!(count, 1, "medium accepted when min_level=medium");
    }

    #[test]
    fn test_level_critical_accepted_when_min_high() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.yml");
        std::fs::write(&path, &rule_with_level("test-lvl-crit", "critical")).unwrap();

        let filter = SigmaFilterConfig {
            min_status: MinStatus::Unsupported,
            min_level: MinLevel::High,
        };
        let mut engine = SigmaEngine::new();
        let count = engine
            .load_rules_from_dirs(&[dir.path()], &HashSet::new(), &filter)
            .unwrap();
        assert_eq!(count, 1, "critical accepted when min_level=high");
    }

    #[test]
    fn test_level_high_rejected_when_min_critical() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.yml");
        std::fs::write(&path, &rule_with_level("test-lvl-high", "high")).unwrap();

        let filter = SigmaFilterConfig {
            min_status: MinStatus::Unsupported,
            min_level: MinLevel::Critical,
        };
        let mut engine = SigmaEngine::new();
        let count = engine
            .load_rules_from_dirs(&[dir.path()], &HashSet::new(), &filter)
            .unwrap();
        assert_eq!(count, 0, "high rejected when min_level=critical");
    }

    #[test]
    fn test_status_level_combined_filter() {
        let dir = tempfile::tempdir().unwrap();

        // experimental + critical → rejected (status too low)
        let path1 = dir.path().join("test1.yml");
        std::fs::write(
            &path1,
            &rule_with_status_level("test-combo-1", "experimental", "critical"),
        )
        .unwrap();

        // test + high → accepted
        let path2 = dir.path().join("test2.yml");
        std::fs::write(
            &path2,
            &rule_with_status_level("test-combo-2", "test", "high"),
        )
        .unwrap();

        // stable + low → rejected (level too low)
        let path3 = dir.path().join("test3.yml");
        std::fs::write(
            &path3,
            &rule_with_status_level("test-combo-3", "stable", "low"),
        )
        .unwrap();

        // stable + high → accepted
        let path4 = dir.path().join("test4.yml");
        std::fs::write(
            &path4,
            &rule_with_status_level("test-combo-4", "stable", "high"),
        )
        .unwrap();

        let filter = SigmaFilterConfig {
            min_status: MinStatus::Test,
            min_level: MinLevel::Medium,
        };
        let mut engine = SigmaEngine::new();
        let count = engine
            .load_rules_from_dirs(&[dir.path()], &HashSet::new(), &filter)
            .unwrap();
        assert_eq!(count, 2, "only test+high and stable+high should pass");
    }

    #[test]
    fn test_rule_without_status_accepted() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.yml");
        std::fs::write(&path, &windows_rule("test-nostatus", "windows")).unwrap();

        let filter = SigmaFilterConfig {
            min_status: MinStatus::Stable,
            min_level: MinLevel::Critical,
        };
        let mut engine = SigmaEngine::new();
        let count = engine
            .load_rules_from_dirs(&[dir.path()], &HashSet::new(), &filter)
            .unwrap();
        assert_eq!(
            count, 1,
            "rule without status/level should be accepted (no metadata = pass-through)"
        );
    }

    #[test]
    fn test_config_yaml_with_sigma_filter() {
        let yaml = r#"
author: testuser
email: user@example.com
log:
  level_file: info
sigma:
  min_status: stable
  min_level: high
"#;
        let config: Config = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(config.sigma.min_status, MinStatus::Stable);
        assert_eq!(config.sigma.min_level, MinLevel::High);
    }

    #[test]
    fn test_config_yaml_defaults_sigma_filter() {
        let yaml = r#"
author: testuser
email: user@example.com
log:
  level_file: info
"#;
        let config: Config = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(config.sigma.min_status, MinStatus::Stable);
        assert_eq!(config.sigma.min_level, MinLevel::Critical);
    }
}
