// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 sigmacatch contributors

use anyhow::{Context, Result};
use std::collections::HashSet;
use std::path::{Path, PathBuf};
use tracing::warn;

use super::IncompleteReason;

/// Représente un triplet de régression complet (info.yml + .json + .evtx).
#[allow(dead_code)]
#[derive(Debug)]
pub struct RegressionTriplet {
    pub info_yml: PathBuf,
    pub json: PathBuf,
    pub evtx: PathBuf,
    pub rule_id: String,
}

/// État de complétude d'un triplet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TripletStatus {
    Complete,
    Incomplete(IncompleteReason),
}

/// Parse le rule_id depuis `rule_metadata[0].id` d'un fichier info.yml.
///
/// Le rule_id canonique est toujours le premier élément de la séquence
/// `rule_metadata` dans le YAML. Le champ `id` au root (instance ID) est ignoré.
pub fn read_rule_id(path: &Path) -> Result<String> {
    let bytes = std::fs::read(path)
        .with_context(|| format!("Failed to read info.yml: {}", path.display()))?;
    let content = std::str::from_utf8(&bytes)
        .with_context(|| format!("Non-UTF8 info.yml: {}", path.display()))?;
    let content = content.strip_prefix('\u{FEFF}').unwrap_or(content);

    let val: serde_yaml::Value = serde_yaml::from_str(content)
        .with_context(|| format!("Invalid YAML: {}", path.display()))?;

    // rule_metadata[0].id — identifiant canonique
    if let Some(id) = val
        .get("rule_metadata")
        .and_then(|m| m.as_sequence())
        .and_then(|seq| seq.first())
        .and_then(|item| item.get("id"))
        .and_then(|id| id.as_str())
    {
        if !id.is_empty() {
            return Ok(id.to_string());
        }
    }

    anyhow::bail!("No rule_metadata[0].id found in {}", path.display())
}

/// Valide un rule_id au format attendu.
///
/// Accepte :
/// - UUID v4 (`8-4-4-4-12`, hex minuscule)
/// - Alphanumeric + underscores + hyphens (lowercase)
pub fn validate_rule_id(id: &str) -> bool {
    if id.is_empty() {
        return false;
    }
    if is_uuid_v4(id) {
        return true;
    }
    id.chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_' || c == '-')
}

fn is_uuid_v4(id: &str) -> bool {
    if id.len() != 36 {
        return false;
    }
    let bytes = id.as_bytes();
    if bytes[8] != b'-' || bytes[13] != b'-' || bytes[18] != b'-' || bytes[23] != b'-' {
        return false;
    }
    for (i, &b) in bytes.iter().enumerate() {
        if i == 8 || i == 13 || i == 18 || i == 23 {
            continue;
        }
        if !b.is_ascii_hexdigit() {
            return false;
        }
    }
    if bytes[14] != b'4' {
        return false;
    }
    matches!(bytes[19], b'8' | b'9' | b'a' | b'b')
}

/// Vérifie la complétude d'un triplet dans un dossier donné.
///
/// Cherche `<rule_id>.json` et `<rule_id>.evtx` dans le même dossier que
/// l'info.yml. Retourne `Complete` si les deux fichiers existent, ou
/// `Incomplete(reason)` si l'un ou les deux manquent.
pub fn validate_triplet(dir: &Path, rule_id: &str) -> TripletStatus {
    let json_path = dir.join(format!("{}.json", rule_id));
    let evtx_path = dir.join(format!("{}.evtx", rule_id));

    let json_exists = json_path.exists();
    let evtx_exists = evtx_path.exists();

    if json_exists && evtx_exists {
        TripletStatus::Complete
    } else {
        TripletStatus::Incomplete(match (json_exists, evtx_exists) {
            (true, false) => IncompleteReason::MissingEvtx,
            (false, true) => IncompleteReason::MissingJson,
            _ => IncompleteReason::MissingJsonAndEvtx,
        })
    }
}

/// Scanne récursivement un dossier pour collecter les rule_id depuis les info.yml.
///
/// Retourne un ensemble de (rule_id, chemin info.yml) pour tous les triplets
/// complets trouvés. Les triplets incomplets et les fichiers invalides sont
/// loggés mais ignorés.
#[allow(dead_code)]
pub fn scan_rule_ids(dir: &Path) -> Vec<(String, PathBuf)> {
    let mut results = Vec::new();
    scan_rule_ids_inner(dir, &mut results, 0, 64);
    results
}

#[allow(dead_code)]
fn scan_rule_ids_inner(
    dir: &Path,
    results: &mut Vec<(String, PathBuf)>,
    depth: u32,
    max_depth: u32,
) {
    if depth > max_depth {
        return;
    }

    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return,
    };

    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            scan_rule_ids_inner(&path, results, depth + 1, max_depth);
        } else if path.file_name() == Some(std::ffi::OsStr::new("info.yml")) {
            match read_rule_id(&path) {
                Ok(rule_id) => {
                    if validate_rule_id(&rule_id) {
                        if let Some(parent) = path.parent() {
                            match validate_triplet(parent, &rule_id) {
                                TripletStatus::Complete => {
                                    results.push((rule_id, path));
                                }
                                TripletStatus::Incomplete(reason) => {
                                    warn!(
                                        "Incomplete triplet for rule '{}' at {:?}: {:?}",
                                        rule_id, path, reason
                                    );
                                }
                            }
                        }
                    } else {
                        warn!("Invalid rule_id '{}' at {:?}", rule_id, path);
                    }
                }
                Err(e) => {
                    warn!("Failed to read rule_id from {:?}: {}", path, e);
                }
            }
        }
    }
}

/// Construit un HashSet de rule_id depuis plusieurs dossiers.
///
/// Utile pour le skip set : collecte tous les rule_id UUID des triplets
/// complets trouvés dans les dossiers donnés.
#[allow(dead_code)]
pub fn build_rule_id_set(dirs: &[&Path]) -> HashSet<String> {
    let mut ids = HashSet::new();
    for dir in dirs {
        if !dir.exists() {
            warn!("Directory not found for rule_id scan: {:?}", dir);
            continue;
        }
        for (rule_id, _) in scan_rule_ids(dir) {
            ids.insert(rule_id);
        }
    }
    ids
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

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
    fn test_read_rule_id_basic() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("info.yml");
        std::fs::write(
            &path,
            valid_info_yml("d059842b-6b9d-4ed1-b5c3-5b89143c6ede"),
        )
        .unwrap();

        let id = read_rule_id(&path).unwrap();
        assert_eq!(id, "d059842b-6b9d-4ed1-b5c3-5b89143c6ede");
    }

    #[test]
    fn test_read_rule_id_bom() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("info.yml");
        std::fs::write(&path, format!("\u{FEFF}{}", valid_info_yml("abc-def-123"))).unwrap();

        let id = read_rule_id(&path).unwrap();
        assert_eq!(id, "abc-def-123");
    }

    #[test]
    fn test_read_rule_id_missing_metadata() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("info.yml");
        std::fs::write(&path, "id: test\ndescription: N/A\n").unwrap();

        assert!(read_rule_id(&path).is_err());
    }

    #[test]
    fn test_validate_rule_id_valid_uuid() {
        assert!(validate_rule_id("d059842b-6b9d-4ed1-b5c3-5b89143c6ede"));
    }

    #[test]
    fn test_validate_rule_id_valid_alphanumeric() {
        assert!(validate_rule_id("proc_creation_win_bitsadmin_download"));
    }

    #[test]
    fn test_validate_rule_id_invalid() {
        assert!(!validate_rule_id("INVALID_ID!"));
        assert!(!validate_rule_id(""));
        assert!(!validate_rule_id("with spaces"));
    }

    #[test]
    fn test_validate_triplet_complete() {
        let tmp = TempDir::new().unwrap();
        let rule_id = "d059842b-6b9d-4ed1-b5c3-5b89143c6ede";
        std::fs::write(tmp.path().join(format!("{}.json", rule_id)), "{}").unwrap();
        std::fs::write(tmp.path().join(format!("{}.evtx", rule_id)), "").unwrap();

        assert_eq!(
            validate_triplet(tmp.path(), rule_id),
            TripletStatus::Complete
        );
    }

    #[test]
    fn test_validate_triplet_missing_json() {
        let tmp = TempDir::new().unwrap();
        let rule_id = "d059842b-6b9d-4ed1-b5c3-5b89143c6ede";
        std::fs::write(tmp.path().join(format!("{}.evtx", rule_id)), "").unwrap();

        assert_eq!(
            validate_triplet(tmp.path(), rule_id),
            TripletStatus::Incomplete(IncompleteReason::MissingJson)
        );
    }

    #[test]
    fn test_validate_triplet_missing_evtx() {
        let tmp = TempDir::new().unwrap();
        let rule_id = "d059842b-6b9d-4ed1-b5c3-5b89143c6ede";
        std::fs::write(tmp.path().join(format!("{}.json", rule_id)), "{}").unwrap();

        assert_eq!(
            validate_triplet(tmp.path(), rule_id),
            TripletStatus::Incomplete(IncompleteReason::MissingEvtx)
        );
    }

    #[test]
    fn test_scan_rule_ids() {
        let tmp = TempDir::new().unwrap();
        let rule_dir = tmp.path().join("test-rule");
        std::fs::create_dir(&rule_dir).unwrap();
        let rule_id = "d059842b-6b9d-4ed1-b5c3-5b89143c6ede";
        std::fs::write(rule_dir.join("info.yml"), valid_info_yml(rule_id)).unwrap();
        std::fs::write(rule_dir.join(format!("{}.json", rule_id)), "{}").unwrap();
        std::fs::write(rule_dir.join(format!("{}.evtx", rule_id)), "").unwrap();

        let results = scan_rule_ids(tmp.path());
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].0, rule_id);
    }

    #[test]
    fn test_build_rule_id_set() {
        let tmp = TempDir::new().unwrap();
        let rule_dir = tmp.path().join("test-rule");
        std::fs::create_dir(&rule_dir).unwrap();
        let rule_id = "d059842b-6b9d-4ed1-b5c3-5b89143c6ede";
        std::fs::write(rule_dir.join("info.yml"), valid_info_yml(rule_id)).unwrap();
        std::fs::write(rule_dir.join(format!("{}.json", rule_id)), "{}").unwrap();
        std::fs::write(rule_dir.join(format!("{}.evtx", rule_id)), "").unwrap();

        let ids = build_rule_id_set(&[tmp.path()]);
        assert_eq!(ids.len(), 1);
        assert!(ids.contains(rule_id));
    }
}
