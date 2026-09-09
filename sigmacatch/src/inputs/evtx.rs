// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 sigmacatch contributors

//! EVTX one-shot input (feature `evtx`): generate Sigma regression data from
//! EVTX files.
//!
//! Recursively scans a directory for `.evtx` files, parses them, matches against
//! Sigma rules, and generates SigmaHQ-format regression data under
//! `sigma/regression_data/`. Selected by `main.rs` when `--evtx` is present
//! (any platform — file parsing only, no Event Log subscription). The EVTX
//! path is passed in from the shared CLI parse — never scanned again here.

use std::path::{Path, PathBuf};

use anyhow::Result;
use sigmacatch_detection::DetectionEngine;
use sigmacatch_runner::{CollectorKind, DataFormat};
use sigmacatch_types::EventProducer;
use walkdir::WalkDir;

/// Default directory containing EVTX files on a Windows host.
const DEFAULT_EVTX_PATH: &str = r"C:\Windows\System32\winevt\Logs";

struct EvtxCollector {
    files: Vec<PathBuf>,
}

impl CollectorKind for EvtxCollector {
    fn name(&self) -> &'static str {
        "sigmacatch"
    }

    fn mode(&self) -> String {
        "EVTX static files (one-shot)".to_string()
    }

    fn channels(
        &self,
        _engine: &DetectionEngine,
        _custom_map: &std::collections::HashMap<String, String>,
    ) -> Option<Vec<String>> {
        None
    }

    fn build(&self, _channels: &[String]) -> Box<dyn EventProducer> {
        let mut collector = input_windows_evtx::EventCollector::new();
        for path in &self.files {
            collector.add_file(path.clone());
        }
        Box::new(collector)
    }

    fn live_capture(&self) -> bool {
        false
    }

    fn regression_format(&self) -> DataFormat {
        DataFormat::Evtx
    }
}

/// Recursively find all *.evtx files in a directory (case-insensitive).
fn find_evtx_files(dir: &Path) -> Result<Vec<PathBuf>> {
    let mut files = Vec::new();
    for entry in WalkDir::new(dir).follow_links(false).into_iter() {
        let entry = entry.map_err(|e| anyhow::anyhow!("WalkDir error: {e}"))?;
        let path = entry.path();
        if path.is_file()
            && let Some(ext) = path.extension()
            && ext.eq_ignore_ascii_case("evtx")
        {
            files.push(path.to_path_buf());
        }
    }
    files.sort();
    Ok(files)
}

/// Extract the EVTX directory: the explicit `--evtx` value when given,
/// otherwise the default Windows Event Log path.
pub fn evtx_path_or_default(evtx_path: Option<PathBuf>) -> PathBuf {
    evtx_path.unwrap_or_else(|| PathBuf::from(DEFAULT_EVTX_PATH))
}

/// Async entry — selected by `main.rs` when `--evtx` is present.
pub async fn run(evtx_path: Option<PathBuf>) -> Result<()> {
    let evtx_path = evtx_path_or_default(evtx_path);

    if !evtx_path.exists() {
        anyhow::bail!("Path does not exist: {}", evtx_path.display());
    }
    if !evtx_path.is_dir() {
        anyhow::bail!("Path is not a directory: {}", evtx_path.display());
    }

    let files = find_evtx_files(&evtx_path)?;
    if files.is_empty() {
        anyhow::bail!("No EVTX files found in {}", evtx_path.display());
    }
    eprintln!(
        "Found {} EVTX file(s) in {}",
        files.len(),
        evtx_path.display()
    );

    let collector = EvtxCollector { files };
    sigmacatch_runner::run(&collector).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::tempdir;

    #[test]
    fn test_find_evtx_files_empty_dir() {
        let dir = tempdir().unwrap();
        let files = find_evtx_files(dir.path()).unwrap();
        assert!(files.is_empty());
    }

    #[test]
    fn test_find_evtx_files_with_evtx() {
        let dir = tempdir().unwrap();
        let file1 = dir.path().join("test1.evtx");
        let file2 = dir.path().join("test2.EVTX");
        let file3 = dir.path().join("test.txt");
        fs::write(&file1, b"").unwrap();
        fs::write(&file2, b"").unwrap();
        fs::write(&file3, b"").unwrap();

        let files = find_evtx_files(dir.path()).unwrap();
        assert_eq!(files.len(), 2);
        assert!(files.iter().any(|p| p.file_name().unwrap() == "test1.evtx"));
        assert!(files.iter().any(|p| p.file_name().unwrap() == "test2.EVTX"));
    }

    #[test]
    fn test_find_evtx_files_recursive() {
        let dir = tempdir().unwrap();
        let subdir = dir.path().join("subdir");
        fs::create_dir(&subdir).unwrap();
        let file1 = dir.path().join("root.evtx");
        let file2 = subdir.join("nested.evtx");
        fs::write(&file1, b"").unwrap();
        fs::write(&file2, b"").unwrap();

        let files = find_evtx_files(dir.path()).unwrap();
        assert_eq!(files.len(), 2);
    }
}
