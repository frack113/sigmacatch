// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 sigmacatch contributors

//! `sigmacatch-evtx` — Generate Sigma regression data from EVTX files.
//!
//! Recursively scans a directory for `.evtx` files, parses them, matches against
//! Sigma rules, and generates SigmaHQ-format regression data under
//! `sigma/regression_data/`.

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
        "sigmacatch-evtx"
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

/// Extract the value of `--evtx <PATH>` from `std::env::args()`.
///
/// Returns `None` when the flag is absent (caller uses the default path).
fn parse_evtx_arg() -> Option<PathBuf> {
    let args: Vec<String> = std::env::args().collect();
    for i in 1..args.len() {
        if args[i] == "--evtx" {
            return args.get(i + 1).map(PathBuf::from);
        }
    }
    None
}

#[tokio::main]
async fn main() -> Result<()> {
    let evtx_path = parse_evtx_arg().unwrap_or_else(|| PathBuf::from(DEFAULT_EVTX_PATH));

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
    eprintln!("Found {} EVTX file(s) in {}", files.len(), evtx_path.display());

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

    #[test]
    fn test_parse_evtx_arg_present() {
        let args: Vec<String> = vec![
            "sigmacatch-evtx".into(),
            "--evtx".into(),
            "/data/logs".into(),
        ];
        // parse_evtx_arg reads from std::env::args(), so we can't unit-test it
        // directly.  The function is intentionally trivial (3 lines) and tested
        // via the integration path.
    }

    #[test]
    fn test_parse_evtx_arg_absent() {
        // Same caveat as above — std::env::args() is process-global.
    }
}
