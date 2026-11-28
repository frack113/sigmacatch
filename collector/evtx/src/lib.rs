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
use sigmacatch_core::exchange::ChannelResolver;
use sigmacatch_core::regression::DataFormat;
use sigmacatch_core::types::EventProducer;
use sigmacatch_runner::CollectorKind;
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
        _resolver: &dyn ChannelResolver,
        _custom_map: &std::collections::HashMap<String, String>,
    ) -> Option<Vec<String>> {
        None
    }

    fn build(&self, _channels: &[String]) -> Box<dyn EventProducer> {
        let mut collector = sigmacatch_core::evtx_reader::EventCollector::new();
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
pub async fn run(
    evtx_path: Option<PathBuf>,
    factory: &dyn sigmacatch_core::RegressionSinkFactory,
) -> Result<()> {
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
    sigmacatch_runner::run(&collector, factory).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::tempdir;

    /// Stub resolver: the EVTX collector never resolves channels.
    struct NoChannels;

    impl ChannelResolver for NoChannels {
        fn resolve_channels(
            &self,
            _custom_map: &std::collections::HashMap<String, String>,
        ) -> Vec<String> {
            Vec::new()
        }
    }

    struct NoSinkFactory;

    impl sigmacatch_core::RegressionSinkFactory for NoSinkFactory {
        fn build(
            &self,
            _path: &std::path::Path,
        ) -> anyhow::Result<Box<dyn sigmacatch_core::RegressionSink>> {
            anyhow::bail!("no sink is needed for these path-validation tests")
        }
    }

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
    fn test_evtx_path_or_default() {
        let explicit = PathBuf::from("/tmp/evtx");
        assert_eq!(evtx_path_or_default(Some(explicit.clone())), explicit);
        assert_eq!(evtx_path_or_default(None), PathBuf::from(DEFAULT_EVTX_PATH));
    }

    #[test]
    fn test_evtx_collector_trait_methods() {
        let collector = EvtxCollector {
            files: vec![PathBuf::from("a.evtx")],
        };
        assert_eq!(collector.name(), "sigmacatch");
        assert!(collector.mode().contains("one-shot"));
        assert!(
            collector
                .channels(&NoChannels, &Default::default())
                .is_none()
        );
        assert!(!collector.live_capture());
        assert!(matches!(collector.regression_format(), DataFormat::Evtx));
    }

    /// `build()` must produce a collector that replays every event of the
    /// configured EVTX files.
    #[tokio::test]
    async fn test_evtx_collector_build_replays_fixture() {
        let fixture = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../common/core/tests/fixtures/sample.evtx");
        if !fixture.exists() {
            return; // fixture absent in some packaging contexts
        }
        let expected = sigmacatch_core::evtx_reader::parse_evtx_file(&fixture)
            .unwrap()
            .len();
        assert!(expected > 0, "fixture should contain events");

        let collector = EvtxCollector {
            files: vec![fixture.clone()],
        };
        let producer = collector.build(&[]);
        let (tx, mut rx) = tokio::sync::mpsc::channel::<sigmacatch_core::types::Event>(256);
        let (_stop_tx, stop_rx) = tokio::sync::watch::channel(false);

        producer.run(tx, stop_rx).await.unwrap();

        let mut got = 0usize;
        while rx.recv().await.is_some() {
            got += 1;
        }
        assert_eq!(got, expected);
    }

    #[tokio::test]
    async fn test_run_missing_path_bails() {
        let err = run(Some(PathBuf::from("/nonexistent/evtx/dir")), &NoSinkFactory)
            .await
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("Path does not exist"),
            "unexpected error: {err}"
        );
    }

    #[tokio::test]
    async fn test_run_file_not_dir_bails() {
        let dir = tempdir().unwrap();
        let file = dir.path().join("not-a-dir.txt");
        fs::write(&file, b"").unwrap();

        let err = run(Some(file), &NoSinkFactory)
            .await
            .unwrap_err()
            .to_string();
        assert!(err.contains("not a directory"), "unexpected error: {err}");
    }

    #[tokio::test]
    async fn test_run_dir_without_evtx_bails() {
        let dir = tempdir().unwrap();

        let err = run(Some(dir.path().to_path_buf()), &NoSinkFactory)
            .await
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("No EVTX files found"),
            "unexpected error: {err}"
        );
    }
}
