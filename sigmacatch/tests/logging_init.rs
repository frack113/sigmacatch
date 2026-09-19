// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 sigmacatch contributors

//! Verifies the two-layer tracing setup in its own process: `logging::init`
//! installs a process-global subscriber and writes a rolling file under the
//! current working directory, so a dedicated test binary (own CWD, own
//! subscriber) is the only safe place to exercise it.

use std::path::PathBuf;

use sigmacatch::config::Config;
use sigmacatch::logging::{self, LoggerError};

/// Both init paths, in one test, so they never contend on the process-global
/// subscriber:
/// 1. `logs` pre-created as a *file* → `create_dir_all` fails → `CreateLogDir`.
/// 2. normal init → a `warn!` lands in the structured rolling file, not only
///    on stderr.
#[test]
fn init_failure_then_success_with_file_output() {
    let dir = tempfile::tempdir().expect("tempdir");
    std::env::set_current_dir(dir.path()).expect("chdir to temp dir");

    std::fs::write("logs", b"not a directory").expect("pre-create logs file");
    let err = match logging::init(&Config::default(), false) {
        Ok(_) => panic!("init must fail when `logs` is a file"),
        Err(e) => e,
    };
    assert!(
        matches!(&err, LoggerError::CreateLogDir { path, .. } if path == &PathBuf::from("logs")),
        "reasonably detailed error: {err}"
    );
    std::fs::remove_file("logs").expect("remove logs file");

    let guard = logging::init(&Config::default(), false).expect("init with writable logs dir");
    tracing::warn!("marker-warn-from-logging-test");
    tracing::info!("marker-info-from-logging-test");
    drop(guard); // flush the non-blocking file writer

    let log_file = std::fs::read_dir("logs")
        .expect("logs dir exists")
        .filter_map(Result::ok)
        .map(|e| e.path())
        .find(|p| p.extension().is_some_and(|e| e == "log"))
        .expect("a sigmacatch rolling file was produced");
    let content = std::fs::read_to_string(&log_file).expect("read rolling file");
    assert!(
        content.contains("marker-warn-from-logging-test"),
        "warn must be recorded in the file layer: {content}"
    );
    assert!(
        // The file layer (config.log.level_file, default debug) captures
        // sub-error levels that the non-verbose stderr layer (error) drops.
        content.contains("marker-info-from-logging-test"),
        "info must be recorded in the file layer: {content}"
    );
}
