// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 sigmacatch contributors

//! Two-layer tracing subscriber:
//! - **stderr**: human-readable format (level + message), info level by default
//! - **file**: structured format (module, file, line), configurable level

use anyhow::{Context, Result};
use sigmacatch_config::Config;
use std::fs;
use std::path::PathBuf;
use tracing_appender::non_blocking::WorkerGuard;
use tracing_subscriber::{
    filter::Directive, fmt, layer::SubscriberExt, util::SubscriberInitExt, EnvFilter, Layer,
    Registry,
};

/// The `evtx` crate logs `info!("Initializing string cache")` once per parsed
/// EVTX chunk; with large exported files this floods both layers. The noise is
/// suppressed at `warn` for that target only.
const EVTX_NOISE_DIRECTIVE: &str = "evtx=warn";

/// Initialise les deux couches de logging : stderr lisible + fichier structuré.
/// When `verbose` is false, stderr only shows `error` level messages.
pub fn init(config: &Config, verbose: bool) -> Result<WorkerGuard> {
    let log_dir = PathBuf::from("logs");
    fs::create_dir_all(&log_dir)
        .with_context(|| format!("Failed to create log directory: {}", log_dir.display()))?;

    let stderr_filter = if verbose {
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"))
    } else {
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("error"))
    }
    .add_directive(noise_directive());

    let stderr_layer = fmt::layer()
        .with_writer(std::io::stderr)
        .with_target(false)
        .with_file(false)
        .with_line_number(false)
        .with_filter(stderr_filter);

    let file_appender = tracing_appender::rolling::RollingFileAppender::builder()
        .rotation(tracing_appender::rolling::Rotation::DAILY)
        .max_log_files(3)
        .filename_prefix("sigmacatch")
        .filename_suffix("log")
        .build(&log_dir)
        .expect("failed to build rolling file appender");
    let (non_blocking, guard) = tracing_appender::non_blocking(file_appender);

    let file_filter =
        EnvFilter::new(config.log.level_file.as_str()).add_directive(noise_directive());

    let file_layer = fmt::layer()
        .with_writer(non_blocking)
        .with_target(true)
        .with_file(true)
        .with_line_number(true)
        .with_ansi(false)
        .with_filter(file_filter);

    Registry::default()
        .with(stderr_layer)
        .with(file_layer)
        .init();

    Ok(guard)
}

fn noise_directive() -> Directive {
    EVTX_NOISE_DIRECTIVE.parse().expect("valid directive")
}
