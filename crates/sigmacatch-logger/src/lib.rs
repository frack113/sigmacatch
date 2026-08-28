// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 sigmacatch contributors

//! Two-layer tracing subscriber:
//! - **stderr**: human-readable format (level + message), info level by default
//! - **file**: structured format (module, file, line), configurable level

use sigmacatch_config::Config;
use std::fs;
use std::path::PathBuf;
use thiserror::Error;
use tracing_appender::non_blocking::WorkerGuard;
use tracing_appender::rolling::InitError;
use tracing_subscriber::{
    EnvFilter, Layer, Registry, filter::Directive, fmt, layer::SubscriberExt,
    util::SubscriberInitExt,
};

/// The `evtx` crate logs `info!("Initializing string cache")` once per parsed
/// EVTX chunk; with large exported files this floods both layers. The noise is
/// suppressed at `warn` for that target only.
const EVTX_NOISE_DIRECTIVE: &str = "evtx=warn";

/// Errors raised while initialising the two logging layers.
#[derive(Debug, Error)]
pub enum LoggerError {
    /// The destination log directory could not be created.
    #[error("failed to create log directory {path}: {source}")]
    CreateLogDir {
        /// The directory that could not be created.
        path: PathBuf,
        /// The underlying filesystem error.
        source: std::io::Error,
    },
    /// The rolling file appender could not be opened for writing.
    #[error("failed to build rolling file appender: {0}")]
    RollingAppender(#[from] InitError),
}

/// Initialise les deux couches de logging : stderr lisible + fichier structuré.
/// When `verbose` is false, stderr only shows `error` level messages.
pub fn init(config: &Config, verbose: bool) -> Result<WorkerGuard, LoggerError> {
    let log_dir = PathBuf::from("logs");
    fs::create_dir_all(&log_dir).map_err(|source| LoggerError::CreateLogDir {
        path: log_dir.clone(),
        source,
    })?;

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
        .build(&log_dir)?;
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
