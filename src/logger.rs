use crate::config::Config;
use anyhow::{Context, Result};
use std::fs;
use std::path::PathBuf;
use tracing_appender::non_blocking::WorkerGuard;
use tracing_subscriber::{
    fmt, layer::SubscriberExt, util::SubscriberInitExt, EnvFilter, Layer, Registry,
};

/// Initialise les deux couches de logging :
/// - **stderr** : format lisible par un humain (niveau + message), niveau info par défaut
/// - **fichier** : format structuré complet (module, fichier, ligne), niveau configurable
pub fn init(config: &Config) -> Result<WorkerGuard> {
    let log_dir = PathBuf::from("logs");
    fs::create_dir_all(&log_dir)
        .with_context(|| format!("Failed to create log directory: {}", log_dir.display()))?;

    // === Console (stderr) — format lisible ===
    let stderr_filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));

    let stderr_layer = fmt::layer()
        .with_writer(std::io::stderr)
        .with_target(false)
        .with_file(false)
        .with_line_number(false)
        .with_filter(stderr_filter);

    // === Fichier — format structuré complet ===
    let file_appender = tracing_appender::rolling::RollingFileAppender::builder()
        .rotation(tracing_appender::rolling::Rotation::DAILY)
        .max_log_files(3)
        .filename_prefix("sigmacatch")
        .filename_suffix("log")
        .build(&log_dir)
        .expect("failed to build rolling file appender");
    let (non_blocking, guard) = tracing_appender::non_blocking(file_appender);

    let file_filter = EnvFilter::new(config.log.level_file.as_str());

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
