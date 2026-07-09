use crate::config::Config;
use anyhow::{Context, Result};
use std::fs;
use std::path::PathBuf;
use tracing_appender::non_blocking::WorkerGuard;
use tracing_subscriber::{
    fmt, layer::SubscriberExt, util::SubscriberInitExt, EnvFilter, Layer, Registry,
};

#[cfg(windows)]
fn setup_windows_console() {
    use windows::Win32::System::Console::*;
    unsafe {
        let _ = SetConsoleOutputCP(65001);
        if let Ok(handle) = GetStdHandle(STD_OUTPUT_HANDLE) {
            let mut mode = CONSOLE_MODE::default();
            if GetConsoleMode(handle, &mut mode).is_ok() {
                mode |= ENABLE_VIRTUAL_TERMINAL_PROCESSING;
                let _ = SetConsoleMode(handle, mode);
            }
        }
    }
}

pub fn init(config: &Config) -> Result<WorkerGuard> {
    #[cfg(windows)]
    setup_windows_console();

    let log_dir = PathBuf::from("logs");
    fs::create_dir_all(&log_dir)
        .with_context(|| format!("Failed to create log directory: {}", log_dir.display()))?;

    if config.log.clear_on_start {
        let canonical_log_dir = log_dir
            .canonicalize()
            .with_context(|| format!("Failed to resolve log directory: {}", log_dir.display()))?;
        if let Ok(entries) = fs::read_dir(&log_dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.extension().is_some_and(|e| e == "log") {
                    if let Ok(canonical_entry) = path.canonicalize() {
                        if canonical_entry.starts_with(&canonical_log_dir) {
                            let _ = fs::remove_file(&path);
                        }
                    }
                }
            }
        }
    }

    let stderr_filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));

    let stderr_layer = fmt::layer()
        .with_writer(std::io::stderr)
        .with_filter(stderr_filter);

    let file_appender = tracing_appender::rolling::RollingFileAppender::builder()
        .rotation(tracing_appender::rolling::Rotation::DAILY)
        .filename_prefix("sigma-regression")
        .filename_suffix("log")
        .build(&log_dir)
        .expect("failed to build rolling file appender");
    let (non_blocking, guard) = tracing_appender::non_blocking(file_appender);

    let file_filter = EnvFilter::new(&config.log.level_file);

    let file_layer = fmt::layer()
        .with_writer(non_blocking)
        .with_ansi(false)
        .with_filter(file_filter);

    Registry::default()
        .with(stderr_layer)
        .with(file_layer)
        .init();

    Ok(guard)
}
