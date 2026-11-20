// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 sigmacatch contributors

//! `sigmacatch` — single binary. The input is chosen at runtime:
//! - `--evtx <PATH>` → one-shot EVTX collector (feature `evtx`);
//! - otherwise the Winevt live collector (feature `winevt`, Windows);
//! - otherwise the Linux collectors (features `auditd`, `builtin`, `sysmon`,
//!   `ebpf`).
//!
//! Cargo features select which inputs are compiled in; requesting an unbuilt
//! input is a clear startup error.
//!
//! CLI parsing is single-sourced in [`sigmacatch::config::parse_args`]
//! (`CliArgs`): the `--evtx` presence test and the EVTX path both come from
//! the same parse, never an ad-hoc `argv` scan.

use std::path::PathBuf;

use anyhow::Result;
use sigmacatch::config::parse_args;

#[tokio::main]
async fn main() -> Result<()> {
    // Diagnostics first: the subcommands must work on machines with no local
    // log source; only the collection loop requires one.
    if let Some(code) = sigmacatch::cli::dispatch() {
        std::process::exit(code);
    }
    // Single argument parse for the whole run (help/unknown flags, --evtx…,
    // --macos-path…).
    let cli = parse_args();
    if cli.evtx_path.is_some() {
        return run_evtx(cli.evtx_path).await;
    }
    if cli.macos_path.is_some() {
        return run_macos(cli.macos_path).await;
    }
    dispatch_collector().await
}

/// One-shot EVTX input, cross-platform. `evtx_path` is unused when the `evtx`
/// input isn't compiled in (the eager `--evtx` check still bails clearly).
#[allow(unused_variables)]
async fn run_macos(macos_path: Option<PathBuf>) -> Result<()> {
    #[cfg(all(target_os = "macos", feature = "macos"))]
    {
        if let Some(path) = macos_path {
            sigmacatch::inputs::macos::run_with_path(path).await
        } else {
            sigmacatch::inputs::macos::run().await
        }
    }
    #[cfg(not(all(target_os = "macos", feature = "macos")))]
    {
        anyhow::bail!(
            "--macos-path requested but the `macos` input is not compiled in; \
             rebuild with `--features macos`"
        )
    }
}

#[allow(unused_variables)]
async fn run_evtx(evtx_path: Option<PathBuf>) -> Result<()> {
    #[cfg(feature = "evtx")]
    {
        sigmacatch::inputs::evtx::run(evtx_path).await
    }
    #[cfg(not(feature = "evtx"))]
    {
        anyhow::bail!(
            "--evtx requested but the `evtx` input is not compiled in; \
             rebuild with `--features evtx`"
        )
    }
}

/// Dispatch to the compiled-in platform input. Each arm is `#[cfg]`-gated; on
/// a given build exactly one platform arm is live, so the trailing bail is
/// unreachable there (allowed).
#[allow(unreachable_code)]
async fn dispatch_collector() -> Result<()> {
    #[cfg(all(target_os = "windows", feature = "winevt"))]
    {
        return sigmacatch::inputs::windows::run().await;
    }
    #[cfg(all(target_os = "macos", feature = "macos"))]
    {
        return sigmacatch::inputs::macos::run().await;
    }
    #[cfg(all(
        target_os = "linux",
        any(
            feature = "auditd",
            feature = "builtin",
            feature = "sysmon",
            feature = "ebpf"
        )
    ))]
    {
        return sigmacatch::inputs::linux::run().await;
    }
    anyhow::bail!(
        "no usable input compiled into this build — rebuild with one of:\n  \
         --features winevt           Windows, live Event Log (default)\n  \
         --features evtx             one-shot EVTX files, any platform\n  \
         --features macos            macOS system.log, one-shot\n  \
         --no-default-features --features auditd,builtin   Linux inputs\n  \
         optionally append ,sysmon or ,ebpf to the Linux set"
    )
}
