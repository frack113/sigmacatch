// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 sigmacatch contributors

//! `sigmacatch` — single binary. The input is chosen at runtime:
//! - `--evtx <PATH>` → one-shot EVTX collector (feature `evtx`);
//! - otherwise the Winevt live collector (feature `winevt`, Windows);
//! - otherwise the Linux collectors (features `auditd`, `builtin`, `sysmon`,
//!   `ebpf`);
//! - otherwise the macOS Endpoint Security collector (feature `macos`).
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
use sigmacatch::outputs::regression_sink_factory;

#[tokio::main]
async fn main() -> Result<()> {
    // Diagnostics first: the subcommands must work on machines with no local
    // log source; only the collection loop requires one.
    if let Some(code) = sigmacatch::cli::dispatch() {
        std::process::exit(code);
    }
    // Single argument parse for the whole run (help/unknown flags, --evtx…).
    let cli = parse_args();
    let factory = regression_sink_factory();
    if cli.evtx_path.is_some() {
        return run_evtx(cli.evtx_path, factory).await;
    }
    dispatch_collector(factory).await
}

#[allow(unused_variables)]
async fn run_evtx(
    evtx_path: Option<PathBuf>,
    factory: &dyn sigmacatch::RegressionSinkFactory,
) -> Result<()> {
    #[cfg(feature = "evtx")]
    {
        sigmacatch::inputs::evtx::run(evtx_path, factory).await
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
/// a given build either one platform arm consumes `factory` or no arm is live,
/// which makes the trailing bail unreachable. The `#[allow]` covers both
/// build-dependent unused bindings.
#[allow(unreachable_code, unused_variables)]
async fn dispatch_collector(factory: &dyn sigmacatch::RegressionSinkFactory) -> Result<()> {
    #[cfg(all(target_os = "windows", feature = "winevt"))]
    {
        return sigmacatch::inputs::windows::run(factory).await;
    }
    #[cfg(all(target_os = "macos", feature = "macos"))]
    {
        return sigmacatch::inputs::macos_es::run(factory).await;
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
        return sigmacatch::inputs::linux::run(factory).await;
    }
    anyhow::bail!(
        "no usable input compiled into this build — rebuild with one of:\n  \
         --features winevt           Windows, live Event Log (default)\n  \
         --features evtx             one-shot EVTX files, any platform\n  \
         --features macos            macOS Endpoint Security\n  \
         --no-default-features --features auditd,builtin   Linux inputs\n  \
         optionally append ,sysmon or ,ebpf to the Linux set"
    )
}
