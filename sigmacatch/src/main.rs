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

use anyhow::Result;

fn has_flag(name: &str) -> bool {
    std::env::args().any(|a| a == name)
}

async fn run_evtx() -> Result<()> {
    #[cfg(feature = "evtx")]
    {
        sigmacatch::evtx::run().await
    }
    #[cfg(not(feature = "evtx"))]
    {
        anyhow::bail!(
            "--evtx requested but the `evtx` input is not compiled in; \
             rebuild with `--features evtx`"
        )
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    // Diagnostics first: the subcommands must work on machines with no local
    // log source; only the collection loop requires one.
    if let Some(code) = sigmacatch::cli::dispatch() {
        std::process::exit(code);
    }
    dispatch_collector().await
}

/// Dispatch to the compiled-in input. Each arm is `#[cfg]`-gated; on a given
/// build exactly one platform arm is live, so the trailing bail is
/// unreachable there (allowed).
#[allow(unreachable_code)]
async fn dispatch_collector() -> Result<()> {
    if has_flag("--evtx") {
        return run_evtx().await;
    }
    #[cfg(all(target_os = "windows", feature = "winevt"))]
    {
        return sigmacatch::winevt::run().await;
    }
    #[cfg(all(
        target_os = "linux",
        any(feature = "auditd", feature = "builtin", feature = "sysmon", feature = "ebpf")
    ))]
    {
        return sigmacatch::linux::run().await;
    }
    anyhow::bail!(
        "no usable input compiled into this build — rebuild with one of:\n  \
         --features winevt           Windows, live Event Log (default)\n  \
         --features evtx             one-shot EVTX files, any platform\n  \
         --no-default-features --features auditd,builtin   Linux inputs\n  \
         optionally append ,sysmon or ,ebpf to the Linux set"
    )
}