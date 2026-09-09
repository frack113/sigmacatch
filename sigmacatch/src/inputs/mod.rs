// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 sigmacatch contributors

//! Input adapters of the `sigmacatch` binary — the single source of the
//! `feature × platform` gate matrix. `lib.rs` exposes this module
//! unconditionally; every file below is compiled only when its input features
//! are enabled (and, for Linux, only on `target_os = "linux"`).
//!
//! Linux impls are gated on `target_os = "linux"` (Unix-only code: `tail`
//! `MetadataExt`, eBPF loaders); enabling a Linux feature on another platform
//! is silently inert.

// Windows inputs.
#[cfg(feature = "winevt")]
pub mod channels;
#[cfg(feature = "winevt")]
pub mod winevt;

// One-shot EVTX cross-platform input. Not `target_os`-gated: pure file
// parsing, runs on Windows and Linux alike.
#[cfg(feature = "evtx")]
pub mod evtx;

// Linux inputs.
#[cfg(all(target_os = "linux", feature = "auditd"))]
pub mod auditd;
#[cfg(all(target_os = "linux", feature = "builtin"))]
pub mod syslog;
// Shared line-tail driver (Linux `MetadataExt`), compiled with any tail-based
// input.
#[cfg(all(
    target_os = "linux",
    any(feature = "auditd", feature = "builtin", feature = "sysmon")
))]
mod tail;
// Parsed by the `builtin` collector (not `sysmon`): the built-in syslog tail
// must recognise Sysmon-for-Linux XML lines so it can hand them to `sysmon`.
#[cfg(all(target_os = "linux", feature = "ebpf"))]
pub mod ebpf;
#[cfg(all(target_os = "linux", feature = "ebpf"))]
pub mod ebpf_event;
#[cfg(all(target_os = "linux", feature = "sysmon"))]
pub mod sysmon;
#[cfg(all(target_os = "linux", feature = "builtin"))]
pub mod sysmon_parse;
// Linux orchestrator: selects every compiled, available source at runtime.
#[cfg(all(
    target_os = "linux",
    any(
        feature = "auditd",
        feature = "builtin",
        feature = "sysmon",
        feature = "ebpf"
    )
))]
pub mod linux;
