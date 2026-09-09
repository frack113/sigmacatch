// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 sigmacatch contributors

//! Single `sigmacatch` binary crate. Cargo features select which inputs are
//! compiled in:
//! - Windows: `winevt` (live Event Log, default), `evtx` (one-shot EVTX files);
//! - Linux: `auditd`, `builtin` (system syslog), `sysmon` (Sysmon-for-Linux
//!   tail), `ebpf` (native probes).
//!
//! The shared collection → detection → regression pipeline lives in
//! `sigmacatch-runner`; this crate only carries the collector wrappers and the
//! thin `main` that picks the runtime input (`--evtx` / live Winevt / Linux).

pub use sigmacatch_runner::{CollectorKind, run};

// Always compiled: diagnostic subcommands (check-filter, list-rules).
pub mod cli;

// Windows inputs.
#[cfg(feature = "winevt")]
pub mod channels;
#[cfg(feature = "winevt")]
pub mod winevt;
#[cfg(feature = "evtx")]
pub mod evtx;

// Linux inputs. Unix-only code (tail MetadataExt, eBPF) is gated on
// `target_os = "linux"`; selecting a Linux feature on another platform is
// silently inert.
#[cfg(all(target_os = "linux", feature = "auditd"))]
pub mod auditd;
#[cfg(all(target_os = "linux", feature = "builtin"))]
pub mod syslog;
#[cfg(all(target_os = "linux", any(feature = "auditd", feature = "builtin", feature = "sysmon")))]
mod tail;
#[cfg(all(target_os = "linux", feature = "builtin"))]
pub mod sysmon_parse;
#[cfg(all(target_os = "linux", feature = "sysmon"))]
pub mod sysmon;
#[cfg(all(target_os = "linux", feature = "ebpf"))]
pub mod ebpf;
#[cfg(all(target_os = "linux", feature = "ebpf"))]
pub mod ebpf_event;
#[cfg(all(
    target_os = "linux",
    any(feature = "auditd", feature = "builtin", feature = "sysmon", feature = "ebpf")
))]
pub mod linux;