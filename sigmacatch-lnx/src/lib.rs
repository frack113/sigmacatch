// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 sigmacatch contributors

//! Linux collectors selected by cargo features: `auditd`, `builtin` (syslog),
//! `sysmon` (legacy tail), `ebpf` (native probes). The shared sysmon XML
//! parsing lives in [`sysmon_parse`] and is always compiled.

pub use sigmacatch_runner::{CollectorKind, run};

#[cfg(feature = "auditd")]
pub mod auditd;
pub mod entry;
#[cfg(feature = "ebpf")]
pub mod ebpf;
#[cfg(feature = "ebpf")]
pub mod ebpf_event;
#[cfg(feature = "builtin")]
pub mod syslog;
// Legacy Sysmon-for-Linux tail collector — flavour-gated: only the
// `-sysmon` binary (or explicit --features sysmon) carries it.
#[cfg(feature = "sysmon")]
pub mod sysmon;
// Wire-format parsing shared by every flavour and the diagnostics CLI.
pub mod sysmon_parse;
