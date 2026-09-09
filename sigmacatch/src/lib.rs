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

// Input adapters. The whole `feature × platform` gate matrix lives in
// `inputs/mod.rs`; this library exposes it unconditionally here.
pub mod inputs;
