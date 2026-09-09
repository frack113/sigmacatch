// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 sigmacatch contributors

//! Single `sigmacatch` package: one binary (`sigmacatch`) plus a second
//! artifact (`regressiondata-check`). Cargo features select which inputs are
//! compiled in:
//! - Windows: `winevt` (live Event Log, default), `evtx` (one-shot EVTX files);
//! - Linux: `auditd`, `builtin` (system syslog), `sysmon` (Sysmon-for-Linux
//!   tail), `ebpf` (native probes).
//!
//! The collection → detection → regression pipeline, configuration, rule
//! management, the Sigma repo layer and the regression data generator all live
//! here as plain modules. Only the input adapters and the eBPF probe code are
//! gated by features.

pub use crate::runner::{CollectorKind, bootstrap_repo_regression, run};

/// Re-export of the regression data format so collector wrappers do not need
/// a deep path into [`crate::regression`].
pub use crate::regression::DataFormat;

// Always compiled: diagnostic subcommands (check-filter, list-rules).
pub mod cli;

/// Shared pipeline (trait + continuous run loop).
pub mod runner;

/// Logging bootstrap shared by `sigmacatch` and `regressiondata-check`.
pub mod logging;

/// Application configuration.
pub mod config;

/// Detection engine wrapped around rsigma-eval.
pub mod detection;

/// Sigma rule management.
pub mod rule;

/// SigmaHQ repository layer (clone, branch, commit, transport).
pub mod repo;

/// Regression data generator + validation structures.
pub mod regression;

/// Shared domain types (Event, Alert, EventProducer…).
pub mod types;

/// EVTX file parsing (cross-platform).
pub mod evtx_reader;

// Wire-format types for the eBPF ring buffer, shared with the probe crate
// (`sigmacatch/ebpf`, which includes this file via `#[path]`).
#[cfg(feature = "ebpf")]
pub mod ebpf_common;

// Input adapters. The whole `feature × platform` gate matrix lives in
// `inputs/mod.rs`; this library exposes it unconditionally here.
pub mod inputs;
