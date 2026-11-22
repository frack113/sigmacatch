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
//! management, the Sigma repo layer and the regression data generator live in
//! [`sigmacatch_core`] and are re-exported here. Only the input adapters and
//! the eBPF probe code are gated by features.

pub use sigmacatch_core::{
    CollectorKind, DataFormat, bootstrap_repo_regression, cli, config, detection, evtx_reader,
    logging, regression, repo, rule, run, runner, types,
};

// Wire-format types for the eBPF ring buffer. The probe crate includes the
// source directly via `#[path]`; the host adapter owns it.
#[cfg(feature = "ebpf")]
pub use sigmacatch_input_ebpf::ebpf_common;

// Input adapters. The whole `feature × platform` gate matrix lives in
// `inputs/mod.rs`; this library exposes it unconditionally here.
pub mod inputs;
