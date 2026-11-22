// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 sigmacatch contributors

//! Single `sigmacatch` package: one binary (`sigmacatch`) plus a second
//! artifact (`regressiondata-check`). Cargo features select which input crates
//! are linked in: `winevt` (default) and `evtx` everywhere, `etw` and `driver`
//! on Windows, `auditd`/`builtin`/`sysmon`/`ebpf` on Linux, `macos` on macOS.
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

// Input adapters. Each crate owns its gates; `inputs/mod.rs` only aliases them
// and hosts the two orchestrators.
pub mod inputs;
