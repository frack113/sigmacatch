// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 sigmacatch contributors

//! Single `sigmacatch` package: one binary (`sigmacatch`) plus a second
//! artifact (`regressiondata-check`). Cargo features select which input crates
//! are linked in: `winevt` (default) and `evtx` everywhere, `etw` and `driver`
//! on Windows, `auditd`/`builtin`/`sysmon`/`ebpf` on Linux, `macos` on macOS.
//!
//! The shared data model and configuration live in [`sigmacatch_core`], the
//! Sigma engine in `sigmacatch-detection`, and the collection → detection →
//! regression orchestration in `sigmacatch-runner`, all re-exported here. Only
//! the input adapters and the eBPF probe code are gated by features.

pub use sigmacatch_core::{
    DataFormat, RegressionSink, RegressionSinkFactory, cli, config, evtx_reader, logging, repo,
    rule, types,
};

/// Shared pipeline (trait + continuous run loop). The concrete detection engine
/// lives in `sigmacatch-detection`; the runner crate wires it into the collector.
pub use sigmacatch_runner::{CollectorKind, bootstrap_repo_regression, run};
/// Re-export of the `sigmacatch-runner` orchestration crate under the binary's
/// module tree, so `crate::runner::…` keeps working inside this crate.
pub mod runner {
    pub use sigmacatch_runner::*;
}

/// Regression-data output: shared vocabulary from core plus the concrete
/// SigmaHQ writer crate.
pub mod regression {
    pub use sigmacatch_core::regression::*;
    pub use sigmacatch_output_regression::{RegressionEntry, SigmahqRegression};
}

/// Output factory. The binary builds the sink and injects it into the runner,
/// mirroring how each input crate builds its event producer.
pub mod output_factory;

// Wire-format types for the eBPF ring buffer. The probe crate includes the
// source directly via `#[path]`; the host adapter owns it.
#[cfg(feature = "ebpf")]
pub use sigmacatch_input_ebpf::ebpf_common;

// Input orchestrators. Each real input crate owns its gates; this module only
// aliases them and hosts the OS-specific fan-in/fan-out glue.
pub mod orchestrators;
