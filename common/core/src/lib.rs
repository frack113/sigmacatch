// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 sigmacatch contributors

//! Common library shared by all sigmacatch crates: data models that cross
//! autonomous boundaries, configuration, rule management, repository layer,
//! regression-data seams, and internal helpers. Input adapters live in their
//! own crates and depend on this one; nothing here knows how an event was
//! captured or how it is persisted.

pub use crate::regression::{DataFormat, RegressionSink, RegressionSinkFactory};

/// Linux auditd log reader (platform-neutral, shared with the validator).
pub mod audit_reader;

/// Data models exchanged between autonomous blocks (input, detection, output).
pub mod exchange;

/// Diagnostic subcommands (check-filter, list-rules).
pub mod cli;

/// Application configuration.
pub mod config;

/// EVTX file parsing (cross-platform).
pub mod evtx_reader;

/// Logging bootstrap shared by the collector and `regressiondata-check`.
pub mod logging;

/// Shared regression-data vocabulary, discovery and output seams.
pub mod regression;

/// SigmaHQ repository layer (clone, branch, commit, transport), re-exported
/// from `sigmacatch-repo`.
pub use sigmacatch_repo as repo;

/// Sigma rule management.
pub mod rule;

/// Shared domain types (Event, Alert, EventProducer…).
pub mod types;

/// Small helpers shared across core modules and the detection engine.
pub mod util;
