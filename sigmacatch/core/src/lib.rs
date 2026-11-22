// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 sigmacatch contributors

//! OS-independent core of `sigmacatch`: collection pipeline, configuration,
//! detection engine, rule management, SigmaHQ repository layer and regression
//! data generator. Input adapters live in their own crates and depend on this
//! one; nothing here knows how an event was captured.

pub use crate::regression::{DataFormat, RegressionSink, RegressionSinkFactory};
pub use crate::runner::{CollectorKind, bootstrap_repo_regression, run};

/// Diagnostic subcommands (check-filter, list-rules).
pub mod cli;

/// Application configuration.
pub mod config;

/// Detection engine wrapped around rsigma-eval.
pub mod detection;

/// EVTX file parsing (cross-platform).
pub mod evtx_reader;

/// Logging bootstrap shared by the collector and `regressiondata-check`.
pub mod logging;

/// Shared regression-data vocabulary, discovery and output seams.
pub mod regression;

/// SigmaHQ repository layer (clone, branch, commit, transport), re-exported
/// from `sigmacatch-git-action`.
pub use sigmacatch_git_action as repo;

/// Sigma rule management.
pub mod rule;

/// Shared pipeline (trait + continuous run loop).
pub mod runner;

/// Shared domain types (Event, Alert, EventProducer…).
pub mod types;
