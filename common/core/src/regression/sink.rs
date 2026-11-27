// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 sigmacatch contributors

//! Output seam used by the shared runner.
//!
//! The concrete regression writer lives in `sigmacatch-output-regression`.
//! Core only names this trait, so the dependency stays one-way: output crates
//! depend on core, core never depends on an output. This mirrors
//! [`crate::runner::CollectorKind`] on the input side.

use std::path::Path;

use anyhow::Result;
use uuid::Uuid;

use super::DataFormat;
use crate::types::Alert;

/// Output adapter driven by the collection loop.
///
/// Implemented by each regression writer crate; the runner talks only to this
/// trait. `Send` is required because the pipeline is moved into
/// `tokio::task::spawn_blocking` for every generation cycle.
pub trait RegressionSink: Send {
    /// Author recorded in generated `info.yml` files.
    fn set_author(&mut self, author: String);

    /// Consecutive failed cycles after which a rule is blocked.
    fn set_max_failed_cycles(&mut self, cycles: u32);

    /// Per-rule data format selected by the active collector.
    fn set_format(&mut self, format: DataFormat);

    /// Whether to write the auxiliary `<rule_id>.json` next to the data file.
    fn set_add_json_output(&mut self, enabled: bool);

    /// Rule ids with committed, non-empty regression data.
    fn active_rule_ids(&self) -> Vec<Uuid>;

    /// True when no regression entry was loaded.
    fn is_empty(&self) -> bool;

    /// Open a new failure-counting cycle.
    fn begin_cycle(&mut self);

    /// Add one alert; returns the generated paths when the rule was written.
    fn add(&mut self, alert: &Alert) -> Option<Vec<String>>;

    /// Drain the rules blocked by repeated generation failures.
    fn take_blocked(&mut self) -> Vec<Uuid>;
}

/// Constructs a sink once the runner has loaded configuration and resolved the
/// regression-data directory. Injected by the binary, never implemented in
/// core, so core stays free of output-crate dependencies.
pub trait RegressionSinkFactory: Send + Sync {
    /// Build a sink rooted at `path`.
    fn build(&self, path: &Path) -> Result<Box<dyn RegressionSink>>;
}
