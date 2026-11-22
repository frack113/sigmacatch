// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 sigmacatch contributors

//! Output adapters of the `sigmacatch` binary.
//!
//! The output sink is built here and injected into the shared runner, exactly
//! as each input crate builds its event producer. Adding another output means
//! adding a crate and a selector here, not touching `core`.

pub use sigmacatch_output_regression as regression;

use sigmacatch_core::regression::RegressionSinkFactory;

/// The compiled-in output sink factory: SigmaHQ regression data.
pub fn regression_sink_factory() -> &'static dyn RegressionSinkFactory {
    static FACTORY: regression::SinkFactory = regression::SinkFactory;
    &FACTORY
}
