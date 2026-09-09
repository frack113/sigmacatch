// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 sigmacatch contributors

//! Shared pipeline: `CollectorKind` trait + the continuous run loop used by
//! every platform binary.
//!
//! # Example
//!
//! ```rust,no_run
//! use sigmacatch_runner::{run, CollectorKind};
//! use sigmacatch_config::Config;
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! // The run function is the main entry point for all collectors.
//! // See the sigmacatch collector crate for implementation.
//! # Ok(())
//! # }
//! ```

pub use runner::{CollectorKind, bootstrap_repo_regression, run};

/// Re-export [`sigmacatch_regression::DataFormat`] so binary crates that
/// implement `CollectorKind` do not need a direct dependency on
/// `sigmacatch-regression`.
pub use sigmacatch_regression::DataFormat;

pub mod cli;
pub mod logging;

mod runner;
