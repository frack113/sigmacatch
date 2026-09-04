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
//! // See sigmacatch-win and sigmacatch-lnx binaries for implementation.
//! # Ok(())
//! # }
//! ```

pub use runner::{CollectorKind, run};

mod runner;
