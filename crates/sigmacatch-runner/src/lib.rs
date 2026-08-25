// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 sigmacatch contributors

//! Shared pipeline: `CollectorKind` trait + the continuous run loop used by
//! every platform binary.

pub use runner::{CollectorKind, run};

mod runner;
