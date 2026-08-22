// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 sigmacatch contributors

pub use sigmacatch_runner::{CollectorKind, run};

#[cfg(feature = "winevt")]
pub mod channels;
#[cfg(feature = "etw")]
pub mod etw;
