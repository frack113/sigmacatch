// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 sigmacatch contributors

//! Windows collectors (Winevt API + direct ETW) behind the `winevt`/`etw`
//! features; non-Windows builds get no-op stubs.

pub use sigmacatch_runner::{CollectorKind, run};

#[cfg(feature = "winevt")]
pub mod channels;
#[cfg(feature = "etw")]
pub mod etw;
