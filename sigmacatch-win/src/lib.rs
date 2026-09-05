// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 sigmacatch contributors

//! Windows collectors (Winevt API) behind the `winevt` feature;
//! non-Windows builds get no-op stubs.

#[cfg(feature = "winevt")]
pub mod channels;
