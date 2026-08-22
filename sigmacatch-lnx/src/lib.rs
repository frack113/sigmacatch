// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 sigmacatch contributors

pub use sigmacatch_runner::{CollectorKind, run};

#[cfg(feature = "auditd")]
pub mod auditd;
#[cfg(feature = "builtin")]
pub mod syslog;
