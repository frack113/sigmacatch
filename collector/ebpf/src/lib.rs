// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 sigmacatch contributors

//! eBPF host adapter: loads the probe object produced by `build.rs`, checks
//! privileges, attaches tracepoints and decodes ring-buffer records into
//! Sysmon-schema [`sigmacatch_core::types::Event`]s.

/// Wire-format types shared with the no_std probe via `#[path]`.
pub mod ebpf_common;

/// Probe loader and `EventProducer` implementation.
#[cfg(feature = "ebpf")]
pub mod ebpf;

/// Kernel ring-buffer record enrichment into Sysmon-schema events.
#[cfg(feature = "ebpf")]
pub mod ebpf_event;

#[cfg(feature = "ebpf")]
pub use ebpf::{EventCollector, has_required_privileges};
#[cfg(feature = "ebpf")]
pub use ebpf_event::EventBuilder;
