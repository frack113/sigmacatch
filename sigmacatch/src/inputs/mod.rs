// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 sigmacatch contributors

//! Input adapters of the `sigmacatch` binary — the single source of the
//! `feature × platform` gate matrix. `lib.rs` exposes this module
//! unconditionally; every file below is compiled only when its input features
//! are enabled (and, for Linux, only on `target_os = "linux"`).
//!
//! Linux impls are gated on `target_os = "linux"` (Unix-only code: `tail`
//! `MetadataExt`, eBPF loaders); enabling a Linux feature on another platform
//! is silently inert.

// Windows inputs. Crate aliases keep host call sites unchanged; the Winevt
// crate owns its `channels` sub-module and compiles its non-Windows stubs.
#[cfg(feature = "winevt")]
pub use sigmacatch_input_winevt as winevt;
#[cfg(feature = "winevt")]
pub use sigmacatch_input_winevt::channels;
// Windows orchestrator: Event Log channels + kernel sensor or ETW.
#[cfg(all(target_os = "windows", feature = "winevt"))]
pub mod windows;
// Native ETW collector (feature `etw`): no Sysmon, no driver. The session
// layer is only meaningful on Windows.
#[cfg(all(target_os = "windows", feature = "etw"))]
pub mod etw;
// Decoding helpers shared with the kernel-sensor client. The Win32-backed
// ones are empty off Windows; the pure format modules are target-independent.
#[cfg(all(target_os = "windows", feature = "etw"))]
pub use sigmacatch_input_etw_common::{
    etw_event, etw_process, etw_registry, etw_sysmon, nt_file, signature, version_info,
};
#[cfg(feature = "etw")]
pub use sigmacatch_input_etw_common::{pe_format, registry_format, wmi_format};
// Kernel-sensor client (feature `driver`, implies `etw`).
#[cfg(all(target_os = "windows", feature = "driver"))]
pub mod etw_driver;

// One-shot EVTX cross-platform input. Not `target_os`-gated: pure file
// parsing, runs on Windows and Linux alike.
#[cfg(feature = "evtx")]
pub use sigmacatch_input_evtx as evtx;

// Linux inputs. Crate aliases keep every `crate::inputs::<name>` call site
// unchanged; each crate is empty off Linux.
#[cfg(all(target_os = "linux", feature = "auditd"))]
pub use sigmacatch_input_auditd as auditd;
#[cfg(all(target_os = "linux", feature = "builtin"))]
pub use sigmacatch_input_syslog as syslog;
// Shared line-tail driver (Linux `MetadataExt`), compiled with any tail-based
// input. The crate is empty off Linux; callers below are themselves gated.
#[cfg(all(
    target_os = "linux",
    any(feature = "auditd", feature = "builtin", feature = "sysmon")
))]
pub use sigmacatch_input_tail as tail;
// Test hook, publicly reachable so integration tests can arm the injected
// tail timing / READY barrier through the collector constructors.
#[cfg(all(target_os = "linux", feature = "ebpf"))]
pub use sigmacatch_input_ebpf::{ebpf, ebpf_event};
#[cfg(all(target_os = "linux", feature = "sysmon"))]
pub use sigmacatch_input_sysmon as sysmon;
#[cfg(all(target_os = "linux", feature = "sysmon"))]
pub use sigmacatch_input_sysmon::sysmon_parse;
#[cfg(all(
    target_os = "linux",
    any(feature = "auditd", feature = "builtin", feature = "sysmon")
))]
pub use sigmacatch_input_tail::TailOptions;
// Linux orchestrator: selects every compiled, available source at runtime.
#[cfg(all(
    target_os = "linux",
    any(
        feature = "auditd",
        feature = "builtin",
        feature = "sysmon",
        feature = "ebpf"
    )
))]
pub mod linux;

// macOS Endpoint Security collector. The platform-independent event model
// is always compiled with the feature so its field mapping can be tested on
// Linux; the ES client itself is `#[cfg(target_os = "macos")]` inside.
#[cfg(feature = "macos")]
pub use sigmacatch_input_macos as macos_es;
