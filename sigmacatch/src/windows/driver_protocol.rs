// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 sigmacatch contributors

//! Wire protocol shared between the kernel sensor (`sigmacatch/driver`) and
//! the user-mode collector (`sigmacatch/src/inputs/etw_driver.rs`, to come).
//!
//! The driver includes this file verbatim via `#[path]` (single source of
//! truth, same pattern as `ebpf_common`); every type is plain `#[repr(C)]`
//! and `no_std` so the layout is the contract across the IOCTL boundary.
//!
//! `CTL_CODE(FILE_DEVICE_UNKNOWN, function, METHOD_BUFFERED, access)`:
//! method `0` contributes nothing, access `FILE_READ_DATA` contributes
//! `1 << 14`, function contributes `function << 2`.

/// Bumped whenever the layout or the IOCTL set changes; both sides refuse to
/// talk across a mismatch.
pub const SIGMACATCH_PROTOCOL_VERSION: u32 = 2;

/// `CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_READ_DATA)`.
pub const IOCTL_GET_VERSION: u32 = 0x0022_2000;
/// `CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_READ_DATA)`.
pub const IOCTL_READ_EVENTS: u32 = 0x0022_2004;

/// One process-creation record, as the notify callback saw it.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct ProcessEvent {
    /// `SIGMACATCH_PROTOCOL_VERSION` the producer was built with.
    pub version: u32,
    /// `1` = process created, `0` = process exited (both are reported so the
    /// user-mode side can time-bracket the process).
    pub creating: u32,
    /// Process id.
    pub pid: u32,
    /// Creating process id.
    pub parent_pid: u32,
    /// Characters (UTF-16) stored in [`Self::image`].
    pub image_length: u16,
    /// Characters (UTF-16) stored in [`Self::command_line`].
    pub command_length: u16,
    /// Image path (the `ImageFileName` of `PS_CREATE_NOTIFY_INFO`).
    pub image: [u16; 512],
    /// Creation-time command line (may be empty: `CommandLine` is optional).
    pub command_line: [u16; 2048],
}

impl ProcessEvent {
    /// All-zero record, usable in a const context.
    pub const fn empty() -> Self {
        Self {
            version: 0,
            creating: 0,
            pid: 0,
            parent_pid: 0,
            image_length: 0,
            command_length: 0,
            image: [0; 512],
            command_line: [0; 2048],
        }
    }
}

/// Max records the ring can hold between user-mode reads.
pub const RING_CAPACITY: usize = 1024;

/// `SIGMACATCH_PROTOCOL_VERSION` the first D0 skeleton exposed; kept for the
/// change note only.
#[doc(hidden)]
pub const _PROTOCOL_V1: u32 = 1;
