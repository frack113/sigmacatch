// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 sigmacatch contributors

//! Wire protocol shared between the kernel sensor (`sigmacatch/driver`) and
//! the user-mode collector.
//!
//! The driver includes this file verbatim via `#[path]` (single source of
//! truth, same pattern as `ebpf_common`); every type is plain `#[repr(C)]`
//! and `no_std` so the layout is the contract across the IOCTL boundary.
//!
//! The record is *kind-tagged*: one fixed layout carries every event the
//! driver produces, so the ring buffer and the read IOCTL do not care what
//! kind they carry. `primary`/`secondary` are the two wide strings most kinds
//! need; `detail` is a per-kind scalar. The mapping from a record to a
//! Sysmon-schema event happens on the user-mode side.
//!
//! `CTL_CODE(FILE_DEVICE_UNKNOWN, function, METHOD_BUFFERED, access)`:
//! method `0` contributes nothing, access `FILE_READ_DATA` contributes
//! `1 << 14`, function contributes `function << 2`.

/// Bumped whenever the layout or the IOCTL set changes; both sides refuse to
/// talk across a mismatch.
pub const SIGMACATCH_PROTOCOL_VERSION: u32 = 3;

/// `CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_READ_DATA)`.
pub const IOCTL_GET_VERSION: u32 = 0x0022_2000;
/// `CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_READ_DATA)`.
pub const IOCTL_READ_EVENTS: u32 = 0x0022_2004;

/// Event kinds carried by [`SensorEvent::kind`].
pub mod kind {
    /// Process created (`PsSetCreateProcessNotifyRoutineEx`, create path).
    pub const PROCESS_CREATE: u32 = 1;
    /// Process exited (same callback, null `CreateInfo`).
    pub const PROCESS_EXIT: u32 = 2;
    /// File created / opened for overwrite (minifilter, D2).
    pub const FILE_CREATE: u32 = 3;
    /// File deleted (minifilter, D2).
    pub const FILE_DELETE: u32 = 4;
    /// File renamed: `primary` = old path, `secondary` = new path (D2).
    pub const FILE_RENAME: u32 = 5;
    /// File security change (ACL or owner): `detail` 0 = ACL (chmod, EID 504),
    /// 1 = owner (chown, EID 505) (D2).
    pub const FILE_SET_SECURITY: u32 = 6;
    /// File truncated: `detail` = new size low bits (D2).
    pub const FILE_TRUNCATE: u32 = 7;
    /// Cross-process access (EID 10): `primary` = target image, `detail` =
    /// granted access mask (D2).
    pub const PROCESS_ACCESS: u32 = 8;
    /// Image (driver) loaded (EID 6): `primary` = image path (D2).
    pub const IMAGE_LOAD: u32 = 9;
}

/// One event record, as the driver observed it.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct SensorEvent {
    /// `SIGMACATCH_PROTOCOL_VERSION` the producer was built with.
    pub version: u32,
    /// One of [`kind`].
    pub kind: u32,
    /// Process id that produced the event (or the subject process).
    pub pid: u32,
    /// Creating process id (process kinds) or 0.
    pub parent_pid: u32,
    /// UTF-16 code units stored in [`SensorEvent::primary`].
    pub primary_length: u16,
    /// UTF-16 code units stored in [`SensorEvent::secondary`].
    pub secondary_length: u16,
    /// Kind-dependent: process → image path; file → the path; access → target
    /// image; image → image path.
    pub primary: [u16; 512],
    /// Kind-dependent: process → command line; rename → new path.
    pub secondary: [u16; 2048],
    /// Kind-dependent scalar (access mask, ACL-vs-owner, new size).
    pub detail: u32,
}

impl SensorEvent {
    /// All-zero record, usable in a const context.
    pub const fn empty() -> Self {
        Self {
            version: 0,
            kind: 0,
            pid: 0,
            parent_pid: 0,
            primary_length: 0,
            secondary_length: 0,
            primary: [0; 512],
            secondary: [0; 2048],
            detail: 0,
        }
    }
}

/// Max records the ring can hold between user-mode reads.
pub const RING_CAPACITY: usize = 1024;
