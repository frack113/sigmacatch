// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 sigmacatch contributors

//! Wire-format types shared between the eBPF probes (`crates/sigmacatch-ebpf`,
//! compiled no_std for `bpfel-unknown-none`) and the userspace loader
//! (`sigmacatch-lnx/src/ebpf.rs`).
//!
//! Every type here is `#[repr(C)]` and [`Pod`]: the layout is the contract
//! across the ring buffer boundary.

#![no_std]

use bytemuck::Pod;
use bytemuck::Zeroable;

/// Ring buffer record tag: process execution.
pub const EVENT_EXEC: u32 = 1;
/// Ring buffer record tag: process termination (group leader only).
pub const EVENT_EXIT: u32 = 2;
/// Ring buffer record tag: outbound network connection attempt.
pub const EVENT_NET: u32 = 3;
/// Ring buffer record tag: successful file creation via openat(O_CREAT).
pub const EVENT_FILE: u32 = 4;
/// Ring buffer record tag: outbound DNS query payload (UDP port 53).
pub const EVENT_DNS: u32 = 5;

/// Directory-fd sentinel meaning "path is relative to cwd".
pub const AT_FDCWD: i32 = -100;
pub const PATH_LEN: usize = 256;
/// Bounded raw DNS wire payload carried in [`DnsEvent`].
pub const DNS_PAYLOAD_LEN: usize = 256;

pub const IMAGE_LEN: usize = 128;
/// First argv element captured in-kernel (race-free naming floor); the full
/// command line is enriched from `/proc` in userspace.
pub const ARG0_LEN: usize = 128;
const COMM_LEN: usize = 16;

/// Process execution event emitted at `sched_process_exec`.
///
/// The kernel captures what is race-free there (`image`, first argv element,
/// uid/gid, comm); userspace enriches with `/proc/<pid>/cmdline` into the
/// full Sysmon command line.
#[repr(C)]
#[derive(Debug, Clone, Copy, Pod, Zeroable)]
pub struct ExecEvent {
    /// Always [`EVENT_EXEC`].
    pub kind: u32,
    /// Process (tgid) that execed.
    pub pid: u32,
    /// Real UID of the executing task.
    pub uid: u32,
    /// Real GID of the executing task.
    pub gid: u32,
    pub _pad0: u32,
    /// Task comm at exec time (NUL-padded, may be truncated by the kernel).
    pub comm: [u8; COMM_LEN],
    /// Executable path passed to execve (NUL-padded).
    pub image: [u8; IMAGE_LEN],
    /// First argv element (NUL-padded) — race-free fallback for CommandLine.
    pub arg0: [u8; ARG0_LEN],
    pub _pad1: u32,
}

/// Process termination event emitted at `sched_process_exit` (group leader).
#[repr(C)]
#[derive(Debug, Clone, Copy, Pod, Zeroable)]
pub struct ExitEvent {
    /// Always [`EVENT_EXIT`].
    pub kind: u32,
    /// Terminating process id.
    pub pid: u32,
}

impl ExecEvent {
    fn cstr(field: &[u8]) -> &str {
        let end = field.iter().position(|&b| b == 0).unwrap_or(field.len());
        core::str::from_utf8(&field[..end]).unwrap_or("")
    }

    /// Image as lossy UTF-8 up to the first NUL.
    pub fn image_str(&self) -> &str {
        Self::cstr(&self.image)
    }

    /// First argv element as lossy UTF-8 up to the first NUL.
    pub fn arg0_str(&self) -> &str {
        Self::cstr(&self.arg0)
    }

    /// Task comm as lossy UTF-8 up to the first NUL.
    pub fn comm_str(&self) -> &str {
        Self::cstr(&self.comm)
    }
}

impl ExitEvent {
    /// Parse a ring buffer record into a typed exit event.
    #[must_use]
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        let r: &[u8; size_of::<Self>()] = bytes.try_into().ok()?;
        Some(*bytemuck::from_bytes(r))
    }
}

/// Outbound connection attempt emitted at `sys_enter_connect`.
///
/// Only the destination is captured (source address/port are not yet bound
/// at this point); `port_be` keeps the network byte order as read from the
/// sockaddr.
#[repr(C)]
#[derive(Debug, Clone, Copy, Pod, Zeroable)]
pub struct NetEvent {
    /// Always [`EVENT_NET`].
    pub kind: u32,
    /// Connecting process id.
    pub pid: u32,
    /// Real UID of the connecting task.
    pub uid: u32,
    /// Real GID of the connecting task.
    pub gid: u32,
    /// Address family (`AF_INET` = 2, `AF_INET6` = 10); others dropped.
    pub family: u16,
    pub _pad0: u16,
    /// Destination port in network byte order.
    pub port_be: u16,
    pub _pad1: u16,
    /// IPv4 bytes occupy `[..4]`; IPv6 fills the whole array.
    pub addr: [u8; 16],
    /// Task comm at connect time (NUL-padded).
    pub comm: [u8; COMM_LEN],
}

impl NetEvent {
    /// Parse a ring buffer record into a typed net event.
    #[must_use]
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        let r: &[u8; size_of::<Self>()] = bytes.try_into().ok()?;
        Some(*bytemuck::from_bytes(r))
    }

    fn cstr(field: &[u8]) -> &str {
        let end = field.iter().position(|&b| b == 0).unwrap_or(field.len());
        core::str::from_utf8(&field[..end]).unwrap_or("")
    }

    /// Task comm as lossy UTF-8 up to the first NUL.
    pub fn comm_str(&self) -> &str {
        Self::cstr(&self.comm)
    }
}

impl ExecEvent {
    /// Parse a ring buffer record into a typed exec event.
    #[must_use]
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        let r: &[u8; size_of::<Self>()] = bytes.try_into().ok()?;
        Some(*bytemuck::from_bytes(r))
    }
}

use core::mem::size_of;

const _: () = assert!(
    core::mem::size_of::<ExecEvent>().is_multiple_of(8),
    "ExecEvent must stay 8-byte aligned for ring buffer records"
);

const _: () = assert!(
    core::mem::size_of::<NetEvent>().is_multiple_of(8),
    "NetEvent must stay 8-byte aligned for ring buffer records"
);

/// File creation event emitted at `sys_exit_openat` when the staged
/// `sys_enter_openat` carried `O_CREAT` and the syscall succeeded.
///
/// `dirfd` lets userspace resolve relative paths through `/proc/<pid>/fd`
/// (or `/proc/<pid>/cwd` for [`AT_FDCWD`]) even if the opener is still alive.
#[repr(C)]
#[derive(Debug, Clone, Copy, Pod, Zeroable)]
pub struct FileCreateEvent {
    /// Always [`EVENT_FILE`].
    pub kind: u32,
    /// Creating process id.
    pub pid: u32,
    /// Real UID of the creating task.
    pub uid: u32,
    /// Real GID of the creating task.
    pub gid: u32,
    /// Directory-fd argument of openat (may be [`AT_FDCWD`]).
    pub dirfd: i32,
    pub _pad0: i32,
    /// Path as passed to openat (NUL-padded; may be relative).
    pub path: [u8; PATH_LEN],
    /// Task comm at exit time (NUL-padded).
    pub comm: [u8; COMM_LEN],
}

impl FileCreateEvent {
    /// Parse a ring buffer record into a typed file-create event.
    #[must_use]
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        let r: &[u8; size_of::<Self>()] = bytes.try_into().ok()?;
        Some(*bytemuck::from_bytes(r))
    }

    fn cstr(field: &[u8]) -> &str {
        let end = field.iter().position(|&b| b == 0).unwrap_or(field.len());
        core::str::from_utf8(&field[..end]).unwrap_or("")
    }

    /// Path as lossy UTF-8 up to the first NUL.
    pub fn path_str(&self) -> &str {
        Self::cstr(&self.path)
    }
}

const _: () = assert!(
    core::mem::size_of::<FileCreateEvent>().is_multiple_of(8),
    "FileCreateEvent must stay 8-byte aligned for ring buffer records"
);

/// Outbound DNS query captured from `sendto`/`sendmsg` to UDP port 53.
///
/// Only the bounded raw wire payload crosses the ring buffer; `QueryName`
/// parsing stays in userspace, out of the verifier-sensitive path (rustinel
/// pattern). QueryResults is not parsed — responses are not observed.
#[repr(C)]
#[derive(Debug, Clone, Copy, Pod, Zeroable)]
pub struct DnsEvent {
    /// Always [`EVENT_DNS`].
    pub kind: u32,
    /// Querying process id.
    pub pid: u32,
    /// Real UID of the querying task.
    pub uid: u32,
    /// Real GID of the querying task.
    pub gid: u32,
    /// Bytes of valid payload written into [`DnsEvent::payload`].
    pub payload_len: u32,
    pub _pad0: u32,
    /// Task comm at query time (NUL-padded).
    pub comm: [u8; 16],
    /// Raw DNS wire bytes (header + question section as sent).
    pub payload: [u8; DNS_PAYLOAD_LEN],
}

impl DnsEvent {
    /// Parse a ring buffer record into a typed dns event.
    #[must_use]
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        let r: &[u8; size_of::<Self>()] = bytes.try_into().ok()?;
        Some(*bytemuck::from_bytes(r))
    }

    fn cstr(field: &[u8]) -> &str {
        let end = field.iter().position(|&b| b == 0).unwrap_or(field.len());
        core::str::from_utf8(&field[..end]).unwrap_or("")
    }

    /// Task comm as lossy UTF-8 up to the first NUL.
    pub fn comm_str(&self) -> &str {
        Self::cstr(&self.comm)
    }
}

const _: () = assert!(
    core::mem::size_of::<DnsEvent>().is_multiple_of(8),
    "DnsEvent must stay 8-byte aligned for ring buffer records"
);
