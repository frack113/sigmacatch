// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 sigmacatch contributors

//! Wire-format types shared between the eBPF probes (`sigmacatch/ebpf`,
//! compiled no_std for `bpfel-unknown-none`) and the userspace loader
//! (`sigmacatch/src/inputs/ebpf.rs`).
//!
//! The probe crate includes this very file via `#[path]` (single source of
//! truth); every type here is `#[repr(C)]` and [`Pod`] so the layout is the
//! contract across the ring buffer boundary.
//!
//! This module is gated on the `ebpf` feature; when the feature is disabled
//! the module is empty (no items are exported).
//!
//! # Example
//!
//! ```rust
//! use sigmacatch::ebpf_common::{ExecEvent, EVENT_EXEC};
//!
//! # fn main() {
//! let event = ExecEvent {
//!     kind: EVENT_EXEC,
//!     pid: 1234,
//!     uid: 1000,
//!     gid: 1000,
//!     _pad0: 0,
//!     comm: [0; 16],
//!     image: [0; 128],
//!     arg0: [0; 128],
//!     arg1: [0; 64],
//!     arg2: [0; 64],
//!     _pad1: 0,
//! };
//! assert_eq!(event.kind, EVENT_EXEC);
//! # }
//! ```

#[cfg(feature = "ebpf")]
mod inner {
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
    /// Ring buffer record tag: socket entered listening state (extension).
    pub const EVENT_LISTEN: u32 = 6;
    /// Ring buffer record tag: file deleted via unlink/unlinkat.
    pub const EVENT_FILE_DELETE: u32 = 7;
    /// Ring buffer record tag: process access (ptrace / process_vm_*).
    pub const EVENT_PROCESS_ACCESS: u32 = 8;
    /// Ring buffer record tag: kernel module load (finit_module).
    pub const EVENT_DRIVER_LOAD: u32 = 9;
    /// Ring buffer record tag: raw device access (open on block/raw devices).
    pub const EVENT_RAW_ACCESS: u32 = 10;
    /// Ring buffer record tag: named pipe / FIFO created (EID 17).
    pub const EVENT_PIPE_CREATE: u32 = 11;
    // Tag 12 was formerly EVENT_PIPE_CONNECT (EID 18, pipe connected). It was
    // retired because the eBPF probe never emitted it; keep the slot unassigned
    // so stray/legacy records are handled as unknown tags.
    /// Ring buffer record tag: process tampering heuristic (EID 25).
    pub const EVENT_PROCESS_TAMPERING: u32 = 13;
    /// Ring buffer record tag: process fork/clone (internal lineage tracking).
    pub const EVENT_FORK: u32 = 14;
    /// Ring buffer record tag: credential change (uid/gid/groups), EID 501.
    pub const EVENT_CREDENTIAL_CHANGE: u32 = 15;
    /// Ring buffer record tag: capability change (capset/prctl caps), EID 502.
    pub const EVENT_CAPABILITY_CHANGE: u32 = 16;
    /// Ring buffer record tag: file rename, EID 503 (extension).
    pub const EVENT_FILE_RENAME: u32 = 17;
    /// Ring buffer record tag: file chmod, EID 504 (extension).
    pub const EVENT_FILE_CHMOD: u32 = 18;
    /// Ring buffer record tag: file chown, EID 505 (extension).
    pub const EVENT_FILE_CHOWN: u32 = 19;
    /// Ring buffer record tag: file truncate, EID 506 (extension).
    pub const EVENT_FILE_TRUNCATE: u32 = 20;
    /// Ring buffer record tag: file change/write, emitted as EID 2.
    pub const EVENT_FILE_CHANGE: u32 = 21;

    /// Directory-fd sentinel meaning "path is relative to cwd".
    pub const AT_FDCWD: i32 = -100;
    /// Bounded path buffer carried by [`FileCreateEvent`].
    pub const PATH_LEN: usize = 256;
    /// Bounded raw DNS wire payload carried in [`DnsEvent`].
    pub const DNS_PAYLOAD_LEN: usize = 256;

    /// Bounded executable-path buffer carried by [`ExecEvent`].
    pub const IMAGE_LEN: usize = 128;
    /// Bounded argv[0] buffer captured in-kernel (race-free).
    pub const ARG0_LEN: usize = 128;
    /// Bounded argv[1] buffer captured in-kernel (race-free).
    pub const ARG1_LEN: usize = 64;
    /// Bounded argv[2] buffer captured in-kernel (race-free).
    pub const ARG2_LEN: usize = 64;
    const COMM_LEN: usize = 16;

    /// Process execution event emitted at `sched_process_exec`.
    ///
    /// The kernel captures what is race-free there (`image`, first argv
    /// elements, uid/gid, comm); userspace prefers `/proc/<pid>/cmdline` for the
    /// full command line when the process is still alive.
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
        /// Explicit padding keeping the record size a multiple of 8 (zeroed).
        pub _pad0: u32,
        /// Task comm at exec time (NUL-padded, may be truncated by the kernel).
        pub comm: [u8; COMM_LEN],
        /// Executable path passed to execve (NUL-padded).
        pub image: [u8; IMAGE_LEN],
        /// argv[0] captured at execve time (NUL-padded, bounded).
        pub arg0: [u8; ARG0_LEN],
        /// argv[1] captured at execve time (NUL-padded, bounded).
        pub arg1: [u8; ARG1_LEN],
        /// argv[2] captured at execve time (NUL-padded, bounded).
        pub arg2: [u8; ARG2_LEN],
        /// Explicit padding keeping the record size a multiple of 8 (zeroed).
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

        /// argv[0] as lossy UTF-8 up to the first NUL.
        pub fn arg0_str(&self) -> &str {
            Self::cstr(&self.arg0)
        }

        /// argv[1] as lossy UTF-8 up to the first NUL.
        pub fn arg1_str(&self) -> &str {
            Self::cstr(&self.arg1)
        }

        /// argv[2] as lossy UTF-8 up to the first NUL.
        pub fn arg2_str(&self) -> &str {
            Self::cstr(&self.arg2)
        }

        /// argv[0] (first argument) as a cheap `&str` view.
        ///
        /// Despite the historical name, this does not reconstruct the full
        /// command line; use [`Self::cmdline_string`] for a joined
        /// `argv[0..2]` string when available.
        pub fn cmdline_str(&self) -> &str {
            self.arg0_str()
        }

        /// Kernel-captured command line reconstructed from available argv fields.
        #[cfg(not(target_arch = "bpf"))]
        pub fn cmdline_string(&self) -> String {
            let mut parts = [self.arg0_str(), self.arg1_str(), self.arg2_str()]
                .into_iter()
                .filter(|s| !s.is_empty());
            let Some(first) = parts.next() else {
                return String::new();
            };
            let mut out = first.to_string();
            for p in parts {
                out.push(' ');
                out.push_str(p);
            }
            out
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

    /// Process fork/clone event emitted at `sched_process_fork`.
    ///
    /// Internal record used to track process lineage (no direct Sysmon event).
    #[repr(C)]
    #[derive(Debug, Clone, Copy, Pod, Zeroable)]
    pub struct ForkEvent {
        /// Always [`EVENT_FORK`].
        pub kind: u32,
        /// Parent process id (tgid).
        pub parent_pid: u32,
        /// Child process id (tgid).
        pub child_pid: u32,
        /// Explicit padding keeping the record size a multiple of 8 (zeroed).
        pub _pad0: u32,
    }

    impl ForkEvent {
        /// Parse a ring buffer record into a typed fork event.
        #[must_use]
        pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
            let r: &[u8; size_of::<Self>()] = bytes.try_into().ok()?;
            Some(*bytemuck::from_bytes(r))
        }
    }

    const _: () = assert!(
        core::mem::size_of::<ForkEvent>().is_multiple_of(8),
        "ForkEvent must stay 8-byte aligned for ring buffer records"
    );

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
        /// Explicit padding keeping field offsets kernel-aligned (zeroed).
        pub _pad0: u16,
        /// Destination port in network byte order.
        pub port_be: u16,
        /// Explicit padding keeping field offsets kernel-aligned (zeroed).
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
        /// Explicit padding keeping the record size a multiple of 8 (zeroed).
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

    /// File deletion event emitted at `sys_exit_unlink`/`sys_exit_unlinkat`
    /// when the staged syscall succeeded.
    #[repr(C)]
    #[derive(Debug, Clone, Copy, Pod, Zeroable)]
    pub struct FileDeleteEvent {
        /// Always [`EVENT_FILE_DELETE`].
        pub kind: u32,
        /// Deleting process id.
        pub pid: u32,
        /// Real UID of the deleting task.
        pub uid: u32,
        /// Real GID of the deleting task.
        pub gid: u32,
        /// Directory-fd argument of unlinkat (may be [`AT_FDCWD`]).
        pub dirfd: i32,
        /// Explicit padding keeping the record size a multiple of 8 (zeroed).
        pub _pad0: i32,
        /// Path as passed to the syscall (NUL-padded; may be relative).
        pub path: [u8; PATH_LEN],
        /// Task comm at exit time (NUL-padded).
        pub comm: [u8; COMM_LEN],
    }

    impl FileDeleteEvent {
        /// Parse a ring buffer record into a typed file-delete event.
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
        core::mem::size_of::<FileDeleteEvent>().is_multiple_of(8),
        "FileDeleteEvent must stay 8-byte aligned for ring buffer records"
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
        /// Explicit padding keeping the record size a multiple of 8 (zeroed).
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

    /// Socket listen event emitted at `sys_exit_listen` when a previously
    /// bound socket enters the listening state (sigmacatch extension).
    ///
    /// The local endpoint comes from the `sys_enter_bind` staging for the
    /// same `(pid, fd)` pair; only `AF_INET`/`AF_INET6` binds are tracked.
    #[repr(C)]
    #[derive(Debug, Clone, Copy, Pod, Zeroable)]
    pub struct ListenEvent {
        /// Always [`EVENT_LISTEN`].
        pub kind: u32,
        /// Listening process id.
        pub pid: u32,
        /// Real UID of the listening task.
        pub uid: u32,
        /// Real GID of the listening task.
        pub gid: u32,
        /// Address family (`AF_INET` = 2, `AF_INET6` = 10).
        pub family: u16,
        /// Explicit padding keeping field offsets kernel-aligned (zeroed).
        pub _pad0: u16,
        /// Local bound port in network byte order.
        pub port_be: u16,
        /// Explicit padding keeping field offsets kernel-aligned (zeroed).
        pub _pad1: u16,
        /// IPv4 bytes occupy `[..4]`; IPv6 fills the whole array.
        pub addr: [u8; 16],
        /// Task comm at listen time (NUL-padded).
        pub comm: [u8; 16],
    }

    impl ListenEvent {
        /// Parse a ring buffer record into a typed listen event.
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
        core::mem::size_of::<ListenEvent>().is_multiple_of(8),
        "ListenEvent must stay 8-byte aligned for ring buffer records"
    );

    /// Process access event emitted at `sys_enter_ptrace` (and optionally
    /// `process_vm_*`). `request` carries the ptrace request code.
    #[repr(C)]
    #[derive(Debug, Clone, Copy, Pod, Zeroable)]
    pub struct ProcessAccessEvent {
        /// Always [`EVENT_PROCESS_ACCESS`].
        pub kind: u32,
        /// Source (accessing) process id (tgid).
        pub source_pid: u32,
        /// Source thread id.
        pub source_tid: u32,
        /// Real UID of the source task.
        pub source_uid: u32,
        /// Real GID of the source task.
        pub source_gid: u32,
        /// Explicit padding keeping the record size a multiple of 8 (zeroed).
        pub _pad0: u32,
        /// Target process id being accessed.
        pub target_pid: u32,
        /// Explicit padding keeping the record size a multiple of 8 (zeroed).
        pub _pad1: u32,
        /// Access request (e.g. ptrace request code).
        pub request: u64,
        /// Source task comm at access time (NUL-padded).
        pub comm: [u8; 16],
    }

    impl ProcessAccessEvent {
        /// Parse a ring buffer record into a typed process-access event.
        #[must_use]
        pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
            let r: &[u8; size_of::<Self>()] = bytes.try_into().ok()?;
            Some(*bytemuck::from_bytes(r))
        }

        fn cstr(field: &[u8]) -> &str {
            let end = field.iter().position(|&b| b == 0).unwrap_or(field.len());
            core::str::from_utf8(&field[..end]).unwrap_or("")
        }

        /// Source task comm as lossy UTF-8 up to the first NUL.
        pub fn comm_str(&self) -> &str {
            Self::cstr(&self.comm)
        }
    }

    const _: () = assert!(
        core::mem::size_of::<ProcessAccessEvent>().is_multiple_of(8),
        "ProcessAccessEvent must stay 8-byte aligned for ring buffer records"
    );

    /// Kernel module load event emitted at `sys_exit_finit_module` on success.
    /// Userspace resolves the module file path via `/proc/<pid>/fd/<fd>`.
    #[repr(C)]
    #[derive(Debug, Clone, Copy, Pod, Zeroable)]
    pub struct DriverLoadEvent {
        /// Always [`EVENT_DRIVER_LOAD`].
        pub kind: u32,
        /// Loading process id (tgid).
        pub pid: u32,
        /// Real UID of the loading task.
        pub uid: u32,
        /// Real GID of the loading task.
        pub gid: u32,
        /// File descriptor argument of `finit_module`.
        pub fd: i32,
        /// Explicit padding keeping the record size a multiple of 8 (zeroed).
        pub _pad0: i32,
        /// Task comm at load time (NUL-padded).
        pub comm: [u8; 16],
    }

    impl DriverLoadEvent {
        /// Parse a ring buffer record into a typed driver-load event.
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
        core::mem::size_of::<DriverLoadEvent>().is_multiple_of(8),
        "DriverLoadEvent must stay 8-byte aligned for ring buffer records"
    );

    /// Raw device access event emitted at `sys_exit_open*` when the path
    /// targets a raw/block device (EID 9).
    #[repr(C)]
    #[derive(Debug, Clone, Copy, Pod, Zeroable)]
    pub struct RawAccessEvent {
        /// Always [`EVENT_RAW_ACCESS`].
        pub kind: u32,
        /// Accessing process id.
        pub pid: u32,
        /// Real UID of the accessing task.
        pub uid: u32,
        /// Real GID of the accessing task.
        pub gid: u32,
        /// Directory-fd argument (may be [`AT_FDCWD`]).
        pub dirfd: i32,
        /// Explicit padding keeping the record size a multiple of 8 (zeroed).
        pub _pad0: i32,
        /// Device path (NUL-padded; may be relative).
        pub path: [u8; PATH_LEN],
        /// Task comm at access time (NUL-padded).
        pub comm: [u8; COMM_LEN],
    }

    impl RawAccessEvent {
        /// Parse a ring buffer record into a typed raw-access event.
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
        core::mem::size_of::<RawAccessEvent>().is_multiple_of(8),
        "RawAccessEvent must stay 8-byte aligned for ring buffer records"
    );

    /// Named pipe (FIFO) creation event (EID 17).
    #[repr(C)]
    #[derive(Debug, Clone, Copy, Pod, Zeroable)]
    pub struct PipeCreateEvent {
        /// Always [`EVENT_PIPE_CREATE`].
        pub kind: u32,
        /// Creating process id.
        pub pid: u32,
        /// Real UID of the creating task.
        pub uid: u32,
        /// Real GID of the creating task.
        pub gid: u32,
        /// Directory-fd argument (may be [`AT_FDCWD`]).
        pub dirfd: i32,
        /// Explicit padding keeping the record size a multiple of 8 (zeroed).
        pub _pad0: i32,
        /// Pipe name/path (NUL-padded; may be relative).
        pub pipe_name: [u8; PATH_LEN],
        /// Task comm at creation time (NUL-padded).
        pub comm: [u8; COMM_LEN],
    }

    impl PipeCreateEvent {
        /// Parse a ring buffer record into a typed pipe-create event.
        #[must_use]
        pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
            let r: &[u8; size_of::<Self>()] = bytes.try_into().ok()?;
            Some(*bytemuck::from_bytes(r))
        }

        fn cstr(field: &[u8]) -> &str {
            let end = field.iter().position(|&b| b == 0).unwrap_or(field.len());
            core::str::from_utf8(&field[..end]).unwrap_or("")
        }

        /// Pipe name as lossy UTF-8 up to the first NUL.
        pub fn pipe_name_str(&self) -> &str {
            Self::cstr(&self.pipe_name)
        }
    }

    const _: () = assert!(
        core::mem::size_of::<PipeCreateEvent>().is_multiple_of(8),
        "PipeCreateEvent must stay 8-byte aligned for ring buffer records"
    );

    /// Process tampering heuristic event (EID 25), emitted for cross-process
    /// memory writes (`process_vm_writev` to another pid). Partial/heuristic.
    #[repr(C)]
    #[derive(Debug, Clone, Copy, Pod, Zeroable)]
    pub struct ProcessTamperingEvent {
        /// Always [`EVENT_PROCESS_TAMPERING`].
        pub kind: u32,
        /// Source (writing) process id.
        pub source_pid: u32,
        /// Target (written) process id.
        pub target_pid: u32,
        /// Real UID of the source task.
        pub uid: u32,
        /// Real GID of the source task.
        pub gid: u32,
        /// Explicit padding keeping the record size a multiple of 8 (zeroed).
        pub _pad0: u32,
        /// Source task comm at tamper time (NUL-padded).
        pub comm: [u8; COMM_LEN],
    }

    impl ProcessTamperingEvent {
        /// Parse a ring buffer record into a typed process-tampering event.
        #[must_use]
        pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
            let r: &[u8; size_of::<Self>()] = bytes.try_into().ok()?;
            Some(*bytemuck::from_bytes(r))
        }
    }

    const _: () = assert!(
        core::mem::size_of::<ProcessTamperingEvent>().is_multiple_of(8),
        "ProcessTamperingEvent must stay 8-byte aligned for ring buffer records"
    );

    /// Credential-change syscall selector: `setuid`.
    pub const CRED_SETUID: u32 = 1;
    /// Credential-change syscall selector: `seteuid`.
    pub const CRED_SETEUID: u32 = 2;
    /// Credential-change syscall selector: `setreuid`.
    pub const CRED_SETREUID: u32 = 3;
    /// Credential-change syscall selector: `setresuid`.
    pub const CRED_SETRESUID: u32 = 4;
    /// Credential-change syscall selector: `setfsuid`.
    pub const CRED_SETFSUID: u32 = 5;
    /// Credential-change syscall selector: `setgid`.
    pub const CRED_SETGID: u32 = 6;
    /// Credential-change syscall selector: `setegid`.
    pub const CRED_SETEGID: u32 = 7;
    /// Credential-change syscall selector: `setregid`.
    pub const CRED_SETREGID: u32 = 8;
    /// Credential-change syscall selector: `setresgid`.
    pub const CRED_SETRESGID: u32 = 9;
    /// Credential-change syscall selector: `setfsgid`.
    pub const CRED_SETFSGID: u32 = 10;
    /// Credential-change syscall selector: `setgroups`.
    pub const CRED_SETGROUPS: u32 = 11;

    /// Credential change event (uid/gid/groups), emitted as Sysmon extension EID 501.
    #[repr(C)]
    #[derive(Debug, Clone, Copy, Pod, Zeroable)]
    pub struct CredentialChangeEvent {
        /// Always [`EVENT_CREDENTIAL_CHANGE`].
        pub kind: u32,
        /// Process id (tgid).
        pub pid: u32,
        /// Real UID at event time.
        pub uid: u32,
        /// Real GID at event time.
        pub gid: u32,
        /// Syscall selector (`CRED_*`).
        pub syscall: u32,
        /// Group count for `setgroups`, 0 otherwise.
        pub groups_count: u32,
        /// First target value (uid/ruid/gid/rgid), syscall-dependent.
        pub arg0: u32,
        /// Second target value (euid/egid), syscall-dependent.
        pub arg1: u32,
        /// Third target value (suid/sgid), syscall-dependent.
        pub arg2: u32,
        /// Syscall result / return code.
        pub result: i32,
        /// Task comm at event time (NUL-padded).
        pub comm: [u8; COMM_LEN],
        /// Explicit padding keeping the record size a multiple of 8 (zeroed).
        pub _pad0: [u32; 2],
    }

    impl CredentialChangeEvent {
        /// Parse a ring buffer record into a typed credential-change event.
        #[must_use]
        pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
            let r: &[u8; size_of::<Self>()] = bytes.try_into().ok()?;
            Some(*bytemuck::from_bytes(r))
        }
    }

    const _: () = assert!(
        core::mem::size_of::<CredentialChangeEvent>().is_multiple_of(8),
        "CredentialChangeEvent must stay 8-byte aligned for ring buffer records"
    );

    /// Capability-change syscall selector: `capset`.
    pub const CAP_CAPSET: u32 = 1;
    /// Capability-change syscall selector: `prctl` (capability-related options).
    pub const CAP_PRCTL: u32 = 2;

    /// Capability change event (capset/prctl capabilities), emitted as Sysmon extension EID 502.
    #[repr(C)]
    #[derive(Debug, Clone, Copy, Pod, Zeroable)]
    pub struct CapabilityChangeEvent {
        /// Always [`EVENT_CAPABILITY_CHANGE`].
        pub kind: u32,
        /// Process id (tgid).
        pub pid: u32,
        /// Real UID at event time.
        pub uid: u32,
        /// Real GID at event time.
        pub gid: u32,
        /// Syscall selector (`CAP_*`).
        pub syscall: u32,
        /// `prctl` option or 0 for `capset`.
        pub option: u32,
        /// First argument (e.g. prctl arg2).
        pub arg2: u64,
        /// Second argument (e.g. prctl arg3).
        pub arg3: u64,
        /// Third argument (e.g. prctl arg4).
        pub arg4: u64,
        /// Syscall result / return code.
        pub result: i64,
        /// Task comm at event time (NUL-padded).
        pub comm: [u8; COMM_LEN],
    }

    impl CapabilityChangeEvent {
        /// Parse a ring buffer record into a typed capability-change event.
        #[must_use]
        pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
            let r: &[u8; size_of::<Self>()] = bytes.try_into().ok()?;
            Some(*bytemuck::from_bytes(r))
        }
    }

    const _: () = assert!(
        core::mem::size_of::<CapabilityChangeEvent>().is_multiple_of(8),
        "CapabilityChangeEvent must stay 8-byte aligned for ring buffer records"
    );

    /// File-rename syscall selector: `rename`.
    pub const RENAME_RENAME: u32 = 1;
    /// File-rename syscall selector: `renameat`.
    pub const RENAME_RENAMEAT: u32 = 2;
    /// File-rename syscall selector: `renameat2`.
    pub const RENAME_RENAMEAT2: u32 = 3;

    /// File rename event (rename/renameat/renameat2), emitted as EID 503.
    #[repr(C)]
    #[derive(Debug, Clone, Copy, Pod, Zeroable)]
    pub struct FileRenameEvent {
        /// Always [`EVENT_FILE_RENAME`].
        pub kind: u32,
        /// Renaming process id (tgid).
        pub pid: u32,
        /// Real UID of the renaming task.
        pub uid: u32,
        /// Real GID of the renaming task.
        pub gid: u32,
        /// Syscall selector (`RENAME_*`).
        pub syscall: u32,
        /// `renameat2` flags (0 for rename/renameat).
        pub flags: u32,
        /// Old directory fd (`AT_FDCWD` for rename/cwd-relative).
        pub old_dirfd: i32,
        /// New directory fd (`AT_FDCWD` for rename/cwd-relative).
        pub new_dirfd: i32,
        /// Syscall result / return code.
        pub result: i32,
        /// Explicit padding keeping the record size a multiple of 8 (zeroed).
        pub _pad0: u32,
        /// Source/old path as passed to the syscall (NUL-padded).
        pub old_path: [u8; PATH_LEN],
        /// Target/new path as passed to the syscall (NUL-padded).
        pub new_path: [u8; PATH_LEN],
        /// Task comm at event time (NUL-padded).
        pub comm: [u8; COMM_LEN],
    }

    impl FileRenameEvent {
        /// Parse a ring buffer record into a typed file-rename event.
        #[must_use]
        pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
            let r: &[u8; size_of::<Self>()] = bytes.try_into().ok()?;
            Some(*bytemuck::from_bytes(r))
        }

        fn cstr(field: &[u8]) -> &str {
            let end = field.iter().position(|&b| b == 0).unwrap_or(field.len());
            core::str::from_utf8(&field[..end]).unwrap_or("")
        }

        /// Source path as lossy UTF-8 up to the first NUL.
        pub fn old_path_str(&self) -> &str {
            Self::cstr(&self.old_path)
        }

        /// Target path as lossy UTF-8 up to the first NUL.
        pub fn new_path_str(&self) -> &str {
            Self::cstr(&self.new_path)
        }
    }

    const _: () = assert!(
        core::mem::size_of::<FileRenameEvent>().is_multiple_of(8),
        "FileRenameEvent must stay 8-byte aligned for ring buffer records"
    );

    /// File-chmod syscall selector: `chmod`.
    pub const CHMOD_CHMOD: u32 = 1;
    /// File-chmod syscall selector: `fchmod`.
    pub const CHMOD_FCHMOD: u32 = 2;
    /// File-chmod syscall selector: `fchmodat`.
    pub const CHMOD_FCHMODAT: u32 = 3;
    /// File-chmod syscall selector: `fchmodat2`.
    pub const CHMOD_FCHMODAT2: u32 = 4;

    /// File chmod event, emitted as EID 504.
    #[repr(C)]
    #[derive(Debug, Clone, Copy, Pod, Zeroable)]
    pub struct FileChmodEvent {
        /// Always [`EVENT_FILE_CHMOD`].
        pub kind: u32,
        /// Process id (tgid).
        pub pid: u32,
        /// Real UID of the task.
        pub uid: u32,
        /// Real GID of the task.
        pub gid: u32,
        /// Syscall selector (`CHMOD_*`).
        pub syscall: u32,
        /// Mode argument.
        pub mode: u32,
        /// Flags (fchmodat/fchmodat2), 0 otherwise.
        pub flags: u32,
        /// Directory fd for *at variants, or `AT_FDCWD`/-1.
        pub dirfd: i32,
        /// File descriptor for fd-based variants, or -1.
        pub fd: i32,
        /// Syscall result / return code.
        pub result: i32,
        /// Target path (NUL-padded; may be empty for fd-based variants).
        pub path: [u8; PATH_LEN],
        /// Task comm at event time (NUL-padded).
        pub comm: [u8; COMM_LEN],
        /// Explicit padding keeping the record size a multiple of 8 (zeroed).
        pub _pad0: [u32; 2],
    }

    impl FileChmodEvent {
        /// Parse a ring buffer record into a typed file-chmod event.
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
        core::mem::size_of::<FileChmodEvent>().is_multiple_of(8),
        "FileChmodEvent must stay 8-byte aligned for ring buffer records"
    );

    /// File-chown syscall selector: `chown`.
    pub const CHOWN_CHOWN: u32 = 1;
    /// File-chown syscall selector: `lchown`.
    pub const CHOWN_LCHOWN: u32 = 2;
    /// File-chown syscall selector: `fchown`.
    pub const CHOWN_FCHOWN: u32 = 3;
    /// File-chown syscall selector: `fchownat`.
    pub const CHOWN_FCHOWNAT: u32 = 4;

    /// File chown event, emitted as EID 505.
    #[repr(C)]
    #[derive(Debug, Clone, Copy, Pod, Zeroable)]
    pub struct FileChownEvent {
        /// Always [`EVENT_FILE_CHOWN`].
        pub kind: u32,
        /// Process id (tgid).
        pub pid: u32,
        /// Real UID of the task.
        pub uid: u32,
        /// Real GID of the task.
        pub gid: u32,
        /// Syscall selector (`CHOWN_*`).
        pub syscall: u32,
        /// New owner uid argument.
        pub owner: u32,
        /// New group gid argument.
        pub group: u32,
        /// Flags (fchownat), 0 otherwise.
        pub flags: u32,
        /// Directory fd for *at variants, or `AT_FDCWD`/-1.
        pub dirfd: i32,
        /// File descriptor for fd-based variants, or -1.
        pub fd: i32,
        /// Syscall result / return code.
        pub result: i32,
        /// Explicit padding keeping the record size a multiple of 8 (zeroed).
        pub _pad0: u32,
        /// Target path (NUL-padded; may be empty for fd-based variants).
        pub path: [u8; PATH_LEN],
        /// Task comm at event time (NUL-padded).
        pub comm: [u8; COMM_LEN],
    }

    impl FileChownEvent {
        /// Parse a ring buffer record into a typed file-chown event.
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
        core::mem::size_of::<FileChownEvent>().is_multiple_of(8),
        "FileChownEvent must stay 8-byte aligned for ring buffer records"
    );

    /// File-truncate syscall selector: `truncate`.
    pub const TRUNCATE_TRUNCATE: u32 = 1;
    /// File-truncate syscall selector: `ftruncate`.
    pub const TRUNCATE_FTRUNCATE: u32 = 2;

    /// File truncate event, emitted as EID 506.
    #[repr(C)]
    #[derive(Debug, Clone, Copy, Pod, Zeroable)]
    pub struct FileTruncateEvent {
        /// Always [`EVENT_FILE_TRUNCATE`].
        pub kind: u32,
        /// Process id (tgid).
        pub pid: u32,
        /// Real UID of the task.
        pub uid: u32,
        /// Real GID of the task.
        pub gid: u32,
        /// Syscall selector (`TRUNCATE_*`).
        pub syscall: u32,
        /// File descriptor for fd-based variants, or -1.
        pub fd: i32,
        /// Requested length.
        pub length: i64,
        /// Syscall result / return code.
        pub result: i64,
        /// Target path (NUL-padded; may be empty for fd-based variants).
        pub path: [u8; PATH_LEN],
        /// Task comm at event time (NUL-padded).
        pub comm: [u8; COMM_LEN],
    }

    impl FileTruncateEvent {
        /// Parse a ring buffer record into a typed file-truncate event.
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
        core::mem::size_of::<FileTruncateEvent>().is_multiple_of(8),
        "FileTruncateEvent must stay 8-byte aligned for ring buffer records"
    );

    /// File-change/write syscall selector: `write`.
    pub const WRITE_WRITE: u32 = 1;
    /// File-change/write syscall selector: `pwrite64`.
    pub const WRITE_PWRITE64: u32 = 2;
    /// File-change/write syscall selector: `writev`.
    pub const WRITE_WRITEV: u32 = 3;
    /// File-change/write syscall selector: `pwritev`.
    pub const WRITE_PWRITEV: u32 = 4;
    /// File-change/write syscall selector: `pwritev2`.
    pub const WRITE_PWRITEV2: u32 = 5;

    /// File change/write event, emitted as Sysmon EID 2 (best-effort).
    #[repr(C)]
    #[derive(Debug, Clone, Copy, Pod, Zeroable)]
    pub struct FileChangeEvent {
        /// Always [`EVENT_FILE_CHANGE`].
        pub kind: u32,
        /// Process id (tgid).
        pub pid: u32,
        /// Real UID of the task.
        pub uid: u32,
        /// Real GID of the task.
        pub gid: u32,
        /// Syscall selector (`WRITE_*`).
        pub syscall: u32,
        /// File descriptor written to.
        pub fd: i32,
        /// Bytes written (syscall result), or -1 on error.
        pub bytes_written: i64,
        /// Task comm at event time (NUL-padded).
        pub comm: [u8; COMM_LEN],
    }

    impl FileChangeEvent {
        /// Parse a ring buffer record into a typed file-change event.
        #[must_use]
        pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
            let r: &[u8; size_of::<Self>()] = bytes.try_into().ok()?;
            Some(*bytemuck::from_bytes(r))
        }
    }

    const _: () = assert!(
        core::mem::size_of::<FileChangeEvent>().is_multiple_of(8),
        "FileChangeEvent must stay 8-byte aligned for ring buffer records"
    );
}

#[cfg(feature = "ebpf")]
pub use inner::*;
