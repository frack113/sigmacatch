// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 sigmacatch contributors

//! sigmacatch eBPF probes.
//!
//! - `syscalls/sys_enter_execve` / `sys_enter_execveat`: stage `image` + first
//!   argv elements per task (race-free capture, spec constraint);
//! - `sched/sched_process_exec`: emit [`ExecEvent`] on the `EVENTS` ring
//!   buffer;
//! - `sched/sched_process_exit`: emit [`ExitEvent`] for group leaders;
//! - `syscalls/sys_enter_openat` (O_CREAT) + `sys_exit_openat`: emit
//!   [`FileCreateEvent`] on successful creations.

#![no_std]
#![no_main]

use core::ptr;

#[allow(deprecated)]
use aya_ebpf::helpers::bpf_probe_read_user_str;
use aya_ebpf::{
    helpers::{
        bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_get_current_uid_gid,
        bpf_probe_read_user, bpf_probe_read_user_buf,
    },
    macros::{map, tracepoint},
    maps::{LruHashMap, PerCpuArray, RingBuf},
    programs::TracePointContext,
};

// Shared wire-format types: same single source as the userspace loader
// (sigmacatch/src/ebpf_common.rs, included via #[path]). The probe only uses
// the constants and struct layouts; the `from_bytes`/`*_str` accessors are
// userspace-only, hence the targeted allow.
#[path = "../../src/ebpf_common.rs"]
#[allow(dead_code)]
mod ebpf_common;

use ebpf_common::{
    ARG0_LEN, ARG1_LEN, ARG2_LEN, AT_FDCWD, CAP_CAPSET, CAP_PRCTL, CHMOD_CHMOD, CHMOD_FCHMOD,
    CHMOD_FCHMODAT, CHMOD_FCHMODAT2, CHOWN_CHOWN, CHOWN_FCHOWN, CHOWN_FCHOWNAT, CHOWN_LCHOWN,
    CRED_SETFSUID, CRED_SETFSGID, CRED_SETGID, CRED_SETGROUPS, CRED_SETREGID, CRED_SETRESGID,
    CRED_SETRESUID, CRED_SETREUID, CRED_SETUID, CapabilityChangeEvent, CredentialChangeEvent,
    DNS_PAYLOAD_LEN, DnsEvent, DriverLoadEvent, EVENT_CAPABILITY_CHANGE, EVENT_CREDENTIAL_CHANGE,
    EVENT_DNS, EVENT_DRIVER_LOAD, EVENT_EXEC, EVENT_EXIT, EVENT_FILE, EVENT_FILE_CHMOD,
    EVENT_FILE_CHOWN, EVENT_FILE_DELETE, EVENT_FILE_RENAME, EVENT_FILE_TRUNCATE, EVENT_FORK,
    EVENT_FILE_CHANGE, EVENT_LISTEN, EVENT_NET, EVENT_PIPE_CREATE, EVENT_PROCESS_ACCESS,
    EVENT_PROCESS_TAMPERING, EVENT_RAW_ACCESS, ExecEvent, ExitEvent, FileChangeEvent,
    FileChmodEvent, FileChownEvent, FileCreateEvent, FileDeleteEvent, FileRenameEvent,
    FileTruncateEvent, ForkEvent, IMAGE_LEN, ListenEvent, NetEvent, PATH_LEN, PipeCreateEvent,
    ProcessAccessEvent, ProcessTamperingEvent, RENAME_RENAME, RENAME_RENAMEAT, RENAME_RENAMEAT2,
    RawAccessEvent, TRUNCATE_FTRUNCATE, TRUNCATE_TRUNCATE, WRITE_PWRITE64, WRITE_PWRITEV,
    WRITE_PWRITEV2, WRITE_WRITE, WRITE_WRITEV,
};

const MAX_ENTRIES: u32 = 1;
const EXEC_ARGS_MAX: u32 = 4096;
const FILE_STAGE_MAX: u32 = 4096;
const DELETE_STAGE_MAX: u32 = 4096;
const FINIT_STAGE_MAX: u32 = 4096;
const RAW_STAGE_MAX: u32 = 4096;
const PIPE_STAGE_MAX: u32 = 4096;
const BIND_STAGE_MAX: u32 = 4096;
const LISTEN_FD_MAX: u32 = 4096;
const CRED_STAGE_MAX: u32 = 4096;
const CAP_STAGE_MAX: u32 = 4096;
const RENAME_STAGE_MAX: u32 = 4096;
const CHMOD_STAGE_MAX: u32 = 4096;
const CHOWN_STAGE_MAX: u32 = 4096;
const TRUNCATE_STAGE_MAX: u32 = 4096;
const WRITE_STAGE_MAX: u32 = 4096;
/// `O_CREAT` bit — openat is staged only when the caller may create.
const O_CREAT: u64 = 0o100;

// prctl capability-related options (v1)
const PR_SET_KEEPCAPS: u64 = 8;
const PR_CAPBSET_DROP: u64 = 24;
const PR_CAP_AMBIENT: u64 = 47;
#[repr(C)]
struct PendingExec {
    image: [u8; IMAGE_LEN],
    arg0: [u8; ARG0_LEN],
    arg1: [u8; ARG1_LEN],
    arg2: [u8; ARG2_LEN],
}

#[repr(C)]
struct PendingFile {
    path: [u8; PATH_LEN],
    dirfd: i32,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct PendingBind {
    family: u16,
    _pad0: u16,
    port_be: u16,
    _pad1: u16,
    addr: [u8; 16],
}

#[repr(C)]
struct DnsQuery {
    pid: u32,
    uid: u32,
    gid: u32,
    payload_len: u32,
    comm: [u8; 16],
    payload: [u8; DNS_PAYLOAD_LEN],
}

#[repr(C)]
#[derive(Clone, Copy)]
struct PendingCred {
    syscall: u32,
    groups_count: u32,
    arg0: u32,
    arg1: u32,
    arg2: u32,
    _pad0: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct PendingCap {
    syscall: u32,
    option: u32,
    arg2: u64,
    arg3: u64,
    arg4: u64,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct PendingRename {
    syscall: u32,
    flags: u32,
    old_dirfd: i32,
    new_dirfd: i32,
    old_path: [u8; PATH_LEN],
    new_path: [u8; PATH_LEN],
}

#[repr(C)]
#[derive(Clone, Copy)]
struct PendingChmod {
    syscall: u32,
    mode: u32,
    flags: u32,
    dirfd: i32,
    fd: i32,
    _pad0: i32,
    path: [u8; PATH_LEN],
}

#[repr(C)]
#[derive(Clone, Copy)]
struct PendingChown {
    syscall: u32,
    owner: u32,
    group: u32,
    flags: u32,
    dirfd: i32,
    fd: i32,
    path: [u8; PATH_LEN],
}

#[repr(C)]
#[derive(Clone, Copy)]
struct PendingTruncate {
    syscall: u32,
    fd: i32,
    length: i64,
    path: [u8; PATH_LEN],
}

#[repr(C)]
#[derive(Clone, Copy)]
struct PendingWrite {
    syscall: u32,
    fd: i32,
}

#[map(name = "EVENTS")]
static EVENTS: RingBuf = RingBuf::with_byte_size(1 << 20, 0);

#[map(name = "EXEC_ARGS")]
static EXEC_ARGS: LruHashMap<u32, PendingExec> = LruHashMap::with_max_entries(EXEC_ARGS_MAX, 0);

// BPF stack is 512 bytes: the ~256-byte staging buffer must live in a map.
#[map(name = "STAGE_SCRATCH")]
static STAGE_SCRATCH: PerCpuArray<PendingExec> = PerCpuArray::with_max_entries(MAX_ENTRIES, 0);

#[map(name = "FILE_STAGE")]
static FILE_STAGE: LruHashMap<u32, PendingFile> = LruHashMap::with_max_entries(FILE_STAGE_MAX, 0);

// Same stack constraint applies to the ~260-byte file staging buffer.
#[map(name = "FILE_SCRATCH")]
static FILE_SCRATCH: PerCpuArray<PendingFile> = PerCpuArray::with_max_entries(MAX_ENTRIES, 0);

#[map(name = "DELETE_STAGE")]
static DELETE_STAGE: LruHashMap<u32, PendingFile> =
    LruHashMap::with_max_entries(DELETE_STAGE_MAX, 0);

#[map(name = "RAW_STAGE")]
static RAW_STAGE: LruHashMap<u32, PendingFile> = LruHashMap::with_max_entries(RAW_STAGE_MAX, 0);

#[map(name = "PIPE_STAGE")]
static PIPE_STAGE: LruHashMap<u32, PendingFile> = LruHashMap::with_max_entries(PIPE_STAGE_MAX, 0);

#[map(name = "FINIT_STAGE")]
static FINIT_STAGE: LruHashMap<u64, i32> = LruHashMap::with_max_entries(FINIT_STAGE_MAX, 0);

#[map(name = "BIND_STAGE")]
static BIND_STAGE: LruHashMap<u64, PendingBind> = LruHashMap::with_max_entries(BIND_STAGE_MAX, 0);

#[map(name = "LISTEN_FD")]
static LISTEN_FD: LruHashMap<u64, i32> = LruHashMap::with_max_entries(LISTEN_FD_MAX, 0);

#[map(name = "CRED_STAGE")]
static CRED_STAGE: LruHashMap<u64, PendingCred> = LruHashMap::with_max_entries(CRED_STAGE_MAX, 0);

#[map(name = "CAP_STAGE")]
static CAP_STAGE: LruHashMap<u64, PendingCap> = LruHashMap::with_max_entries(CAP_STAGE_MAX, 0);

#[map(name = "RENAME_STAGE")]
static RENAME_STAGE: LruHashMap<u32, PendingRename> =
    LruHashMap::with_max_entries(RENAME_STAGE_MAX, 0);

#[map(name = "RENAME_SCRATCH")]
static RENAME_SCRATCH: PerCpuArray<PendingRename> = PerCpuArray::with_max_entries(MAX_ENTRIES, 0);

#[map(name = "CHMOD_STAGE")]
static CHMOD_STAGE: LruHashMap<u32, PendingChmod> = LruHashMap::with_max_entries(CHMOD_STAGE_MAX, 0);

#[map(name = "CHMOD_SCRATCH")]
static CHMOD_SCRATCH: PerCpuArray<PendingChmod> = PerCpuArray::with_max_entries(MAX_ENTRIES, 0);

#[map(name = "CHOWN_STAGE")]
static CHOWN_STAGE: LruHashMap<u32, PendingChown> = LruHashMap::with_max_entries(CHOWN_STAGE_MAX, 0);

#[map(name = "CHOWN_SCRATCH")]
static CHOWN_SCRATCH: PerCpuArray<PendingChown> = PerCpuArray::with_max_entries(MAX_ENTRIES, 0);

#[map(name = "TRUNCATE_STAGE")]
static TRUNCATE_STAGE: LruHashMap<u32, PendingTruncate> =
    LruHashMap::with_max_entries(TRUNCATE_STAGE_MAX, 0);

#[map(name = "TRUNCATE_SCRATCH")]
static TRUNCATE_SCRATCH: PerCpuArray<PendingTruncate> =
    PerCpuArray::with_max_entries(MAX_ENTRIES, 0);

#[map(name = "WRITE_STAGE")]
static WRITE_STAGE: LruHashMap<u32, PendingWrite> = LruHashMap::with_max_entries(WRITE_STAGE_MAX, 0);

/// Read a NUL-terminated user string into `dst`, returning the stored length
/// (excluding the NUL), provably bounded by `dst.len() - 1`.
#[allow(deprecated)]
fn read_cstr(dst: &mut [u8], src: *const u8) -> usize {
    if src.is_null() || dst.is_empty() {
        return 0;
    }
    let cap = dst.len();
    // SAFETY: bpf_probe_read_user_str reads at most dst.len() bytes and stops
    // at the user-space NUL; faults on unmapped user addresses are handled by
    // the helper (Err), never trap the probe.
    let raw = unsafe { bpf_probe_read_user_str(src, dst) }.unwrap_or(0);
    raw.min(cap).saturating_sub(1)
}

#[tracepoint(category = "syscalls", name = "sys_enter_execve")]
fn sys_enter_execve(ctx: TracePointContext) -> i32 {
    match try_stage_execve(&ctx) {
        Ok(()) => 0,
        Err(e) => e as i32,
    }
}

fn try_stage_execve(ctx: &TracePointContext) -> Result<(), i64> {
    // SAFETY: read_at validates the offset against the tracepoint context
    // size and copies a pointer-sized argument; out-of-range yields Err.
    let filename: *const u8 = unsafe { ctx.read_at(16)? };
    let argv_base: *const *const u8 = unsafe { ctx.read_at(24)? };
    stage_exec_args(filename, argv_base)
}

#[tracepoint(category = "syscalls", name = "sys_enter_execveat")]
fn sys_enter_execveat(ctx: TracePointContext) -> i32 {
    match try_stage_execveat(&ctx) {
        Ok(()) => 0,
        Err(e) => e as i32,
    }
}

fn try_stage_execveat(ctx: &TracePointContext) -> Result<(), i64> {
    // SAFETY: offsets match the sys_enter_execveat tracepoint format
    // (fd@16, filename@24, argv@32, envp@40, flags@48).
    let filename: *const u8 = unsafe { ctx.read_at(24)? };
    let argv_base: *const *const u8 = unsafe { ctx.read_at(32)? };
    stage_exec_args(filename, argv_base)
}

fn stage_exec_args(filename: *const u8, argv_base: *const *const u8) -> Result<(), i64> {
    // Key by task id (tid) for syscall-instance correlation with sched_process_exec.
    let tid = bpf_get_current_pid_tgid() as u32;

    let pending = match STAGE_SCRATCH.get_ptr_mut(0) {
        // SAFETY: index 0 < MAX_ENTRIES(1) is checked by get_ptr_mut; the
        // returned pointer targets per-cpu map storage valid for the whole
        // program run and exclusive to this CPU.
        Some(p) => unsafe { &mut *p },
        None => return Err(-28),
    };
    pending.image = [0; IMAGE_LEN];
    pending.arg0 = [0; ARG0_LEN];
    pending.arg1 = [0; ARG1_LEN];
    pending.arg2 = [0; ARG2_LEN];
    read_cstr(&mut pending.image, filename);

    // Capture a bounded, race-free command line from argv[0..2] at exec time.
    // This is essential for short-lived processes where userspace can no longer
    // read /proc/<pid>/cmdline by the time the ring-buffer event is handled.
    // Each argument is read into a fixed buffer (verifier-friendly).
    // SAFETY: argv_base points to a user argv pointer array; fixed-size pointer
    // reads are fault-tolerant via the helper.
    let arg0p: *const u8 = unsafe { bpf_probe_read_user(argv_base.add(0)) }.unwrap_or(ptr::null());
    if !arg0p.is_null() {
        read_cstr(&mut pending.arg0, arg0p);
    }
    let arg1p: *const u8 = unsafe { bpf_probe_read_user(argv_base.add(1)) }.unwrap_or(ptr::null());
    if !arg1p.is_null() {
        read_cstr(&mut pending.arg1, arg1p);
    }
    let arg2p: *const u8 = unsafe { bpf_probe_read_user(argv_base.add(2)) }.unwrap_or(ptr::null());
    if !arg2p.is_null() {
        read_cstr(&mut pending.arg2, arg2p);
    }

    let _ = EXEC_ARGS.insert(&tid, pending, 0);
    Ok(())
}

#[tracepoint(category = "sched", name = "sched_process_exec")]
fn sched_process_exec(_ctx: TracePointContext) -> i32 {
    match try_emit_exec() {
        Ok(()) => 0,
        Err(e) => e as i32,
    }
}

fn try_emit_exec() -> Result<(), i64> {
    let tgid = (bpf_get_current_pid_tgid() >> 32) as u32;
    let tid = bpf_get_current_pid_tgid() as u32;
    // Copy staged argv/image out before removal to avoid holding a reference
    // across map mutation. Staging uses the task id (tid) for syscall-instance
    // correlation; prefer tid, fall back to tgid for robustness.
    let staged = match unsafe { EXEC_ARGS.get(&tid) } {
        Some(s) => {
            let s = PendingExec {
                image: s.image,
                arg0: s.arg0,
                arg1: s.arg1,
                arg2: s.arg2,
            };
            EXEC_ARGS.remove(&tid)?;
            s
        }
        None => match unsafe { EXEC_ARGS.get(&tgid) } {
            Some(s) => {
                let s = PendingExec {
                    image: s.image,
                    arg0: s.arg0,
                    arg1: s.arg1,
                    arg2: s.arg2,
                };
                EXEC_ARGS.remove(&tgid)?;
                s
            }
            None => return Ok(()),
        },
    };

    let uidgid = bpf_get_current_uid_gid();
    let comm = bpf_get_current_comm().unwrap_or([0; 16]);
    if let Some(mut entry) = EVENTS.reserve::<ExecEvent>(0) {
        let p = entry.as_mut_ptr();
        // SAFETY: reserve handed us a T-sized, T-aligned ring-buffer slot
        // owned exclusively until submit(); all field writes stay in bounds
        // of ExecEvent.
        unsafe {
            (*p).kind = EVENT_EXEC;
            (*p).pid = tgid;
            (*p).uid = uidgid as u32;
            (*p).gid = (uidgid >> 32) as u32;
            (*p)._pad0 = 0;
            (*p).comm = comm;
            (*p).image = staged.image;
            (*p).arg0 = staged.arg0;
            (*p).arg1 = staged.arg1;
            (*p).arg2 = staged.arg2;
            (*p)._pad1 = 0;
        }
        entry.submit(0);
    }
    Ok(())
}

#[tracepoint(category = "sched", name = "sched_process_exit")]
fn sched_process_exit(_ctx: TracePointContext) -> i32 {
    let ids = bpf_get_current_pid_tgid();
    // Group leaders only: threads terminate silently.
    if (ids >> 32) != (ids & 0xffff_ffff) {
        return 0;
    }
    if let Some(mut entry) = EVENTS.reserve::<ExitEvent>(0) {
        entry.write(ExitEvent {
            kind: EVENT_EXIT,
            pid: (ids >> 32) as u32,
        });
        entry.submit(0);
    }
    0
}

#[tracepoint(category = "sched", name = "sched_process_fork")]
fn sched_process_fork(ctx: TracePointContext) -> i32 {
    match try_emit_fork(&ctx) {
        Ok(()) => 0,
        Err(e) => e as i32,
    }
}

fn try_emit_fork(ctx: &TracePointContext) -> Result<(), i64> {
    // SAFETY: offsets match the sched_process_fork tracepoint format
    // (parent_pid@24, child_pid@44).
    let parent_pid: u32 = unsafe { ctx.read_at::<i32>(24)? } as u32;
    let child_pid: u32 = unsafe { ctx.read_at::<i32>(44)? } as u32;
    if let Some(mut entry) = EVENTS.reserve::<ForkEvent>(0) {
        entry.write(ForkEvent {
            kind: EVENT_FORK,
            parent_pid,
            child_pid,
            _pad0: 0,
        });
        entry.submit(0);
    }
    Ok(())
}

/// Kernel `sockaddr_in` / `sockaddr_in6` mirrors (repr(C), natural offsets
/// match the kernel definitions for these field layouts).
#[repr(C)]
struct SockAddr4 {
    family: u16,
    port: u16,
    addr: [u8; 4],
    _zero: [u8; 8],
}

#[repr(C)]
struct SockAddr6 {
    family: u16,
    port: u16,
    _flowinfo: u32,
    addr: [u8; 16],
    _scope: u32,
}

#[tracepoint(category = "syscalls", name = "sys_enter_connect")]
fn sys_enter_connect(ctx: TracePointContext) -> i32 {
    match try_emit_connect(&ctx) {
        Ok(()) => 0,
        Err(e) => e as i32,
    }
}

fn try_emit_connect(ctx: &TracePointContext) -> Result<(), i64> {
    // SAFETY: read_at bounds-checked against the tracepoint context.
    let uservaddr: *const u8 = unsafe { ctx.read_at(24)? };
    // SAFETY: two-byte user read; fault handled by helper → 0.
    let family = unsafe { bpf_probe_read_user::<u16>(uservaddr.cast()) }.unwrap_or(0);
    let (port_be, addr) = match family {
        // AF_INET
        2 => {
            // SAFETY: sizeof::<SockAddr4>() fixed-size user read; helper is
            // fault-tolerant and the struct mirrors the kernel sockaddr_in.
            let s: SockAddr4 = unsafe { bpf_probe_read_user(uservaddr.cast()) }?;
            let mut a = [0u8; 16];
            a[..4].copy_from_slice(&s.addr);
            (s.port, a)
        }
        // AF_INET6
        10 => {
            // SAFETY: fixed-size user read of sockaddr_in6 mirror; helper
            // handles page faults by returning Err.
            let s: SockAddr6 = unsafe { bpf_probe_read_user(uservaddr.cast()) }?;
            (s.port, s.addr)
        }
        _ => return Ok(()),
    };

    let ids = bpf_get_current_pid_tgid();
    let uidgid = bpf_get_current_uid_gid();
    let comm = bpf_get_current_comm().unwrap_or([0; 16]);
    if let Some(mut entry) = EVENTS.reserve::<NetEvent>(0) {
        let p = entry.as_mut_ptr();
        // SAFETY: exclusive reserved NetEvent slot; field writes in bounds.
        unsafe {
            (*p).kind = EVENT_NET;
            (*p).pid = (ids >> 32) as u32;
            (*p).uid = uidgid as u32;
            (*p).gid = (uidgid >> 32) as u32;
            (*p).family = family;
            (*p)._pad0 = 0;
            (*p).port_be = port_be;
            (*p)._pad1 = 0;
            (*p).addr = addr;
            (*p).comm = comm;
        }
        entry.submit(0);
    }
    Ok(())
}

// ─── Socket listen capture (extension B6) ───────────────────────────────────

fn bind_key(tgid: u32, fd: i32) -> u64 {
    ((tgid as u64) << 32) | (fd as u32 as u64)
}

#[tracepoint(category = "syscalls", name = "sys_enter_bind")]
fn sys_enter_bind(ctx: TracePointContext) -> i32 {
    match try_stage_bind(&ctx) {
        Ok(()) => 0,
        Err(e) => e as i32,
    }
}

fn try_stage_bind(ctx: &TracePointContext) -> Result<(), i64> {
    // SAFETY: bounds-checked context reads (bind args fd, umyaddr).
    let fd: i32 = unsafe { ctx.read_at(16)? };
    let uservaddr: *const u8 = unsafe { ctx.read_at(24)? };
    // SAFETY: two-byte user read; fault handled by helper → 0.
    let family = unsafe { bpf_probe_read_user::<u16>(uservaddr.cast()) }.unwrap_or(0);
    let (port_be, addr) = match family {
        // AF_INET
        2 => {
            // SAFETY: fixed-size sockaddr_in user read; fault-tolerant helper.
            let s: SockAddr4 = unsafe { bpf_probe_read_user(uservaddr.cast()) }?;
            let mut a = [0u8; 16];
            a[..4].copy_from_slice(&s.addr);
            (s.port, a)
        }
        // AF_INET6
        10 => {
            // SAFETY: fixed-size sockaddr_in6 user read; fault-tolerant helper.
            let s: SockAddr6 = unsafe { bpf_probe_read_user(uservaddr.cast()) }?;
            (s.port, s.addr)
        }
        _ => return Ok(()),
    };

    let tgid = (bpf_get_current_pid_tgid() >> 32) as u32;
    let pending = PendingBind {
        family,
        _pad0: 0,
        port_be,
        _pad1: 0,
        addr,
    };
    let _ = BIND_STAGE.insert(&bind_key(tgid, fd), &pending, 0);
    Ok(())
}

#[tracepoint(category = "syscalls", name = "sys_enter_listen")]
fn sys_enter_listen(ctx: TracePointContext) -> i32 {
    match try_stage_listen(&ctx) {
        Ok(()) => 0,
        Err(e) => e as i32,
    }
}

fn try_stage_listen(ctx: &TracePointContext) -> Result<(), i64> {
    // SAFETY: bounds-checked context read (listen arg fd).
    let fd: i32 = unsafe { ctx.read_at(16)? };
    let tid_key = bpf_get_current_pid_tgid();
    let _ = LISTEN_FD.insert(&tid_key, &fd, 0);
    Ok(())
}

#[tracepoint(category = "syscalls", name = "sys_exit_listen")]
fn sys_exit_listen(ctx: TracePointContext) -> i32 {
    match try_emit_listen(&ctx) {
        Ok(()) => 0,
        Err(e) => e as i32,
    }
}

fn try_emit_listen(ctx: &TracePointContext) -> Result<(), i64> {
    // SAFETY: bounds-checked context read of the syscall return value.
    let ret: i64 = unsafe { ctx.read_at(16)? };
    let tid_key = bpf_get_current_pid_tgid();
    // SAFETY: read-only map borrow of a fixed-size value.
    let Some(fd) = (unsafe { LISTEN_FD.get(&tid_key) }).copied() else {
        return Ok(());
    };
    LISTEN_FD.remove(&tid_key)?;

    let tgid = (bpf_get_current_pid_tgid() >> 32) as u32;
    let key = bind_key(tgid, fd);
    // SAFETY: read-only map borrow of a fixed-size value.
    let Some(staged) = (unsafe { BIND_STAGE.get(&key) }).copied() else {
        return Ok(());
    };
    // Consume staged bind regardless of listen outcome to bound map growth.
    BIND_STAGE.remove(&key)?;
    if ret < 0 {
        return Ok(());
    }

    let uidgid = bpf_get_current_uid_gid();
    let comm = bpf_get_current_comm().unwrap_or([0; 16]);
    if let Some(mut entry) = EVENTS.reserve::<ListenEvent>(0) {
        let p = entry.as_mut_ptr();
        // SAFETY: exclusive reserved ListenEvent slot; writes in bounds.
        unsafe {
            (*p).kind = EVENT_LISTEN;
            (*p).pid = tgid;
            (*p).uid = uidgid as u32;
            (*p).gid = (uidgid >> 32) as u32;
            (*p).family = staged.family;
            (*p)._pad0 = 0;
            (*p).port_be = staged.port_be;
            (*p)._pad1 = 0;
            (*p).addr = staged.addr;
            (*p).comm = comm;
        }
        entry.submit(0);
    }
    Ok(())
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

fn path_starts_with(path: &[u8; PATH_LEN], prefix: &[u8]) -> bool {
    let n = prefix.len();
    if n > PATH_LEN {
        return false;
    }
    let mut i = 0;
    while i < n {
        if path[i] != prefix[i] {
            return false;
        }
        i += 1;
    }
    true
}

fn is_raw_device_path(path: &[u8; PATH_LEN]) -> bool {
    path_starts_with(path, b"/dev/mem\0")
        || path_starts_with(path, b"/dev/kmem\0")
        || path_starts_with(path, b"/dev/sd")
        || path_starts_with(path, b"/dev/hd")
        || path_starts_with(path, b"/dev/vd")
        || path_starts_with(path, b"/dev/xvd")
        || path_starts_with(path, b"/dev/nvme")
        || path_starts_with(path, b"/dev/loop")
        || path_starts_with(path, b"/dev/dm-")
        || path_starts_with(path, b"/dev/md")
        || path_starts_with(path, b"/dev/mmcblk")
        || path_starts_with(path, b"/dev/pmem")
        || path_starts_with(path, b"/dev/disk/")
}

fn stage_open_path(pathname: *const u8, dirfd: i32, flags: u64, check_create: bool) {
    // Key by task id for syscall-instance correlation between enter/exit.
    let tid = bpf_get_current_pid_tgid() as u32;
    let pending = match FILE_SCRATCH.get_ptr_mut(0) {
        // SAFETY: index validated by get_ptr_mut; per-cpu map storage valid
        // and unaliased for this program invocation.
        Some(p) => unsafe { &mut *p },
        None => return,
    };
    pending.path = [0; PATH_LEN];
    pending.dirfd = dirfd;
    read_cstr(&mut pending.path, pathname);

    let wants_create = check_create && (flags & O_CREAT != 0);
    let wants_raw = is_raw_device_path(&pending.path);
    if wants_create {
        let _ = FILE_STAGE.insert(&tid, &*pending, 0);
    }
    if wants_raw {
        let _ = RAW_STAGE.insert(&tid, &*pending, 0);
    }
}

#[tracepoint(category = "syscalls", name = "sys_enter_openat")]
fn sys_enter_openat(ctx: TracePointContext) -> i32 {
    // SAFETY: bounds-checked reads from tracepoint context.
    let dirfd: i32 = unsafe { ctx.read_at(16).unwrap_or(-100) };
    let pathname: *const u8 = unsafe { ctx.read_at(24).unwrap_or(ptr::null()) };
    let flags: u64 = unsafe { ctx.read_at(32).unwrap_or(0) };
    stage_open_path(pathname, dirfd, flags, true);
    0
}

#[tracepoint(category = "syscalls", name = "sys_exit_openat")]
fn sys_exit_openat(ctx: TracePointContext) -> i32 {
    let _ = try_emit_file_create(&ctx);
    let _ = try_emit_raw_access(&ctx);
    0
}

#[tracepoint(category = "syscalls", name = "sys_enter_open")]
fn sys_enter_open(ctx: TracePointContext) -> i32 {
    // SAFETY: bounds-checked reads from tracepoint context.
    let pathname: *const u8 = unsafe { ctx.read_at(16).unwrap_or(ptr::null()) };
    let flags: u64 = unsafe { ctx.read_at(24).unwrap_or(0) };
    stage_open_path(pathname, ebpf_common::AT_FDCWD, flags, true);
    0
}

#[tracepoint(category = "syscalls", name = "sys_exit_open")]
fn sys_exit_open(ctx: TracePointContext) -> i32 {
    let _ = try_emit_file_create(&ctx);
    let _ = try_emit_raw_access(&ctx);
    0
}

#[tracepoint(category = "syscalls", name = "sys_enter_openat2")]
fn sys_enter_openat2(ctx: TracePointContext) -> i32 {
    // SAFETY: bounds-checked reads from tracepoint context.
    let dirfd: i32 = unsafe { ctx.read_at(16).unwrap_or(-100) };
    let pathname: *const u8 = unsafe { ctx.read_at(24).unwrap_or(ptr::null()) };
    let how: *const u8 = unsafe { ctx.read_at(32).unwrap_or(ptr::null()) };
    let usize_arg: usize = unsafe { ctx.read_at(40).unwrap_or(0) };
    if how.is_null() || usize_arg < 8 {
        return 0;
    }
    // SAFETY: fixed 8-byte user read; fault-tolerant helper.
    let flags: u64 = unsafe { bpf_probe_read_user(how.cast()) }.unwrap_or(0);
    stage_open_path(pathname, dirfd, flags, true);
    0
}

#[tracepoint(category = "syscalls", name = "sys_exit_openat2")]
fn sys_exit_openat2(ctx: TracePointContext) -> i32 {
    let _ = try_emit_file_create(&ctx);
    let _ = try_emit_raw_access(&ctx);
    0
}

fn try_emit_file_create(ctx: &TracePointContext) -> Result<(), i64> {
    // SAFETY: bounds-checked context read of the syscall return value.
    let ret: i64 = unsafe { ctx.read_at(16)? };
    if ret < 0 {
        return Ok(()); // failed open — nothing was created
    }
    let ids = bpf_get_current_pid_tgid();
    let pid = (ids >> 32) as u32;
    let tid = ids as u32;
    // SAFETY: read-only map borrow, copied out immediately; lifetime ends
    // with the expression.
    let Some(staged) = (unsafe { FILE_STAGE.get(&tid) }).map(|p| PendingFile {
        path: p.path,
        dirfd: p.dirfd,
    }) else {
        return Ok(());
    };
    FILE_STAGE.remove(&tid)?;

    let uidgid = bpf_get_current_uid_gid();
    let comm = bpf_get_current_comm().unwrap_or([0; 16]);
    if let Some(mut entry) = EVENTS.reserve::<FileCreateEvent>(0) {
        let p = entry.as_mut_ptr();
        // SAFETY: exclusive reserved FileCreateEvent slot; writes in bounds.
        unsafe {
            (*p).kind = EVENT_FILE;
            (*p).pid = pid;
            (*p).uid = uidgid as u32;
            (*p).gid = (uidgid >> 32) as u32;
            (*p).dirfd = staged.dirfd;
            (*p)._pad0 = 0;
            (*p).path = staged.path;
            (*p).comm = comm;
        }
        entry.submit(0);
    }
    Ok(())
}

fn try_emit_raw_access(ctx: &TracePointContext) -> Result<(), i64> {
    // SAFETY: bounds-checked context read of the syscall return value.
    let ret: i64 = unsafe { ctx.read_at(16)? };
    if ret < 0 {
        return Ok(());
    }
    let ids = bpf_get_current_pid_tgid();
    let pid = (ids >> 32) as u32;
    let tid = ids as u32;
    // SAFETY: read-only map borrow, copied out immediately.
    let Some(staged) = (unsafe { RAW_STAGE.get(&tid) }).map(|p| PendingFile {
        path: p.path,
        dirfd: p.dirfd,
    }) else {
        return Ok(());
    };
    RAW_STAGE.remove(&tid)?;

    let uidgid = bpf_get_current_uid_gid();
    let comm = bpf_get_current_comm().unwrap_or([0; 16]);
    if let Some(mut entry) = EVENTS.reserve::<RawAccessEvent>(0) {
        let p = entry.as_mut_ptr();
        // SAFETY: exclusive reserved RawAccessEvent slot; writes in bounds.
        unsafe {
            (*p).kind = EVENT_RAW_ACCESS;
            (*p).pid = pid;
            (*p).uid = uidgid as u32;
            (*p).gid = (uidgid >> 32) as u32;
            (*p).dirfd = staged.dirfd;
            (*p)._pad0 = 0;
            (*p).path = staged.path;
            (*p).comm = comm;
        }
        entry.submit(0);
    }
    Ok(())
}

// ─── Process access capture (B8, EID 10) ────────────────────────────────────

#[tracepoint(category = "syscalls", name = "sys_enter_ptrace")]
fn sys_enter_ptrace(ctx: TracePointContext) -> i32 {
    match try_emit_ptrace(&ctx) {
        Ok(()) => 0,
        Err(e) => e as i32,
    }
}

fn try_emit_ptrace(ctx: &TracePointContext) -> Result<(), i64> {
    // SAFETY: offsets from sys_enter_ptrace format (request@16, pid@24).
    let request: i64 = unsafe { ctx.read_at(16)? };
    let target: i64 = unsafe { ctx.read_at(24)? };
    if target <= 0 {
        return Ok(());
    }
    let ids = bpf_get_current_pid_tgid();
    let source_pid = (ids >> 32) as u32;
    let target_pid = target as u32;
    if target_pid == source_pid {
        return Ok(());
    }
    let uidgid = bpf_get_current_uid_gid();
    let comm = bpf_get_current_comm().unwrap_or([0; 16]);
    if let Some(mut entry) = EVENTS.reserve::<ProcessAccessEvent>(0) {
        let p = entry.as_mut_ptr();
        // SAFETY: exclusive reserved ProcessAccessEvent slot; writes in bounds.
        unsafe {
            (*p).kind = EVENT_PROCESS_ACCESS;
            (*p).source_pid = source_pid;
            (*p).source_tid = ids as u32;
            (*p).source_uid = uidgid as u32;
            (*p).source_gid = (uidgid >> 32) as u32;
            (*p)._pad0 = 0;
            (*p).target_pid = target_pid;
            (*p)._pad1 = 0;
            (*p).request = request as u64;
            (*p).comm = comm;
        }
        entry.submit(0);
    }
    Ok(())
}

// ─── Process tampering capture (B12, EID 25, heuristic) ─────────────────────

#[tracepoint(category = "syscalls", name = "sys_enter_process_vm_writev")]
fn sys_enter_process_vm_writev(ctx: TracePointContext) -> i32 {
    match try_emit_process_tampering(&ctx) {
        Ok(()) => 0,
        Err(e) => e as i32,
    }
}

fn try_emit_process_tampering(ctx: &TracePointContext) -> Result<(), i64> {
    // SAFETY: offsets from sys_enter_process_vm_writev format (pid@16).
    let target: i64 = unsafe { ctx.read_at(16)? };
    if target <= 0 {
        return Ok(());
    }
    let ids = bpf_get_current_pid_tgid();
    let source_pid = (ids >> 32) as u32;
    let target_pid = target as u32;
    if target_pid == source_pid {
        return Ok(());
    }
    let uidgid = bpf_get_current_uid_gid();
    let comm = bpf_get_current_comm().unwrap_or([0; 16]);
    if let Some(mut entry) = EVENTS.reserve::<ProcessTamperingEvent>(0) {
        let p = entry.as_mut_ptr();
        // SAFETY: exclusive reserved ProcessTamperingEvent slot; writes in bounds.
        unsafe {
            (*p).kind = EVENT_PROCESS_TAMPERING;
            (*p).source_pid = source_pid;
            (*p).target_pid = target_pid;
            (*p).uid = uidgid as u32;
            (*p).gid = (uidgid >> 32) as u32;
            (*p)._pad0 = 0;
            (*p).comm = comm;
        }
        entry.submit(0);
    }
    Ok(())
}

// ─── Driver/module load capture (B9, EID 6) ─────────────────────────────────

#[tracepoint(category = "syscalls", name = "sys_enter_finit_module")]
fn sys_enter_finit_module(ctx: TracePointContext) -> i32 {
    match try_stage_finit_module(&ctx) {
        Ok(()) => 0,
        Err(e) => e as i32,
    }
}

fn try_stage_finit_module(ctx: &TracePointContext) -> Result<(), i64> {
    // SAFETY: offset from sys_enter_finit_module format (fd@16).
    let fd: i32 = unsafe { ctx.read_at(16)? };
    let tid_key = bpf_get_current_pid_tgid();
    let _ = FINIT_STAGE.insert(&tid_key, &fd, 0);
    Ok(())
}

#[tracepoint(category = "syscalls", name = "sys_exit_finit_module")]
fn sys_exit_finit_module(ctx: TracePointContext) -> i32 {
    match try_emit_finit_module(&ctx) {
        Ok(()) => 0,
        Err(e) => e as i32,
    }
}

fn try_emit_finit_module(ctx: &TracePointContext) -> Result<(), i64> {
    // SAFETY: bounds-checked context read of the syscall return value.
    let ret: i64 = unsafe { ctx.read_at(16)? };
    let tid_key = bpf_get_current_pid_tgid();
    // SAFETY: read-only map borrow of a fixed-size value.
    let Some(fd) = (unsafe { FINIT_STAGE.get(&tid_key) }).copied() else {
        return Ok(());
    };
    FINIT_STAGE.remove(&tid_key)?;
    if ret != 0 {
        return Ok(());
    }

    let ids = bpf_get_current_pid_tgid();
    let uidgid = bpf_get_current_uid_gid();
    let comm = bpf_get_current_comm().unwrap_or([0; 16]);
    if let Some(mut entry) = EVENTS.reserve::<DriverLoadEvent>(0) {
        let p = entry.as_mut_ptr();
        // SAFETY: exclusive reserved DriverLoadEvent slot; writes in bounds.
        unsafe {
            (*p).kind = EVENT_DRIVER_LOAD;
            (*p).pid = (ids >> 32) as u32;
            (*p).uid = uidgid as u32;
            (*p).gid = (uidgid >> 32) as u32;
            (*p).fd = fd;
            (*p)._pad0 = 0;
            (*p).comm = comm;
        }
        entry.submit(0);
    }
    Ok(())
}

// ─── Pipe create capture (B11, EID 17) ──────────────────────────────────────

const S_IFMT: u64 = 0o170000;
const S_IFIFO: u64 = 0o010000;

#[tracepoint(category = "syscalls", name = "sys_enter_mknodat")]
fn sys_enter_mknodat(ctx: TracePointContext) -> i32 {
    match try_stage_mknodat(&ctx) {
        Ok(()) => 0,
        Err(e) => e as i32,
    }
}

fn try_stage_mknodat(ctx: &TracePointContext) -> Result<(), i64> {
    // SAFETY: offsets from sys_enter_mknodat format (dfd@16, filename@24, mode@32).
    let dirfd: i32 = unsafe { ctx.read_at(16)? };
    let pathname: *const u8 = unsafe { ctx.read_at(24)? };
    let mode: u64 = unsafe { ctx.read_at(32)? };
    if mode & S_IFMT != S_IFIFO {
        return Ok(());
    }
    let tid = bpf_get_current_pid_tgid() as u32;

    let pending = match FILE_SCRATCH.get_ptr_mut(0) {
        // SAFETY: index validated by get_ptr_mut; per-cpu exclusivity.
        Some(p) => unsafe { &mut *p },
        None => return Err(-28),
    };
    pending.path = [0; PATH_LEN];
    pending.dirfd = dirfd;
    read_cstr(&mut pending.path, pathname);
    let _ = PIPE_STAGE.insert(&tid, pending, 0);
    Ok(())
}

#[tracepoint(category = "syscalls", name = "sys_exit_mknodat")]
fn sys_exit_mknodat(ctx: TracePointContext) -> i32 {
    match try_emit_pipe_create(&ctx) {
        Ok(()) => 0,
        Err(e) => e as i32,
    }
}

#[tracepoint(category = "syscalls", name = "sys_enter_mknod")]
fn sys_enter_mknod(ctx: TracePointContext) -> i32 {
    match try_stage_mknod(&ctx) {
        Ok(()) => 0,
        Err(e) => e as i32,
    }
}

fn try_stage_mknod(ctx: &TracePointContext) -> Result<(), i64> {
    // SAFETY: offsets from sys_enter_mknod format (filename@16, mode@24).
    let pathname: *const u8 = unsafe { ctx.read_at(16)? };
    let mode: u64 = unsafe { ctx.read_at(24)? };
    if mode & S_IFMT != S_IFIFO {
        return Ok(());
    }
    let tid = bpf_get_current_pid_tgid() as u32;

    let pending = match FILE_SCRATCH.get_ptr_mut(0) {
        // SAFETY: index validated by get_ptr_mut; per-cpu exclusivity.
        Some(p) => unsafe { &mut *p },
        None => return Err(-28),
    };
    pending.path = [0; PATH_LEN];
    pending.dirfd = ebpf_common::AT_FDCWD;
    read_cstr(&mut pending.path, pathname);
    let _ = PIPE_STAGE.insert(&tid, pending, 0);
    Ok(())
}

#[tracepoint(category = "syscalls", name = "sys_exit_mknod")]
fn sys_exit_mknod(ctx: TracePointContext) -> i32 {
    match try_emit_pipe_create(&ctx) {
        Ok(()) => 0,
        Err(e) => e as i32,
    }
}

fn try_emit_pipe_create(ctx: &TracePointContext) -> Result<(), i64> {
    // SAFETY: bounds-checked context read of the syscall return value.
    let ret: i64 = unsafe { ctx.read_at(16)? };
    if ret != 0 {
        return Ok(());
    }
    let ids = bpf_get_current_pid_tgid();
    let pid = (ids >> 32) as u32;
    let tid = ids as u32;
    // SAFETY: read-only map borrow, copied out immediately.
    let Some(staged) = (unsafe { PIPE_STAGE.get(&tid) }).map(|p| PendingFile {
        path: p.path,
        dirfd: p.dirfd,
    }) else {
        return Ok(());
    };
    PIPE_STAGE.remove(&tid)?;

    let uidgid = bpf_get_current_uid_gid();
    let comm = bpf_get_current_comm().unwrap_or([0; 16]);
    if let Some(mut entry) = EVENTS.reserve::<PipeCreateEvent>(0) {
        let p = entry.as_mut_ptr();
        // SAFETY: exclusive reserved PipeCreateEvent slot; writes in bounds.
        unsafe {
            (*p).kind = EVENT_PIPE_CREATE;
            (*p).pid = pid;
            (*p).uid = uidgid as u32;
            (*p).gid = (uidgid >> 32) as u32;
            (*p).dirfd = staged.dirfd;
            (*p)._pad0 = 0;
            (*p).pipe_name = staged.path;
            (*p).comm = comm;
        }
        entry.submit(0);
    }
    Ok(())
}

fn emit_anonymous_pipe() {
    let ids = bpf_get_current_pid_tgid();
    let uidgid = bpf_get_current_uid_gid();
    let comm = bpf_get_current_comm().unwrap_or([0; 16]);
    if let Some(mut entry) = EVENTS.reserve::<PipeCreateEvent>(0) {
        let p = entry.as_mut_ptr();
        // SAFETY: exclusive reserved PipeCreateEvent slot; writes in bounds.
        unsafe {
            (*p).kind = EVENT_PIPE_CREATE;
            (*p).pid = (ids >> 32) as u32;
            (*p).uid = uidgid as u32;
            (*p).gid = (uidgid >> 32) as u32;
            (*p).dirfd = ebpf_common::AT_FDCWD;
            (*p)._pad0 = 0;
            (*p).pipe_name = [0; PATH_LEN];
            // best-effort anonymous marker
            (*p).pipe_name[0] = b'-';
            (*p).comm = comm;
        }
        entry.submit(0);
    }
}

#[tracepoint(category = "syscalls", name = "sys_exit_pipe")]
fn sys_exit_pipe(ctx: TracePointContext) -> i32 {
    // SAFETY: bounds-checked context read of the syscall return value.
    let ret: i64 = unsafe { ctx.read_at(16).unwrap_or(-1) };
    if ret == 0 {
        emit_anonymous_pipe();
    }
    0
}

#[tracepoint(category = "syscalls", name = "sys_exit_pipe2")]
fn sys_exit_pipe2(ctx: TracePointContext) -> i32 {
    // SAFETY: bounds-checked context read of the syscall return value.
    let ret: i64 = unsafe { ctx.read_at(16).unwrap_or(-1) };
    if ret == 0 {
        emit_anonymous_pipe();
    }
    0
}

// ─── File deletion capture (B7, EID 23) ─────────────────────────────────────

#[tracepoint(category = "syscalls", name = "sys_enter_unlink")]
fn sys_enter_unlink(ctx: TracePointContext) -> i32 {
    match try_stage_unlink(&ctx) {
        Ok(()) => 0,
        Err(e) => e as i32,
    }
}

fn try_stage_unlink(ctx: &TracePointContext) -> Result<(), i64> {
    // SAFETY: offset from sys_enter_unlink format (pathname@16).
    let pathname: *const u8 = unsafe { ctx.read_at(16)? };
    let tid = bpf_get_current_pid_tgid() as u32;

    let pending = match FILE_SCRATCH.get_ptr_mut(0) {
        // SAFETY: index validated by get_ptr_mut; per-cpu map storage valid
        // and unaliased for this program invocation.
        Some(p) => unsafe { &mut *p },
        None => return Err(-28),
    };
    pending.path = [0; PATH_LEN];
    pending.dirfd = ebpf_common::AT_FDCWD;
    read_cstr(&mut pending.path, pathname);

    let _ = DELETE_STAGE.insert(&tid, pending, 0);
    Ok(())
}

#[tracepoint(category = "syscalls", name = "sys_exit_unlink")]
fn sys_exit_unlink(ctx: TracePointContext) -> i32 {
    match try_emit_file_delete(&ctx) {
        Ok(()) => 0,
        Err(e) => e as i32,
    }
}

#[tracepoint(category = "syscalls", name = "sys_enter_unlinkat")]
fn sys_enter_unlinkat(ctx: TracePointContext) -> i32 {
    match try_stage_unlinkat(&ctx) {
        Ok(()) => 0,
        Err(e) => e as i32,
    }
}

fn try_stage_unlinkat(ctx: &TracePointContext) -> Result<(), i64> {
    // SAFETY: offsets from sys_enter_unlinkat format (dfd@16, pathname@24).
    let dirfd: i32 = unsafe { ctx.read_at(16)? };
    let pathname: *const u8 = unsafe { ctx.read_at(24)? };
    let tid = bpf_get_current_pid_tgid() as u32;

    let pending = match FILE_SCRATCH.get_ptr_mut(0) {
        // SAFETY: index validated by get_ptr_mut; per-cpu map storage valid
        // and unaliased for this program invocation.
        Some(p) => unsafe { &mut *p },
        None => return Err(-28),
    };
    pending.path = [0; PATH_LEN];
    pending.dirfd = dirfd;
    read_cstr(&mut pending.path, pathname);

    let _ = DELETE_STAGE.insert(&tid, pending, 0);
    Ok(())
}

#[tracepoint(category = "syscalls", name = "sys_exit_unlinkat")]
fn sys_exit_unlinkat(ctx: TracePointContext) -> i32 {
    match try_emit_file_delete(&ctx) {
        Ok(()) => 0,
        Err(e) => e as i32,
    }
}

fn try_emit_file_delete(ctx: &TracePointContext) -> Result<(), i64> {
    // SAFETY: bounds-checked context read of the syscall return value.
    let ret: i64 = unsafe { ctx.read_at(16)? };
    if ret != 0 {
        return Ok(());
    }
    let ids = bpf_get_current_pid_tgid();
    let pid = (ids >> 32) as u32;
    let tid = ids as u32;
    // SAFETY: read-only map borrow, copied out immediately.
    let Some(staged) = (unsafe { DELETE_STAGE.get(&tid) }).map(|p| PendingFile {
        path: p.path,
        dirfd: p.dirfd,
    }) else {
        return Ok(());
    };
    DELETE_STAGE.remove(&tid)?;

    let uidgid = bpf_get_current_uid_gid();
    let comm = bpf_get_current_comm().unwrap_or([0; 16]);
    if let Some(mut entry) = EVENTS.reserve::<FileDeleteEvent>(0) {
        let p = entry.as_mut_ptr();
        // SAFETY: exclusive reserved FileDeleteEvent slot; writes in bounds.
        unsafe {
            (*p).kind = EVENT_FILE_DELETE;
            (*p).pid = pid;
            (*p).uid = uidgid as u32;
            (*p).gid = (uidgid >> 32) as u32;
            (*p).dirfd = staged.dirfd;
            (*p)._pad0 = 0;
            (*p).path = staged.path;
            (*p).comm = comm;
        }
        entry.submit(0);
    }
    Ok(())
}

// ─── DNS capture (extension CAP-5) ──────────────────────────────────────────

#[map(name = "DNS_SCRATCH")]
static DNS_SCRATCH: PerCpuArray<DnsQuery> = PerCpuArray::with_max_entries(MAX_ENTRIES, 0);

/// Copy up to `dst.len()` payload bytes, returning the stored length.
fn read_user_bytes(dst: &mut [u8], src: *const u8, size: usize) -> usize {
    if src.is_null() || dst.is_empty() {
        return 0;
    }
    let n = size.min(dst.len());
    let head = &mut dst[..n];
    // SAFETY: n ≤ dst.len() clamps the copy; the helper tolerates user-page
    // faults by returning Err instead of trapping.
    match unsafe { bpf_probe_read_user_buf(src, head) } {
        Ok(()) => n,
        Err(_) => 0,
    }
}

/// Emit a DnsEvent from prepared scratch state.
fn emit_dns(scratch: &DnsQuery) {
    if let Some(mut entry) = EVENTS.reserve::<DnsEvent>(0) {
        let p = entry.as_mut_ptr();
        // SAFETY: exclusive reserved DnsEvent slot; writes in bounds.
        unsafe {
            (*p).kind = EVENT_DNS;
            (*p).pid = scratch.pid;
            (*p).uid = scratch.uid;
            (*p).gid = scratch.gid;
            (*p).payload_len = scratch.payload_len;
            (*p)._pad0 = 0;
            (*p).comm = scratch.comm;
            (*p).payload = scratch.payload;
        }
        entry.submit(0);
    }
}

/// Fill scratch with current-task facts + bounded payload copy.
fn fill_dns(
    scratch: &mut DnsQuery,
    buf: *const u8,
    size: usize,
    ids: u64,
    uidgid: u64,
    comm: [u8; 16],
) {
    scratch.pid = (ids >> 32) as u32;
    scratch.uid = uidgid as u32;
    scratch.gid = (uidgid >> 32) as u32;
    scratch.comm = comm;
    scratch.payload = [0; DNS_PAYLOAD_LEN];
    scratch.payload_len =
        read_user_bytes(&mut scratch.payload, buf, size.min(DNS_PAYLOAD_LEN)) as u32;
}

/// Cheap kernel-side guard: drop payloads that cannot be DNS queries before
/// they cross the ring buffer. This mirrors the userspace parser's header
/// rules (QR=0 response flag clear, QDCOUNT>=1) without depending on the
/// destination socket address, so it stays safe for connected and
/// unconnected `sendto`/`sendmsg`. On a user-memory read failure we return
/// `true` and let userspace decide (conservative).
fn dns_query_plausible(buf: *const u8, size: usize) -> bool {
    if size < 12 || buf.is_null() {
        return false;
    }
    // SAFETY: fixed 12-byte read of the DNS header; the helper is
    // fault-tolerant and returns Err on unmapped user pages.
    let hdr: [u8; 12] = match unsafe { bpf_probe_read_user(buf.cast()) } {
        Ok(v) => v,
        Err(_) => return true,
    };
    let flags = u16::from_be_bytes([hdr[2], hdr[3]]);
    let qdcount = u16::from_be_bytes([hdr[4], hdr[5]]);
    flags & 0x8000 == 0 && qdcount != 0
}

#[tracepoint(category = "syscalls", name = "sys_enter_sendto")]
fn sys_enter_sendto(ctx: TracePointContext) -> i32 {
    match try_dns_sendto(&ctx) {
        Ok(()) => 0,
        Err(e) => e as i32,
    }
}

fn try_dns_sendto(ctx: &TracePointContext) -> Result<(), i64> {
    // sendto(fd, buf, len, flags, addr, addrlen)
    // SAFETY: bounds-checked context reads (sendto args buf/len).
    let buf: *const u8 = unsafe { ctx.read_at(24)? };
    let size: usize = unsafe { ctx.read_at(32)? };
    if !dns_query_plausible(buf, size) {
        return Ok(());
    }
    // No kernel-side destination port filter: port resolution proved flaky
    // across connected/unconnected sockets; the header guard above plus the
    // userspace parser keep false positives out.
    // SAFETY: bounds-checked context read of the addr argument (unused).
    let _addr: *const u8 = unsafe { ctx.read_at(48)? };
    let ids = bpf_get_current_pid_tgid();
    let uidgid = bpf_get_current_uid_gid();
    let comm = bpf_get_current_comm().unwrap_or([0; 16]);
    let scratch = match DNS_SCRATCH.get_ptr_mut(0) {
        // SAFETY: index validated by get_ptr_mut; per-cpu exclusivity.
        Some(p) => unsafe { &mut *p },
        None => return Err(-28),
    };
    fill_dns(scratch, buf, size, ids, uidgid, comm);
    emit_dns(scratch);
    Ok(())
}

#[tracepoint(category = "syscalls", name = "sys_enter_sendmsg")]
fn sys_enter_sendmsg(ctx: TracePointContext) -> i32 {
    match try_dns_sendmsg(&ctx) {
        Ok(()) => 0,
        Err(e) => e as i32,
    }
}

fn try_dns_sendmsg(ctx: &TracePointContext) -> Result<(), i64> {
    // sendmsg(fd, msg, flags): struct msghdr { msg_name, msg_namelen,
    // msg_iov, msg_iovlen, ... } — user pointers dereferenced one level.
    // SAFETY: bounds-checked context read of the msghdr argument.
    let msghdr: *const u8 = unsafe { ctx.read_at(24)? };
    // Connected sockets pass msg_name=NULL — captured too; the userspace
    // query parser drops non-DNS payloads.
    // SAFETY: fixed-size reads of user msghdr/iovec fields at the documented
    // x86_64 offsets (msg_name@0, msg_iov@16, msg_iovlen@24; iov_base@0,
    // iov_len@8). Every access is fault-tolerant via the helper.
    let _msg_name: *const u8 = unsafe { bpf_probe_read_user(msghdr.cast()) }?;
    let msg_iov: *const u8 = unsafe { bpf_probe_read_user(msghdr.wrapping_add(16).cast()) }?;
    let msg_iovlen: usize = unsafe { bpf_probe_read_user(msghdr.wrapping_add(24).cast()) }?;
    if msg_iov.is_null() || msg_iovlen == 0 {
        return Ok(());
    }
    // Capture only the first iovec (bounded payload); scattered DNS queries
    // across multiple iovecs are not fully reconstructed here.
    let iov_base: *const u8 = unsafe { bpf_probe_read_user(msg_iov.cast()) }?;
    let iov_len: usize = unsafe { bpf_probe_read_user(msg_iov.wrapping_add(8).cast()) }?;
    if !dns_query_plausible(iov_base, iov_len) {
        return Ok(());
    }

    let ids = bpf_get_current_pid_tgid();
    let uidgid = bpf_get_current_uid_gid();
    let comm = bpf_get_current_comm().unwrap_or([0; 16]);
    let scratch = match DNS_SCRATCH.get_ptr_mut(0) {
        // SAFETY: index validated by get_ptr_mut; per-cpu exclusivity.
        Some(p) => unsafe { &mut *p },
        None => return Err(-28),
    };
    fill_dns(scratch, iov_base, iov_len, ids, uidgid, comm);
    emit_dns(scratch);
    Ok(())
}

// ─── Credential/capability change capture (EID 501/502) ─────────────────────

fn stage_cred(syscall: u32, arg0: u32, arg1: u32, arg2: u32, groups_count: u32) {
    let key = bpf_get_current_pid_tgid();
    let pending = PendingCred {
        syscall,
        groups_count,
        arg0,
        arg1,
        arg2,
        _pad0: 0,
    };
    let _ = CRED_STAGE.insert(&key, &pending, 0);
}

fn emit_cred_exit(ctx: &TracePointContext) -> Result<(), i64> {
    let key = bpf_get_current_pid_tgid();
    let Some(pending) = (unsafe { CRED_STAGE.get(&key) }) else {
        return Ok(());
    };
    let pending = *pending;
    let _ = CRED_STAGE.remove(&key);
    // SAFETY: sys_exit_* tracepoints have ret at offset 16.
    let ret: i64 = unsafe { ctx.read_at(16)? };
    let ids = bpf_get_current_pid_tgid();
    let uidgid = bpf_get_current_uid_gid();
    let comm = bpf_get_current_comm().unwrap_or([0; 16]);
    if let Some(mut entry) = EVENTS.reserve::<CredentialChangeEvent>(0) {
        entry.write(CredentialChangeEvent {
            kind: EVENT_CREDENTIAL_CHANGE,
            pid: (ids >> 32) as u32,
            uid: uidgid as u32,
            gid: (uidgid >> 32) as u32,
            syscall: pending.syscall,
            groups_count: pending.groups_count,
            arg0: pending.arg0,
            arg1: pending.arg1,
            arg2: pending.arg2,
            result: ret as i32,
            comm,
            _pad0: [0; 2],
        });
        entry.submit(0);
    }
    Ok(())
}

fn stage_cap(syscall: u32, option: u32, arg2: u64, arg3: u64, arg4: u64) {
    let key = bpf_get_current_pid_tgid();
    let pending = PendingCap {
        syscall,
        option,
        arg2,
        arg3,
        arg4,
    };
    let _ = CAP_STAGE.insert(&key, &pending, 0);
}

fn emit_cap_exit(ctx: &TracePointContext) -> Result<(), i64> {
    let key = bpf_get_current_pid_tgid();
    let Some(pending) = (unsafe { CAP_STAGE.get(&key) }) else {
        return Ok(());
    };
    let pending = *pending;
    let _ = CAP_STAGE.remove(&key);
    // SAFETY: sys_exit_* tracepoints have ret at offset 16.
    let ret: i64 = unsafe { ctx.read_at(16)? };
    let ids = bpf_get_current_pid_tgid();
    let uidgid = bpf_get_current_uid_gid();
    let comm = bpf_get_current_comm().unwrap_or([0; 16]);
    if let Some(mut entry) = EVENTS.reserve::<CapabilityChangeEvent>(0) {
        entry.write(CapabilityChangeEvent {
            kind: EVENT_CAPABILITY_CHANGE,
            pid: (ids >> 32) as u32,
            uid: uidgid as u32,
            gid: (uidgid >> 32) as u32,
            syscall: pending.syscall,
            option: pending.option,
            arg2: pending.arg2,
            arg3: pending.arg3,
            arg4: pending.arg4,
            result: ret,
            comm,
        });
        entry.submit(0);
    }
    Ok(())
}

#[tracepoint(category = "syscalls", name = "sys_enter_setuid")]
fn sys_enter_setuid(ctx: TracePointContext) -> i32 {
    match unsafe { ctx.read_at::<u64>(16) } {
        Ok(v) => stage_cred(CRED_SETUID, v as u32, 0, 0, 0),
        Err(_) => {}
    }
    0
}
#[tracepoint(category = "syscalls", name = "sys_exit_setuid")]
fn sys_exit_setuid(ctx: TracePointContext) -> i32 {
    let _ = emit_cred_exit(&ctx);
    0
}

#[tracepoint(category = "syscalls", name = "sys_enter_setfsuid")]
fn sys_enter_setfsuid(ctx: TracePointContext) -> i32 {
    match unsafe { ctx.read_at::<u64>(16) } {
        Ok(v) => stage_cred(CRED_SETFSUID, v as u32, 0, 0, 0),
        Err(_) => {}
    }
    0
}
#[tracepoint(category = "syscalls", name = "sys_exit_setfsuid")]
fn sys_exit_setfsuid(ctx: TracePointContext) -> i32 {
    let _ = emit_cred_exit(&ctx);
    0
}

#[tracepoint(category = "syscalls", name = "sys_enter_setreuid")]
fn sys_enter_setreuid(ctx: TracePointContext) -> i32 {
    let ruid = unsafe { ctx.read_at::<u64>(16) }.unwrap_or(0) as u32;
    let euid = unsafe { ctx.read_at::<u64>(24) }.unwrap_or(0) as u32;
    stage_cred(CRED_SETREUID, ruid, euid, 0, 0);
    0
}
#[tracepoint(category = "syscalls", name = "sys_exit_setreuid")]
fn sys_exit_setreuid(ctx: TracePointContext) -> i32 {
    let _ = emit_cred_exit(&ctx);
    0
}

#[tracepoint(category = "syscalls", name = "sys_enter_setresuid")]
fn sys_enter_setresuid(ctx: TracePointContext) -> i32 {
    let ruid = unsafe { ctx.read_at::<u64>(16) }.unwrap_or(0) as u32;
    let euid = unsafe { ctx.read_at::<u64>(24) }.unwrap_or(0) as u32;
    let suid = unsafe { ctx.read_at::<u64>(32) }.unwrap_or(0) as u32;
    stage_cred(CRED_SETRESUID, ruid, euid, suid, 0);
    0
}
#[tracepoint(category = "syscalls", name = "sys_exit_setresuid")]
fn sys_exit_setresuid(ctx: TracePointContext) -> i32 {
    let _ = emit_cred_exit(&ctx);
    0
}

#[tracepoint(category = "syscalls", name = "sys_enter_setgid")]
fn sys_enter_setgid(ctx: TracePointContext) -> i32 {
    match unsafe { ctx.read_at::<u64>(16) } {
        Ok(v) => stage_cred(CRED_SETGID, v as u32, 0, 0, 0),
        Err(_) => {}
    }
    0
}
#[tracepoint(category = "syscalls", name = "sys_exit_setgid")]
fn sys_exit_setgid(ctx: TracePointContext) -> i32 {
    let _ = emit_cred_exit(&ctx);
    0
}

#[tracepoint(category = "syscalls", name = "sys_enter_setfsgid")]
fn sys_enter_setfsgid(ctx: TracePointContext) -> i32 {
    match unsafe { ctx.read_at::<u64>(16) } {
        Ok(v) => stage_cred(CRED_SETFSGID, v as u32, 0, 0, 0),
        Err(_) => {}
    }
    0
}
#[tracepoint(category = "syscalls", name = "sys_exit_setfsgid")]
fn sys_exit_setfsgid(ctx: TracePointContext) -> i32 {
    let _ = emit_cred_exit(&ctx);
    0
}

#[tracepoint(category = "syscalls", name = "sys_enter_setregid")]
fn sys_enter_setregid(ctx: TracePointContext) -> i32 {
    let rgid = unsafe { ctx.read_at::<u64>(16) }.unwrap_or(0) as u32;
    let egid = unsafe { ctx.read_at::<u64>(24) }.unwrap_or(0) as u32;
    stage_cred(CRED_SETREGID, rgid, egid, 0, 0);
    0
}
#[tracepoint(category = "syscalls", name = "sys_exit_setregid")]
fn sys_exit_setregid(ctx: TracePointContext) -> i32 {
    let _ = emit_cred_exit(&ctx);
    0
}

#[tracepoint(category = "syscalls", name = "sys_enter_setresgid")]
fn sys_enter_setresgid(ctx: TracePointContext) -> i32 {
    let rgid = unsafe { ctx.read_at::<u64>(16) }.unwrap_or(0) as u32;
    let egid = unsafe { ctx.read_at::<u64>(24) }.unwrap_or(0) as u32;
    let sgid = unsafe { ctx.read_at::<u64>(32) }.unwrap_or(0) as u32;
    stage_cred(CRED_SETRESGID, rgid, egid, sgid, 0);
    0
}
#[tracepoint(category = "syscalls", name = "sys_exit_setresgid")]
fn sys_exit_setresgid(ctx: TracePointContext) -> i32 {
    let _ = emit_cred_exit(&ctx);
    0
}

#[tracepoint(category = "syscalls", name = "sys_enter_setgroups")]
fn sys_enter_setgroups(ctx: TracePointContext) -> i32 {
    let size = unsafe { ctx.read_at::<u64>(16) }.unwrap_or(0) as u32;
    stage_cred(CRED_SETGROUPS, 0, 0, 0, size);
    0
}
#[tracepoint(category = "syscalls", name = "sys_exit_setgroups")]
fn sys_exit_setgroups(ctx: TracePointContext) -> i32 {
    let _ = emit_cred_exit(&ctx);
    0
}

#[tracepoint(category = "syscalls", name = "sys_enter_capset")]
fn sys_enter_capset(_ctx: TracePointContext) -> i32 {
    stage_cap(CAP_CAPSET, 0, 0, 0, 0);
    0
}
#[tracepoint(category = "syscalls", name = "sys_exit_capset")]
fn sys_exit_capset(ctx: TracePointContext) -> i32 {
    let _ = emit_cap_exit(&ctx);
    0
}

#[tracepoint(category = "syscalls", name = "sys_enter_prctl")]
fn sys_enter_prctl(ctx: TracePointContext) -> i32 {
    let option = unsafe { ctx.read_at::<u64>(16) }.unwrap_or(u64::MAX);
    if option != PR_SET_KEEPCAPS && option != PR_CAPBSET_DROP && option != PR_CAP_AMBIENT {
        return 0;
    }
    let arg2 = unsafe { ctx.read_at::<u64>(24) }.unwrap_or(0);
    let arg3 = unsafe { ctx.read_at::<u64>(32) }.unwrap_or(0);
    let arg4 = unsafe { ctx.read_at::<u64>(40) }.unwrap_or(0);
    stage_cap(CAP_PRCTL, option as u32, arg2, arg3, arg4);
    0
}
#[tracepoint(category = "syscalls", name = "sys_exit_prctl")]
fn sys_exit_prctl(ctx: TracePointContext) -> i32 {
    let _ = emit_cap_exit(&ctx);
    0
}

// ─── File rename capture (EID 503, extension) ─────────────────────────────────

fn try_stage_rename(ctx: &TracePointContext, syscall: u32) -> Result<(), i64> {
    let tid = bpf_get_current_pid_tgid() as u32;
    // SAFETY: offsets from sys_enter_rename/renameat/renameat2 formats (x86_64).
    let (old_dirfd, oldname, new_dirfd, newname, flags): (i32, *const u8, i32, *const u8, u32) =
        match syscall {
            RENAME_RENAME => {
                let old: *const u8 = unsafe { ctx.read_at(16)? };
                let new: *const u8 = unsafe { ctx.read_at(24)? };
                (AT_FDCWD, old, AT_FDCWD, new, 0)
            }
            RENAME_RENAMEAT => {
                let od: i32 = unsafe { ctx.read_at(16)? };
                let old: *const u8 = unsafe { ctx.read_at(24)? };
                let nd: i32 = unsafe { ctx.read_at(32)? };
                let new: *const u8 = unsafe { ctx.read_at(40)? };
                (od, old, nd, new, 0)
            }
            _ => {
                let od: i32 = unsafe { ctx.read_at(16)? };
                let old: *const u8 = unsafe { ctx.read_at(24)? };
                let nd: i32 = unsafe { ctx.read_at(32)? };
                let new: *const u8 = unsafe { ctx.read_at(40)? };
                let flags: u64 = unsafe { ctx.read_at(48)? };
                (od, old, nd, new, flags as u32)
            }
        };

    let pending = match RENAME_SCRATCH.get_ptr_mut(0) {
        // SAFETY: index validated by get_ptr_mut; per-cpu exclusivity.
        Some(p) => unsafe { &mut *p },
        None => return Err(-28),
    };
    pending.syscall = syscall;
    pending.flags = flags;
    pending.old_dirfd = old_dirfd;
    pending.new_dirfd = new_dirfd;
    // SAFETY: write into per-cpu scratch to avoid large stack temporaries.
    unsafe {
        ptr::write_bytes(pending.old_path.as_mut_ptr(), 0, PATH_LEN);
        ptr::write_bytes(pending.new_path.as_mut_ptr(), 0, PATH_LEN);
    }
    read_cstr(&mut pending.old_path, oldname);
    read_cstr(&mut pending.new_path, newname);
    let _ = RENAME_STAGE.insert(&tid, pending, 0);
    Ok(())
}

fn try_emit_rename(ctx: &TracePointContext) -> Result<(), i64> {
    // SAFETY: sys_exit_* tracepoints have ret at offset 16.
    let ret: i64 = unsafe { ctx.read_at(16)? };
    let tid = bpf_get_current_pid_tgid() as u32;
    // SAFETY: read-only map borrow of a fixed-size value.
    let Some(staged) = (unsafe { RENAME_STAGE.get(&tid) }) else {
        return Ok(());
    };
    if ret < 0 {
        let _ = RENAME_STAGE.remove(&tid);
        return Ok(());
    }
    let ids = bpf_get_current_pid_tgid();
    let uidgid = bpf_get_current_uid_gid();
    let comm = bpf_get_current_comm().unwrap_or([0; 16]);
    if let Some(mut entry) = EVENTS.reserve::<FileRenameEvent>(0) {
        // SAFETY: ring buffer entry is exclusively owned until submit;
        // field writes are within bounds and the struct is repr(C). The staged
        // map value is read by reference (no large stack copy).
        let p = entry.as_mut_ptr();
        unsafe {
            ptr::write_bytes(p as *mut u8, 0, core::mem::size_of::<FileRenameEvent>());
            (*p).kind = EVENT_FILE_RENAME;
            (*p).pid = (ids >> 32) as u32;
            (*p).uid = uidgid as u32;
            (*p).gid = (uidgid >> 32) as u32;
            (*p).syscall = staged.syscall;
            (*p).flags = staged.flags;
            (*p).old_dirfd = staged.old_dirfd;
            (*p).new_dirfd = staged.new_dirfd;
            (*p).result = ret as i32;
            (*p)._pad0 = 0;
            (*p).old_path = staged.old_path;
            (*p).new_path = staged.new_path;
            (*p).comm = comm;
        }
        entry.submit(0);
    }
    let _ = RENAME_STAGE.remove(&tid);
    Ok(())
}

#[tracepoint(category = "syscalls", name = "sys_enter_rename")]
fn sys_enter_rename(ctx: TracePointContext) -> i32 {
    match try_stage_rename(&ctx, RENAME_RENAME) {
        Ok(()) => 0,
        Err(e) => e as i32,
    }
}

#[tracepoint(category = "syscalls", name = "sys_exit_rename")]
fn sys_exit_rename(ctx: TracePointContext) -> i32 {
    match try_emit_rename(&ctx) {
        Ok(()) => 0,
        Err(e) => e as i32,
    }
}

#[tracepoint(category = "syscalls", name = "sys_enter_renameat")]
fn sys_enter_renameat(ctx: TracePointContext) -> i32 {
    match try_stage_rename(&ctx, RENAME_RENAMEAT) {
        Ok(()) => 0,
        Err(e) => e as i32,
    }
}

#[tracepoint(category = "syscalls", name = "sys_exit_renameat")]
fn sys_exit_renameat(ctx: TracePointContext) -> i32 {
    match try_emit_rename(&ctx) {
        Ok(()) => 0,
        Err(e) => e as i32,
    }
}

#[tracepoint(category = "syscalls", name = "sys_enter_renameat2")]
fn sys_enter_renameat2(ctx: TracePointContext) -> i32 {
    match try_stage_rename(&ctx, RENAME_RENAMEAT2) {
        Ok(()) => 0,
        Err(e) => e as i32,
    }
}

#[tracepoint(category = "syscalls", name = "sys_exit_renameat2")]
fn sys_exit_renameat2(ctx: TracePointContext) -> i32 {
    match try_emit_rename(&ctx) {
        Ok(()) => 0,
        Err(e) => e as i32,
    }
}

// ─── File chmod/chown/truncate capture (EID 504/505/506, extensions) ────────

fn try_stage_chmod(ctx: &TracePointContext, syscall: u32) -> Result<(), i64> {
    let tid = bpf_get_current_pid_tgid() as u32;
    let pending = match CHMOD_SCRATCH.get_ptr_mut(0) {
        // SAFETY: index validated by get_ptr_mut; per-cpu exclusivity.
        Some(p) => unsafe { &mut *p },
        None => return Err(-28),
    };
    pending.syscall = syscall;
    pending.flags = 0;
    pending.dirfd = AT_FDCWD;
    pending.fd = -1;
    pending.mode = 0;
    pending._pad0 = 0;
    unsafe {
        ptr::write_bytes(pending.path.as_mut_ptr(), 0, PATH_LEN);
    }
    match syscall {
        CHMOD_CHMOD => {
            // SAFETY: sys_enter_chmod format: filename@16, mode@24.
            let filename: *const u8 = unsafe { ctx.read_at(16)? };
            let mode: u64 = unsafe { ctx.read_at(24)? };
            pending.mode = mode as u32;
            read_cstr(&mut pending.path, filename);
        }
        CHMOD_FCHMOD => {
            // SAFETY: sys_enter_fchmod format: fd@16, mode@24.
            let fd: u64 = unsafe { ctx.read_at(16)? };
            let mode: u64 = unsafe { ctx.read_at(24)? };
            pending.fd = fd as i32;
            pending.mode = mode as u32;
        }
        CHMOD_FCHMODAT => {
            // SAFETY: sys_enter_fchmodat format: dfd@16, filename@24, mode@32.
            let dfd: i64 = unsafe { ctx.read_at(16)? };
            let filename: *const u8 = unsafe { ctx.read_at(24)? };
            let mode: u64 = unsafe { ctx.read_at(32)? };
            pending.dirfd = dfd as i32;
            pending.mode = mode as u32;
            read_cstr(&mut pending.path, filename);
        }
        _ => {
            // SAFETY: sys_enter_fchmodat2 format: dfd@16, filename@24, mode@32, flags@40.
            let dfd: i64 = unsafe { ctx.read_at(16)? };
            let filename: *const u8 = unsafe { ctx.read_at(24)? };
            let mode: u64 = unsafe { ctx.read_at(32)? };
            let flags: u64 = unsafe { ctx.read_at(40)? };
            pending.dirfd = dfd as i32;
            pending.mode = mode as u32;
            pending.flags = flags as u32;
            read_cstr(&mut pending.path, filename);
        }
    }
    let _ = CHMOD_STAGE.insert(&tid, pending, 0);
    Ok(())
}

fn try_emit_chmod(ctx: &TracePointContext) -> Result<(), i64> {
    // SAFETY: sys_exit_* tracepoints have ret at offset 16.
    let ret: i64 = unsafe { ctx.read_at(16)? };
    let tid = bpf_get_current_pid_tgid() as u32;
    let Some(staged) = (unsafe { CHMOD_STAGE.get(&tid) }) else {
        return Ok(());
    };
    if ret < 0 {
        let _ = CHMOD_STAGE.remove(&tid);
        return Ok(());
    }
    let ids = bpf_get_current_pid_tgid();
    let uidgid = bpf_get_current_uid_gid();
    let comm = bpf_get_current_comm().unwrap_or([0; 16]);
    if let Some(mut entry) = EVENTS.reserve::<FileChmodEvent>(0) {
        let p = entry.as_mut_ptr();
        unsafe {
            ptr::write_bytes(p as *mut u8, 0, core::mem::size_of::<FileChmodEvent>());
            (*p).kind = EVENT_FILE_CHMOD;
            (*p).pid = (ids >> 32) as u32;
            (*p).uid = uidgid as u32;
            (*p).gid = (uidgid >> 32) as u32;
            (*p).syscall = staged.syscall;
            (*p).mode = staged.mode;
            (*p).flags = staged.flags;
            (*p).dirfd = staged.dirfd;
            (*p).fd = staged.fd;
            (*p).result = ret as i32;
            (*p).path = staged.path;
            (*p).comm = comm;
            (*p)._pad0 = [0; 2];
        }
        entry.submit(0);
    }
    let _ = CHMOD_STAGE.remove(&tid);
    Ok(())
}

fn try_stage_chown(ctx: &TracePointContext, syscall: u32) -> Result<(), i64> {
    let tid = bpf_get_current_pid_tgid() as u32;
    let pending = match CHOWN_SCRATCH.get_ptr_mut(0) {
        // SAFETY: index validated by get_ptr_mut; per-cpu exclusivity.
        Some(p) => unsafe { &mut *p },
        None => return Err(-28),
    };
    pending.syscall = syscall;
    pending.owner = 0;
    pending.group = 0;
    pending.flags = 0;
    pending.dirfd = AT_FDCWD;
    pending.fd = -1;
    unsafe {
        ptr::write_bytes(pending.path.as_mut_ptr(), 0, PATH_LEN);
    }
    match syscall {
        CHOWN_CHOWN | CHOWN_LCHOWN => {
            // SAFETY: sys_enter_chown/lchown: filename@16, user@24, group@32.
            let filename: *const u8 = unsafe { ctx.read_at(16)? };
            let owner: u64 = unsafe { ctx.read_at(24)? };
            let group: u64 = unsafe { ctx.read_at(32)? };
            pending.owner = owner as u32;
            pending.group = group as u32;
            read_cstr(&mut pending.path, filename);
        }
        CHOWN_FCHOWN => {
            // SAFETY: sys_enter_fchown: fd@16, user@24, group@32.
            let fd: u64 = unsafe { ctx.read_at(16)? };
            let owner: u64 = unsafe { ctx.read_at(24)? };
            let group: u64 = unsafe { ctx.read_at(32)? };
            pending.fd = fd as i32;
            pending.owner = owner as u32;
            pending.group = group as u32;
        }
        _ => {
            // SAFETY: sys_enter_fchownat: dfd@16, filename@24, user@32, group@40, flag@48.
            let dfd: i64 = unsafe { ctx.read_at(16)? };
            let filename: *const u8 = unsafe { ctx.read_at(24)? };
            let owner: u64 = unsafe { ctx.read_at(32)? };
            let group: u64 = unsafe { ctx.read_at(40)? };
            let flags: u64 = unsafe { ctx.read_at(48)? };
            pending.dirfd = dfd as i32;
            pending.owner = owner as u32;
            pending.group = group as u32;
            pending.flags = flags as u32;
            read_cstr(&mut pending.path, filename);
        }
    }
    let _ = CHOWN_STAGE.insert(&tid, pending, 0);
    Ok(())
}

fn try_emit_chown(ctx: &TracePointContext) -> Result<(), i64> {
    // SAFETY: sys_exit_* tracepoints have ret at offset 16.
    let ret: i64 = unsafe { ctx.read_at(16)? };
    let tid = bpf_get_current_pid_tgid() as u32;
    let Some(staged) = (unsafe { CHOWN_STAGE.get(&tid) }) else {
        return Ok(());
    };
    if ret < 0 {
        let _ = CHOWN_STAGE.remove(&tid);
        return Ok(());
    }
    let ids = bpf_get_current_pid_tgid();
    let uidgid = bpf_get_current_uid_gid();
    let comm = bpf_get_current_comm().unwrap_or([0; 16]);
    if let Some(mut entry) = EVENTS.reserve::<FileChownEvent>(0) {
        let p = entry.as_mut_ptr();
        unsafe {
            ptr::write_bytes(p as *mut u8, 0, core::mem::size_of::<FileChownEvent>());
            (*p).kind = EVENT_FILE_CHOWN;
            (*p).pid = (ids >> 32) as u32;
            (*p).uid = uidgid as u32;
            (*p).gid = (uidgid >> 32) as u32;
            (*p).syscall = staged.syscall;
            (*p).owner = staged.owner;
            (*p).group = staged.group;
            (*p).flags = staged.flags;
            (*p).dirfd = staged.dirfd;
            (*p).fd = staged.fd;
            (*p).result = ret as i32;
            (*p)._pad0 = 0;
            (*p).path = staged.path;
            (*p).comm = comm;
        }
        entry.submit(0);
    }
    let _ = CHOWN_STAGE.remove(&tid);
    Ok(())
}

fn try_stage_truncate(ctx: &TracePointContext, syscall: u32) -> Result<(), i64> {
    let tid = bpf_get_current_pid_tgid() as u32;
    let pending = match TRUNCATE_SCRATCH.get_ptr_mut(0) {
        // SAFETY: index validated by get_ptr_mut; per-cpu exclusivity.
        Some(p) => unsafe { &mut *p },
        None => return Err(-28),
    };
    pending.syscall = syscall;
    pending.fd = -1;
    pending.length = 0;
    unsafe {
        ptr::write_bytes(pending.path.as_mut_ptr(), 0, PATH_LEN);
    }
    match syscall {
        TRUNCATE_TRUNCATE => {
            // SAFETY: sys_enter_truncate: path@16, length@24.
            let path: *const u8 = unsafe { ctx.read_at(16)? };
            let length: i64 = unsafe { ctx.read_at(24)? };
            pending.length = length;
            read_cstr(&mut pending.path, path);
        }
        _ => {
            // SAFETY: sys_enter_ftruncate: fd@16, length@24.
            let fd: u64 = unsafe { ctx.read_at(16)? };
            let length: i64 = unsafe { ctx.read_at(24)? };
            pending.fd = fd as i32;
            pending.length = length;
        }
    }
    let _ = TRUNCATE_STAGE.insert(&tid, pending, 0);
    Ok(())
}

fn try_emit_truncate(ctx: &TracePointContext) -> Result<(), i64> {
    // SAFETY: sys_exit_* tracepoints have ret at offset 16.
    let ret: i64 = unsafe { ctx.read_at(16)? };
    let tid = bpf_get_current_pid_tgid() as u32;
    let Some(staged) = (unsafe { TRUNCATE_STAGE.get(&tid) }) else {
        return Ok(());
    };
    if ret < 0 {
        let _ = TRUNCATE_STAGE.remove(&tid);
        return Ok(());
    }
    let ids = bpf_get_current_pid_tgid();
    let uidgid = bpf_get_current_uid_gid();
    let comm = bpf_get_current_comm().unwrap_or([0; 16]);
    if let Some(mut entry) = EVENTS.reserve::<FileTruncateEvent>(0) {
        let p = entry.as_mut_ptr();
        unsafe {
            ptr::write_bytes(p as *mut u8, 0, core::mem::size_of::<FileTruncateEvent>());
            (*p).kind = EVENT_FILE_TRUNCATE;
            (*p).pid = (ids >> 32) as u32;
            (*p).uid = uidgid as u32;
            (*p).gid = (uidgid >> 32) as u32;
            (*p).syscall = staged.syscall;
            (*p).fd = staged.fd;
            (*p).length = staged.length;
            (*p).result = ret;
            (*p).path = staged.path;
            (*p).comm = comm;
        }
        entry.submit(0);
    }
    let _ = TRUNCATE_STAGE.remove(&tid);
    Ok(())
}

#[tracepoint(category = "syscalls", name = "sys_enter_chmod")]
fn sys_enter_chmod(ctx: TracePointContext) -> i32 {
    match try_stage_chmod(&ctx, CHMOD_CHMOD) {
        Ok(()) => 0,
        Err(e) => e as i32,
    }
}
#[tracepoint(category = "syscalls", name = "sys_exit_chmod")]
fn sys_exit_chmod(ctx: TracePointContext) -> i32 {
    match try_emit_chmod(&ctx) {
        Ok(()) => 0,
        Err(e) => e as i32,
    }
}

#[tracepoint(category = "syscalls", name = "sys_enter_fchmod")]
fn sys_enter_fchmod(ctx: TracePointContext) -> i32 {
    match try_stage_chmod(&ctx, CHMOD_FCHMOD) {
        Ok(()) => 0,
        Err(e) => e as i32,
    }
}
#[tracepoint(category = "syscalls", name = "sys_exit_fchmod")]
fn sys_exit_fchmod(ctx: TracePointContext) -> i32 {
    match try_emit_chmod(&ctx) {
        Ok(()) => 0,
        Err(e) => e as i32,
    }
}

#[tracepoint(category = "syscalls", name = "sys_enter_fchmodat")]
fn sys_enter_fchmodat(ctx: TracePointContext) -> i32 {
    match try_stage_chmod(&ctx, CHMOD_FCHMODAT) {
        Ok(()) => 0,
        Err(e) => e as i32,
    }
}
#[tracepoint(category = "syscalls", name = "sys_exit_fchmodat")]
fn sys_exit_fchmodat(ctx: TracePointContext) -> i32 {
    match try_emit_chmod(&ctx) {
        Ok(()) => 0,
        Err(e) => e as i32,
    }
}

#[tracepoint(category = "syscalls", name = "sys_enter_fchmodat2")]
fn sys_enter_fchmodat2(ctx: TracePointContext) -> i32 {
    match try_stage_chmod(&ctx, CHMOD_FCHMODAT2) {
        Ok(()) => 0,
        Err(e) => e as i32,
    }
}
#[tracepoint(category = "syscalls", name = "sys_exit_fchmodat2")]
fn sys_exit_fchmodat2(ctx: TracePointContext) -> i32 {
    match try_emit_chmod(&ctx) {
        Ok(()) => 0,
        Err(e) => e as i32,
    }
}

#[tracepoint(category = "syscalls", name = "sys_enter_chown")]
fn sys_enter_chown(ctx: TracePointContext) -> i32 {
    match try_stage_chown(&ctx, CHOWN_CHOWN) {
        Ok(()) => 0,
        Err(e) => e as i32,
    }
}
#[tracepoint(category = "syscalls", name = "sys_exit_chown")]
fn sys_exit_chown(ctx: TracePointContext) -> i32 {
    match try_emit_chown(&ctx) {
        Ok(()) => 0,
        Err(e) => e as i32,
    }
}

#[tracepoint(category = "syscalls", name = "sys_enter_lchown")]
fn sys_enter_lchown(ctx: TracePointContext) -> i32 {
    match try_stage_chown(&ctx, CHOWN_LCHOWN) {
        Ok(()) => 0,
        Err(e) => e as i32,
    }
}
#[tracepoint(category = "syscalls", name = "sys_exit_lchown")]
fn sys_exit_lchown(ctx: TracePointContext) -> i32 {
    match try_emit_chown(&ctx) {
        Ok(()) => 0,
        Err(e) => e as i32,
    }
}

#[tracepoint(category = "syscalls", name = "sys_enter_fchown")]
fn sys_enter_fchown(ctx: TracePointContext) -> i32 {
    match try_stage_chown(&ctx, CHOWN_FCHOWN) {
        Ok(()) => 0,
        Err(e) => e as i32,
    }
}
#[tracepoint(category = "syscalls", name = "sys_exit_fchown")]
fn sys_exit_fchown(ctx: TracePointContext) -> i32 {
    match try_emit_chown(&ctx) {
        Ok(()) => 0,
        Err(e) => e as i32,
    }
}

#[tracepoint(category = "syscalls", name = "sys_enter_fchownat")]
fn sys_enter_fchownat(ctx: TracePointContext) -> i32 {
    match try_stage_chown(&ctx, CHOWN_FCHOWNAT) {
        Ok(()) => 0,
        Err(e) => e as i32,
    }
}
#[tracepoint(category = "syscalls", name = "sys_exit_fchownat")]
fn sys_exit_fchownat(ctx: TracePointContext) -> i32 {
    match try_emit_chown(&ctx) {
        Ok(()) => 0,
        Err(e) => e as i32,
    }
}

#[tracepoint(category = "syscalls", name = "sys_enter_truncate")]
fn sys_enter_truncate(ctx: TracePointContext) -> i32 {
    match try_stage_truncate(&ctx, TRUNCATE_TRUNCATE) {
        Ok(()) => 0,
        Err(e) => e as i32,
    }
}
#[tracepoint(category = "syscalls", name = "sys_exit_truncate")]
fn sys_exit_truncate(ctx: TracePointContext) -> i32 {
    match try_emit_truncate(&ctx) {
        Ok(()) => 0,
        Err(e) => e as i32,
    }
}

#[tracepoint(category = "syscalls", name = "sys_enter_ftruncate")]
fn sys_enter_ftruncate(ctx: TracePointContext) -> i32 {
    match try_stage_truncate(&ctx, TRUNCATE_FTRUNCATE) {
        Ok(()) => 0,
        Err(e) => e as i32,
    }
}
#[tracepoint(category = "syscalls", name = "sys_exit_ftruncate")]
fn sys_exit_ftruncate(ctx: TracePointContext) -> i32 {
    match try_emit_truncate(&ctx) {
        Ok(()) => 0,
        Err(e) => e as i32,
    }
}

// ─── File change/write capture (EID 2, best-effort) ─────────────────────────

fn try_stage_write(ctx: &TracePointContext, syscall: u32) -> Result<(), i64> {
    let tid = bpf_get_current_pid_tgid() as u32;
    // SAFETY: all write* sys_enter tracepoints have fd at offset 16.
    let fd: u64 = unsafe { ctx.read_at(16)? };
    let pending = PendingWrite {
        syscall,
        fd: fd as i32,
    };
    let _ = WRITE_STAGE.insert(&tid, &pending, 0);
    Ok(())
}

fn try_emit_write(ctx: &TracePointContext) -> Result<(), i64> {
    // SAFETY: sys_exit_* tracepoints have ret at offset 16.
    let ret: i64 = unsafe { ctx.read_at(16)? };
    let tid = bpf_get_current_pid_tgid() as u32;
    let Some(staged) = (unsafe { WRITE_STAGE.get(&tid) }) else {
        return Ok(());
    };
    let staged = *staged;
    let _ = WRITE_STAGE.remove(&tid);
    if ret <= 0 {
        return Ok(());
    }
    let ids = bpf_get_current_pid_tgid();
    let uidgid = bpf_get_current_uid_gid();
    let comm = bpf_get_current_comm().unwrap_or([0; 16]);
    if let Some(mut entry) = EVENTS.reserve::<FileChangeEvent>(0) {
        let p = entry.as_mut_ptr();
        unsafe {
            ptr::write_bytes(p as *mut u8, 0, core::mem::size_of::<FileChangeEvent>());
            (*p).kind = EVENT_FILE_CHANGE;
            (*p).pid = (ids >> 32) as u32;
            (*p).uid = uidgid as u32;
            (*p).gid = (uidgid >> 32) as u32;
            (*p).syscall = staged.syscall;
            (*p).fd = staged.fd;
            (*p).bytes_written = ret;
            (*p).comm = comm;
        }
        entry.submit(0);
    }
    Ok(())
}

#[tracepoint(category = "syscalls", name = "sys_enter_write")]
fn sys_enter_write(ctx: TracePointContext) -> i32 {
    match try_stage_write(&ctx, WRITE_WRITE) {
        Ok(()) => 0,
        Err(e) => e as i32,
    }
}
#[tracepoint(category = "syscalls", name = "sys_exit_write")]
fn sys_exit_write(ctx: TracePointContext) -> i32 {
    match try_emit_write(&ctx) {
        Ok(()) => 0,
        Err(e) => e as i32,
    }
}

#[tracepoint(category = "syscalls", name = "sys_enter_pwrite64")]
fn sys_enter_pwrite64(ctx: TracePointContext) -> i32 {
    match try_stage_write(&ctx, WRITE_PWRITE64) {
        Ok(()) => 0,
        Err(e) => e as i32,
    }
}
#[tracepoint(category = "syscalls", name = "sys_exit_pwrite64")]
fn sys_exit_pwrite64(ctx: TracePointContext) -> i32 {
    match try_emit_write(&ctx) {
        Ok(()) => 0,
        Err(e) => e as i32,
    }
}

#[tracepoint(category = "syscalls", name = "sys_enter_writev")]
fn sys_enter_writev(ctx: TracePointContext) -> i32 {
    match try_stage_write(&ctx, WRITE_WRITEV) {
        Ok(()) => 0,
        Err(e) => e as i32,
    }
}
#[tracepoint(category = "syscalls", name = "sys_exit_writev")]
fn sys_exit_writev(ctx: TracePointContext) -> i32 {
    match try_emit_write(&ctx) {
        Ok(()) => 0,
        Err(e) => e as i32,
    }
}

#[tracepoint(category = "syscalls", name = "sys_enter_pwritev")]
fn sys_enter_pwritev(ctx: TracePointContext) -> i32 {
    match try_stage_write(&ctx, WRITE_PWRITEV) {
        Ok(()) => 0,
        Err(e) => e as i32,
    }
}
#[tracepoint(category = "syscalls", name = "sys_exit_pwritev")]
fn sys_exit_pwritev(ctx: TracePointContext) -> i32 {
    match try_emit_write(&ctx) {
        Ok(()) => 0,
        Err(e) => e as i32,
    }
}

#[tracepoint(category = "syscalls", name = "sys_enter_pwritev2")]
fn sys_enter_pwritev2(ctx: TracePointContext) -> i32 {
    match try_stage_write(&ctx, WRITE_PWRITEV2) {
        Ok(()) => 0,
        Err(e) => e as i32,
    }
}
#[tracepoint(category = "syscalls", name = "sys_exit_pwritev2")]
fn sys_exit_pwritev2(ctx: TracePointContext) -> i32 {
    match try_emit_write(&ctx) {
        Ok(()) => 0,
        Err(e) => e as i32,
    }
}
