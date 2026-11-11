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
    ARG0_LEN, ARG1_LEN, ARG2_LEN, DNS_PAYLOAD_LEN, DnsEvent, DriverLoadEvent, EVENT_DNS,
    EVENT_DRIVER_LOAD, EVENT_EXEC, EVENT_EXIT, EVENT_FILE, EVENT_FILE_DELETE, EVENT_LISTEN,
    EVENT_NET, EVENT_PIPE_CREATE, EVENT_PROCESS_ACCESS, EVENT_PROCESS_TAMPERING, EVENT_RAW_ACCESS,
    ExecEvent, ExitEvent, FileCreateEvent, FileDeleteEvent, IMAGE_LEN, ListenEvent, NetEvent,
    PATH_LEN, PipeCreateEvent, ProcessAccessEvent, ProcessTamperingEvent, RawAccessEvent,
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
/// `O_CREAT` bit — openat is staged only when the caller may create.
const O_CREAT: u64 = 0o100;
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
