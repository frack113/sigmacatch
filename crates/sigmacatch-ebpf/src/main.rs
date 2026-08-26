// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 sigmacatch contributors

//! sigmacatch eBPF probes.
//!
//! - `syscalls/sys_enter_execve`: stage `image` + first argv element per pid
//!   (race-free capture, spec constraint);
//! - `sched/sched_process_exec`: emit [`ExecEvent`] on the `EVENTS` ring
//!   buffer;
//! - `sched/sched_process_exit`: emit [`ExitEvent`] for group leaders;
//! - `syscalls/sys_enter_openat` (O_CREAT) + `sys_exit_openat`: emit
//!   [`FileCreateEvent`] on successful creations.

#![no_std]
#![no_main]

use core::ptr;

use aya_ebpf::{
    helpers::{
        bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_get_current_uid_gid,
        bpf_probe_read_user, bpf_probe_read_user_buf,
    },
    macros::{map, tracepoint},
    maps::{LruHashMap, PerCpuArray, RingBuf},
    programs::TracePointContext,
};
#[allow(deprecated)]
use aya_ebpf::helpers::bpf_probe_read_user_str;
use sigmacatch_ebpf_common::{
    ARG0_LEN, DNS_PAYLOAD_LEN, EVENT_DNS, EVENT_EXEC, EVENT_EXIT, EVENT_FILE, EVENT_NET,
    DnsEvent, ExecEvent, ExitEvent, FileCreateEvent, IMAGE_LEN, NetEvent, PATH_LEN,
};

const MAX_ENTRIES: u32 = 1;
const EXEC_ARGS_MAX: u32 = 4096;
const FILE_STAGE_MAX: u32 = 4096;
/// `O_CREAT` bit — openat is staged only when the caller may create.
const O_CREAT: u64 = 0o100;
#[repr(C)]
struct PendingExec {
    image: [u8; IMAGE_LEN],
    arg0: [u8; ARG0_LEN],
}

#[repr(C)]
struct PendingFile {
    path: [u8; PATH_LEN],
    dirfd: i32,
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
static STAGE_SCRATCH: PerCpuArray<PendingExec> =
    PerCpuArray::with_max_entries(MAX_ENTRIES, 0);

#[map(name = "FILE_STAGE")]
static FILE_STAGE: LruHashMap<u32, PendingFile> = LruHashMap::with_max_entries(FILE_STAGE_MAX, 0);

// Same stack constraint applies to the ~260-byte file staging buffer.
#[map(name = "FILE_SCRATCH")]
static FILE_SCRATCH: PerCpuArray<PendingFile> =
    PerCpuArray::with_max_entries(MAX_ENTRIES, 0);

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
    let pid = bpf_get_current_pid_tgid() as u32;

    let pending = match STAGE_SCRATCH.get_ptr_mut(0) {
        // SAFETY: index 0 < MAX_ENTRIES(1) is checked by get_ptr_mut; the
        // returned pointer targets per-cpu map storage valid for the whole
        // program run and exclusive to this CPU.
        Some(p) => unsafe { &mut *p },
        None => return Err(-28),
    };
    pending.image = [0; IMAGE_LEN];
    pending.arg0 = [0; ARG0_LEN];
    read_cstr(&mut pending.image, filename);
    // argv[0]: one indirection, fixed-size destination — trivially provable.
    // SAFETY: argv_base points to user memory (validated non-faulting by the
    // helper); a fixed-size pointer read whose failure degrades to null.
    let arg0p: *const u8 = unsafe { bpf_probe_read_user(argv_base) }.unwrap_or(ptr::null());
    read_cstr(&mut pending.arg0, arg0p);

    let _ = EXEC_ARGS.insert(&pid, pending, 0);
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
    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
    // Field-wise copy into the ring buffer slot: a whole-PendingExec local
    // would eat into the 512-byte BPF stack for no benefit.
    // SAFETY: get returns a borrowed view of map value storage, alive until
    // the remove below; no mutation aliases it inside this program run.
    let Some(staged) = (unsafe { EXEC_ARGS.get(&pid) }) else {
        return Ok(());
    };
    EXEC_ARGS.remove(&pid)?;

    let uidgid = bpf_get_current_uid_gid();
    let comm = bpf_get_current_comm().unwrap_or([0; 16]);
    if let Some(mut entry) = EVENTS.reserve::<ExecEvent>(0) {
        let p = entry.as_mut_ptr();
        // SAFETY: reserve handed us a T-sized, T-aligned ring-buffer slot
        // owned exclusively until submit(); all field writes stay in bounds
        // of ExecEvent.
        unsafe {
            (*p).kind = EVENT_EXEC;
            (*p).pid = pid;
            (*p).uid = uidgid as u32;
            (*p).gid = (uidgid >> 32) as u32;
            (*p)._pad0 = 0;
            (*p).comm = comm;
            (*p).image = staged.image;
            (*p).arg0 = staged.arg0;
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

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[tracepoint(category = "syscalls", name = "sys_enter_openat")]
fn sys_enter_openat(ctx: TracePointContext) -> i32 {
    match try_stage_openat(&ctx) {
        Ok(()) => 0,
        Err(e) => e as i32,
    }
}

fn try_stage_openat(ctx: &TracePointContext) -> Result<(), i64> {
    // SAFETY: read_at offsets are bounds-checked against the syscall
    // tracepoint context (args[0..2]).
    let dirfd: i32 = unsafe { ctx.read_at(16)? };
    let pathname: *const u8 = unsafe { ctx.read_at(24)? };
    let flags: u64 = unsafe { ctx.read_at(32)? };
    if flags & O_CREAT == 0 {
        return Ok(());
    }
    let pid = bpf_get_current_pid_tgid() as u32;

    let pending = match FILE_SCRATCH.get_ptr_mut(0) {
        // SAFETY: index validated by get_ptr_mut; per-cpu map storage valid
        // and unaliased for this program invocation.
        Some(p) => unsafe { &mut *p },
        None => return Err(-28),
    };
    pending.path = [0; PATH_LEN];
    pending.dirfd = dirfd;
    read_cstr(&mut pending.path, pathname);

    let _ = FILE_STAGE.insert(&pid, pending, 0);
    Ok(())
}

#[tracepoint(category = "syscalls", name = "sys_exit_openat")]
fn sys_exit_openat(ctx: TracePointContext) -> i32 {
    match try_emit_file_create(&ctx) {
        Ok(()) => 0,
        Err(e) => e as i32,
    }
}

fn try_emit_file_create(ctx: &TracePointContext) -> Result<(), i64> {
    // SAFETY: bounds-checked context read of the syscall return value.
    let ret: i64 = unsafe { ctx.read_at(16)? };
    if ret < 0 {
        return Ok(()); // failed open — nothing was created
    }
    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
    // SAFETY: read-only map borrow, copied out immediately; lifetime ends
    // with the expression.
    let Some(staged) = (unsafe { FILE_STAGE.get(&pid) }).map(|p| PendingFile {
        path: p.path,
        dirfd: p.dirfd,
    }) else {
        return Ok(());
    };
    FILE_STAGE.remove(&pid)?;

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
    // No kernel-side port filter: destination resolution proved flaky across
    // connected/unconnected sockets; userspace DNS parsing is the filter.
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
    // SAFETY: each read dereferences one level of a user msghdr/iovec at the
    // documented x86_64 field offsets (msg_name@0, msg_iov@16; iov_base@0,
    // iov_len@8); every access is fixed-size and fault-tolerant via the
    // helper — a bad pointer fails the probe, not the kernel.
    let _msg_name: *const u8 = unsafe { bpf_probe_read_user(msghdr.cast()) }?;
    let msg_iov: *const u8 = unsafe { bpf_probe_read_user(msghdr.wrapping_add(16).cast()) }?;
    let iov_base: *const u8 = unsafe { bpf_probe_read_user(msg_iov.cast()) }?;
    let iov_len: usize = unsafe { bpf_probe_read_user(msg_iov.wrapping_add(8).cast()) }?;

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
