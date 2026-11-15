// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 sigmacatch contributors

//! Minifilter FFI and the file-create callback (EID 11).
//!
//! `wdk-sys` does not bind `fltmgr`, so the subset this driver needs is
//! transcribed from the WDK `fltkernel.h` (10.0.22621) we build against.
//! Only the fields actually read are declared, at their exact C offsets:
//! `FLT_CALLBACK_DATA` and `FLT_IO_PARAMETER_BLOCK` are kernel-allocated, so a
//! partial prefix is layout-compatible, and the `FLT_PARAMETERS` union only
//! needs the members we dereference.
//!
//! Coverage: `IRP_MJ_CREATE` (EID 11, and EID 17 on the named-pipe volume),
//! `IRP_MJ_SET_INFORMATION` (EID 2 creation time, 23 delete, 503 rename, 506
//! truncate), `IRP_MJ_SET_SECURITY` (EID 504/505) and `IRP_MJ_READ` (EID 9,
//! raw volume reads).

use wdk_sys::ntddk::PsGetCurrentProcessId;
use wdk_sys::{
    DRIVER_OBJECT, FILE_CREATED, FILE_OPENED, HANDLE, IO_STATUS_BLOCK, NTSTATUS, STATUS_SUCCESS,
    UNICODE_STRING,
};

use crate::{SIGMACATCH_PROTOCOL_VERSION, SensorEvent, kind, ring_push};

// ---------------------------------------------------------------------------
// Types (transcribed from fltkernel.h)
// ---------------------------------------------------------------------------

/// Opaque minifilter handle.
type PfltFilter = *mut core::ffi::c_void;

/// `FLT_CALLBACK_DATA` prefix: only the fields the callbacks read.
#[repr(C)]
#[allow(dead_code)]
struct FltCallbackData {
    flags: u32,
    thread: *mut core::ffi::c_void,
    iopb: *mut FltIoParameterBlock,
    io_status: IO_STATUS_BLOCK,
}

/// `FLT_IO_PARAMETER_BLOCK`: everything up to `Parameters`.
#[repr(C)]
#[allow(dead_code)]
struct FltIoParameterBlock {
    irp_flags: u32,
    major_function: u8,
    minor_function: u8,
    operation_flags: u8,
    reserved: u8,
    target_file_object: *mut core::ffi::c_void,
    target_instance: *mut core::ffi::c_void,
    parameters: FltParameters,
}

/// `FLT_PARAMETERS` subset: the union members this driver dereferences.
#[repr(C)]
#[allow(dead_code)]
union FltParameters {
    create: FltCreateParameters,
    set_file_information: FltSetInformationParameters,
    set_security: FltSetSecurityParameters,
}

/// `FLT_PARAMETERS.SetFileInformation` (the header names it that way).
#[repr(C)]
#[derive(Clone, Copy)]
#[allow(dead_code)]
struct FltSetInformationParameters {
    length: u32,
    /// `FileInformationClass` is declared `POINTER_ALIGNMENT` in
    /// `fltkernel.h`: 8-byte aligned, so it sits at offset 8 on x64.
    _alignment: u32,
    file_information_class: u32,
    _padding: u32,
    parent_of_target: *mut core::ffi::c_void,
    /// Overlaps `ReplaceIfExists`/`ClusterCount`/`DeleteHandle`.
    replace: [u8; 8],
    info_buffer: *mut core::ffi::c_void,
}

/// `IO_SECURITY_CONTEXT`: only the requested access mask is read.
#[repr(C)]
#[allow(dead_code)]
struct IoSecurityContext {
    security_qos: *mut core::ffi::c_void,
    access_state: *mut core::ffi::c_void,
    desired_access: u32,
    full_create_options: u32,
}

/// `FLT_PARAMETERS.Create`.
#[repr(C)]
#[derive(Clone, Copy)]
#[allow(dead_code)]
struct FltCreateParameters {
    security_context: *mut IoSecurityContext,
    options: u32,
    _pad: u32,
    /// `POINTER_ALIGNMENT` in the header: offset 16 on x64.
    file_attributes: u16,
    share_access: u16,
    _pad2: u32,
    /// `POINTER_ALIGNMENT` as well: offset 24.
    ea_length: u32,
    _pad3: u32,
    ea_buffer: *mut core::ffi::c_void,
    allocation_size: i64,
}

/// `FLT_PARAMETERS.SetSecurity`.
#[repr(C)]
#[derive(Clone, Copy)]
#[allow(dead_code)]
struct FltSetSecurityParameters {
    security_information: u32,
    security_descriptor: *mut core::ffi::c_void,
}

/// `FILE_OBJECT` prefix: the fields needed to recognise a raw volume handle
/// (`FileName` empty, no parent) and to read a named pipe's relative name.
///
/// Offsets on x64: `RelatedFileObject` 0x40, `Flags` 0x50, `FileName` 0x58.
#[repr(C)]
#[allow(dead_code)]
struct FileObject {
    file_type: i16,
    size: i16,
    device_object: *mut core::ffi::c_void,
    vpb: *mut core::ffi::c_void,
    fs_context: *mut core::ffi::c_void,
    fs_context2: *mut core::ffi::c_void,
    section_object_pointer: *mut core::ffi::c_void,
    private_cache_map: *mut core::ffi::c_void,
    final_status: i32,
    related_file_object: *mut FileObject,
    lock_operation: u8,
    delete_pending: u8,
    read_access: u8,
    write_access: u8,
    delete_access: u8,
    shared_read: u8,
    shared_write: u8,
    shared_delete: u8,
    flags: u32,
    file_name: UNICODE_STRING,
}

/// `FLT_RELATED_OBJECTS`.
#[repr(C)]
#[allow(dead_code)]
struct FltRelatedObjects {
    size: u16,
    transaction_context: u16,
    filter: *mut core::ffi::c_void,
    volume: *mut core::ffi::c_void,
    instance: *mut core::ffi::c_void,
    file_object: *mut FileObject,
    transaction: *mut core::ffi::c_void,
}

/// `FILE_BASIC_INFORMATION`. When *setting* it, `ChangeTime` carries the new
/// creation time (the other three times are ignored by the file systems).
#[repr(C)]
#[derive(Clone, Copy)]
#[allow(dead_code)]
struct FileBasicInformation {
    creation_time: i64,
    last_access_time: i64,
    last_write_time: i64,
    change_time: i64,
    file_attributes: u32,
}

/// `FLT_FILE_NAME_INFORMATION`.
#[repr(C)]
#[allow(dead_code)]
struct FltFileNameInformation {
    size: u16,
    names_parsed: u16,
    format: u32,
    name: UNICODE_STRING,
    extension: UNICODE_STRING,
    stream: UNICODE_STRING,
    final_component: UNICODE_STRING,
    parent_dir: UNICODE_STRING,
    volume: UNICODE_STRING,
}

/// `FILE_RENAME_INFORMATION` (as passed in `SetFileInformation.InfoBuffer`).
#[repr(C)]
#[allow(dead_code)]
struct FileRenameInformation {
    replace_if_exists: u8,
    root_directory: HANDLE,
    file_name_length: u32,
    file_name: [u16; 1],
}

/// `FILE_END_OF_FILE_INFORMATION`.
#[repr(C)]
struct FileEndOfFileInformation {
    end_of_file: i64,
}

/// `FILE_DISPOSITION_INFORMATION_EX`.
#[repr(C)]
struct FileDispositionInformationEx {
    flags: u32,
}

/// `FILE_DISPOSITION_INFORMATION`.
#[repr(C)]
struct FileDispositionInformation {
    delete_file: u8,
}

/// `FLT_OPERATION_REGISTRATION`.
#[repr(C)]
#[derive(Clone, Copy)]
struct FltOperationRegistration {
    major_function: u8,
    flags: u32,
    pre_operation: Option<
        unsafe extern "C" fn(
            *mut FltCallbackData,
            *mut core::ffi::c_void,
            *mut *mut core::ffi::c_void,
        ) -> i32,
    >,
    post_operation: Option<
        unsafe extern "C" fn(
            *mut FltCallbackData,
            *mut core::ffi::c_void,
            *mut core::ffi::c_void,
            u32,
        ) -> i32,
    >,
    reserved1: *mut core::ffi::c_void,
}

// SAFETY: the registration tables are immutable constants handed to fltmgr.
unsafe impl Sync for FltOperationRegistration {}

/// `FLT_REGISTRATION` for the current (2.03) interface version.
#[repr(C)]
struct FltRegistration {
    size: u16,
    version: u16,
    flags: u32,
    context_registration: *const core::ffi::c_void,
    operation_registration: *const FltOperationRegistration,
    filter_unload_callback: Option<unsafe extern "C" fn(PfltFilter) -> NTSTATUS>,
    instance_setup_callback:
        Option<unsafe extern "C" fn(*mut core::ffi::c_void, u32, u32, u32) -> NTSTATUS>,
    instance_query_teardown_callback: *const core::ffi::c_void,
    instance_teardown_start_callback: *const core::ffi::c_void,
    instance_teardown_complete_callback: *const core::ffi::c_void,
    generate_file_name_callback: *const core::ffi::c_void,
    normalize_name_component_callback: *const core::ffi::c_void,
    normalize_context_cleanup_callback: *const core::ffi::c_void,
    transaction_notification_callback: *const core::ffi::c_void,
    normalize_name_component_ex_callback: *const core::ffi::c_void,
    section_notification_callback: *const core::ffi::c_void,
}

// SAFETY: the registration table is an immutable constant handed to fltmgr.
unsafe impl Sync for FltRegistration {}

// ---------------------------------------------------------------------------
// fltmgr imports
// ---------------------------------------------------------------------------

#[link(name = "fltmgr")]
unsafe extern "C" {
    fn FltRegisterFilter(
        driver: *mut DRIVER_OBJECT,
        registration: *const FltRegistration,
        filter: *mut PfltFilter,
    ) -> NTSTATUS;
    fn FltStartFiltering(filter: PfltFilter) -> NTSTATUS;
    fn FltUnregisterFilter(filter: PfltFilter);
    fn FltGetFileNameInformation(
        data: *mut FltCallbackData,
        flags: u32,
        information: *mut *mut FltFileNameInformation,
    ) -> NTSTATUS;
    fn FltParseFileNameInformation(information: *mut FltFileNameInformation) -> NTSTATUS;
    fn FltReleaseFileNameInformation(information: *mut FltFileNameInformation);
    fn FltGetRequestorProcessId(data: *mut FltCallbackData) -> HANDLE;
    fn FltGetVolumeName(
        volume: *mut core::ffi::c_void,
        volume_name: *mut UNICODE_STRING,
        buffer_size_needed: *mut u32,
    ) -> NTSTATUS;
    fn FltQueryInformationFile(
        instance: *mut core::ffi::c_void,
        file_object: *mut core::ffi::c_void,
        file_information: *mut core::ffi::c_void,
        length: u32,
        file_information_class: u32,
        length_returned: *mut u32,
    ) -> NTSTATUS;
    fn FltGetDestinationFileNameInformation(
        instance: *mut core::ffi::c_void,
        file_object: *mut core::ffi::c_void,
        root_directory: HANDLE,
        file_name: *mut u16,
        file_name_length: u32,
        options: u32,
        information: *mut *mut FltFileNameInformation,
    ) -> NTSTATUS;
}

/// `FLT_REGISTRATION_VERSION` (2.03 on Windows 10+).
const FLT_REGISTRATION_VERSION: u16 = 0x0203;
/// `FLTFL_REGISTRATION_SUPPORT_NPFS_MSFS`: fltmgr only attaches the filter to
/// the named-pipe and mailslot volumes when this is set.
const SUPPORT_NPFS_MSFS: u32 = 0x0002;
/// `FLTFL_OPERATION_REGISTRATION_SKIP_PAGING_IO`.
const SKIP_PAGING_IO: u32 = 0x0001;
/// `FLTFL_OPERATION_REGISTRATION_SKIP_CACHED_IO`: a raw volume read never
/// comes from the cache, and skipping cached I/O keeps ordinary reads out.
const SKIP_CACHED_IO: u32 = 0x0002;
/// `FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT`.
const NAME_FLAGS: u32 = 0x01 | 0x0100;
/// `FLT_POSTOP_FINISHED_PROCESSING`.
const POSTOP_FINISHED: i32 = 0;
/// `FLT_PREOP_SUCCESS_WITH_CALLBACK`: the post-op must run.
const PREOP_SUCCESS_WITH_CALLBACK: i32 = 0;
/// `FLT_PREOP_SUCCESS_NO_CALLBACK`: the post-op is not wanted.
const PREOP_SUCCESS_NO_CALLBACK: i32 = 1;
/// `\Device\Mailslot`: the MSFS volume device name.
const MAILSLOT_DEVICE: &[u16] = &[
    b'\\' as u16,
    b'D' as u16,
    b'e' as u16,
    b'v' as u16,
    b'i' as u16,
    b'c' as u16,
    b'e' as u16,
    b'\\' as u16,
    b'M' as u16,
    b'a' as u16,
    b'i' as u16,
    b'l' as u16,
    b's' as u16,
    b'l' as u16,
    b'o' as u16,
    b't' as u16,
];
/// `\Device\NamedPipe`: the NPFS volume device name.
const NAMED_PIPE_DEVICE: &[u16] = &[
    b'\\' as u16,
    b'D' as u16,
    b'e' as u16,
    b'v' as u16,
    b'i' as u16,
    b'c' as u16,
    b'e' as u16,
    b'\\' as u16,
    b'N' as u16,
    b'a' as u16,
    b'm' as u16,
    b'e' as u16,
    b'd' as u16,
    b'P' as u16,
    b'i' as u16,
    b'p' as u16,
    b'e' as u16,
];
/// `IRP_MJ_OPERATION_END`: terminator of the operation array.
const IRP_MJ_OPERATION_END: u8 = 0x80;
/// `IRP_MJ_CREATE`.
const IRP_MJ_CREATE: u8 = 0;
/// `IRP_MJ_READ`.
const IRP_MJ_READ: u8 = 3;
/// `IRP_MJ_CREATE_NAMED_PIPE`: the *server* side of `CreateNamedPipe`.
/// `0x01` — `0x11` is `IRP_MJ_LOCK_CONTROL`.
const IRP_MJ_CREATE_NAMED_PIPE: u8 = 0x01;
/// `IRP_MJ_SET_INFORMATION`.
const IRP_MJ_SET_INFORMATION: u8 = 6;
/// `IRP_MJ_SET_SECURITY`.
const IRP_MJ_SET_SECURITY: u8 = 21;
/// `FILE_INFORMATION_CLASS` values handled by the SetInformation post-op.
const FILE_RENAME_INFORMATION_CLASS: u32 = 10;
const FILE_DISPOSITION_INFORMATION_CLASS: u32 = 13;
const FILE_END_OF_FILE_INFORMATION_CLASS: u32 = 20;
const FILE_BASIC_INFORMATION_CLASS: u32 = 4;
const FILE_DISPOSITION_INFORMATION_EX_CLASS: u32 = 64;
const FILE_RENAME_INFORMATION_EX_CLASS: u32 = 65;
/// `FILE_DISPOSITION_INFORMATION_EX.Flags` bit that requests the delete.
const FILE_DISPOSITION_DELETE: u32 = 0x1;
/// `ACCESS_MASK` bits that make an open interesting: the file is about to be
/// written to. Read-only opens are left out, they are both far more numerous
/// and far less useful.
const FILE_WRITE_DATA: u32 = 0x0002;
const FILE_APPEND_DATA: u32 = 0x0004;
/// Events per second the best-effort kind (509) may add to the ring.
///
/// A burst — an installer touching thousands of files — must not turn into a
/// ring overflow that costs the other kinds their events.
const FILE_OPEN_BUDGET: u32 = 64;
/// Second `BUDGET_COUNT` belongs to, in 100 ns units divided down.
static BUDGET_SECOND: core::sync::atomic::AtomicI64 = core::sync::atomic::AtomicI64::new(0);
/// Events admitted during `BUDGET_SECOND`.
static BUDGET_COUNT: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);

/// `SECURITY_INFORMATION` bits.
const OWNER_SECURITY_INFORMATION: u32 = 0x1;
const DACL_SECURITY_INFORMATION: u32 = 0x4;

static OPERATIONS: [FltOperationRegistration; 6] = [
    FltOperationRegistration {
        major_function: IRP_MJ_CREATE,
        flags: SKIP_PAGING_IO,
        pre_operation: Some(pre_create),
        post_operation: Some(post_create),
        reserved1: core::ptr::null_mut(),
    },
    FltOperationRegistration {
        major_function: IRP_MJ_SET_INFORMATION,
        flags: SKIP_PAGING_IO,
        pre_operation: Some(pre_set_information),
        post_operation: Some(post_set_information),
        reserved1: core::ptr::null_mut(),
    },
    FltOperationRegistration {
        major_function: IRP_MJ_SET_SECURITY,
        flags: SKIP_PAGING_IO,
        pre_operation: Some(pre_pass),
        post_operation: Some(post_set_security),
        reserved1: core::ptr::null_mut(),
    },
    FltOperationRegistration {
        major_function: IRP_MJ_READ,
        flags: SKIP_PAGING_IO | SKIP_CACHED_IO,
        pre_operation: Some(pre_read),
        post_operation: None,
        reserved1: core::ptr::null_mut(),
    },
    FltOperationRegistration {
        major_function: IRP_MJ_CREATE_NAMED_PIPE,
        flags: SKIP_PAGING_IO,
        pre_operation: Some(pre_pass),
        post_operation: Some(post_create_pipe),
        reserved1: core::ptr::null_mut(),
    },
    FltOperationRegistration {
        major_function: IRP_MJ_OPERATION_END,
        flags: 0,
        pre_operation: None,
        post_operation: None,
        reserved1: core::ptr::null_mut(),
    },
];

static REGISTRATION: FltRegistration = FltRegistration {
    size: core::mem::size_of::<FltRegistration>() as u16,
    version: FLT_REGISTRATION_VERSION,
    flags: SUPPORT_NPFS_MSFS,
    context_registration: core::ptr::null(),
    operation_registration: OPERATIONS.as_ptr(),
    filter_unload_callback: Some(filter_unload),
    instance_setup_callback: Some(instance_setup),
    instance_query_teardown_callback: core::ptr::null(),
    instance_teardown_start_callback: core::ptr::null(),
    instance_teardown_complete_callback: core::ptr::null(),
    generate_file_name_callback: core::ptr::null(),
    normalize_name_component_callback: core::ptr::null(),
    normalize_context_cleanup_callback: core::ptr::null(),
    transaction_notification_callback: core::ptr::null(),
    normalize_name_component_ex_callback: core::ptr::null(),
    section_notification_callback: core::ptr::null(),
};

/// Registered filter handle, released on unload.
static mut FILTER: PfltFilter = core::ptr::null_mut();

/// Register the minifilter. Starting is separate (see [`start`]) because the
/// first callback runs as soon as filtering starts, and it needs the ring
/// spinlock to exist already.
pub unsafe fn register(driver: *mut DRIVER_OBJECT) -> NTSTATUS {
    let mut filter: PfltFilter = core::ptr::null_mut();
    // SAFETY: the registration table is a static and outlives the filter.
    let status = unsafe { FltRegisterFilter(driver, &raw const REGISTRATION, &mut filter) };
    if status != STATUS_SUCCESS {
        return status;
    }
    // SAFETY: written before any callback can use it.
    unsafe { FILTER = filter };
    STATUS_SUCCESS
}

/// Start filtering. Must be called once the ring lock exists: the filter
/// manager may deliver create callbacks immediately.
pub unsafe fn start() -> NTSTATUS {
    // SAFETY: `FILTER` was set by `register`.
    let filter = unsafe { FILTER };
    if filter.is_null() {
        return STATUS_SUCCESS;
    }
    // SAFETY: the handle came from `FltRegisterFilter`.
    unsafe { FltStartFiltering(filter) }
}

/// Unregister the filter (called from the driver unload path).
pub unsafe fn unregister() {
    // SAFETY: the handle was stored by `register` and is cleared here.
    unsafe {
        let filter = FILTER;
        FILTER = core::ptr::null_mut();
        if !filter.is_null() {
            FltUnregisterFilter(filter);
        }
    }
}

/// `InstanceSetupCallback`: attach to every volume.
unsafe extern "C" fn instance_setup(
    _volume: *mut core::ffi::c_void,
    _flags: u32,
    _device_type: u32,
    _filesystem_type: u32,
) -> NTSTATUS {
    STATUS_SUCCESS
}

/// `FilterUnloadCallback`.
unsafe extern "C" fn filter_unload(_filter: PfltFilter) -> NTSTATUS {
    STATUS_SUCCESS
}

/// Copy a volume's device name (e.g. `\Device\HarddiskVolume3`) into
/// `buffer`, returning the number of code units written.
unsafe fn volume_device_name(volume: *mut core::ffi::c_void, buffer: &mut [u16]) -> Option<usize> {
    let mut name = UNICODE_STRING {
        Length: 0,
        MaximumLength: (buffer.len() * 2) as u16,
        Buffer: buffer.as_mut_ptr(),
    };
    let mut needed = 0u32;
    // SAFETY: fltmgr writes at most `MaximumLength` bytes into `buffer`.
    let status = unsafe { FltGetVolumeName(volume, &mut name, &mut needed) };
    (status == STATUS_SUCCESS).then_some(name.Length as usize / 2)
}

/// ASCII lowercase of one UTF-16 code unit.
fn ascii_lower(unit: u16) -> u16 {
    if unit >= u16::from(b'A') && unit <= u16::from(b'Z') {
        unit + 32
    } else {
        unit
    }
}

/// ASCII-case-insensitive comparison of two wide strings (no `alloc`, and the
/// core slice helper does not exist for `u16`).
fn wide_eq_ignore_ascii_case(left: &[u16], right: &[u16]) -> bool {
    left.len() == right.len()
        && left
            .iter()
            .zip(right)
            .all(|(left, right)| ascii_lower(*left) == ascii_lower(*right))
}

/// Which kind of device a request targets.
#[derive(Clone, Copy, PartialEq)]
enum VolumeKind {
    /// A real file system volume.
    FileSystem,
    /// `\Device\NamedPipe` (NPFS): named pipes, EID 17.
    NamedPipe,
    /// `\Device\Mailslot` (MSFS): no Sysmon equivalent, ignored.
    Mailslot,
}

/// Classify the volume the request targets.
unsafe fn volume_kind(flt_objects: *mut core::ffi::c_void) -> VolumeKind {
    // SAFETY: `flt_objects` is a live FLT_RELATED_OBJECTS for the call.
    let Some(objects) = (unsafe { (flt_objects as *mut FltRelatedObjects).as_ref() }) else {
        return VolumeKind::FileSystem;
    };
    let mut buffer = [0u16; 128];
    let Some(units) = (unsafe { volume_device_name(objects.volume, &mut buffer) }) else {
        return VolumeKind::FileSystem;
    };
    if wide_eq_ignore_ascii_case(&buffer[..units], NAMED_PIPE_DEVICE) {
        VolumeKind::NamedPipe
    } else if wide_eq_ignore_ascii_case(&buffer[..units], MAILSLOT_DEVICE) {
        VolumeKind::Mailslot
    } else {
        VolumeKind::FileSystem
    }
}

/// `IRP_MJ_READ` pre-op: raw volume reads (EID 9).
///
/// A raw read comes from a handle opened on a volume itself rather than on a
/// file inside it: the file object carries no name and no parent. It is
/// reported from the pre-op because the post-op can run at DPC level, where
/// the volume name lookup is not allowed.
unsafe extern "C" fn pre_read(
    data: *mut FltCallbackData,
    flt_objects: *mut core::ffi::c_void,
    _completion_context: *mut *mut core::ffi::c_void,
) -> i32 {
    if unsafe { volume_kind(flt_objects) } != VolumeKind::FileSystem {
        return PREOP_SUCCESS_NO_CALLBACK;
    }
    // SAFETY: `flt_objects` is a live FLT_RELATED_OBJECTS for the call.
    let Some(objects) = (unsafe { (flt_objects as *mut FltRelatedObjects).as_ref() }) else {
        return PREOP_SUCCESS_NO_CALLBACK;
    };
    // SAFETY: the file object belongs to the volume the request targets.
    let Some(file) = (unsafe { objects.file_object.as_ref() }) else {
        return PREOP_SUCCESS_NO_CALLBACK;
    };
    if file.file_name.Length != 0 || !file.related_file_object.is_null() {
        return PREOP_SUCCESS_NO_CALLBACK;
    }
    let mut buffer = [0u16; 128];
    let Some(units) = (unsafe { volume_device_name(objects.volume, &mut buffer) }) else {
        return PREOP_SUCCESS_NO_CALLBACK;
    };
    let mut event = SensorEvent::empty();
    event.version = SIGMACATCH_PROTOCOL_VERSION;
    event.kind = kind::RAW_READ;
    event.pid = unsafe { FltGetRequestorProcessId(data) } as usize as u32;
    let count = units.min(event.primary.len());
    // SAFETY: both buffers are local and `count` is bounded by both.
    unsafe {
        core::ptr::copy_nonoverlapping(buffer.as_ptr(), event.primary.as_mut_ptr(), count);
        event.primary_length = count as u16;
        ring_push(&event);
    }
    PREOP_SUCCESS_NO_CALLBACK
}

/// Pre-op on `IRP_MJ_CREATE`: request the post-op, change nothing.
unsafe extern "C" fn pre_create(
    _data: *mut FltCallbackData,
    _flt_objects: *mut core::ffi::c_void,
    _completion_context: *mut *mut core::ffi::c_void,
) -> i32 {
    PREOP_SUCCESS_WITH_CALLBACK
}

/// `IRP_MJ_SET_INFORMATION` pre-op: report renames (EID 503) and deletes
/// (EID 23).
///
/// Both have to be reported here rather than in the post-op: the buffered
/// destination name (`FILE_RENAME_INFORMATION`) is consumed by the file
/// system, the file object already carries the new name once the rename
/// completed, and a disposition marks the file for deletion before the
/// post-op runs.
unsafe extern "C" fn pre_set_information(
    data: *mut FltCallbackData,
    flt_objects: *mut core::ffi::c_void,
    _completion_context: *mut *mut core::ffi::c_void,
) -> i32 {
    // Only file systems carry the information classes handled here.
    if unsafe { volume_kind(flt_objects) } != VolumeKind::FileSystem {
        return PREOP_SUCCESS_WITH_CALLBACK;
    }
    // SAFETY: `data` is valid for the callback's duration.
    let Some(callback) = (unsafe { data.as_ref() }) else {
        return PREOP_SUCCESS_WITH_CALLBACK;
    };
    // SAFETY: `iopb` points to the live parameter block.
    let Some(iopb) = (unsafe { callback.iopb.as_ref() }) else {
        return PREOP_SUCCESS_WITH_CALLBACK;
    };
    // SAFETY: the SetFileInformation member is the active union member here.
    let parameters = unsafe { &iopb.parameters.set_file_information };
    match parameters.file_information_class {
        FILE_BASIC_INFORMATION_CLASS => {
            // SAFETY: the buffer holds a FILE_BASIC_INFORMATION.
            let basic = parameters.info_buffer.cast::<FileBasicInformation>();
            if basic.is_null() {
                return PREOP_SUCCESS_WITH_CALLBACK;
            }
            // `SetFileTime` fills the homonymous `CreationTime`; zero means
            // "leave it alone". `ChangeTime` is the metadata-change stamp and
            // is written on its own (as `-1`, "now") by kernel components
            // touching hundreds of files at boot — reading it here turned
            // every one of those into a false EID 2.
            let new_creation = unsafe { (*basic).creation_time };
            if new_creation == 0 {
                return PREOP_SUCCESS_WITH_CALLBACK;
            }
            let mut previous = FileBasicInformation {
                creation_time: 0,
                last_access_time: 0,
                last_write_time: 0,
                change_time: 0,
                file_attributes: 0,
            };
            let mut returned = 0u32;
            // SAFETY: `previous` is sized for the class; the query is issued
            // on the file object of this very operation.
            let status = unsafe {
                FltQueryInformationFile(
                    iopb.target_instance,
                    iopb.target_file_object,
                    (&raw mut previous).cast::<core::ffi::c_void>(),
                    core::mem::size_of::<FileBasicInformation>() as u32,
                    FILE_BASIC_INFORMATION_CLASS,
                    &mut returned,
                )
            };
            let old = if status == STATUS_SUCCESS {
                previous.creation_time
            } else {
                0
            };
            if old != 0 && old == new_creation {
                return PREOP_SUCCESS_WITH_CALLBACK;
            }
            // A negative value means "now"; the resulting stamp is not
            // exposed here, so it is left out rather than invented.
            let new_value = u64::try_from(new_creation).unwrap_or(0);
            let old_value = u64::try_from(old).unwrap_or(0);
            unsafe {
                push_named_values(data, kind::FILE_CREATION_TIME, 0, old_value, new_value);
            }
            return PREOP_SUCCESS_WITH_CALLBACK;
        }
        FILE_DISPOSITION_INFORMATION_CLASS => {
            // SAFETY: the buffer holds a FILE_DISPOSITION_INFORMATION.
            let disposition = parameters.info_buffer.cast::<FileDispositionInformation>();
            if !disposition.is_null() && unsafe { (*disposition).delete_file } != 0 {
                // Sysmon reports both ids for one delete: 23 (FileDelete,
                // archived) and 26 (FileDeleteDetected, no backup). This
                // sensor keeps no archive, so both carry the same shape.
                unsafe {
                    push_named(data, kind::FILE_DELETE, 0);
                    push_named(data, kind::FILE_DELETE_DETECTED, 0);
                }
            }
            return PREOP_SUCCESS_WITH_CALLBACK;
        }
        FILE_DISPOSITION_INFORMATION_EX_CLASS => {
            // SAFETY: the buffer holds a FILE_DISPOSITION_INFORMATION_EX.
            let disposition = parameters
                .info_buffer
                .cast::<FileDispositionInformationEx>();
            if !disposition.is_null()
                && unsafe { (*disposition).flags } & FILE_DISPOSITION_DELETE != 0
            {
                unsafe {
                    push_named(data, kind::FILE_DELETE, 0);
                    push_named(data, kind::FILE_DELETE_DETECTED, 0);
                }
            }
            return PREOP_SUCCESS_WITH_CALLBACK;
        }
        FILE_RENAME_INFORMATION_CLASS | FILE_RENAME_INFORMATION_EX_CLASS => {}
        _ => return PREOP_SUCCESS_WITH_CALLBACK,
    }
    // SAFETY: the buffer holds a FILE_RENAME_INFORMATION for these classes.
    let rename = parameters.info_buffer.cast::<FileRenameInformation>();
    if rename.is_null() {
        return PREOP_SUCCESS_WITH_CALLBACK;
    }
    let rename = unsafe { &*rename };

    let mut old = core::ptr::null_mut();
    if unsafe { FltGetFileNameInformation(data, NAME_FLAGS, &mut old) } != STATUS_SUCCESS {
        return PREOP_SUCCESS_WITH_CALLBACK;
    }
    let mut new = core::ptr::null_mut();
    let status = unsafe {
        FltGetDestinationFileNameInformation(
            iopb.target_instance,
            iopb.target_file_object,
            rename.root_directory,
            rename.file_name.as_ptr().cast_mut(),
            rename.file_name_length,
            NAME_FLAGS,
            &mut new,
        )
    };
    // SAFETY: both name information structures are live until released below.
    unsafe {
        let _ = FltParseFileNameInformation(old);
        if status == STATUS_SUCCESS {
            let _ = FltParseFileNameInformation(new);
            let mut event = SensorEvent::empty();
            event.version = SIGMACATCH_PROTOCOL_VERSION;
            event.kind = kind::FILE_RENAME;
            event.pid = FltGetRequestorProcessId(data) as usize as u32;
            if let Some(old_info) = old.as_ref() {
                copy_wide(
                    &old_info.name,
                    &mut event.primary,
                    &mut event.primary_length,
                );
            }
            if let Some(new_info) = new.as_ref() {
                copy_wide(
                    &new_info.name,
                    &mut event.secondary,
                    &mut event.secondary_length,
                );
            }
            ring_push(&event);
            FltReleaseFileNameInformation(new);
        }
        FltReleaseFileNameInformation(old);
    }
    PREOP_SUCCESS_WITH_CALLBACK
}

/// Pre-op for every operation that only needs the post-op.
unsafe extern "C" fn pre_pass(
    _data: *mut FltCallbackData,
    _flt_objects: *mut core::ffi::c_void,
    _completion_context: *mut *mut core::ffi::c_void,
) -> i32 {
    PREOP_SUCCESS_WITH_CALLBACK
}

/// Push an event carrying the file's current normalized name.
unsafe fn push_named(data: *mut FltCallbackData, kind: u32, detail: u32) {
    // SAFETY: forwarded to the value-carrying variant with no values.
    unsafe { push_named_values(data, kind, detail, 0, 0) };
}

/// [`push_named`] plus the two kind-specific 64-bit values.
unsafe fn push_named_values(
    data: *mut FltCallbackData,
    kind: u32,
    detail: u32,
    value_a: u64,
    value_b: u64,
) {
    let mut information: *mut FltFileNameInformation = core::ptr::null_mut();
    // SAFETY: fltmgr allocates the name information; released below.
    if unsafe { FltGetFileNameInformation(data, NAME_FLAGS, &mut information) } != STATUS_SUCCESS {
        return;
    }
    // SAFETY: `information` is live until the release below.
    unsafe {
        let _ = FltParseFileNameInformation(information);
        if let Some(name_info) = information.as_ref() {
            let mut event = SensorEvent::empty();
            event.version = SIGMACATCH_PROTOCOL_VERSION;
            event.kind = kind;
            event.detail = detail;
            event.value_a = value_a;
            event.value_b = value_b;
            event.pid = FltGetRequestorProcessId(data) as usize as u32;
            copy_wide(
                &name_info.name,
                &mut event.primary,
                &mut event.primary_length,
            );
            ring_push(&event);
        }
        FltReleaseFileNameInformation(information);
    }
}

/// `IRP_MJ_SET_INFORMATION` post-op: truncate (506).
///
/// Renames and deletes are reported from the pre-op, see
/// [`pre_set_information`]: there the file object still carries the name. This
/// post-op only runs for the classes that survive the pre-op.
unsafe extern "C" fn post_set_information(
    data: *mut FltCallbackData,
    flt_objects: *mut core::ffi::c_void,
    _context: *mut core::ffi::c_void,
    _flags: u32,
) -> i32 {
    if unsafe { volume_kind(flt_objects) } != VolumeKind::FileSystem {
        return POSTOP_FINISHED;
    }
    // SAFETY: `data` is valid for the callback's duration.
    let Some(callback) = (unsafe { data.as_ref() }) else {
        return POSTOP_FINISHED;
    };
    if unsafe { callback.io_status.__bindgen_anon_1.Status } < 0 {
        return POSTOP_FINISHED;
    }
    // SAFETY: `iopb` points to the live parameter block.
    let Some(iopb) = (unsafe { callback.iopb.as_ref() }) else {
        return POSTOP_FINISHED;
    };
    // SAFETY: the SetFileInformation member is the active union member for
    // this major function.
    let parameters = unsafe { &iopb.parameters.set_file_information };
    match parameters.file_information_class {
        FILE_END_OF_FILE_INFORMATION_CLASS => {
            // SAFETY: the buffer holds a FILE_END_OF_FILE_INFORMATION.
            let truncate = parameters.info_buffer.cast::<FileEndOfFileInformation>();
            if truncate.is_null() {
                return POSTOP_FINISHED;
            }
            let size = unsafe { (*truncate).end_of_file };
            unsafe { push_named(data, kind::FILE_TRUNCATE, size as u32) };
        }
        _ => {}
    }
    POSTOP_FINISHED
}

/// `IRP_MJ_SET_SECURITY` post-op: DACL change (504) and owner change (505).
unsafe extern "C" fn post_set_security(
    data: *mut FltCallbackData,
    flt_objects: *mut core::ffi::c_void,
    _context: *mut core::ffi::c_void,
    _flags: u32,
) -> i32 {
    if unsafe { volume_kind(flt_objects) } != VolumeKind::FileSystem {
        return POSTOP_FINISHED;
    }
    // SAFETY: `data` is valid for the callback's duration.
    let Some(callback) = (unsafe { data.as_ref() }) else {
        return POSTOP_FINISHED;
    };
    if unsafe { callback.io_status.__bindgen_anon_1.Status } < 0 {
        return POSTOP_FINISHED;
    }
    // SAFETY: `iopb` points to the live parameter block.
    let Some(iopb) = (unsafe { callback.iopb.as_ref() }) else {
        return POSTOP_FINISHED;
    };
    // SAFETY: the SetSecurity member is the active union member here.
    let security_information = unsafe { iopb.parameters.set_security.security_information };
    if security_information & DACL_SECURITY_INFORMATION != 0 {
        unsafe { push_named(data, kind::FILE_SET_SECURITY, 0) };
    }
    if security_information & OWNER_SECURITY_INFORMATION != 0 {
        unsafe { push_named(data, kind::FILE_SET_SECURITY, 1) };
    }
    POSTOP_FINISHED
}

/// Post-op on `IRP_MJ_CREATE`: report files actually created (EID 11).
unsafe extern "C" fn post_create(
    data: *mut FltCallbackData,
    flt_objects: *mut core::ffi::c_void,
    _context: *mut core::ffi::c_void,
    _flags: u32,
) -> i32 {
    // SAFETY: `data` is valid for the callback's duration.
    let Some(callback) = (unsafe { data.as_ref() }) else {
        return POSTOP_FINISHED;
    };
    // SAFETY: `IoStatus` is a plain field of the callback data.
    let status = unsafe { callback.io_status.__bindgen_anon_1.Status };
    if status < 0 {
        return POSTOP_FINISHED;
    }

    // Named pipes and mailslots live on their own volumes. A pipe *creation*
    // arrives as `IRP_MJ_CREATE_NAMED_PIPE` (EID 17); a create on NPFS is a
    // client connecting to an existing pipe, which is EID 18. A mailslot has
    // no Sysmon equivalent and is dropped.
    match unsafe { volume_kind(flt_objects) } {
        VolumeKind::NamedPipe => {
            if callback.io_status.Information == u64::from(FILE_OPENED) {
                unsafe { push_pipe_create(data, flt_objects, kind::PIPE_CONNECT) };
            }
            return POSTOP_FINISHED;
        }
        VolumeKind::Mailslot => return POSTOP_FINISHED,
        VolumeKind::FileSystem => {}
    }

    if callback.io_status.Information == u64::from(FILE_OPENED) {
        // EID 509: the process opened an existing file for writing. Best
        // effort by design — the mask is read from the security context and
        // the per-second budget bounds what a burst can add.
        if callback.iopb.is_null() {
            return POSTOP_FINISHED;
        }
        // SAFETY: `iopb` is live for the callback and the Create member is the
        // active union member for a create.
        let parameters = unsafe { &(*callback.iopb).parameters.create };
        let desired = if parameters.security_context.is_null() {
            0
        } else {
            // SAFETY: the buffer belongs to this create request.
            unsafe { (*parameters.security_context).desired_access }
        };
        if desired & (FILE_WRITE_DATA | FILE_APPEND_DATA) != 0 && under_budget() {
            unsafe { push_named(data, kind::FILE_OPEN, desired) };
        }
        return POSTOP_FINISHED;
    }

    if callback.io_status.Information != u64::from(FILE_CREATED) {
        return POSTOP_FINISHED;
    }

    let mut information: *mut FltFileNameInformation = core::ptr::null_mut();
    // SAFETY: fltmgr allocates the name information; released below.
    if unsafe { FltGetFileNameInformation(data, NAME_FLAGS, &mut information) } != STATUS_SUCCESS {
        return POSTOP_FINISHED;
    }
    // SAFETY: `information` is live until the release below.
    unsafe {
        let _ = FltParseFileNameInformation(information);
        if let Some(name_info) = information.as_ref() {
            let pid = FltGetRequestorProcessId(data) as usize as u32;
            let mut event = SensorEvent::empty();
            event.version = SIGMACATCH_PROTOCOL_VERSION;
            // An alternate data stream is a create whose name carries a
            // `:stream` component: Sysmon reports those as EID 15, with the
            // stream in `TargetFilename`. The name is already complete —
            // `FltParseFileNameInformation` leaves `stream` empty for a
            // normalized name — so the check reads the path itself.
            event.kind = if has_stream(&name_info.name) {
                kind::FILE_STREAM
            } else {
                kind::FILE_CREATE
            };
            event.pid = if pid != 0 {
                pid
            } else {
                PsGetCurrentProcessId() as usize as u32
            };
            event.timestamp = 0;
            copy_wide(
                &name_info.name,
                &mut event.primary,
                &mut event.primary_length,
            );
            ring_push(&event);
        }
        FltReleaseFileNameInformation(information);
    }
    POSTOP_FINISHED
}

/// `IRP_MJ_CREATE_NAMED_PIPE` post-op: a pipe server was created (EID 17).
unsafe extern "C" fn post_create_pipe(
    data: *mut FltCallbackData,
    flt_objects: *mut core::ffi::c_void,
    _context: *mut core::ffi::c_void,
    _flags: u32,
) -> i32 {
    // SAFETY: `data` is valid for the callback's duration.
    let Some(callback) = (unsafe { data.as_ref() }) else {
        return POSTOP_FINISHED;
    };
    if unsafe { callback.io_status.__bindgen_anon_1.Status } < 0 {
        return POSTOP_FINISHED;
    }
    if unsafe { volume_kind(flt_objects) } != VolumeKind::NamedPipe {
        return POSTOP_FINISHED;
    }
    unsafe { push_pipe_create(data, flt_objects, kind::PIPE_CREATE) };
    POSTOP_FINISHED
}

/// Report a named pipe creation (EID 17) or connection (EID 18) with its
/// relative name.
unsafe fn push_pipe_create(
    data: *mut FltCallbackData,
    flt_objects: *mut core::ffi::c_void,
    kind: u32,
) {
    // SAFETY: `flt_objects` is a live FLT_RELATED_OBJECTS for the call.
    let Some(objects) = (unsafe { (flt_objects as *mut FltRelatedObjects).as_ref() }) else {
        return;
    };
    // SAFETY: the file object belongs to the volume the request targets.
    let Some(file) = (unsafe { objects.file_object.as_ref() }) else {
        return;
    };
    let mut event = SensorEvent::empty();
    event.version = SIGMACATCH_PROTOCOL_VERSION;
    event.kind = kind;
    event.pid = unsafe { FltGetRequestorProcessId(data) } as usize as u32;
    // SAFETY: the name lives as long as the file object we hold.
    unsafe {
        copy_wide(
            &file.file_name,
            &mut event.primary,
            &mut event.primary_length,
        );
        ring_push(&event);
    }
}

/// True when `name` carries an alternate data stream, i.e. a `:` after the
/// last path separator (`...\file.txt:hidden:$DATA`).
///
/// Device paths (`\Device\HarddiskVolume3\...`) hold no drive-letter colon,
/// so any colon after the last separator is a stream.
fn has_stream(name: &UNICODE_STRING) -> bool {
    if name.Buffer.is_null() || name.Length < 2 {
        return false;
    }
    let units = unsafe { core::slice::from_raw_parts(name.Buffer, (name.Length as usize) / 2) };
    for unit in units.iter().rev() {
        match *unit {
            u if u == u16::from(b'\\') => return false,
            u if u == u16::from(b':') => return true,
            _ => {}
        }
    }
    false
}

/// True while the per-second budget for the best-effort kinds is not spent.
fn under_budget() -> bool {
    use core::sync::atomic::Ordering;
    let mut now = wdk_sys::LARGE_INTEGER::default();
    // SAFETY: the call only reads the clock.
    unsafe { wdk_sys::ntddk::KeQuerySystemTimePrecise(&raw mut now) };
    // SAFETY: `LARGE_INTEGER` is a union; `KeQuerySystemTimePrecise` filled it.
    let second = unsafe { now.QuadPart } / 10_000_000;
    if BUDGET_SECOND.swap(second, Ordering::Relaxed) != second {
        BUDGET_COUNT.store(0, Ordering::Relaxed);
    }
    BUDGET_COUNT.fetch_add(1, Ordering::Relaxed) < FILE_OPEN_BUDGET
}

/// Copy a counted wide string into a fixed record field.
unsafe fn copy_wide(source: &UNICODE_STRING, destination: &mut [u16], copied: &mut u16) {
    if source.Buffer.is_null() || source.Length == 0 {
        *copied = 0;
        return;
    }
    let units = (source.Length as usize) / 2;
    let count = units.min(destination.len());
    // SAFETY: the source is valid for the callback; the destination is sized.
    unsafe {
        core::ptr::copy_nonoverlapping(source.Buffer, destination.as_mut_ptr(), count);
    }
    *copied = count as u16;
}
