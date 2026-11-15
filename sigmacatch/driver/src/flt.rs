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
//! D2b.2a covers `IRP_MJ_CREATE` post-op (EID 11). The other file kinds
//! (rename/truncate/delete/security) reuse the same registration.

use wdk_sys::ntddk::PsGetCurrentProcessId;
use wdk_sys::{
    DRIVER_OBJECT, FILE_CREATED, HANDLE, IO_STATUS_BLOCK, NTSTATUS, STATUS_SUCCESS, UNICODE_STRING,
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
    set_file_information: FltSetInformationParameters,
    set_security: FltSetSecurityParameters,
}

/// `FLT_PARAMETERS.SetFileInformation` (the header names it that way).
#[repr(C)]
#[derive(Clone, Copy)]
#[allow(dead_code)]
struct FltSetInformationParameters {
    length: u32,
    file_information_class: u32,
    parent_of_target: *mut core::ffi::c_void,
    /// Overlaps `ReplaceIfExists`/`ClusterCount`/`DeleteHandle`.
    replace: [u8; 8],
    info_buffer: *mut core::ffi::c_void,
}

/// `FLT_PARAMETERS.SetSecurity`.
#[repr(C)]
#[derive(Clone, Copy)]
#[allow(dead_code)]
struct FltSetSecurityParameters {
    security_information: u32,
    security_descriptor: *mut core::ffi::c_void,
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
            *mut core::ffi::c_void,
            *mut FltCallbackData,
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
}

/// `FLT_REGISTRATION_VERSION` (2.03 on Windows 10+).
const FLT_REGISTRATION_VERSION: u16 = 0x0203;
/// `FLTFL_OPERATION_REGISTRATION_SKIP_PAGING_IO`.
const SKIP_PAGING_IO: u32 = 0x0001;
/// `FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT`.
const NAME_FLAGS: u32 = 0x01 | 0x0100;
/// `FLT_POSTOP_FINISHED_PROCESSING`.
const POSTOP_FINISHED: i32 = 0;
/// `FLT_PREOP_SUCCESS_WITH_CALLBACK`: the post-op must run.
const PREOP_SUCCESS_WITH_CALLBACK: i32 = 0;
/// `IRP_MJ_OPERATION_END`: terminator of the operation array.
const IRP_MJ_OPERATION_END: u8 = 0x80;
/// `IRP_MJ_CREATE`.
const IRP_MJ_CREATE: u8 = 0;

static OPERATIONS: [FltOperationRegistration; 2] = [
    FltOperationRegistration {
        major_function: IRP_MJ_CREATE,
        flags: SKIP_PAGING_IO,
        pre_operation: Some(pre_create),
        post_operation: Some(post_create),
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
    flags: 0,
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

/// Pre-op on `IRP_MJ_CREATE`: request the post-op, change nothing.
unsafe extern "C" fn pre_create(
    _data: *mut FltCallbackData,
    _flt_objects: *mut core::ffi::c_void,
    _completion_context: *mut *mut core::ffi::c_void,
) -> i32 {
    PREOP_SUCCESS_WITH_CALLBACK
}

/// Post-op on `IRP_MJ_CREATE`: report files actually created (EID 11).
unsafe extern "C" fn post_create(
    _flt_objects: *mut core::ffi::c_void,
    data: *mut FltCallbackData,
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
            event.kind = kind::FILE_CREATE;
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
