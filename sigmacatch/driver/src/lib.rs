// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 sigmacatch contributors

//! sigmacatch kernel sensor — D1: process creation into a ring buffer.
//!
//! The user-mode collector produces Sysmon-schema telemetry from ETW and the
//! live process table. A few events cannot be produced that way on a host
//! without Sysmon: process creation at the instant it happens (EID 1/5),
//! `ObRegisterCallbacks`-grade process access (EID 10), named pipes (EID
//! 17/18) and creation-time / alternate-data-stream / detected-delete file
//! events (EID 2/15/26). This driver exists only for those.
//!
//! D1 registers `PsSetCreateProcessNotifyRoutineEx` and copies every process
//! create/exit into a fixed ring, read by the collector through
//! `IOCTL_READ_EVENTS`. The record layout is shared with user mode in
//! `sigmacatch/src/windows/driver_protocol.rs`.
//!
//! Build: Windows host with the WDK and LLVM, `cargo build --release`
//! (`.github/workflows/driver.yml` is the reference). See README.md.

#![no_std]

#[cfg(not(test))]
extern crate wdk_panic;

use wdk::println;
use wdk_sys::_OB_PREOP_CALLBACK_STATUS::OB_PREOP_SUCCESS;
use wdk_sys::ntddk::{
    ObRegisterCallbacks, ObUnRegisterCallbacks, PsGetCurrentProcessId, PsGetProcessId,
    PsSetCreateProcessNotifyRoutineEx,
};
use wdk_sys::{
    _WDF_DEVICE_IO_TYPE, _WDF_IO_QUEUE_DISPATCH_TYPE, HANDLE, NTSTATUS, OB_CALLBACK_REGISTRATION,
    OB_FLT_REGISTRATION_VERSION, OB_OPERATION, OB_OPERATION_HANDLE_CREATE,
    OB_OPERATION_HANDLE_DUPLICATE, OB_OPERATION_REGISTRATION, OB_POST_OPERATION_INFORMATION,
    OB_PRE_OPERATION_INFORMATION, OB_PREOP_SUCCESS, PCUNICODE_STRING, PDRIVER_OBJECT, PEPROCESS,
    POB_POST_OPERATION_CALLBACK, POB_POST_OPERATION_INFORMATION, POB_PRE_OPERATION_CALLBACK,
    POB_PRE_OPERATION_INFORMATION, POBJECT_TYPE, PPS_CREATE_NOTIFY_INFO, PVOID, PWDFDEVICE_INIT,
    STATUS_INVALID_DEVICE_REQUEST, STATUS_SUCCESS, UNICODE_STRING, WDF_DRIVER_CONFIG,
    WDF_IO_QUEUE_CONFIG, WDF_NO_OBJECT_ATTRIBUTES, WDFDEVICE, WDFDRIVER, WDFQUEUE, WDFREQUEST,
    WDFSPINLOCK, call_unsafe_wdf_function_binding,
};

// `PsProcessType` is not bound by wdk-sys; it is an exported kernel variable.
unsafe extern "C" {
    static PsProcessType: POBJECT_TYPE;
}

// The protocol lives in the user-mode crate and is included verbatim, so the
// two sides cannot drift.
#[path = "../../src/windows/driver_protocol.rs"]
mod protocol;
use protocol::{
    IOCTL_GET_VERSION, IOCTL_READ_EVENTS, RING_CAPACITY, SIGMACATCH_PROTOCOL_VERSION, SensorEvent,
    kind,
};

/// `\Device\sigmacatch`, NUL-terminated.
static DEVICE_NAME: [u16; 19] = [
    b'\\' as u16,
    b'D' as u16,
    b'e' as u16,
    b'v' as u16,
    b'i' as u16,
    b'c' as u16,
    b'e' as u16,
    b'\\' as u16,
    b's' as u16,
    b'i' as u16,
    b'g' as u16,
    b'm' as u16,
    b'a' as u16,
    b'c' as u16,
    b'a' as u16,
    b't' as u16,
    b'c' as u16,
    b'h' as u16,
    0,
];

/// `\DosDevices\sigmacatch`, NUL-terminated.
static SYMBOLIC_LINK: [u16; 24] = [
    b'\\' as u16,
    b'D' as u16,
    b'o' as u16,
    b's' as u16,
    b'D' as u16,
    b'e' as u16,
    b'v' as u16,
    b'i' as u16,
    b'c' as u16,
    b'e' as u16,
    b's' as u16,
    b'\\' as u16,
    b's' as u16,
    b'i' as u16,
    b'g' as u16,
    b'm' as u16,
    b'a' as u16,
    b'c' as u16,
    b'a' as u16,
    b't' as u16,
    b'c' as u16,
    b'h' as u16,
    0,
    0,
];

/// Security descriptor for the control device: SYSTEM and Administrators get
/// full access, everyone else nothing. The same as `SDDL_DEVOBJ_SYS_ALL_ADM_ALL`.
static SDDL: [u16; 35] = [
    b'O' as u16,
    b':' as u16,
    b'S' as u16,
    b'Y' as u16,
    b'G' as u16,
    b':' as u16,
    b'S' as u16,
    b'Y' as u16,
    b'D' as u16,
    b':' as u16,
    b'(' as u16,
    b'A' as u16,
    b';' as u16,
    b';' as u16,
    b'G' as u16,
    b'A' as u16,
    b';' as u16,
    b';' as u16,
    b';' as u16,
    b'S' as u16,
    b'Y' as u16,
    b')' as u16,
    b'(' as u16,
    b'A' as u16,
    b';' as u16,
    b';' as u16,
    b'G' as u16,
    b'A' as u16,
    b';' as u16,
    b';' as u16,
    b';' as u16,
    b'B' as u16,
    b'A' as u16,
    b')' as u16,
    0,
];

/// Callback registration altitude (informational for object callbacks).
static ALTITUDE: [u16; 7] = [
    b'3' as u16,
    b'7' as u16,
    b'0' as u16,
    b'0' as u16,
    b'0' as u16,
    b'0' as u16,
    0,
];

/// Handle returned by `ObRegisterCallbacks`, released on unload.
static mut OB_REGISTRATION_HANDLE: PVOID = core::ptr::null_mut();

/// True once the object callbacks are registered.
static mut OB_REGISTERED: bool = false;

/// Process-handle rights worth reporting as EID 10 (the "injection" set).
const INTERESTING_ACCESS: u32 = 0x0001 // TERMINATE
    | 0x0002 // CREATE_THREAD
    | 0x0008 // VM_OPERATION
    | 0x0010 // VM_READ
    | 0x0020 // VM_WRITE
    | 0x0040 // DUP_HANDLE
    | 0x0080 // CREATE_PROCESS
    | 0x0200 // SET_INFORMATION
    | 0x0800; // SUSPEND_RESUME

/// The process-event ring, guarded by [`EVENT_LOCK`].
struct Ring {
    events: [SensorEvent; RING_CAPACITY],
    head: usize,
    count: usize,
}

// SAFETY: every access is guarded by `EVENT_LOCK` (producer = the notify
// callback at PASSIVE_LEVEL, consumer = the sequential queue at PASSIVE_LEVEL).
static mut RING: Ring = Ring {
    events: [SensorEvent::empty(); RING_CAPACITY],
    head: 0,
    count: 0,
};

/// KMDF spinlock serialising [`RING`]. Created in `evt_device_add`, before
/// the notify routine is registered.
static mut EVENT_LOCK: WDFSPINLOCK = core::ptr::null_mut();

/// True once the notify routine is registered (device add runs once).
static mut NOTIFY_REGISTERED: bool = false;

/// Wrap a static UTF-16 buffer as a counted `UNICODE_STRING`.
fn unicode_string(buffer: &'static [u16]) -> UNICODE_STRING {
    let length = buffer
        .iter()
        .position(|unit| *unit == 0)
        .unwrap_or(buffer.len());
    UNICODE_STRING {
        Length: (length * 2) as u16,
        MaximumLength: (buffer.len() * 2) as u16,
        Buffer: buffer.as_ptr().cast_mut(),
    }
}

/// Copy a counted wide string into a fixed buffer, reporting the characters
/// copied. Silently truncates to the buffer (the consumer also bounds reads).
unsafe fn copy_wide(source: &UNICODE_STRING, destination: &mut [u16], copied: &mut u16) {
    if source.Buffer.is_null() || source.Length == 0 {
        *copied = 0;
        return;
    }
    let units = (source.Length as usize) / 2;
    let count = units.min(destination.len());
    // SAFETY: `source.Buffer` points to `units` wide chars, valid for the
    // duration of the callback; `destination` is at least `count` wide.
    unsafe {
        core::ptr::copy_nonoverlapping(source.Buffer, destination.as_mut_ptr(), count);
    }
    *copied = count as u16;
}

/// Append one record, overwriting the oldest when full.
unsafe fn ring_push(event: &SensorEvent) {
    // SAFETY: the spinlock is created before the notify routine runs.
    unsafe { call_unsafe_wdf_function_binding!(WdfSpinLockAcquire, EVENT_LOCK) };
    // SAFETY: the lock is held.
    unsafe {
        let ring = &mut *core::ptr::addr_of_mut!(RING);
        let slot = (ring.head + ring.count) % RING_CAPACITY;
        ring.events[slot] = *event;
        if ring.count < RING_CAPACITY {
            ring.count += 1;
        } else {
            ring.head = (ring.head + 1) % RING_CAPACITY;
        }
    }
    // SAFETY: paired with the acquire above.
    unsafe { call_unsafe_wdf_function_binding!(WdfSpinLockRelease, EVENT_LOCK) };
}

/// `PsSetCreateProcessNotifyRoutineEx` callback: copy the create/exit record.
unsafe extern "C" fn process_notify(
    _process: PEPROCESS,
    process_id: HANDLE,
    create_info: PPS_CREATE_NOTIFY_INFO,
) {
    let mut event = SensorEvent::empty();
    event.version = SIGMACATCH_PROTOCOL_VERSION;
    event.pid = process_id as usize as u32;
    if !create_info.is_null() {
        event.kind = kind::PROCESS_CREATE;
        // SAFETY: `create_info` is valid for the duration of the callback.
        let info = unsafe { &*create_info };
        event.parent_pid = info.ParentProcessId as usize as u32;
        // `ImageFileName` and `CommandLine` are `PCUNICODE_STRING` here; both
        // may be null, and the strings are copied out immediately.
        // SAFETY: the pointers and their UNICODE_STRINGs are valid for the
        // duration of the callback.
        unsafe {
            if !info.ImageFileName.is_null() {
                copy_wide(
                    &*info.ImageFileName,
                    &mut event.primary,
                    &mut event.primary_length,
                );
            }
            if !info.CommandLine.is_null() {
                copy_wide(
                    &*info.CommandLine,
                    &mut event.secondary,
                    &mut event.secondary_length,
                );
            }
        }
    } else {
        event.kind = kind::PROCESS_EXIT;
    }
    // SAFETY: the callback runs at PASSIVE_LEVEL, where the spinlock is legal.
    unsafe { ring_push(&event) };
}

/// `ObRegisterCallbacks` pre-op: pass every handle operation through.
unsafe extern "C" fn process_access_pre_op(
    _context: PVOID,
    _information: POB_PRE_OPERATION_INFORMATION,
) -> OB_PREOP_CALLBACK_STATUS {
    OB_PREOP_SUCCESS
}

/// `ObRegisterCallbacks` post-op: report interesting process-handle access.
unsafe extern "C" fn process_access_post_op(
    _context: PVOID,
    information: POB_POST_OPERATION_INFORMATION,
) {
    // SAFETY: `information` is valid for the duration of the callback.
    let info = unsafe { &*information };
    // `Object` is the target process (PEPROCESS) for handle-create/duplicate.
    let granted = unsafe { (*info.Parameters).CreateHandleInformation.GrantedAccess };
    if granted & INTERESTING_ACCESS == 0 {
        return;
    }
    // SAFETY: both run in the opening process's context.
    let source_pid = unsafe { PsGetCurrentProcessId() } as usize as u32;
    let target_pid = unsafe { PsGetProcessId(info.Object as PEPROCESS) } as usize as u32;
    if source_pid == target_pid {
        return;
    }
    let mut event = SensorEvent::empty();
    event.version = SIGMACATCH_PROTOCOL_VERSION;
    event.kind = kind::PROCESS_ACCESS;
    event.pid = source_pid;
    event.parent_pid = target_pid;
    event.detail = granted;
    // SAFETY: the callback runs at PASSIVE_LEVEL, where the spinlock is legal.
    unsafe { ring_push(&event) };
}

/// Register the process-access object callbacks.
fn register_ob_callbacks() -> NTSTATUS {
    let mut operation = OB_OPERATION_REGISTRATION {
        ObjectType: unsafe { PsProcessType } as *mut POBJECT_TYPE,
        Operations: OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE,
        PreOperation: Some(process_access_pre_op),
        PostOperation: Some(process_access_post_op),
    };
    let mut registration = OB_CALLBACK_REGISTRATION {
        Version: OB_FLT_REGISTRATION_VERSION as u16,
        OperationRegistrationCount: 1,
        Altitude: unicode_string(&ALTITUDE),
        RegistrationContext: core::ptr::null_mut(),
        OperationRegistration: &raw mut operation,
    };
    let mut handle: PVOID = core::ptr::null_mut();
    // SAFETY: the registration struct and operation outlive the call.
    let status = unsafe { ObRegisterCallbacks(&raw mut registration, &raw mut handle) };
    if status == STATUS_SUCCESS {
        // SAFETY: written before any callback can fire.
        unsafe { OB_REGISTRATION_HANDLE = handle };
    }
    status
}

/// Driver entry point, called by the I/O manager when the service starts.
///
/// KMDF requires the exported symbol to be named `DriverEntry`.
#[unsafe(link_section = "INIT")]
#[unsafe(export_name = "DriverEntry")]
extern "system" fn driver_entry(
    driver: &mut wdk_sys::DRIVER_OBJECT,
    registry_path: PCUNICODE_STRING,
) -> NTSTATUS {
    let mut config = WDF_DRIVER_CONFIG {
        Size: core::mem::size_of::<WDF_DRIVER_CONFIG>() as u32,
        EvtDriverUnload: Some(evt_driver_unload),
        ..WDF_DRIVER_CONFIG::default()
    };
    let mut driver_handle: WDFDRIVER = core::ptr::null_mut();

    // SAFETY: standard KMDF entry sequence; `driver` and `registry_path` come
    // from the I/O manager and stay valid for the call.
    let status = unsafe {
        call_unsafe_wdf_function_binding!(
            WdfDriverCreate,
            driver as PDRIVER_OBJECT,
            registry_path,
            WDF_NO_OBJECT_ATTRIBUTES,
            &raw mut config,
            &mut driver_handle,
        )
    };
    if status != STATUS_SUCCESS {
        println!("sigmacatch: WdfDriverCreate failed {status:#010X}");
        return status;
    }

    // A legacy `sc create type= kernel` service is not PnP-enumerated, so
    // `EvtDriverDeviceAdd` would never run: allocate the control device here.
    let sddl = unicode_string(&SDDL);
    // SAFETY: `driver_handle` came from `WdfDriverCreate`; the SDDL string is
    // copied by the call.
    let device_init = unsafe {
        call_unsafe_wdf_function_binding!(
            WdfControlDeviceInitAllocate,
            driver_handle,
            &raw const sddl
        )
    };
    if device_init.is_null() {
        println!("sigmacatch: WdfControlDeviceInitAllocate failed");
        return wdk_sys::STATUS_INSUFFICIENT_RESOURCES;
    }

    create_device(device_init)
}

/// Remove the notify routine before the driver is unloaded.
unsafe extern "C" fn evt_driver_unload(_driver: WDFDRIVER) {
    // SAFETY: removes the routine registered in `create_device`.
    unsafe {
        if NOTIFY_REGISTERED {
            let _ = PsSetCreateProcessNotifyRoutineEx(Some(process_notify), 1);
            NOTIFY_REGISTERED = false;
        }
        if OB_REGISTERED {
            ObUnRegisterCallbacks(OB_REGISTRATION_HANDLE);
            OB_REGISTERED = false;
        }
    }
}

/// Create the control device, its queue and lock, and register the notify
/// routine.
fn create_device(mut device_init: PWDFDEVICE_INIT) -> NTSTATUS {
    let name = unicode_string(&DEVICE_NAME);
    let link = unicode_string(&SYMBOLIC_LINK);

    // SAFETY: `device_init` is owned by KMDF for the duration of the callback.
    unsafe {
        let mut status = call_unsafe_wdf_function_binding!(
            WdfDeviceInitAssignName,
            device_init,
            &raw const name,
        );
        if status != STATUS_SUCCESS {
            println!("sigmacatch: WdfDeviceInitAssignName failed {status:#010X}");
            return status;
        }

        // Buffered I/O: the user-mode side sends and receives fixed small
        // structures, so the kernel copies them for us.
        call_unsafe_wdf_function_binding!(
            WdfDeviceInitSetIoType,
            device_init,
            _WDF_DEVICE_IO_TYPE::WdfDeviceIoBuffered,
        );

        let mut device: WDFDEVICE = core::ptr::null_mut();
        status = call_unsafe_wdf_function_binding!(
            WdfDeviceCreate,
            &raw mut device_init,
            WDF_NO_OBJECT_ATTRIBUTES,
            &mut device,
        );
        if status != STATUS_SUCCESS {
            println!("sigmacatch: WdfDeviceCreate failed {status:#010X}");
            return status;
        }

        status = call_unsafe_wdf_function_binding!(
            WdfDeviceCreateSymbolicLink,
            device,
            &raw const link,
        );
        if status != STATUS_SUCCESS {
            println!("sigmacatch: WdfDeviceCreateSymbolicLink failed {status:#010X}");
            return status;
        }

        // Default queue: every request reaches `evt_io_device_control`.
        let mut queue_config = WDF_IO_QUEUE_CONFIG {
            Size: core::mem::size_of::<WDF_IO_QUEUE_CONFIG>() as u32,
            DefaultQueue: u8::from(true),
            DispatchType: _WDF_IO_QUEUE_DISPATCH_TYPE::WdfIoQueueDispatchSequential,
            EvtIoDeviceControl: Some(evt_io_device_control),
            ..WDF_IO_QUEUE_CONFIG::default()
        };
        let mut queue: WDFQUEUE = core::ptr::null_mut();
        status = call_unsafe_wdf_function_binding!(
            WdfIoQueueCreate,
            device,
            &raw mut queue_config,
            WDF_NO_OBJECT_ATTRIBUTES,
            &mut queue,
        );
        if status != STATUS_SUCCESS {
            println!("sigmacatch: WdfIoQueueCreate failed {status:#010X}");
            return status;
        }

        // The spinlock and the notify routine must exist before any process
        // event can be produced, and only here is the device fully built.
        let mut lock: WDFSPINLOCK = core::ptr::null_mut();
        status = call_unsafe_wdf_function_binding!(
            WdfSpinLockCreate,
            WDF_NO_OBJECT_ATTRIBUTES,
            &mut lock
        );
        if status != STATUS_SUCCESS {
            println!("sigmacatch: WdfSpinLockCreate failed {status:#010X}");
            return status;
        }
        EVENT_LOCK = lock;

        if !NOTIFY_REGISTERED {
            let result = PsSetCreateProcessNotifyRoutineEx(Some(process_notify), 0);
            if result != STATUS_SUCCESS {
                println!("sigmacatch: PsSetCreateProcessNotifyRoutineEx failed {result:#010X}");
                return result;
            }
            NOTIFY_REGISTERED = true;
        }

        if !OB_REGISTERED {
            let result = register_ob_callbacks();
            if result != STATUS_SUCCESS {
                println!("sigmacatch: ObRegisterCallbacks failed {result:#010X}");
                return result;
            }
            OB_REGISTERED = true;
        }

        status
    }
}

/// IOCTL dispatch.
unsafe extern "C" fn evt_io_device_control(
    _queue: WDFQUEUE,
    request: WDFREQUEST,
    _output_buffer_length: usize,
    _input_buffer_length: usize,
    io_control_code: u32,
) {
    // SAFETY: KMDF owns the request for the duration of the callback.
    unsafe {
        if io_control_code == IOCTL_GET_VERSION {
            let mut buffer: *mut core::ffi::c_void = core::ptr::null_mut();
            let mut length: usize = 0;
            let status = call_unsafe_wdf_function_binding!(
                WdfRequestRetrieveOutputBuffer,
                request,
                core::mem::size_of::<u32>(),
                &mut buffer,
                &mut length,
            );
            if status != STATUS_SUCCESS {
                call_unsafe_wdf_function_binding!(WdfRequestComplete, request, status);
                return;
            }
            buffer.cast::<u32>().write(SIGMACATCH_PROTOCOL_VERSION);
            call_unsafe_wdf_function_binding!(
                WdfRequestCompleteWithInformation,
                request,
                STATUS_SUCCESS,
                core::mem::size_of::<u32>() as u64,
            );
            return;
        }

        if io_control_code == IOCTL_READ_EVENTS {
            let mut buffer: *mut core::ffi::c_void = core::ptr::null_mut();
            let mut length: usize = 0;
            let status = call_unsafe_wdf_function_binding!(
                WdfRequestRetrieveOutputBuffer,
                request,
                core::mem::size_of::<SensorEvent>(),
                &mut buffer,
                &mut length,
            );
            if status != STATUS_SUCCESS {
                call_unsafe_wdf_function_binding!(WdfRequestComplete, request, status);
                return;
            }
            let output = buffer.cast::<SensorEvent>();
            let capacity = length / core::mem::size_of::<SensorEvent>();

            call_unsafe_wdf_function_binding!(WdfSpinLockAcquire, EVENT_LOCK);
            // SAFETY: the lock is held.
            let ring = &mut *core::ptr::addr_of_mut!(RING);
            let count = ring.count.min(capacity);
            // Drain the oldest `count` records.
            for index in 0..count {
                let source = ring.events[(ring.head + index) % RING_CAPACITY];
                output.add(index).write(source);
            }
            ring.head = (ring.head + count) % RING_CAPACITY;
            ring.count -= count;
            call_unsafe_wdf_function_binding!(WdfSpinLockRelease, EVENT_LOCK);

            call_unsafe_wdf_function_binding!(
                WdfRequestCompleteWithInformation,
                request,
                STATUS_SUCCESS,
                (count * core::mem::size_of::<SensorEvent>()) as u64,
            );
            return;
        }

        call_unsafe_wdf_function_binding!(
            WdfRequestComplete,
            request,
            STATUS_INVALID_DEVICE_REQUEST,
        );
    }
}
