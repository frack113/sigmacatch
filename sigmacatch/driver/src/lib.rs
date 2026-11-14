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
use wdk_sys::ntddk::{KeAcquireSpinLock, KeReleaseSpinLock, PsSetCreateProcessNotifyRoutineEx};
use wdk_sys::{
    _WDF_DEVICE_IO_TYPE, _WDF_IO_QUEUE_DISPATCH_TYPE, HANDLE, KIRQL, KSPIN_LOCK, NTSTATUS,
    PCUNICODE_STRING, PDRIVER_OBJECT, PEPROCESS, PPS_CREATE_NOTIFY_INFO, PWDFDEVICE_INIT,
    STATUS_INVALID_DEVICE_REQUEST, STATUS_SUCCESS, UNICODE_STRING, WDF_DRIVER_CONFIG,
    WDF_IO_QUEUE_CONFIG, WDF_NO_OBJECT_ATTRIBUTES, WDFDEVICE, WDFDRIVER, WDFQUEUE, WDFREQUEST,
    call_unsafe_wdf_function_binding,
};

// The protocol lives in the user-mode crate and is included verbatim, so the
// two sides cannot drift.
#[path = "../../src/windows/driver_protocol.rs"]
mod protocol;
use protocol::{
    IOCTL_GET_VERSION, IOCTL_READ_EVENTS, ProcessEvent, RING_CAPACITY, SIGMACATCH_PROTOCOL_VERSION,
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

/// The process-event ring, guarded by [`RING_LOCK`].
struct Ring {
    events: [ProcessEvent; RING_CAPACITY],
    head: usize,
    count: usize,
}

// SAFETY: every access is guarded by `RING_LOCK` (producer = the notify
// callback at PASSIVE_LEVEL, consumer = the sequential queue at PASSIVE_LEVEL).
static mut RING: Ring = Ring {
    events: [ProcessEvent::empty(); RING_CAPACITY],
    head: 0,
    count: 0,
};

/// Spinlock serialising [`RING`].
static mut RING_LOCK: KSPIN_LOCK = 0;

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

unsafe fn ring_lock() -> KIRQL {
    let mut irql: KIRQL = 0;
    // SAFETY: `RING_LOCK` is a static spinlock, acquired exactly once here.
    unsafe { KeAcquireSpinLock(core::ptr::addr_of_mut!(RING_LOCK), &mut irql) };
    irql
}

unsafe fn ring_unlock(irql: KIRQL) {
    // SAFETY: `irql` is the value `KeAcquireSpinLock` returned for this lock.
    unsafe { KeReleaseSpinLock(core::ptr::addr_of_mut!(RING_LOCK), irql) };
}

/// Append one record, overwriting the oldest when full.
unsafe fn ring_push(event: &ProcessEvent) {
    let irql = ring_lock();
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
    ring_unlock(irql);
}

/// `PsSetCreateProcessNotifyRoutineEx` callback: copy the create/exit record.
unsafe extern "C" fn process_notify(
    _process: PEPROCESS,
    process_id: HANDLE,
    create_info: PPS_CREATE_NOTIFY_INFO,
) {
    let mut event = ProcessEvent::empty();
    event.version = SIGMACATCH_PROTOCOL_VERSION;
    event.pid = process_id as usize as u32;
    event.creating = u32::from(!create_info.is_null());
    if !create_info.is_null() {
        // SAFETY: `create_info` is valid for the duration of the callback.
        let info = unsafe { &*create_info };
        event.parent_pid = info.ParentProcessId as usize as u32;
        // SAFETY: the UNICODE_STRINGs are valid for the duration of the
        // callback; the strings are copied out immediately.
        unsafe {
            copy_wide(
                &info.ImageFileName,
                &mut event.image,
                &mut event.image_length,
            );
            if !info.CommandLine.Buffer.is_null() {
                copy_wide(
                    &info.CommandLine,
                    &mut event.command_line,
                    &mut event.command_length,
                );
            }
        }
    }
    // SAFETY: the callback runs at PASSIVE_LEVEL, where the spinlock is legal.
    unsafe { ring_push(&event) };
}

/// Driver entry point, called by the I/O manager when the service starts.
///
/// KMDF requires the exported symbol to be named `DriverEntry`.
#[link_section = "INIT"]
#[export_name = "DriverEntry"]
extern "system" fn driver_entry(
    driver: &mut wdk_sys::DRIVER_OBJECT,
    registry_path: PCUNICODE_STRING,
) -> NTSTATUS {
    let mut config = WDF_DRIVER_CONFIG {
        Size: core::mem::size_of::<WDF_DRIVER_CONFIG>() as u32,
        EvtDriverDeviceAdd: Some(evt_device_add),
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

    // SAFETY: the callback is a plain `extern "C"` fn; the routine is removed
    // again in `evt_driver_unload`.
    let status = unsafe { PsSetCreateProcessNotifyRoutineEx(Some(process_notify), 0) };
    if status != STATUS_SUCCESS {
        println!("sigmacatch: PsSetCreateProcessNotifyRoutineEx failed {status:#010X}");
    }
    status
}

/// Remove the notify routine before the driver is unloaded.
unsafe extern "C" fn evt_driver_unload(_driver: WDFDRIVER) {
    // SAFETY: removes the routine registered in `driver_entry`.
    unsafe {
        PsSetCreateProcessNotifyRoutineEx(Some(process_notify), 1);
    }
}

/// Create the control device and its request queue.
unsafe extern "C" fn evt_device_add(
    _driver: WDFDRIVER,
    mut device_init: PWDFDEVICE_INIT,
) -> NTSTATUS {
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
                core::mem::size_of::<ProcessEvent>(),
                &mut buffer,
                &mut length,
            );
            if status != STATUS_SUCCESS {
                call_unsafe_wdf_function_binding!(WdfRequestComplete, request, status);
                return;
            }
            let output = buffer.cast::<ProcessEvent>();
            let capacity = length / core::mem::size_of::<ProcessEvent>();

            let irql = ring_lock();
            // SAFETY: the lock is held.
            let ring = unsafe { &mut *core::ptr::addr_of_mut!(RING) };
            let count = ring.count.min(capacity);
            // Drain the oldest `count` records.
            for index in 0..count {
                let source = ring.events[(ring.head + index) % RING_CAPACITY];
                unsafe { output.add(index).write(source) };
            }
            ring.head = (ring.head + count) % RING_CAPACITY;
            ring.count -= count;
            ring_unlock(irql);

            call_unsafe_wdf_function_binding!(
                WdfRequestCompleteWithInformation,
                request,
                STATUS_SUCCESS,
                (count * core::mem::size_of::<ProcessEvent>()) as u64,
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
