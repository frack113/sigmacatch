// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 sigmacatch contributors

//! sigmacatch kernel sensor — D0 skeleton.
//!
//! The user-mode collector produces Sysmon-schema telemetry from ETW and the
//! live process table. A few events cannot be produced that way on a host
//! without Sysmon: process creation at the instant it happens (EID 1/5),
//! `ObRegisterCallbacks`-grade process access (EID 10), named pipes (EID
//! 17/18) and creation-time / alternate-data-stream / detected-delete file
//! events (EID 2/15/26). This driver exists only for those.
//!
//! D0 is the channel, not the coverage: a control device
//! (`\Device\sigmacatch` + `\DosDevices\sigmacatch`) with one IOCTL that
//! reports the protocol version. The process-notify ring is D1.
//!
//! Build: Windows host, WDK + LLVM, `cargo build --release`. See README.md.

#![no_std]

extern crate alloc;

#[cfg(not(test))]
extern crate wdk_panic;

use wdk::println;
use wdk_sys::{
    call_unsafe_wdf_function_binding, NTSTATUS, PCUNICODE_STRING, PDRIVER_OBJECT, PWDFDEVICE_INIT,
    STATUS_SUCCESS, UNICODE_STRING, WDFDEVICE, WDFDRIVER, WDFIOQUEUE, WDFOBJECT,
    WDF_DRIVER_CONFIG, WDF_IO_QUEUE_CONFIG, WDF_NO_HANDLE, WDF_NO_OBJECT_ATTRIBUTES, WDFREQUEST,
    WDF_REQUEST_PARAMETERS,
};
use wdk_sys::{
    _WDF_IO_QUEUE_STATE, _WDF_OBJECT_CONTEXT_TYPE_INFO, _WDF_REQUEST_PARAMETERS,
};

/// Bumped whenever the IOCTL layout changes; the user-mode side refuses to
/// talk to a driver it does not know.
const SIGMACATCH_PROTOCOL_VERSION: u32 = 1;

/// `IOCTL_SIGMACATCH_GET_VERSION` — `CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_READ_DATA)`.
const IOCTL_SIGMACATCH_GET_VERSION: u32 = 0x0022_2000;

/// Driver entry point, called by the I/O manager after the service starts.
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
        ..WDF_DRIVER_CONFIG::default()
    };
    let mut driver_handle = WDF_NO_HANDLE.cast::<WDFDRIVER>();

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
    }
    status
}

/// Create the control device and its queue.
extern "C" fn evt_device_add(
    _driver: WDFDRIVER,
    mut device_init: PWDFDEVICE_INIT,
) -> NTSTATUS {
    // SAFETY: `device_init` is owned by KMDF for the duration of the callback.
    unsafe {
        // Device name and DOS alias, both NUL-terminated UTF-16.
        let mut device_name = UNICODE_STRING::default();
        let name: [u16; 19] = [
            '\\' as u16, 'D' as u16, 'e' as u16, 'v' as u16, 'i' as u16, 'c' as u16, 'e' as u16,
            '\\' as u16, 's' as u16, 'i' as u16, 'g' as u16, 'm' as u16, 'a' as u16, 'c' as u16,
            'a' as u16, 't' as u16, 'c' as u16, 'h' as u16, 0,
        ];
        device_name.Buffer = name.as_ptr() as *mut u16;
        device_name.Length = (name.len() as u16 - 1) * 2;
        device_name.MaximumLength = name.len() as u16 * 2;

        let mut status = call_unsafe_wdf_function_binding!(
            WdfDeviceInitAssignName,
            device_init,
            &raw const device_name,
        );
        if status != STATUS_SUCCESS {
            println!("sigmacatch: WdfDeviceInitAssignName failed {status:#010X}");
            return status;
        }

        // Buffered I/O: the user-mode side passes a small, fixed request.
        call_unsafe_wdf_function_binding!(
            WdfDeviceInitSetIoType,
            device_init,
            wdk_sys::_WDF_DEVICE_IO_TYPE::WdfDeviceIoBuffered,
        );

        let mut device: WDFDEVICE = WDF_NO_HANDLE.cast();
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

        let link: [u16; 24] = [
            '\\' as u16, 'D' as u16, 'o' as u16, 's' as u16, 'D' as u16, 'e' as u16, 'v' as u16,
            'i' as u16, 'c' as u16, 'e' as u16, 's' as u16, '\\' as u16, 's' as u16, 'i' as u16,
            'g' as u16, 'm' as u16, 'a' as u16, 'c' as u16, 'a' as u16, 't' as u16, 'c' as u16,
            'h' as u16, 0, 0,
        ];
        let mut symbolic_link = UNICODE_STRING::default();
        symbolic_link.Buffer = link.as_ptr() as *mut u16;
        symbolic_link.Length = (link.len() as u16 - 1) * 2;
        symbolic_link.MaximumLength = link.len() as u16 * 2;
        status = call_unsafe_wdf_function_binding!(
            WdfDeviceCreateSymbolicLink,
            device,
            &raw const symbolic_link,
        );
        if status != STATUS_SUCCESS {
            println!("sigmacatch: WdfDeviceCreateSymbolicLink failed {status:#010X}");
            return status;
        }

        // Default queue: every request goes to `evt_io_device_control`.
        let mut queue_config = WDF_IO_QUEUE_CONFIG {
            Size: core::mem::size_of::<WDF_IO_QUEUE_CONFIG>() as u32,
            QueueDispatch: wdk_sys::_WDF_IO_QUEUE_DISPATCH_TYPE::WdfIoQueueDispatchSequential,
            EvtIoDeviceControl: Some(evt_io_device_control),
            ..WDF_IO_QUEUE_CONFIG::default()
        };
        let mut queue: WDFIOQUEUE = WDF_NO_HANDLE.cast();
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
extern "C" fn evt_io_device_control(
    _queue: WDFIOQUEUE,
    request: WDFREQUEST,
    _output_buffer_length: usize,
    _input_buffer_length: usize,
    io_control_code: u32,
) {
    // SAFETY: KMDF owns the request for the duration of the callback.
    unsafe {
        if io_control_code != IOCTL_SIGMACATCH_GET_VERSION {
            call_unsafe_wdf_function_binding!(
                WdfRequestComplete,
                request,
                wdk_sys::STATUS_INVALID_DEVICE_REQUEST,
            );
            return;
        }

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
        *(buffer.cast::<u32>()) = SIGMACATCH_PROTOCOL_VERSION;
        call_unsafe_wdf_function_binding!(
            WdfRequestCompleteWithInformation,
            request,
            STATUS_SUCCESS,
            core::mem::size_of::<u32>(),
        );
    }
}

// Keep the KMDF state types referenced so the bindings stay explicit.
#[allow(dead_code)]
type _Unused = (
    _WDF_IO_QUEUE_STATE,
    _WDF_OBJECT_CONTEXT_TYPE_INFO,
    _WDF_REQUEST_PARAMETERS,
    WDFDEVICE,
    WDFOBJECT,
    WDF_REQUEST_PARAMETERS,
);
