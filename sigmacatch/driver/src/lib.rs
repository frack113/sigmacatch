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
//! Build: Windows host with the WDK and LLVM, `cargo build --release`
//! (`.github/workflows/driver.yml` is the reference). See README.md.

#![no_std]

#[cfg(not(test))]
extern crate wdk_panic;

use wdk::println;
use wdk_sys::{
    _WDF_DEVICE_IO_TYPE, _WDF_IO_QUEUE_DISPATCH_TYPE, NTSTATUS, PCUNICODE_STRING, PDRIVER_OBJECT,
    PWDFDEVICE_INIT, STATUS_INVALID_DEVICE_REQUEST, STATUS_SUCCESS, UNICODE_STRING,
    WDF_DRIVER_CONFIG, WDF_IO_QUEUE_CONFIG, WDF_NO_OBJECT_ATTRIBUTES, WDFDEVICE, WDFDRIVER,
    WDFQUEUE, WDFREQUEST, call_unsafe_wdf_function_binding,
};

/// Bumped whenever the IOCTL layout changes; the user-mode side refuses to
/// talk to a driver it does not know.
const SIGMACATCH_PROTOCOL_VERSION: u32 = 1;

/// `IOCTL_SIGMACATCH_GET_VERSION`:
/// `CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_READ_DATA)`.
const IOCTL_SIGMACATCH_GET_VERSION: u32 = 0x0022_2000;

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
    }
    status
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
        if io_control_code != IOCTL_SIGMACATCH_GET_VERSION {
            call_unsafe_wdf_function_binding!(
                WdfRequestComplete,
                request,
                STATUS_INVALID_DEVICE_REQUEST,
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
        buffer.cast::<u32>().write(SIGMACATCH_PROTOCOL_VERSION);
        call_unsafe_wdf_function_binding!(
            WdfRequestCompleteWithInformation,
            request,
            STATUS_SUCCESS,
            core::mem::size_of::<u32>() as u64,
        );
    }
}
