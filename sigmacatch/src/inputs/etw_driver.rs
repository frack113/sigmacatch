// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 sigmacatch contributors

//! Client for the sigmacatch kernel sensor (feature `driver`, Windows only).
//!
//! Opens `\\.\sigmacatch`, checks the protocol version, and drains the
//! process-event ring into Sysmon-schema events. The kernel supplies the
//! fields that race with process exit (image path and, above all, the
//! creation-time command line); the token facts (user, integrity) and the
//! creation time are best-effort enriched from the still-alive process, which
//! is safe because those fields do not change for the process lifetime.

use std::collections::HashMap;
use std::ffi::c_void;
use std::mem::size_of;

use anyhow::{Context, Result};
use windows::Win32::Foundation::{CloseHandle, HANDLE, INVALID_HANDLE_VALUE};
use windows::Win32::Storage::FileSystem::{
    CreateFileW, FILE_GENERIC_READ, FILE_GENERIC_WRITE, FILE_SHARE_NONE, OPEN_EXISTING,
};
use windows::Win32::System::IO::DeviceIoControl;
use windows::core::PCWSTR;

use crate::inputs::etw_process::{ProcessFacts, enrich};
use crate::inputs::etw_sysmon::{process_start_xml, process_terminate_xml};
use crate::types::Event;

// The protocol lives next to the driver crate and is included verbatim, so
// the two sides cannot drift.
#[path = "../windows/driver_protocol.rs"]
mod protocol;
pub use protocol::{
    IOCTL_GET_VERSION, IOCTL_READ_EVENTS, RING_CAPACITY, SIGMACATCH_PROTOCOL_VERSION, SensorEvent,
    kind,
};

/// The control device, opened via its DOS alias.
const DEVICE_PATH: &str = "\\\\.\\sigmacatch";

/// A handle to the sigmacatch control device.
pub struct Device {
    handle: HANDLE,
}

impl Device {
    /// Open the control device, or `None` when the driver is not loaded.
    pub fn open() -> Option<Self> {
        let path: Vec<u16> = DEVICE_PATH
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();
        // SAFETY: `path` is a NUL-terminated wide string, valid for the call.
        let handle = unsafe {
            CreateFileW(
                PCWSTR(path.as_ptr()),
                (FILE_GENERIC_READ | FILE_GENERIC_WRITE).0,
                FILE_SHARE_NONE,
                None,
                OPEN_EXISTING,
                Default::default(),
                None,
            )
        }
        .ok()?;
        if handle == INVALID_HANDLE_VALUE {
            return None;
        }
        Some(Self { handle })
    }

    /// Protocol version the loaded driver speaks, or `None` on mismatch/error.
    pub fn version(&self) -> Option<u32> {
        let mut output = 0u32;
        let mut returned = 0u32;
        // SAFETY: the buffers describe themselves; `returned` is out-only.
        unsafe {
            DeviceIoControl(
                self.handle,
                IOCTL_GET_VERSION,
                None,
                0,
                Some(std::ptr::addr_of_mut!(output).cast::<c_void>()),
                size_of::<u32>() as u32,
                Some(&mut returned),
                None,
            )
        }
        .ok()?;
        (returned as usize == size_of::<u32>()).then_some(output)
    }

    /// Drain up to one full ring of events. Returns the number copied.
    pub fn read_events(&self, output: &mut Vec<SensorEvent>) -> Result<usize> {
        let mut buffer = vec![0u8; RING_CAPACITY * size_of::<SensorEvent>()];
        let mut returned = 0u32;
        // SAFETY: `buffer` is writable for its full length.
        unsafe {
            DeviceIoControl(
                self.handle,
                IOCTL_READ_EVENTS,
                None,
                0,
                Some(buffer.as_mut_ptr().cast::<c_void>()),
                buffer.len() as u32,
                Some(&mut returned),
                None,
            )
        }
        .context("IOCTL_READ_EVENTS")?;
        let count = returned as usize / size_of::<SensorEvent>();
        output.clear();
        let (records, _) =
            buffer[..count * size_of::<SensorEvent>()].as_chunks::<{ size_of::<SensorEvent>() }>();
        for slot in records {
            // SAFETY: `slot` is exactly one `SensorEvent`, copied from the
            // driver's buffer.
            output.push(unsafe { std::ptr::read(slot.as_ptr().cast::<SensorEvent>()) });
        }
        Ok(count)
    }
}

impl Drop for Device {
    fn drop(&mut self) {
        // SAFETY: the handle came from `CreateFileW` exactly once.
        unsafe {
            let _ = CloseHandle(self.handle);
        }
    }
}

/// Turns a stream of [`SensorEvent`] records into [`Event`]s, keeping the
/// pid → facts cache that fills `ParentImage`/`ParentCommandLine`.
pub struct Mapper {
    computer: String,
    cache: HashMap<u32, ProcessFacts>,
}

impl Default for Mapper {
    fn default() -> Self {
        Self::new()
    }
}

impl Mapper {
    /// Create a mapper that reports for this host.
    pub fn new() -> Self {
        let computer = std::env::var("COMPUTERNAME").unwrap_or_default();
        Self {
            computer,
            cache: HashMap::new(),
        }
    }

    /// Map one record into a detection event, or `None` for an unknown kind.
    pub fn map(&mut self, event: &SensorEvent) -> Option<Event> {
        match event.kind {
            kind::PROCESS_CREATE => self.map_create(event),
            kind::PROCESS_EXIT => self.map_exit(event),
            _ => None,
        }
    }

    fn map_create(&mut self, event: &SensorEvent) -> Option<Event> {
        // The driver's copy is authoritative: image and command line come from
        // the kernel at creation time, before the process can exit.
        let mut facts = ProcessFacts {
            pid: event.pid,
            parent_pid: event.parent_pid,
            image: Some(wide(&event.primary, event.primary_length)),
            command_line: Some(wide(&event.secondary, event.secondary_length)),
            ..ProcessFacts::default()
        };
        // Token facts and the creation time do not race with exit; enrich them
        // from the live process when it is still around.
        if let Some(live) = enrich(event.pid) {
            facts.user = live.user;
            facts.user_sid = live.user_sid;
            facts.integrity = live.integrity;
            facts.created = live.created;
        }
        let parent = self.cache.get(&facts.parent_pid).cloned();
        self.cache.insert(event.pid, facts.clone());
        let xml = process_start_xml(&self.computer, &facts, parent.as_ref());
        Event::from_xml_injected(&xml, "windows", Some("sysmon")).ok()
    }

    fn map_exit(&mut self, event: &SensorEvent) -> Option<Event> {
        // The exit record carries no image; reuse the create-time facts, and
        // enrich the exit time from the (soon gone) process.
        let facts = self
            .cache
            .get(&event.pid)
            .cloned()
            .unwrap_or_else(|| ProcessFacts {
                pid: event.pid,
                ..ProcessFacts::default()
            });
        let mut facts = facts;
        if facts.created.is_none()
            && let Some(live) = enrich(event.pid)
        {
            facts.user = live.user;
            facts.integrity = live.integrity;
            facts.created = live.created;
        }
        let xml = process_terminate_xml(&self.computer, &facts);
        Event::from_xml_injected(&xml, "windows", Some("sysmon")).ok()
    }
}

/// Copy `length` UTF-16 units out of a fixed record field.
fn wide(field: &[u16], length: u16) -> String {
    let units = (length as usize).min(field.len());
    String::from_utf16_lossy(&field[..units])
}
