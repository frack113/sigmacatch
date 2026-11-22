// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 sigmacatch contributors

//! Native Windows ETW collector (feature `etw`, Windows only).
//!
//! The analogue of `sigmacatch-input-ebpf` on Linux: a realtime trace session feeds
//! kernel providers straight to `sigmacatch_input_etw_common::etw_event::decode`, with no Sysmon
//! installed and no kernel driver. Two sessions are used, on the reference
//! implementation's findings (see `docs/dev/etw-collector.md`):
//!
//! - a small-buffer **process session** (`Microsoft-Windows-Kernel-Process`)
//!   so short-lived processes are delivered before they exit;
//! - a larger-buffer **main session** for network, file, registry and DNS
//!   traffic, which is bursty but not latency-sensitive;
//! - the **classic kernel logger** for the fields the manifest providers do
//!   not publish: process `CommandLine` and `UserSID`.
//!
//! Starting any of these needs an elevated token (`SeSystemProfilePrivilege`);
//! [`ensure_privileges`] fails with a clear message otherwise, mirroring
//! `ebpf::has_required_privileges`.

#![cfg(target_os = "windows")]

// The Windows orchestrator builds its process cache through this path.
pub use sigmacatch_input_etw_common::etw_process;

use std::ffi::c_void;
use std::mem::size_of;
use std::ptr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use anyhow::{Context, Result, bail};
use windows::Win32::Foundation::{ERROR_SUCCESS, HANDLE, WIN32_ERROR};
use windows::Win32::Security::{GetTokenInformation, TOKEN_ELEVATION, TOKEN_QUERY, TokenElevation};
use windows::Win32::System::Diagnostics::Etw::{
    CONTROLTRACE_HANDLE, ENABLE_TRACE_PARAMETERS, ENABLE_TRACE_PARAMETERS_VERSION_2,
    EVENT_CONTROL_CODE_ENABLE_PROVIDER, EVENT_FILTER_DESCRIPTOR, EVENT_RECORD,
    EVENT_TRACE_CONTROL_STOP, EVENT_TRACE_FLAG, EVENT_TRACE_LOGFILEW,
    EVENT_TRACE_NO_PER_PROCESSOR_BUFFERING, EVENT_TRACE_PROPERTIES, EVENT_TRACE_REAL_TIME_MODE,
    EVENT_TRACE_SYSTEM_LOGGER_MODE, EnableTraceEx2, OpenTraceW, PROCESS_TRACE_MODE_EVENT_RECORD,
    PROCESS_TRACE_MODE_REAL_TIME, PROCESSTRACE_HANDLE, ProcessTrace, StartTraceW,
    WNODE_FLAG_TRACED_GUID,
};
use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
use windows::core::{GUID, PCWSTR, PWSTR};

/// Name of the classic kernel logger session. Windows allows exactly one, and
/// it must carry this exact name.
pub const KERNEL_LOGGER_NAME: &str = "NT Kernel Logger";

/// Slack reserved after the logger name and file path in the properties blob.
const NAME_PADDING: usize = 1024;

/// Buffer policy for one session.
#[derive(Debug, Clone, Copy)]
pub struct SessionConfig {
    /// Per-buffer size in KiB.
    pub buffer_kb: u32,
    /// Minimum number of buffers the session allocates up front.
    pub min_buffers: u32,
    /// Maximum number of buffers the session may grow to.
    pub max_buffers: u32,
}

impl SessionConfig {
    /// Low-latency policy for process lifecycle events.
    ///
    /// Small buffers are the point: a 256 KiB buffer delays delivery past the
    /// exit of a short-lived process, which is exactly the race that eats
    /// command lines.
    pub const PROCESS: Self = Self {
        buffer_kb: 256,
        min_buffers: 128,
        max_buffers: 256,
    };

    /// Burst-tolerant policy for file/registry/network traffic.
    pub const MAIN: Self = Self {
        buffer_kb: 256,
        min_buffers: 40,
        max_buffers: 160,
    };
}

/// One provider to enable, with the subscription the manifest requires.
#[derive(Debug, Clone, Copy)]
pub struct ProviderSpec {
    /// Provider name, for diagnostics only.
    pub name: &'static str,
    /// Provider GUID.
    pub guid: GUID,
    /// Maximum level (ETW levels are a ceiling).
    pub level: u8,
    /// Keyword mask.
    pub keywords: u64,
}

/// `Microsoft-Windows-Kernel-Process`: process starts/stops and image loads.
///
/// Measured on Windows 11 (see `docs/dev/etw-collector.md`): filtering this
/// provider by keyword — even by its own manifest keywords, `0x10 | 0x40` —
/// silently drops every `ProcessStart`/`ProcessStop`, while `ImageLoad` keeps
/// flowing. The subscription therefore leaves keyword filtering off and the
/// routing layer drops the verbose `ThreadStart`/`ImageLoad` ids it does not
/// need. Level must be `Verbose` for the same reason: at `Informational` the
/// process lifecycle events are not delivered at all.
pub const KERNEL_PROCESS: ProviderSpec = ProviderSpec {
    name: "Microsoft-Windows-Kernel-Process",
    guid: GUID::from_u128(0x22fb2cd6_0e7b_422b_a0c7_2fad1fd0e716),
    level: 5,
    keywords: 0,
};

/// `Microsoft-Windows-Kernel-Network`: TCP/UDP send, receive and connect.
pub const KERNEL_NETWORK: ProviderSpec = ProviderSpec {
    name: "Microsoft-Windows-Kernel-Network",
    guid: GUID::from_u128(0x7dd42a49_5329_4832_8dfd_43d979153a88),
    level: 4,
    // TCPIP (0x10) | UDP (0x20)
    keywords: 0x0010 | 0x0020,
};

/// `Microsoft-Windows-Kernel-File`: create/delete/rename, with `FileName`.
pub const KERNEL_FILE: ProviderSpec = ProviderSpec {
    name: "Microsoft-Windows-Kernel-File",
    guid: GUID::from_u128(0xedd08927_9cc4_4e65_b970_c2560fb5c289),
    level: 4,
    // NAME (0x10) | FILEIO (0x20) | CREATE (0x80) | WRITE (0x200)
    // | DELETE_PATH (0x400) | RENAME_SETLINK_PATH (0x800)
    keywords: 0x0010 | 0x0020 | 0x0080 | 0x0200 | 0x0400 | 0x0800,
};

/// `Microsoft-Windows-Kernel-Registry`: key/value operations.
///
/// The value writes are 0x100 (`SetValueKey`) and 0x200 (`DeleteValueKey`);
/// 0x2000 and 0x8000 are `OpenKey` and `QueryKey`, so a mask built from those
/// subscribes to reads and silently misses every write.
pub const KERNEL_REGISTRY: ProviderSpec = ProviderSpec {
    name: "Microsoft-Windows-Kernel-Registry",
    guid: GUID::from_u128(0x70eb4f03_c1de_4f73_a051_33d13d5413bd),
    level: 4,
    // CLOSE_KEY (0x1) | SET_VALUE_KEY (0x100) | DELETE_VALUE_KEY (0x200)
    // | CREATE_KEY (0x1000) | OPEN_KEY (0x2000) | DELETE_KEY (0x4000)
    keywords: 0x0001 | 0x0100 | 0x0200 | 0x1000 | 0x2000 | 0x4000,
};

/// `Microsoft-Windows-DNS-Client`: query and response pairs (Sysmon EID 22).
///
/// The useful events (3006 query, 3008 response) carry keyword `0`, so a
/// keyword-filtered subscription — including the Operational-channel mask,
/// which is what their *channel* is published under — never receives them.
/// The subscription therefore leaves keyword filtering off and the routing
/// layer drops the rest by event id.
pub const DNS_CLIENT: ProviderSpec = ProviderSpec {
    name: "Microsoft-Windows-DNS-Client",
    guid: GUID::from_u128(0x1c95126e_7eea_49a9_a3fe_a378b03ddb4d),
    level: 4,
    keywords: 0,
};

/// `Microsoft-Windows-WMI-Activity`: WMI provider operations and permanent
/// subscriptions (Sysmon EID 19/20/21).
pub const WMI_ACTIVITY: ProviderSpec = ProviderSpec {
    name: "Microsoft-Windows-WMI-Activity",
    guid: GUID::from_u128(0x1418_ef04_b0b4_4623_bf7e_d74a_b47b_bdaa),
    level: 4,
    // Operational channel: 5857-5861 carry the subscription traffic.
    keywords: 0x4000_0000_0000_0000,
};

/// Classic kernel logger flags used for command lines and SIDs.
pub const PROCESS_SESSION_PROVIDERS: &[ProviderSpec] = &[KERNEL_PROCESS];

/// Providers on the burst-tolerant main session.
pub const MAIN_SESSION_PROVIDERS: &[ProviderSpec] = &[
    KERNEL_NETWORK,
    KERNEL_FILE,
    KERNEL_REGISTRY,
    DNS_CLIENT,
    WMI_ACTIVITY,
    KERNEL_PROCESS_UNLOAD,
];

/// `Microsoft-Windows-Kernel-Process`, image unload only: the driver covers
/// loads (EID 6/7) but its notify routine never reports an unload, and
/// `ImageUnload` (event 6) is the only source for EID 507.
pub const KERNEL_PROCESS_UNLOAD: ProviderSpec = ProviderSpec {
    name: "Microsoft-Windows-Kernel-Process",
    guid: GUID::from_u128(0x22fb2cd6_0e7b_422b_a0c7_2fad1fd0e716),
    level: 4,
    // IMAGE (0x40) for the unloads, PROCESS (0x10) for the exits: an image
    // unloaded from a process that has *not* exited is process tampering, and
    // the exit is the only way to tell the two apart.
    keywords: 0x0040 | 0x0010,
};

/// Classic kernel logger flags used for command lines and SIDs.
///
/// `PROCESS` (0x1) is the only one needed: the manifest `Kernel-Process`
/// provider already carries the image path, integrity label and timestamps.
pub const KERNEL_LOGGER_FLAGS: EVENT_TRACE_FLAG = EVENT_TRACE_FLAG(0x0000_0001);

/// Fail unless the current process can start a trace session.
///
/// Trace sessions need an elevated token; the kernel providers additionally
/// need `SeSystemProfilePrivilege`, which an elevated administrator token
/// holds. A filtered (UAC) administrator token is rejected here before the
/// first `StartTraceW`, so the failure names the cause.
pub fn ensure_privileges() -> Result<()> {
    if is_elevated()? {
        return Ok(());
    }
    bail!(
        "ETW collection needs an elevated (administrator) token: \
         start sigmacatch from an elevated prompt, or disable UAC filtering \
         for the account that runs it"
    )
}

/// True when the process token is elevated (high integrity).
fn is_elevated() -> Result<bool> {
    unsafe {
        let mut token = HANDLE::default();
        // SAFETY: pseudo-handle for the current process; the token handle is
        // closed below.
        OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token)
            .context("OpenProcessToken")?;
        let mut elevation = TOKEN_ELEVATION::default();
        let mut returned = 0u32;
        let result = GetTokenInformation(
            token,
            TokenElevation,
            Some(ptr::addr_of_mut!(elevation).cast::<c_void>()),
            size_of::<TOKEN_ELEVATION>() as u32,
            &mut returned,
        );
        let _ = windows::Win32::Foundation::CloseHandle(token);
        result.context("GetTokenInformation(TokenElevation)")?;
        Ok(elevation.TokenIsElevated != 0)
    }
}

/// Counters reported by a live session.
#[derive(Debug, Clone, Copy, Default)]
pub struct SessionStats {
    /// Records the session could not buffer (the fidelity-relevant counter).
    pub events_lost: u32,
    /// Buffers handed to consumers so far.
    pub buffers_written: u32,
    /// Realtime buffers lost because no consumer kept up.
    pub realtime_buffers_lost: u32,
}

/// A realtime trace session, owned by this process.
pub struct TraceSession {
    /// Session name, kept alive because the properties blob points into it.
    name: Vec<u16>,
    /// `EVENT_TRACE_PROPERTIES` followed by the name, as UTF-16, in an 8-byte
    /// aligned allocation. `ControlTraceW` needs the same blob back.
    properties: Vec<u64>,
    handle: CONTROLTRACE_HANDLE,
}

impl TraceSession {
    /// Start a realtime user-mode (manifest provider) session.
    pub fn start(name: &str, config: SessionConfig) -> Result<Self> {
        Self::start_with(name, config, None, None)
    }

    /// Start the same session writing to an ETL file instead of realtime.
    ///
    /// Diagnostic only: file mode is the reference the realtime path is
    /// measured against (a `logman`-style capture of the same providers).
    pub fn start_file(name: &str, config: SessionConfig, path: &str) -> Result<Self> {
        Self::start_with(name, config, None, Some(path))
    }

    /// Start the classic kernel logger session.
    ///
    /// Unlike manifest providers, the kernel logger is subscribed through the
    /// `EnableFlags` mask in the properties, not `EnableTraceEx2`.
    pub fn start_kernel_logger(flags: EVENT_TRACE_FLAG, config: SessionConfig) -> Result<Self> {
        Self::start_with(KERNEL_LOGGER_NAME, config, Some(flags), None)
    }

    fn start_with(
        name: &str,
        config: SessionConfig,
        kernel_flags: Option<EVENT_TRACE_FLAG>,
        file_path: Option<&str>,
    ) -> Result<Self> {
        ensure_privileges()?;
        // A previous run that crashed leaves the session behind; reclaim it
        // instead of failing the whole collection.
        Self::stop_orphan(name);

        let name_wide: Vec<u16> = name.encode_utf16().chain(std::iter::once(0)).collect();
        let path_wide: Vec<u16> = file_path
            .unwrap_or_default()
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();
        let properties_size = size_of::<EVENT_TRACE_PROPERTIES>();
        // Windows is handed a buffer that must hold the header, the logger
        // name and the optional file path. Pad it like the reference
        // implementation does: a buffer that is exactly the string bytes
        // makes the session start but misbehave.
        let total = properties_size
            + name_wide.len() * size_of::<u16>()
            + path_wide.len() * size_of::<u16>()
            + NAME_PADDING;
        let mut properties = vec![0u64; total.div_ceil(size_of::<u64>())];
        let props = properties.as_mut_ptr().cast::<EVENT_TRACE_PROPERTIES>();

        unsafe {
            // SAFETY: the allocation is at least `total` bytes and 8-byte
            // aligned, so the header fits and the name can follow it.
            let header = &mut *props;
            header.Wnode.BufferSize = total as u32;
            header.Wnode.Flags = WNODE_FLAG_TRACED_GUID;
            // QPC timestamps (the reference implementation's choice); the
            // conversion to UTC happens in the decoder.
            header.Wnode.ClientContext = 1;
            header.BufferSize = config.buffer_kb;
            header.MinimumBuffers = config.min_buffers;
            header.MaximumBuffers = config.max_buffers;
            // Single global buffer stream instead of per-processor buffers:
            // event order is load-bearing (path pairing), and this is also
            // what the reference consumer uses.
            header.LogFileMode = match file_path {
                None => EVENT_TRACE_REAL_TIME_MODE | EVENT_TRACE_NO_PER_PROCESSOR_BUFFERING,
                Some(_) => 1, // EVENT_TRACE_FILE_MODE_SEQUENTIAL
            };
            // The classic kernel logger only delivers live events when the
            // session is flagged as a *system* logger; without this the
            // session starts and reports its own configuration, then goes
            // silent.
            if kernel_flags.is_some() {
                header.LogFileMode |= EVENT_TRACE_SYSTEM_LOGGER_MODE;
            }
            header.FlushTimer = 1;
            header.LoggerNameOffset = properties_size as u32;
            if let Some(flags) = kernel_flags {
                header.EnableFlags = flags;
            }
            ptr::copy_nonoverlapping(
                name_wide.as_ptr().cast::<u8>(),
                properties.as_mut_ptr().cast::<u8>().add(properties_size),
                name_wide.len() * size_of::<u16>(),
            );
            if file_path.is_some() {
                let offset = properties_size + name_wide.len() * size_of::<u16>();
                header.LogFileNameOffset = offset as u32;
                ptr::copy_nonoverlapping(
                    path_wide.as_ptr().cast::<u8>(),
                    properties.as_mut_ptr().cast::<u8>().add(offset),
                    path_wide.len() * size_of::<u16>(),
                );
            }
        }

        let mut handle = CONTROLTRACE_HANDLE::default();
        let status = unsafe {
            // SAFETY: properties blob and name are valid for the call.
            StartTraceW(&mut handle, PCWSTR(name_wide.as_ptr()), props)
        };
        if status != ERROR_SUCCESS {
            bail!(
                "StartTraceW({name}) failed: {}",
                std::io::Error::from_raw_os_error(status.0 as i32)
            );
        }

        Ok(Self {
            name: name_wide,
            properties,
            handle,
        })
    }

    /// Ask `Microsoft-Windows-Kernel-Registry` to fill `CapturedData`.
    ///
    /// Undocumented: the provider declares `CapturedData` on `SetValueKey` but
    /// delivers it empty unless the enablement carries an
    /// `EVENT_FILTER_DESCRIPTOR` whose four-byte payload has bit `0x2` set.
    /// Without it `Details` would have to be omitted, and the ~180 SigmaHQ
    /// rules that match on the value data would silently stop matching.
    ///
    /// The provider is re-enabled, which replaces the first enablement: level
    /// and keywords have to be passed again or the session widens.
    fn enable_value_data(&self, provider: &ProviderSpec) -> Result<()> {
        let capture: u32 = 0x2;
        let mut descriptors = [EVENT_FILTER_DESCRIPTOR {
            Ptr: std::ptr::addr_of!(capture) as u64,
            Size: std::mem::size_of::<u32>() as u32,
            Type: 0,
        }];
        let parameters = ENABLE_TRACE_PARAMETERS {
            Version: ENABLE_TRACE_PARAMETERS_VERSION_2,
            EnableProperty: 0,
            ControlFlags: 0,
            SourceId: GUID::zeroed(),
            EnableFilterDesc: descriptors.as_mut_ptr(),
            FilterDescCount: descriptors.len() as u32,
        };
        // SAFETY: the session handle is live, the descriptor and its payload
        // outlive the call, and `parameters` points at them.
        let status = unsafe {
            EnableTraceEx2(
                self.handle,
                &provider.guid,
                EVENT_CONTROL_CODE_ENABLE_PROVIDER.0,
                provider.level,
                provider.keywords,
                0,
                0,
                Some(&parameters),
            )
        };
        if status.is_err() {
            anyhow::bail!(
                "registry value data unavailable ({}): {status:?}",
                provider.name
            );
        }
        Ok(())
    }

    /// Subscribe a manifest provider to this session.
    pub fn enable_provider(&self, provider: &ProviderSpec) -> Result<()> {
        let status = unsafe {
            // SAFETY: the session handle is live and the GUID is a local.
            EnableTraceEx2(
                self.handle,
                &provider.guid,
                EVENT_CONTROL_CODE_ENABLE_PROVIDER.0,
                provider.level,
                provider.keywords,
                0,
                0,
                None,
            )
        };
        if status == ERROR_SUCCESS {
            if provider.name == KERNEL_REGISTRY.name
                && let Err(error) = self.enable_value_data(provider)
            {
                // Non-fatal by design: registry events still flow without
                // `Details`, which is better than losing the whole provider.
                tracing::warn!("{error:#}");
            }
            return Ok(());
        }
        // Kernel providers need a matching system-wide privilege; a failure
        // here is worth naming precisely, the rest of the session still runs.
        bail!(
            "EnableTraceEx2({}) failed: {}",
            provider.name,
            std::io::Error::from_raw_os_error(status.0 as i32)
        )
    }

    /// Stop and release the session. Idempotent enough: the OS ignores a stop
    /// on a session that already ended.
    pub fn stop(&self) {
        self.stop_inner();
    }

    /// Force the kernel to hand the current buffer to the consumer.
    ///
    /// A realtime session otherwise waits for the buffer to fill or for the
    /// one-second `FlushTimer`, which is past the lifetime of a short-lived
    /// process. Cheap enough to run every few milliseconds on the process
    /// session; returns `false` once the session is gone.
    pub fn flush(&self) -> bool {
        let props = self.properties.as_ptr().cast::<EVENT_TRACE_PROPERTIES>();
        // SAFETY: the blob is the one `StartTraceW` accepted; a flush only
        // reads it.
        let status = unsafe {
            windows::Win32::System::Diagnostics::Etw::ControlTraceW(
                self.handle,
                PCWSTR(self.name.as_ptr()),
                props.cast_mut(),
                windows::Win32::System::Diagnostics::Etw::EVENT_TRACE_CONTROL_FLUSH,
            )
        };
        status == ERROR_SUCCESS
    }

    /// Current session counters, queried from the OS.
    ///
    /// `events_lost` is the number that matters for the fidelity rule: a
    /// non-zero value means the session dropped records, so the regression
    /// data generated from that run cannot be trusted.
    pub fn stats(&self) -> Option<SessionStats> {
        let props = self.properties.as_ptr().cast::<EVENT_TRACE_PROPERTIES>();
        // SAFETY: the blob is the one `StartTraceW` accepted; a query only
        // writes counters into it.
        let status = unsafe {
            windows::Win32::System::Diagnostics::Etw::ControlTraceW(
                self.handle,
                PCWSTR(self.name.as_ptr()),
                props.cast_mut(),
                windows::Win32::System::Diagnostics::Etw::EVENT_TRACE_CONTROL_QUERY,
            )
        };
        if status != ERROR_SUCCESS {
            return None;
        }
        // SAFETY: the query filled the header in place.
        let props = unsafe { &*props };
        Some(SessionStats {
            events_lost: props.EventsLost,
            buffers_written: props.BuffersWritten,
            realtime_buffers_lost: props.RealTimeBuffersLost,
        })
    }

    fn stop_inner(&self) {
        // The blob is only written by the kernel; a shared reference is fine.
        let props = self
            .properties
            .as_ptr()
            .cast_mut()
            .cast::<EVENT_TRACE_PROPERTIES>();
        // SAFETY: blob shape is the one `StartTraceW` accepted.
        unsafe {
            let _ = windows::Win32::System::Diagnostics::Etw::ControlTraceW(
                self.handle,
                PCWSTR(self.name.as_ptr()),
                props,
                EVENT_TRACE_CONTROL_STOP,
            );
        }
    }

    /// Stop a same-named session left behind by a previous process.
    fn stop_orphan(name: &str) {
        let mut wide: Vec<u16> = name.encode_utf16().chain(std::iter::once(0)).collect();
        let properties_size = size_of::<EVENT_TRACE_PROPERTIES>();
        let total = properties_size + wide.len() * size_of::<u16>();
        let mut properties = vec![0u64; total.div_ceil(size_of::<u64>())];
        // SAFETY: `properties` is a zeroed, 8-byte-aligned allocation of at least
        // `total` bytes; the header and the name are written inside it below.
        unsafe {
            let header = properties.as_mut_ptr().cast::<EVENT_TRACE_PROPERTIES>();
            (*header).Wnode.BufferSize = total as u32;
            (*header).LoggerNameOffset = properties_size as u32;
            ptr::copy_nonoverlapping(
                wide.as_ptr().cast::<u8>(),
                properties.as_mut_ptr().cast::<u8>().add(properties_size),
                wide.len() * size_of::<u16>(),
            );
            let _ = windows::Win32::System::Diagnostics::Etw::ControlTraceW(
                CONTROLTRACE_HANDLE::default(),
                PCWSTR(wide.as_mut_ptr()),
                header,
                EVENT_TRACE_CONTROL_STOP,
            );
        }
    }
}

/// Sink invoked for every record, inside the consumer thread.
pub type Sink = Box<dyn Fn(&EVENT_RECORD) + Send + Sync + 'static>;

/// A realtime consumer for one session.
///
/// `ProcessTrace` blocks until the session stops; run it on a dedicated OS
/// thread (see [`Consumer::process`]).
pub struct Consumer {
    /// Session name, pointed at by `logfile.LoggerName`. Kept alive for the
    /// lifetime of the consumer, never read.
    #[allow(dead_code)]
    name: Vec<u16>,
    /// Owned by the consumer because `ProcessTrace` dereferences it for as
    /// long as it runs (callback pointer, logger name).
    #[allow(dead_code)]
    logfile: Box<EVENT_TRACE_LOGFILEW>,
    /// Owned sink; the logfile holds a raw copy of this pointer as `Context`,
    /// which the kernel copies into every `EVENT_RECORD.UserContext`.
    sink: *mut Sink,
    handle: PROCESSTRACE_HANDLE,
}

// SAFETY: the sink is `Send + Sync`, and the raw pointers are not shared
// across threads: `Consumer` is created and moved to exactly one consumer
// thread before `process` is called.
unsafe impl Send for Consumer {}

impl Consumer {
    /// Attach a realtime consumer to an already-started session.
    pub fn open(session_name: &str, sink: Sink) -> Result<Self> {
        let name: Vec<u16> = session_name
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();
        let mut logfile = Box::new(EVENT_TRACE_LOGFILEW::default());
        logfile.LoggerName = PWSTR(name.as_ptr() as *mut u16);
        logfile.Anonymous1.ProcessTraceMode =
            PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD;
        logfile.Anonymous2.EventRecordCallback = Some(on_event);

        let sink = Box::into_raw(Box::new(sink));
        logfile.Context = sink.cast::<c_void>();

        let handle = unsafe {
            // SAFETY: logfile is fully initialised and outlives the handle
            // (it is owned by `self`).
            OpenTraceW(&mut *logfile)
        };
        if handle.Value == u64::MAX {
            // Reclaim the sink; the consumer was never created.
            // SAFETY: `sink` came from `Box::into_raw` above and ownership was
            // not transferred, because `OpenTraceW` failed.
            unsafe { drop(Box::from_raw(sink)) };
            bail!(
                "OpenTraceW({session_name}) failed: {}",
                std::io::Error::last_os_error()
            );
        }

        Ok(Self {
            name,
            logfile,
            sink,
            handle,
        })
    }

    /// Blocking consume loop. Returns the `ProcessTrace` status; `ERROR_CANCELLED`
    /// (or a torn-down session) is the normal shutdown result.
    pub fn process(&self) -> WIN32_ERROR {
        // SAFETY: handle came from `OpenTraceW` on this consumer.
        unsafe { ProcessTrace(&[self.handle], None, None) }
    }
}

impl Drop for Consumer {
    fn drop(&mut self) {
        // SAFETY: the handle came from `OpenTraceW` and is closed exactly once;
        // this also stops the callback before the sink is freed.
        unsafe {
            let _ = windows::Win32::System::Diagnostics::Etw::CloseTrace(self.handle);
        }
        // SAFETY: `sink` was created by `Box::into_raw` in `open` and is
        // released exactly once here.
        unsafe { drop(Box::from_raw(self.sink)) };
    }
}

/// Record callback: hands the record to the sink stored in its `UserContext`.
unsafe extern "system" fn on_event(record: *mut EVENT_RECORD) {
    // SAFETY: the callback only runs while a session with this sink is open,
    // and `EVENT_RECORD.UserContext` is the `Context` set on the logfile.
    let Some(record) = (unsafe { record.as_ref() }) else {
        return;
    };
    let sink = record.UserContext.cast::<Sink>();
    if sink.is_null() {
        return;
    }
    // SAFETY: pointer was produced by `Box::into_raw` in `open`.
    let sink = unsafe { &*sink };
    // A panic must never cross the FFI boundary: it would abort the process
    // and lose the whole capture. One malformed record is dropped instead.
    let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| sink(record)));
}

/// Convenience wrapper: start and consume one session on a background thread.
///
/// Stops the session when the returned guard is dropped, which unblocks
/// `ProcessTrace`.
pub struct RunningSession {
    session: Option<Arc<TraceSession>>,
    thread: Option<std::thread::JoinHandle<(u32, std::time::Duration)>>,
    flusher: Option<std::thread::JoinHandle<()>>,
    flush_stop: Arc<AtomicBool>,
}

impl RunningSession {
    /// Start `session`, enable `providers`, open a consumer and spawn the
    /// blocking `ProcessTrace` loop.
    pub fn spawn(
        session: TraceSession,
        name: &str,
        providers: &[ProviderSpec],
        sink: Sink,
    ) -> Result<Self> {
        Self::spawn_with_flush(session, name, providers, sink, None)
    }

    /// Same as [`spawn`](Self::spawn), with a periodic forced flush.
    ///
    /// `EVENT_TRACE_CONTROL_FLUSH` is what makes a short-lived process's
    /// records reach the consumer before the process exits; without it the
    /// session falls back to the one-second flush timer.
    pub fn spawn_with_flush(
        session: TraceSession,
        name: &str,
        providers: &[ProviderSpec],
        sink: Sink,
        flush_interval: Option<std::time::Duration>,
    ) -> Result<Self> {
        for provider in providers {
            session.enable_provider(provider)?;
        }
        let consumer = Consumer::open(name, sink)?;
        let thread = std::thread::Builder::new()
            .name(format!("etw-{name}"))
            .spawn(move || {
                let started = std::time::Instant::now();
                let status = consumer.process().0;
                (status, started.elapsed())
            })
            .context("spawn ETW consumer thread")?;

        let session = Arc::new(session);
        let flush_stop = Arc::new(AtomicBool::new(false));
        let flusher = match flush_interval {
            None => None,
            Some(interval) => {
                let session = Arc::clone(&session);
                let stop = Arc::clone(&flush_stop);
                Some(
                    std::thread::Builder::new()
                        .name(format!("etw-flush-{name}"))
                        .spawn(move || {
                            while !stop.load(Ordering::Relaxed) {
                                if !session.flush() {
                                    break;
                                }
                                std::thread::sleep(interval);
                            }
                        })
                        .context("spawn ETW flush thread")?,
                )
            }
        };

        Ok(Self {
            session: Some(session),
            thread: Some(thread),
            flusher,
            flush_stop,
        })
    }

    /// Live counters for the underlying session, when still running.
    pub fn stats(&self) -> Option<SessionStats> {
        self.session.as_ref().and_then(|s| s.stats())
    }

    /// Stop the session and wait for the consumer loop to return.
    ///
    /// Returns the `ProcessTrace` status and how long the loop actually ran:
    /// a duration far below the capture window means the consumer detached
    /// early, which is what makes events "disappear" without any loss counter.
    pub fn stop(mut self) -> (u32, std::time::Duration) {
        self.flush_stop.store(true, Ordering::Relaxed);
        if let Some(flusher) = self.flusher.take() {
            let _ = flusher.join();
        }
        if let Some(session) = self.session.take() {
            session.stop();
        }
        match self.thread.take() {
            Some(thread) => thread
                .join()
                .unwrap_or((u32::MAX, std::time::Duration::ZERO)),
            None => (ERROR_SUCCESS.0, std::time::Duration::ZERO),
        }
    }
}

impl Drop for RunningSession {
    fn drop(&mut self) {
        self.flush_stop.store(true, Ordering::Relaxed);
        if let Some(flusher) = self.flusher.take() {
            let _ = flusher.join();
        }
        if let Some(session) = self.session.take() {
            session.stop();
        }
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

// ---------------------------------------------------------------------------
// Main-session routing: the Sysmon events user-mode ETW can produce
// ---------------------------------------------------------------------------

/// Provider name `decode` reports for the kernel network provider.
const KERNEL_NETWORK_NAME: &str = "Microsoft-Windows-Kernel-Network";
/// Provider name `decode` reports for the DNS client provider.
const DNS_CLIENT_NAME: &str = "Microsoft-Windows-DNS-Client";
/// Provider name `decode` reports for the kernel registry provider.
const KERNEL_REGISTRY_NAME: &str = "Microsoft-Windows-Kernel-Registry";
/// Provider name `decode` reports for the WMI activity provider.
const WMI_ACTIVITY_NAME: &str = "Microsoft-Windows-WMI-Activity";
/// `WmiProviderOperation`: carries the `Operation` string of a WMI call.
const WMI_PROVIDER_OPERATION: u16 = 5858;
/// Provider name `decode` reports for the kernel process provider.
const KERNEL_PROCESS_NAME: &str = "Microsoft-Windows-Kernel-Process";
/// `ImageUnload`: an image was unmapped from a process (EID 507).
const IMAGE_UNLOAD: u16 = 6;
/// `ProcessStop`: the process is exiting — its images unload next.
const PROCESS_STOP: u16 = 2;
/// Upper bound on the set of processes known to have exited.
const EXITED_LIMIT: usize = 4096;
// `Kernel-Registry` ids the router accepts (see `sigmacatch_input_etw_common::etw_registry`).
const CREATE_KEY_ID: u16 = 1;
const OPEN_KEY_ID: u16 = 2;
const DELETE_KEY_ID: u16 = 3;
const SET_VALUE_ID: u16 = 5;
const DELETE_VALUE_ID: u16 = 6;
const CLOSE_KEY_ID: u16 = 13;

// `Microsoft-Windows-Kernel-Network` event ids. The provider publishes one id
// per operation and its opcode repeats the id; these four were measured with
// `etw_dump` on the test VM (a TCP connect to :80, a UDP DNS query, and the
// matching reply).
/// `TcpIp` connection attempt — Sysmon EID 3.
const NET_TCP_CONNECT: u16 = 12;
/// `TcpIp` accept — a listening socket became a connection (EID 500).
const NET_TCP_ACCEPT: u16 = 15;
/// `UdpIp` datagram sent — Sysmon EID 3 with `Protocol=udp`.
const NET_UDP_SEND: u16 = 42;

/// `Microsoft-Windows-DNS-Client` completion event: carries `QueryResults`
/// and `QueryStatus` for the process that asked.
const DNS_QUERY_COMPLETED: u16 = 3008;

/// Upper bound on the pid/IP → hostname cache; the map is cleared when it is
/// reached rather than growing without bound in a long capture.
const DNS_CACHE_LIMIT: usize = 4096;

/// Turns main-session ETW records into Sysmon-schema events.
///
/// Only the events the driver cannot produce are routed here: network
/// connections (EID 3), listening sockets (EID 500) and DNS queries (EID 22).
/// Everything else the main session carries (Kernel-File, Kernel-Registry) is
/// either covered by the driver or not mapped yet.
pub struct MainRouter {
    computer: String,
    tracker:
        std::sync::Arc<std::sync::Mutex<sigmacatch_input_etw_common::etw_process::ProcessTracker>>,
    /// `(pid, ip)` → queried name, filled from the DNS answers.
    dns: std::sync::Mutex<std::collections::HashMap<(u32, String), String>>,
    /// Key-handle → path cache for the registry events.
    registry: std::sync::Mutex<sigmacatch_input_etw_common::etw_registry::RegistryMapper>,
    /// Image paths the kernel sensor published at process start.
    images: sigmacatch_input_etw_common::etw_process::ImageCache,
    /// Processes the same session saw exiting: their image unloads are
    /// teardown, not tampering.
    exited: std::sync::Mutex<std::collections::HashSet<u32>>,
}

impl MainRouter {
    /// Create a router reporting for `computer`, resolving `Image` through
    /// `tracker`.
    pub fn new(
        computer: String,
        tracker: std::sync::Arc<
            std::sync::Mutex<sigmacatch_input_etw_common::etw_process::ProcessTracker>,
        >,
        images: sigmacatch_input_etw_common::etw_process::ImageCache,
    ) -> Self {
        Self {
            computer,
            tracker,
            dns: std::sync::Mutex::new(std::collections::HashMap::new()),
            registry: std::sync::Mutex::new(
                sigmacatch_input_etw_common::etw_registry::RegistryMapper::new(),
            ),
            images,
            exited: std::sync::Mutex::new(std::collections::HashSet::new()),
        }
    }

    /// True when this record is one the router maps.
    ///
    /// Checked before decoding: the main session is subscribed to dense
    /// providers (Kernel-File, ImageLoad) whose records are dropped, and a TDH
    /// decode per dropped record is a measurable cost.
    fn wants(record: &EVENT_RECORD) -> bool {
        let id = record.EventHeader.EventDescriptor.Id;
        let provider = record.EventHeader.ProviderId;
        let has = |spec: &ProviderSpec, ids: &[u16]| provider == spec.guid && ids.contains(&id);
        has(
            &KERNEL_NETWORK,
            &[NET_TCP_CONNECT, NET_TCP_ACCEPT, NET_UDP_SEND],
        ) || has(&DNS_CLIENT, &[DNS_QUERY_COMPLETED])
            || has(
                &KERNEL_REGISTRY,
                &[
                    CREATE_KEY_ID,
                    OPEN_KEY_ID,
                    DELETE_KEY_ID,
                    SET_VALUE_ID,
                    DELETE_VALUE_ID,
                    CLOSE_KEY_ID,
                ],
            )
            || has(&WMI_ACTIVITY, &[WMI_PROVIDER_OPERATION])
            || has(&KERNEL_PROCESS_UNLOAD, &[IMAGE_UNLOAD, PROCESS_STOP])
    }

    /// Map one record into zero, one or two events.
    ///
    /// Unknown providers and ids are dropped silently: the main session is
    /// deliberately subscribed to more than it maps. The vector is a `Vec`
    /// because one record can produce a pair — an image unloaded from a live
    /// process is both a module unload (EID 507) and process tampering
    /// (EID 25).
    pub fn map(&self, record: &EVENT_RECORD) -> Vec<sigmacatch_core::types::Event> {
        if !Self::wants(record) {
            return Vec::new();
        }
        let Some(decoded) = sigmacatch_input_etw_common::etw_event::decode(record) else {
            return Vec::new();
        };
        let at = decoded.utc().unwrap_or_else(chrono::Utc::now);
        self.decoded(&decoded, at)
    }

    /// Wrap the single-event mappers for the `Vec`-returning dispatcher.
    fn one(event: Option<sigmacatch_core::types::Event>) -> Vec<sigmacatch_core::types::Event> {
        event.into_iter().collect()
    }

    /// Dispatch one decoded record.
    fn decoded(
        &self,
        decoded: &sigmacatch_input_etw_common::etw_event::DecodedEvent,
        at: chrono::DateTime<chrono::Utc>,
    ) -> Vec<sigmacatch_core::types::Event> {
        match (decoded.provider.as_str(), decoded.event_id) {
            (KERNEL_NETWORK_NAME, NET_TCP_CONNECT) => {
                Self::one(self.connection(decoded, at, "tcp", true))
            }
            (KERNEL_NETWORK_NAME, NET_UDP_SEND) => {
                Self::one(self.connection(decoded, at, "udp", true))
            }
            (KERNEL_NETWORK_NAME, NET_TCP_ACCEPT) => Self::one(self.listen(decoded, at)),
            (DNS_CLIENT_NAME, DNS_QUERY_COMPLETED) => Self::one(self.dns(decoded, at)),
            (KERNEL_REGISTRY_NAME, _) => Self::one(self.registry_event(decoded, at)),
            (WMI_ACTIVITY_NAME, WMI_PROVIDER_OPERATION) => Self::one(self.wmi(decoded, at)),
            (KERNEL_PROCESS_NAME, PROCESS_STOP) => {
                let mut exited = self
                    .exited
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                if exited.len() >= EXITED_LIMIT {
                    exited.clear();
                }
                exited.insert(decoded.process_id);
                Vec::new()
            }
            (KERNEL_PROCESS_NAME, IMAGE_UNLOAD) => self.module_unload(decoded, at),
            _ => Vec::new(),
        }
    }

    /// Map a record and send every resulting event on the producer channel.
    fn route(
        &self,
        record: &EVENT_RECORD,
        tx: &tokio::sync::mpsc::Sender<sigmacatch_core::types::Event>,
    ) {
        for event in self.map(record) {
            let _ = tx.blocking_send(event);
        }
    }

    /// Token user of a pid: the tracker's facts, then the live process.
    fn user_of(&self, pid: u32) -> Option<String> {
        let cached = self
            .tracker
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(pid)
            .and_then(|facts| facts.user.clone());
        cached.or_else(|| {
            sigmacatch_input_etw_common::etw_process::enrich(pid).and_then(|facts| facts.user)
        })
    }

    /// Image path for a pid.
    ///
    /// The kernel sensor's map wins: it learned the path at process start, so
    /// it still answers for a process that has already exited. Otherwise the
    /// live process is enriched once and the answer published to the cache.
    fn image_of(&self, pid: u32) -> Option<String> {
        if let Some(image) = self.images.get(pid) {
            return Some(image);
        }
        let image = self
            .tracker
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .image_of(pid)?;
        self.images.insert(pid, &image);
        Some(image)
    }

    /// `Microsoft-Windows-Kernel-Network` connect/send → EID 3.
    fn connection(
        &self,
        decoded: &sigmacatch_input_etw_common::etw_event::DecodedEvent,
        at: chrono::DateTime<chrono::Utc>,
        protocol: &str,
        initiated: bool,
    ) -> Option<sigmacatch_core::types::Event> {
        let pid = decoded.uint("PID")? as u32;
        // Every field has to come from the provider: an invented address would
        // poison the committed regression data.
        let (source_ip, destination_ip) = (decoded.ip("saddr")?, decoded.ip("daddr")?);
        let (source_port, destination_port) = (decoded.uint("sport")?, decoded.uint("dport")?);
        let image = self.image_of(pid);
        let user = self.user_of(pid);
        let hostname = self.lookup_hostname(pid, destination_ip);
        let fields = sigmacatch_input_etw_common::etw_sysmon::NetworkFields {
            protocol,
            initiated,
            source_ip,
            source_port: source_port as u16,
            destination_ip,
            destination_port: destination_port as u16,
            destination_hostname: hostname.as_deref(),
            user: user.as_deref(),
        };
        let xml = sigmacatch_input_etw_common::etw_sysmon::network_xml(
            &self.computer,
            3,
            at,
            pid,
            image.as_deref(),
            &fields,
        );
        sigmacatch_core::types::Event::from_xml_injected(&xml, "windows", Some("sysmon")).ok()
    }

    /// `Microsoft-Windows-Kernel-Network` accept → EID 500 (`network_listen`).
    fn listen(
        &self,
        decoded: &sigmacatch_input_etw_common::etw_event::DecodedEvent,
        at: chrono::DateTime<chrono::Utc>,
    ) -> Option<sigmacatch_core::types::Event> {
        let pid = decoded.uint("PID")? as u32;
        let (source_ip, source_port) = (decoded.ip("saddr")?, decoded.uint("sport")?);
        let image = self.image_of(pid);
        let user = self.user_of(pid);
        let zero = if source_ip.contains(':') {
            "::"
        } else {
            "0.0.0.0"
        };
        let fields = sigmacatch_input_etw_common::etw_sysmon::NetworkFields {
            protocol: "tcp",
            initiated: false,
            source_ip,
            source_port: source_port as u16,
            destination_ip: zero,
            destination_port: 0,
            destination_hostname: None,
            user: user.as_deref(),
        };
        let xml = sigmacatch_input_etw_common::etw_sysmon::network_xml(
            &self.computer,
            500,
            at,
            pid,
            image.as_deref(),
            &fields,
        );
        sigmacatch_core::types::Event::from_xml_injected(&xml, "windows", Some("sysmon")).ok()
    }

    /// `Microsoft-Windows-DNS-Client` 3008 → EID 22, and feed the hostname
    /// cache the network events consult.
    fn dns(
        &self,
        decoded: &sigmacatch_input_etw_common::etw_event::DecodedEvent,
        at: chrono::DateTime<chrono::Utc>,
    ) -> Option<sigmacatch_core::types::Event> {
        let pid = decoded.process_id;
        let query_name = decoded.str("QueryName")?;
        if query_name.is_empty() {
            return None;
        }
        let status = decoded.uint("QueryStatus").unwrap_or(0).to_string();
        let results = decoded.str("QueryResults").unwrap_or("-");
        self.remember_hostnames(pid, query_name, results);

        let image = self.image_of(pid);
        let xml = sigmacatch_input_etw_common::etw_sysmon::event_xml(
            &self.computer,
            22,
            at,
            pid,
            image.as_deref(),
            &[
                ("QueryName", query_name),
                ("QueryStatus", &status),
                ("QueryResults", results),
            ],
        );
        sigmacatch_core::types::Event::from_xml_injected(&xml, "windows", Some("sysmon")).ok()
    }

    /// `Microsoft-Windows-Kernel-Registry` → EID 12/13/14.
    fn registry_event(
        &self,
        decoded: &sigmacatch_input_etw_common::etw_event::DecodedEvent,
        at: chrono::DateTime<chrono::Utc>,
    ) -> Option<sigmacatch_core::types::Event> {
        let event = self
            .registry
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .observe(decoded)?;
        let pid = decoded.process_id;
        let image = self.image_of(pid);
        let mut fields: Vec<(&str, &str)> = vec![
            ("EventType", event.event_type),
            ("TargetObject", &event.target_object),
        ];
        if let Some(details) = event.details.as_deref() {
            fields.push(("Details", details));
        }
        let xml = sigmacatch_input_etw_common::etw_sysmon::event_xml(
            &self.computer,
            event.event_id,
            at,
            pid,
            image.as_deref(),
            &fields,
        );
        sigmacatch_core::types::Event::from_xml_injected(&xml, "windows", Some("sysmon")).ok()
    }

    /// `Microsoft-Windows-WMI-Activity` 5858 → EID 19/20/21.
    fn wmi(
        &self,
        decoded: &sigmacatch_input_etw_common::etw_event::DecodedEvent,
        at: chrono::DateTime<chrono::Utc>,
    ) -> Option<sigmacatch_core::types::Event> {
        let parsed =
            sigmacatch_input_etw_common::wmi_format::parse_operation(decoded.str("Operation")?)?;
        let (event_id, event_type) = parsed.classification()?;
        let pid = decoded.uint("ClientProcessId").unwrap_or(0) as u32;
        let image = self.image_of(pid);
        let mut fields: Vec<(&str, &str)> = vec![
            ("EventType", event_type),
            ("Operation", &parsed.method),
            ("EventNamespace", &parsed.namespace),
        ];
        // Sysmon keys a binding on the two objects it links, spelled the way
        // the WMI object path spells them.
        let (consumer, filter) =
            sigmacatch_input_etw_common::wmi_format::binding_parts(&parsed.target);
        if event_id == 21 {
            if let Some(consumer) = consumer.as_deref() {
                fields.push(("Consumer", consumer));
            }
            if let Some(filter) = filter.as_deref() {
                fields.push(("Filter", filter));
            }
        } else if let Some(name) = parsed.name.as_deref() {
            fields.push(("Name", name));
        }
        if let Some(user) = decoded.str("User") {
            fields.push(("User", user));
        }
        let xml = sigmacatch_input_etw_common::etw_sysmon::event_xml(
            &self.computer,
            event_id,
            at,
            pid,
            image.as_deref(),
            &fields,
        );
        sigmacatch_core::types::Event::from_xml_injected(&xml, "windows", Some("sysmon")).ok()
    }

    /// `Kernel-Process` `ImageUnload` → EID 507 (`module_unload` extension),
    /// and EID 25 when the image is the process's own while it is still alive.
    fn module_unload(
        &self,
        decoded: &sigmacatch_input_etw_common::etw_event::DecodedEvent,
        at: chrono::DateTime<chrono::Utc>,
    ) -> Vec<sigmacatch_core::types::Event> {
        let Some(module) = decoded.str("ImageName") else {
            return Vec::new();
        };
        if module.is_empty() {
            return Vec::new();
        }
        let pid = decoded
            .uint("ProcessID")
            .map_or(decoded.process_id, |pid| pid as u32);
        // A kernel image unloads with no process behind it: this is the
        // driver-unload extension, not a module unload (Sysmon has no id for
        // it either).
        if pid == 0 {
            let xml = sigmacatch_input_etw_common::etw_sysmon::event_xml(
                &self.computer,
                511,
                at,
                0,
                None,
                &[("ModuleName", module)],
            );
            return sigmacatch_core::types::Event::from_xml_injected(
                &xml,
                "windows",
                Some("sysmon"),
            )
            .ok()
            .into_iter()
            .collect();
        }
        let image = self.image_of(pid);
        // Process tampering: the image a process was started from is unmapped
        // while the process keeps running (hollowing). A process that is
        // exiting unmaps its images too, which is why the exits are tracked.
        // Two independent filters, because ETW ordering is not a guarantee:
        // the exit record may arrive after the unloads it explains, so the
        // process is also asked whether it is still running.
        let not_exited = !self
            .exited
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .contains(&pid);
        let tampering = not_exited
            && sigmacatch_input_etw_common::etw_process::is_running(pid)
            && image
                .as_deref()
                .map(|image| image.strip_prefix(r"\??\").unwrap_or(image))
                .is_some_and(|image| {
                    sigmacatch_input_etw_common::nt_file::same_file(module, image)
                });
        let mut events = Vec::new();
        if tampering {
            let xml = sigmacatch_input_etw_common::etw_sysmon::event_xml(
                &self.computer,
                25,
                at,
                pid,
                image.as_deref(),
                &[("Type", "ImageUnloaded")],
            );
            if let Ok(event) =
                sigmacatch_core::types::Event::from_xml_injected(&xml, "windows", Some("sysmon"))
            {
                events.push(event);
            }
        }
        let xml = sigmacatch_input_etw_common::etw_sysmon::event_xml(
            &self.computer,
            507,
            at,
            pid,
            image.as_deref(),
            &[("ModuleName", module)],
        );
        if let Ok(event) =
            sigmacatch_core::types::Event::from_xml_injected(&xml, "windows", Some("sysmon"))
        {
            events.push(event);
        }
        events
    }

    /// Record `name` for every address in a `QueryResults` answer list.
    fn remember_hostnames(&self, pid: u32, name: &str, results: &str) {
        let mut cache = self
            .dns
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if cache.len() >= DNS_CACHE_LIMIT {
            cache.clear();
        }
        for entry in results.split(';') {
            let address = entry.trim();
            if address.is_empty() {
                continue;
            }
            // Answers are IPv4-mapped; Sysmon reports the plain address.
            let address = address.strip_prefix("::ffff:").unwrap_or(address);
            cache.insert((pid, address.to_string()), name.to_string());
        }
    }

    /// Name last resolved by `pid` for `address`, if any.
    fn lookup_hostname(&self, pid: u32, address: &str) -> Option<String> {
        self.dns
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(&(pid, address.to_string()))
            .cloned()
    }
}

// ---------------------------------------------------------------------------
// Async producer: the ETW path as an `EventProducer`.
// ---------------------------------------------------------------------------

/// Name of the process-latency session.
const PROCESS_SESSION_NAME: &str = "sigmacatch-process";
/// Name of the burst-tolerant session.
const MAIN_SESSION_NAME: &str = "sigmacatch-main";
/// Process-table poll interval, in milliseconds.
const POLL_INTERVAL_MS: u64 = 50;

/// Async producer running the ETW sessions.
///
/// [`new`](Self::new) owns both the process source (EID 1) and the main
/// session; the kernel sensor supersedes the former, while
/// [`main_only`](Self::main_only) keeps the network/DNS events flowing next
/// to it. See the `windows` orchestrator in `sigmacatch`.
pub struct EventCollector {
    /// Whether this instance also runs the process session (the fallback when
    /// the kernel sensor is absent).
    process: bool,
    /// Image paths shared with the kernel sensor.
    images: sigmacatch_input_etw_common::etw_process::ImageCache,
}

impl EventCollector {
    /// Create the producer that owns both sessions.
    pub fn new(images: sigmacatch_input_etw_common::etw_process::ImageCache) -> Self {
        Self {
            process: true,
            images,
        }
    }

    /// Create the producer for the main session only.
    ///
    /// The driver owns process telemetry when it is loaded, so starting the
    /// process session too would report every process twice.
    pub fn main_only(images: sigmacatch_input_etw_common::etw_process::ImageCache) -> Self {
        Self {
            process: false,
            images,
        }
    }
}

impl Default for EventCollector {
    fn default() -> Self {
        Self::new(sigmacatch_input_etw_common::etw_process::ImageCache::new())
    }
}

/// Enrich `pid` and, when it is a process created during the capture, send
/// its EID 1 event.
fn emit_process(
    tracker: &std::sync::Mutex<sigmacatch_input_etw_common::etw_process::ProcessTracker>,
    computer: &str,
    tx: &tokio::sync::mpsc::Sender<sigmacatch_core::types::Event>,
    pid: u32,
) {
    let observed = tracker
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .observe(pid);
    let Some((mut facts, parent)) = observed else {
        return;
    };
    if let Some(image) = facts.image.as_deref() {
        facts.hashes = sigmacatch_input_etw_common::nt_file::hashes_of(image);
    }
    let xml = sigmacatch_input_etw_common::etw_sysmon::process_start_xml(
        computer,
        &facts,
        parent.as_ref(),
    );
    if let Ok(event) =
        sigmacatch_core::types::Event::from_xml_injected(&xml, "windows", Some("sysmon"))
    {
        let _ = tx.blocking_send(event);
    }
}

#[async_trait::async_trait]
impl sigmacatch_core::types::EventProducer for EventCollector {
    async fn run(
        self: Box<Self>,
        tx: tokio::sync::mpsc::Sender<sigmacatch_core::types::Event>,
        mut stop: tokio::sync::watch::Receiver<bool>,
    ) -> Result<(), sigmacatch_core::types::ProducerError> {
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::sync::{Arc, Mutex};

        use sigmacatch_input_etw_common::etw_process::ProcessTracker;

        let tracker = Arc::new(Mutex::new(ProcessTracker::new()));
        let computer = std::env::var("COMPUTERNAME").unwrap_or_default();
        let halt = Arc::new(AtomicBool::new(false));

        let router = std::sync::Arc::new(MainRouter::new(
            computer.clone(),
            Arc::clone(&tracker),
            self.images.clone(),
        ));

        let sink: Sink = {
            let tx = tx.clone();
            let tracker = Arc::clone(&tracker);
            let computer = computer.clone();
            let halt = Arc::clone(&halt);
            Box::new(move |record: &EVENT_RECORD| {
                if halt.load(Ordering::Relaxed) {
                    return;
                }
                emit_process(&tracker, &computer, &tx, record.EventHeader.ProcessId);
            })
        };

        let running = if self.process {
            let process = TraceSession::start(PROCESS_SESSION_NAME, SessionConfig::PROCESS)
                .map_err(|e| {
                    sigmacatch_core::types::ProducerError::Message(format!(
                        "ETW process session: {e:#}"
                    ))
                })?;
            Some(
                RunningSession::spawn_with_flush(
                    process,
                    PROCESS_SESSION_NAME,
                    PROCESS_SESSION_PROVIDERS,
                    sink,
                    Some(std::time::Duration::from_millis(5)),
                )
                .map_err(|e| {
                    sigmacatch_core::types::ProducerError::Message(format!(
                        "ETW process consumer: {e:#}"
                    ))
                })?,
            )
        } else {
            None
        };

        // The main session routes the Sysmon events user-mode ETW can produce
        // (network, DNS) and is optional: a failure there must not kill the
        // process path.
        let main = {
            let router = std::sync::Arc::clone(&router);
            let tx = tx.clone();
            let halt = std::sync::Arc::clone(&halt);
            match TraceSession::start(MAIN_SESSION_NAME, SessionConfig::MAIN) {
                Ok(session) => RunningSession::spawn_with_flush(
                    session,
                    MAIN_SESSION_NAME,
                    MAIN_SESSION_PROVIDERS,
                    Box::new(move |record: &EVENT_RECORD| {
                        if halt.load(Ordering::Relaxed) {
                            return;
                        }
                        router.route(record, &tx);
                    }),
                    Some(std::time::Duration::from_millis(20)),
                )
                .ok(),
                Err(error) => {
                    tracing::warn!("ETW main session unavailable: {error:#}");
                    None
                }
            }
        };

        // The poller catches processes whose events the session never
        // delivered (short-lived ones on this platform).
        let poller = if self.process {
            let tracker = Arc::clone(&tracker);
            let computer = computer.clone();
            let tx = tx.clone();
            let halt = Arc::clone(&halt);
            std::thread::Builder::new()
                .name("etw-poller".into())
                .spawn(move || {
                    while !halt.load(Ordering::Relaxed) {
                        for pid in sigmacatch_input_etw_common::etw_process::snapshot() {
                            emit_process(&tracker, &computer, &tx, pid);
                        }
                        std::thread::sleep(std::time::Duration::from_millis(POLL_INTERVAL_MS));
                    }
                })
                .ok()
        } else {
            None
        };

        loop {
            if *stop.borrow() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        }
        halt.store(true, Ordering::Relaxed);
        if let Some(running) = running {
            let _ = running.stop();
        }
        if let Some(main) = main {
            let _ = main.stop();
        }
        if let Some(poller) = poller {
            let _ = poller.join();
        }
        let _ = &mut stop;
        Ok(())
    }
}
