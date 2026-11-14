// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 sigmacatch contributors

//! Native Windows ETW collector (feature `etw`, Windows only).
//!
//! The analogue of [`super::ebpf`] on Linux: a realtime trace session feeds
//! kernel providers straight to [`super::etw_event::decode`], with no Sysmon
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

use std::ffi::c_void;
use std::mem::size_of;
use std::ptr;

use anyhow::{Context, Result, bail};
use windows::Win32::Foundation::{ERROR_SUCCESS, HANDLE, WIN32_ERROR};
use windows::Win32::Security::{GetTokenInformation, TOKEN_ELEVATION, TOKEN_QUERY, TokenElevation};
use windows::Win32::System::Diagnostics::Etw::{
    CONTROLTRACE_HANDLE, EVENT_CONTROL_CODE_ENABLE_PROVIDER, EVENT_RECORD,
    EVENT_TRACE_CONTROL_STOP, EVENT_TRACE_FLAG, EVENT_TRACE_LOGFILEW, EVENT_TRACE_PROPERTIES,
    EVENT_TRACE_REAL_TIME_MODE, EVENT_TRACE_SYSTEM_LOGGER_MODE, EnableTraceEx2, OpenTraceW,
    PROCESS_TRACE_MODE_EVENT_RECORD, PROCESS_TRACE_MODE_REAL_TIME, PROCESSTRACE_HANDLE,
    ProcessTrace, StartTraceW, WNODE_FLAG_TRACED_GUID,
};
use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
use windows::core::{GUID, PCWSTR, PWSTR};

/// Name of the classic kernel logger session. Windows allows exactly one, and
/// it must carry this exact name.
pub const KERNEL_LOGGER_NAME: &str = "NT Kernel Logger";

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

/// Providers on the low-latency process session.
pub const PROCESS_SESSION_PROVIDERS: &[ProviderSpec] = &[KERNEL_PROCESS];

/// Providers on the burst-tolerant main session.
pub const MAIN_SESSION_PROVIDERS: &[ProviderSpec] =
    &[KERNEL_NETWORK, KERNEL_FILE, KERNEL_REGISTRY, DNS_CLIENT];

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

/// A realtime trace session, owned by this process.
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
        Self::start_with(name, config, None)
    }

    /// Start the classic kernel logger session.
    ///
    /// Unlike manifest providers, the kernel logger is subscribed through the
    /// `EnableFlags` mask in the properties, not `EnableTraceEx2`.
    pub fn start_kernel_logger(flags: EVENT_TRACE_FLAG, config: SessionConfig) -> Result<Self> {
        Self::start_with(KERNEL_LOGGER_NAME, config, Some(flags))
    }

    fn start_with(
        name: &str,
        config: SessionConfig,
        kernel_flags: Option<EVENT_TRACE_FLAG>,
    ) -> Result<Self> {
        ensure_privileges()?;
        // A previous run that crashed leaves the session behind; reclaim it
        // instead of failing the whole collection.
        Self::stop_orphan(name);

        let name_wide: Vec<u16> = name.encode_utf16().chain(std::iter::once(0)).collect();
        let properties_size = size_of::<EVENT_TRACE_PROPERTIES>();
        let total = properties_size + name_wide.len() * size_of::<u16>();
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
            header.LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
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
    pub fn stop(self) {
        let mut this = self;
        this.stop_inner();
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

    fn stop_inner(&mut self) {
        let props = self
            .properties
            .as_mut_ptr()
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
    sink(record);
}

/// Convenience wrapper: start and consume one session on a background thread.
///
/// Stops the session when the returned guard is dropped, which unblocks
/// `ProcessTrace`.
pub struct RunningSession {
    session: Option<TraceSession>,
    thread: Option<std::thread::JoinHandle<(u32, std::time::Duration)>>,
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
        Ok(Self {
            session: Some(session),
            thread: Some(thread),
        })
    }

    /// Live counters for the underlying session, when still running.
    pub fn stats(&self) -> Option<SessionStats> {
        self.session.as_ref().and_then(TraceSession::stats)
    }

    /// Stop the session and wait for the consumer loop to return.
    ///
    /// Returns the `ProcessTrace` status and how long the loop actually ran:
    /// a duration far below the capture window means the consumer detached
    /// early, which is what makes events "disappear" without any loss counter.
    pub fn stop(mut self) -> (u32, std::time::Duration) {
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
        if let Some(session) = self.session.take() {
            session.stop();
        }
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}
