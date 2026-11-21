// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 sigmacatch contributors

//! macOS Endpoint Security collector (feature `macos`).
//!
//! The sole macOS input: selected by `main.rs` on macOS when the `macos`
//! cargo feature is built in.
//!
//! # Why Endpoint Security
//!
//! Endpoint Security (`ESClient`) is Apple's official kernel-telemetry API for
//! security products. It needs no kernel extension, no DTrace and no SIP
//! change. A client process must, however,
//!
//! 1. be signed with the `com.apple.developer.endpoint-security.client`
//!    entitlement (a *restricted* entitlement that Apple must grant),
//! 2. be approved by the user (a TCC prompt on first connection), and
//! 3. run as root.
//!
//! Point 1 is the hard part: Apple grants that entitlement to specific
//! binaries (Fleet, Santa, …), and an ad-hoc- or self-signed local build is
//! **killed by AMFI at launch** when it carries the entitlement. So a generic
//! sigmacatch binary cannot create its own ES client on a stock machine.
//!
//! This collector therefore offers two backends:
//!
//! * [`Backend::Native`] — sigmacatch's own `endpoint-sec` client. Used when
//!   the binary *is* entitled (a vendor build, or a machine where Apple has
//!   granted the entitlement). No fallback is possible if it fails for a
//!   reason other than the missing entitlement.
//! * [`Backend::Eslogger`] — Apple's first-party `eslogger` ES client
//!   (`/usr/bin/eslogger`), which is itself entitled and runs as root. It
//!   emits one NDJSON object per notification, which we parse with the pure,
//!   cross-platform [`RawNotification::from_eslogger_json`]. This is the
//!   backend that works out of the box on a stock machine with SIP enabled.
//! * [`Backend::Auto`] (default) — try the native client first and fall back
//!   to `eslogger` when the native client reports that it is not entitled.
//!
//! # Shape
//!
//! Each notification becomes a [`RawNotification`] (owned, testable on any
//! platform) and is converted into a [`Event`] pushed into the shared runner
//! channel.
//!
//! # Event model
//!
//! JSON keeps the Sigma field names the `product: macos` rules use (`Image`,
//! `CommandLine`, `ParentImage`, `TargetFilename`) plus `UtcTime`,
//! `ProcessId`/`ParentProcessId`, `User`/`UserId`, `Provider` and
//! `EventType`. `ParentImage` is the pre-exec image of the exec'ing process
//! (`Message::process()`), which is the shell that spawned the new image in the
//! usual fork+exec sequence.
//!
//! Regression data is written as JSON (`DataFormat::Json`): one document per
//! matched event, no binary container needed.

use std::collections::HashMap;

use crate::detection::DetectionEngine;
use crate::regression::DataFormat;
use crate::runner::CollectorKind;
use crate::types::{Event, EventProducer, ProducerError};
use anyhow::Result;
use async_trait::async_trait;
use serde_json::{Map, Value};
use tokio::sync::{mpsc, watch};

/// Provider recorded in `info.yml` for Endpoint Security regression data.
pub const PROVIDER: &str = "sigmacatch-endpoint-security";

/// Kind of Endpoint Security notification this collector understands.
///
/// The kind drives the emitted `EventType`, and (when it exists in the Sigma
/// taxonomy) the `category` used for rule pruning. Kinds without a matching
/// category stay category-less so the engine fails open instead of pruning
/// rules that might match them.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub enum Kind {
    /// `ES_EVENT_TYPE_NOTIFY_EXEC` — process execution.
    #[default]
    Exec,
    /// `ES_EVENT_TYPE_NOTIFY_CREATE` — file or directory creation.
    Create,
    /// `ES_EVENT_TYPE_NOTIFY_OPEN` — file open.
    Open,
    /// `ES_EVENT_TYPE_NOTIFY_WRITE` — file write.
    Write,
    /// `ES_EVENT_TYPE_NOTIFY_RENAME` — file rename.
    Rename,
    /// `ES_EVENT_TYPE_NOTIFY_UNLINK` — file deletion.
    Unlink,
    /// `ES_EVENT_TYPE_NOTIFY_SETUID` — privilege change.
    Setuid,
    /// `ES_EVENT_TYPE_NOTIFY_SUDO` — `sudo` invocation (macOS 13+).
    Sudo,
    /// `ES_EVENT_TYPE_NOTIFY_KEXTLOAD` — kernel extension load.
    KextLoad,
    /// `ES_EVENT_TYPE_NOTIFY_LOGIN_LOGIN` — console login (macOS 13+).
    Login,
}

impl Kind {
    /// Stable `EventType` string written to the event JSON.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Exec => "exec",
            Self::Create => "create",
            Self::Open => "open",
            Self::Write => "write",
            Self::Rename => "rename",
            Self::Unlink => "unlink",
            Self::Setuid => "setuid",
            Self::Sudo => "sudo",
            Self::KextLoad => "kextload",
            Self::Login => "login",
        }
    }

    /// `eslogger` short name for this kind, when the backend is `eslogger`.
    ///
    /// `eslogger` takes event types by lowercase short name
    /// (`exec`, `create`, …); `login_login` is the console-login name.
    pub fn eslogger_name(self) -> Option<&'static str> {
        match self {
            Self::Exec => Some("exec"),
            Self::Create => Some("create"),
            Self::Open => Some("open"),
            Self::Write => Some("write"),
            Self::Rename => Some("rename"),
            Self::Unlink => Some("unlink"),
            Self::Setuid => Some("setuid"),
            Self::Sudo => Some("sudo"),
            Self::KextLoad => Some("kextload"),
            Self::Login => Some("login_login"),
        }
    }

    /// Sigma `category` for this notification, when the taxonomy has one.
    pub fn category(self) -> Option<&'static str> {
        match self {
            Self::Exec => Some("process_creation"),
            Self::Create | Self::Open | Self::Write | Self::Unlink => Some("file_event"),
            Self::Rename => Some("file_rename"),
            Self::KextLoad => Some("driver_load"),
            Self::Setuid | Self::Sudo | Self::Login => None,
        }
    }
}

/// Kinds subscribed to by default.
///
/// `Open` and `Write` are intentionally absent: on a live macOS system they
/// fire thousands of times per second and would drown the runner channel. They
/// remain available through [`MacosEsCollector::with_kinds`] for targeted
/// captures.
pub const DEFAULT_KINDS: &[Kind] = &[
    Kind::Exec,
    Kind::Create,
    Kind::Rename,
    Kind::Unlink,
    Kind::Setuid,
    Kind::Sudo,
    Kind::KextLoad,
    Kind::Login,
];

/// Which Endpoint Security source the collector uses.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum Backend {
    /// sigmacatch's own `endpoint-sec` client (requires the Apple-granted
    /// entitlement on the binary).
    Native,
    /// Apple's first-party `eslogger` ES client (`/usr/bin/eslogger`), which
    /// is itself entitled and needs no entitlement on sigmacatch.
    Eslogger,
    /// Try [`Backend::Native`] first and fall back to [`Backend::Eslogger`]
    /// when the native client is not entitled.
    #[default]
    Auto,
}

/// Owned snapshot of one Endpoint Security notification.
///
/// Built by the macOS-only ES layer and converted into an [`Event`] here, so
/// the field mapping is testable on any platform.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RawNotification {
    /// Notification kind (drives `EventType` and `category`).
    pub kind: Kind,
    /// Event time, RFC 3339 UTC.
    pub timestamp: Option<String>,
    /// Executable image of the process that acted (`Image`).
    pub image: Option<String>,
    /// Arguments of the executed process (`CommandLine`).
    pub command_line: Option<String>,
    /// Pre-exec image of the process that called `execve` (`ParentImage`).
    pub parent_image: Option<String>,
    /// Acting process id (`ProcessId`).
    pub process_id: Option<i32>,
    /// Parent process id (`ParentProcessId`).
    pub parent_process_id: Option<i32>,
    /// Resolved account name of the acting process (`User`).
    pub user: Option<String>,
    /// Numeric account id of the acting process (`UserId`).
    pub user_id: Option<u32>,
    /// File path created/opened/written/deleted (`TargetFilename`).
    pub target_filename: Option<String>,
    /// Source path of a rename (`SourceFilename`).
    pub source_filename: Option<String>,
    /// Kernel extension identifier (`DriverName`).
    pub driver_name: Option<String>,
}

impl RawNotification {
    /// Start an empty notification of the given kind.
    pub fn new(kind: Kind) -> Self {
        Self {
            kind,
            ..Self::default()
        }
    }

    /// Build a notification from one `eslogger` NDJSON document.
    ///
    /// `eslogger` (Apple's Endpoint Security client) emits one JSON object per
    /// notification. The shape mirrors the ES C structures: `process` is the
    /// acting (pre-exec) process and `event` carries the typed payload. This
    /// parser is pure and platform-independent so the field mapping is
    /// testable on any host.
    pub fn from_eslogger_json(doc: &Value) -> Option<Self> {
        let (kind, typed) = match doc.get("event")?.as_object()? {
            obj if obj.contains_key("exec") => (Kind::Exec, &obj["exec"]),
            obj if obj.contains_key("create") => (Kind::Create, &obj["create"]),
            obj if obj.contains_key("open") => (Kind::Open, &obj["open"]),
            obj if obj.contains_key("write") => (Kind::Write, &obj["write"]),
            obj if obj.contains_key("rename") => (Kind::Rename, &obj["rename"]),
            obj if obj.contains_key("unlink") => (Kind::Unlink, &obj["unlink"]),
            obj if obj.contains_key("setuid") => (Kind::Setuid, &obj["setuid"]),
            obj if obj.contains_key("sudo") => (Kind::Sudo, &obj["sudo"]),
            obj if obj.contains_key("kextload") => (Kind::KextLoad, &obj["kextload"]),
            obj if obj.contains_key("login_login") => (Kind::Login, &obj["login_login"]),
            _ => return None,
        };

        let mut notification = Self::new(kind);
        notification.timestamp = doc.get("time").and_then(|t| t.as_str()).map(str::to_string);

        // The acting (pre-exec) process is the `process` block.
        let process = doc.get("process");
        let process_image = process
            .and_then(|p| p.get("executable"))
            .and_then(|e| e.get("path"))
            .and_then(|v| v.as_str())
            .map(str::to_string);
        let process_id = process
            .and_then(|p| p.get("audit_token"))
            .and_then(|t| t.get("pid"))
            .and_then(|v| v.as_i64())
            .map(|v| v as i32);
        let process_uid = process
            .and_then(|p| p.get("audit_token"))
            .and_then(|t| t.get("ruid"))
            .and_then(|v| v.as_u64())
            .map(|v| v as u32);
        let process_ppid = process
            .and_then(|p| p.get("ppid"))
            .and_then(|v| v.as_i64())
            .map(|v| v as i32);

        match kind {
            Kind::Exec => {
                let target = typed.get("target");
                notification.image = target
                    .and_then(|t| t.get("executable"))
                    .and_then(|e| e.get("path"))
                    .and_then(|v| v.as_str())
                    .map(str::to_string);
                notification.process_id = target
                    .and_then(|t| t.get("audit_token"))
                    .and_then(|t| t.get("pid"))
                    .and_then(|v| v.as_i64())
                    .map(|v| v as i32);
                notification.user_id = target
                    .and_then(|t| t.get("audit_token"))
                    .and_then(|t| t.get("ruid"))
                    .and_then(|v| v.as_u64())
                    .map(|v| v as u32);
                notification.command_line = typed
                    .get("args")
                    .and_then(|a| a.as_array())
                    .map(|args| {
                        args.iter()
                            .filter_map(|a| a.as_str())
                            .map(str::to_string)
                            .collect::<Vec<_>>()
                            .join(" ")
                    })
                    .filter(|s| !s.is_empty());
                notification.parent_image = process_image.clone();
                notification.parent_process_id = process_id;
            }
            Kind::Create => {
                notification.image = process_image.clone();
                notification.process_id = process_id;
                notification.parent_process_id = process_ppid;
                notification.target_filename = eslogger_destination(typed.get("destination"));
            }
            Kind::Open => {
                notification.image = process_image.clone();
                notification.process_id = process_id;
                notification.parent_process_id = process_ppid;
                notification.target_filename = typed
                    .get("file")
                    .and_then(|f| f.get("path"))
                    .and_then(|v| v.as_str())
                    .map(str::to_string);
            }
            Kind::Write => {
                notification.image = process_image.clone();
                notification.process_id = process_id;
                notification.parent_process_id = process_ppid;
                notification.target_filename = typed
                    .get("target")
                    .and_then(|f| f.get("path"))
                    .and_then(|v| v.as_str())
                    .map(str::to_string);
            }
            Kind::Unlink => {
                notification.image = process_image.clone();
                notification.process_id = process_id;
                notification.parent_process_id = process_ppid;
                notification.target_filename = typed
                    .get("target")
                    .and_then(|f| f.get("path"))
                    .and_then(|v| v.as_str())
                    .map(str::to_string);
            }
            Kind::Rename => {
                notification.image = process_image.clone();
                notification.process_id = process_id;
                notification.parent_process_id = process_ppid;
                notification.source_filename = typed
                    .get("source")
                    .and_then(|f| f.get("path"))
                    .and_then(|v| v.as_str())
                    .map(str::to_string);
                notification.target_filename = eslogger_destination(typed.get("destination"));
            }
            Kind::Setuid => {
                notification.image = process_image.clone();
                notification.process_id = process_id;
                notification.user_id = typed.get("uid").and_then(|v| v.as_u64()).map(|v| v as u32);
            }
            Kind::Sudo => {
                notification.image = process_image.clone();
                notification.process_id = process_id;
                notification.user = typed
                    .get("to_username")
                    .and_then(|v| v.as_str())
                    .map(str::to_string);
                notification.user_id = typed
                    .get("to_uid")
                    .and_then(|v| v.as_u64())
                    .map(|v| v as u32);
                notification.command_line = typed
                    .get("command")
                    .and_then(|v| v.as_str())
                    .map(str::to_string);
            }
            Kind::KextLoad => {
                notification.image = process_image.clone();
                notification.process_id = process_id;
                notification.driver_name = typed
                    .get("identifier")
                    .and_then(|v| v.as_str())
                    .map(str::to_string);
            }
            Kind::Login => {
                notification.image = process_image.clone();
                notification.process_id = process_id;
                notification.user = typed
                    .get("username")
                    .and_then(|v| v.as_str())
                    .map(str::to_string);
                notification.user_id = typed.get("uid").and_then(|v| v.as_u64()).map(|v| v as u32);
            }
        }

        // Fallbacks shared by all kinds: fall back to the acting process.
        if notification.process_id.is_none() {
            notification.process_id = process_id;
        }
        if notification.user_id.is_none() {
            notification.user_id = process_uid;
        }
        if notification.image.is_none() {
            notification.image = process_image;
        }

        Some(notification)
    }

    /// Raw JSON view: the captured fields only, without logsource injection.
    pub fn to_json(&self) -> Value {
        let mut map = Map::new();
        map.insert("Provider".to_string(), Value::String(PROVIDER.to_string()));
        map.insert(
            "EventType".to_string(),
            Value::String(self.kind.as_str().to_string()),
        );
        insert_opt_str(&mut map, "UtcTime", &self.timestamp);
        insert_opt_str(&mut map, "Image", &self.image);
        insert_opt_str(&mut map, "CommandLine", &self.command_line);
        insert_opt_str(&mut map, "ParentImage", &self.parent_image);
        insert_opt_str(&mut map, "User", &self.user);
        insert_opt_str(&mut map, "TargetFilename", &self.target_filename);
        insert_opt_str(&mut map, "SourceFilename", &self.source_filename);
        insert_opt_str(&mut map, "DriverName", &self.driver_name);
        if let Some(v) = self.process_id {
            map.insert("ProcessId".to_string(), Value::from(v));
        }
        if let Some(v) = self.parent_process_id {
            map.insert("ParentProcessId".to_string(), Value::from(v));
        }
        if let Some(v) = self.user_id {
            map.insert("UserId".to_string(), Value::from(v));
        }
        Value::Object(map)
    }

    /// Build the sigmacatch [`Event`] for this notification.
    ///
    /// The detection view carries `product: macos` and, when available, the
    /// Sigma `category`; the raw view stays logsource-free for regression data.
    pub fn to_event(&self) -> Event {
        let raw = self.to_json();
        let mut detection = raw.clone();
        if let (Some(map), Some(category)) = (detection.as_object_mut(), self.kind.category()) {
            map.insert("category".to_string(), Value::String(category.to_string()));
        }
        let raw_bytes = serde_json::to_vec(&raw).unwrap_or_default();
        Event::new_injected(raw, detection, raw_bytes, "macos", None)
    }

    /// Resolve `User` from `UserId` when the source supplied no account name.
    ///
    /// Both backends carry the acting uid, but only the native one resolves it
    /// on its own. Keeping the fallback here makes both paths agree and keeps
    /// the behaviour testable without a macOS host.
    pub fn fill_user_from_id(&mut self, resolve: impl Fn(u32) -> Option<String>) {
        if self.user.is_none() {
            self.user = self.user_id.and_then(resolve);
        }
    }
}

/// Resolve an eslogger `destination` object (existing file or new path).
fn eslogger_destination(destination: Option<&Value>) -> Option<String> {
    let obj = destination?.as_object()?;
    if let Some(existing) = obj.get("existing_file") {
        return existing
            .get("path")
            .and_then(|v| v.as_str())
            .map(str::to_string);
    }
    let new_path = obj.get("new_path")?;
    let dir = new_path.get("dir")?.get("path")?.as_str()?;
    let filename = new_path.get("filename")?.as_str()?;
    Some(format!("{dir}/{filename}"))
}

/// Insert a string field when present.
fn insert_opt_str(map: &mut Map<String, Value>, key: &str, value: &Option<String>) {
    if let Some(v) = value {
        map.insert(key.to_string(), Value::String(v.clone()));
    }
}

/// Endpoint Security collector: one live source, one event channel.
#[derive(Debug, Clone)]
pub struct MacosEsCollector {
    /// Notification kinds to subscribe to.
    pub kinds: Vec<Kind>,
    /// Which Endpoint Security source to use.
    pub backend: Backend,
}

impl Default for MacosEsCollector {
    fn default() -> Self {
        Self {
            kinds: DEFAULT_KINDS.to_vec(),
            backend: Backend::default(),
        }
    }
}

impl MacosEsCollector {
    /// Collector with the default kinds and backend (`Auto`: native client
    /// first, `eslogger` fallback).
    pub fn new() -> Self {
        Self::default()
    }

    /// Collector subscribing to a custom kind set (default backend).
    pub fn with_kinds(kinds: Vec<Kind>) -> Self {
        Self {
            kinds,
            ..Self::default()
        }
    }

    /// Collector with a custom backend (default kinds).
    pub fn with_backend(backend: Backend) -> Self {
        Self {
            backend,
            ..Self::default()
        }
    }
}

impl CollectorKind for MacosEsCollector {
    fn name(&self) -> &'static str {
        "macos-es"
    }

    fn mode(&self) -> String {
        format!(
            "macOS Endpoint Security ({} kind{}, backend {})",
            self.kinds.len(),
            if self.kinds.len() == 1 { "" } else { "s" },
            self.backend.as_str()
        )
    }

    fn channels(
        &self,
        _engine: &DetectionEngine,
        _custom_map: &HashMap<String, String>,
    ) -> Option<Vec<String>> {
        // Endpoint Security has no channel resolution.
        None
    }

    fn build(&self, _channels: &[String]) -> Box<dyn EventProducer> {
        Box::new(self.clone())
    }

    fn regression_format(&self) -> DataFormat {
        DataFormat::Json
    }

    fn rule_product(&self) -> &'static str {
        "macos"
    }
}

/// Outcome of attempting the native Endpoint Security client.
pub enum NativeOutcome {
    /// The native client served events until stop; nothing more to do.
    Served,
    /// The native client could not be created (missing entitlement, not
    /// running as root, …). An alternative source should be used.
    Fallback(String),
    /// A fatal error; no fallback is appropriate.
    Fatal(ProducerError),
}

impl Backend {
    /// Short name for log messages.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Native => "native",
            Self::Eslogger => "eslogger",
            Self::Auto => "auto",
        }
    }
}

#[async_trait]
impl EventProducer for MacosEsCollector {
    async fn run(
        self: Box<Self>,
        tx: mpsc::Sender<Event>,
        stop: watch::Receiver<bool>,
    ) -> Result<(), ProducerError> {
        #[cfg(target_os = "macos")]
        {
            match self.backend {
                Backend::Native => match es::run(self.kinds, tx, stop).await {
                    NativeOutcome::Served => Ok(()),
                    NativeOutcome::Fallback(reason) => Err(ProducerError::Message(reason)),
                    NativeOutcome::Fatal(e) => Err(e),
                },
                Backend::Eslogger => eslogger::run(self.kinds, tx, stop).await,
                Backend::Auto => {
                    match es::run(self.kinds.clone(), tx.clone(), stop.clone()).await {
                        NativeOutcome::Served => Ok(()),
                        NativeOutcome::Fallback(reason) => {
                            tracing::warn!(
                                "native Endpoint Security client unavailable ({reason}); \
                             falling back to eslogger"
                            );
                            eslogger::run(self.kinds, tx, stop).await
                        }
                        NativeOutcome::Fatal(e) => Err(e),
                    }
                }
            }
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = (self, tx, stop);
            Err(ProducerError::Message(
                "the Endpoint Security input is only available in a macOS build".to_string(),
            ))
        }
    }
}

/// Module-level entry point: subscribe with the default kind set and run the
/// shared pipeline.
pub async fn run() -> Result<()> {
    let collector = MacosEsCollector::new();
    crate::runner::run(&collector).await
}

/// macOS-only native Endpoint Security plumbing.
#[cfg(target_os = "macos")]
mod es {
    use std::ffi::OsStr;
    use std::panic::RefUnwindSafe;
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
    use std::sync::{Arc, OnceLock};
    use std::time::Duration;

    use endpoint_sec::sys::es_event_type_t;
    use endpoint_sec::{Client, Event as EsEvent, Message};
    use tokio::sync::{mpsc, oneshot, watch};
    use tracing::{info, warn};

    use super::{Kind, NativeOutcome, RawNotification, user_name};
    use crate::types::{Event, ProducerError};

    /// Why the native client could not be created.
    enum ConnectError {
        /// Recoverable: the binary lacks the entitlement (or is not root). An
        /// alternative source should be used.
        NotEntitled,
        /// Fatal: no fallback is appropriate.
        Other(String),
    }

    /// Delivery handle shared with the ES message handler.
    ///
    /// `RefUnwindSafe` is asserted manually: the handler is wrapped in
    /// `catch_unwind` by the crate, and a panic while holding the channel
    /// sender has no observable effect on it.
    #[derive(Clone)]
    struct EventSink {
        /// Runner event channel.
        tx: mpsc::Sender<Event>,
        /// Events dropped because the channel was full.
        dropped: Arc<AtomicU64>,
        /// Whether the "channel full" warning was already emitted.
        warned: Arc<AtomicBool>,
    }

    impl RefUnwindSafe for EventSink {}

    impl EventSink {
        /// Non-blocking send: the ES handler thread must never wait on the
        /// runner, or shutdown could deadlock on a full channel.
        fn deliver(&self, event: Event) {
            match self.tx.try_send(event) {
                Ok(()) => {}
                Err(mpsc::error::TrySendError::Full(_)) => {
                    let dropped = self.dropped.fetch_add(1, Ordering::Relaxed) + 1;
                    if !self.warned.swap(true, Ordering::Relaxed) || dropped.is_multiple_of(10_000)
                    {
                        warn!(
                            dropped,
                            "Event channel full — Endpoint Security notifications are being dropped"
                        );
                    }
                }
                Err(mpsc::error::TrySendError::Closed(_)) => {}
            }
        }
    }

    /// Detect the running macOS version and publish it to the ES bindings.
    ///
    /// The bindings default to 10.15 and refuse version-gated calls otherwise;
    /// `sw_vers` is the single source of truth here (no SDK dependency).
    fn init_runtime_version() {
        static INIT: OnceLock<()> = OnceLock::new();
        INIT.get_or_init(|| {
            let (major, minor, patch) = detect_macos_version().unwrap_or((10, 15, 0));
            endpoint_sec::version::set_runtime_version(major, minor, patch);
            info!(
                macOS = format!("{major}.{minor}.{patch}"),
                "Endpoint Security runtime version"
            );
        });
    }

    /// Parse `sw_vers -productVersion` into a `(major, minor, patch)` tuple.
    fn detect_macos_version() -> Option<(u64, u64, u64)> {
        let output = std::process::Command::new("/usr/bin/sw_vers")
            .arg("-productVersion")
            .output()
            .ok()?;
        let text = String::from_utf8(output.stdout).ok()?;
        let mut parts = text.trim().split('.');
        let major = parts.next()?.parse().ok()?;
        let minor = parts.next().unwrap_or("0").parse().ok()?;
        let patch = parts.next().unwrap_or("0").parse().ok()?;
        Some((major, minor, patch))
    }

    /// ES event type and the minimum macOS version that delivers it.
    fn es_event_type(kind: Kind) -> (es_event_type_t, (u64, u64, u64)) {
        match kind {
            Kind::Exec => (es_event_type_t::ES_EVENT_TYPE_NOTIFY_EXEC, (10, 15, 0)),
            Kind::Create => (es_event_type_t::ES_EVENT_TYPE_NOTIFY_CREATE, (10, 15, 0)),
            Kind::Open => (es_event_type_t::ES_EVENT_TYPE_NOTIFY_OPEN, (10, 15, 0)),
            Kind::Write => (es_event_type_t::ES_EVENT_TYPE_NOTIFY_WRITE, (10, 15, 0)),
            Kind::Rename => (es_event_type_t::ES_EVENT_TYPE_NOTIFY_RENAME, (10, 15, 0)),
            Kind::Unlink => (es_event_type_t::ES_EVENT_TYPE_NOTIFY_UNLINK, (10, 15, 0)),
            Kind::KextLoad => (es_event_type_t::ES_EVENT_TYPE_NOTIFY_KEXTLOAD, (10, 15, 0)),
            Kind::Setuid => (es_event_type_t::ES_EVENT_TYPE_NOTIFY_SETUID, (12, 0, 0)),
            Kind::Sudo => (es_event_type_t::ES_EVENT_TYPE_NOTIFY_SUDO, (13, 0, 0)),
            Kind::Login => (
                es_event_type_t::ES_EVENT_TYPE_NOTIFY_LOGIN_LOGIN,
                (13, 0, 0),
            ),
        }
    }

    /// Resolve the requested kinds to the subscriptions this OS supports.
    fn subscription_types(kinds: &[Kind]) -> Vec<es_event_type_t> {
        let mut types = Vec::with_capacity(kinds.len());
        for kind in kinds {
            let (event_type, (major, minor, patch)) = es_event_type(*kind);
            let supported = endpoint_sec::version::is_version_or_more(major, minor, patch);
            if supported {
                types.push(event_type);
            } else {
                warn!(
                    kind = kind.as_str(),
                    required = format!("{major}.{minor}.{patch}"),
                    "Endpoint Security event kind unavailable on this macOS version — skipped"
                );
            }
        }
        types
    }

    /// Convert one ES message into the platform-independent notification.
    fn notification(message: &Message) -> Option<RawNotification> {
        let event = message.event()?;
        let actor = message.process();
        let actor_token = actor.audit_token();
        let mut notification = match event {
            EsEvent::NotifyExec(exec) => {
                let target = exec.target();
                let target_token = target.audit_token();
                let mut notification = RawNotification::new(Kind::Exec);
                notification.process_id = Some(target_token.pid());
                notification.user_id = Some(target_token.ruid());
                notification.image = process_image(&target);
                notification.command_line = join_args(exec.args());
                notification.parent_process_id = Some(actor_token.pid());
                notification.parent_image = process_image(&actor);
                notification
            }
            EsEvent::NotifyCreate(create) => {
                let mut notification = RawNotification::new(Kind::Create);
                notification.target_filename = create_destination(&create);
                notification
            }
            EsEvent::NotifyOpen(open) => {
                let mut notification = RawNotification::new(Kind::Open);
                notification.target_filename = path_string(open.file().path());
                notification
            }
            EsEvent::NotifyWrite(write) => {
                let mut notification = RawNotification::new(Kind::Write);
                notification.target_filename = path_string(write.target().path());
                notification
            }
            EsEvent::NotifyUnlink(unlink) => {
                let mut notification = RawNotification::new(Kind::Unlink);
                notification.target_filename = path_string(unlink.target().path());
                notification
            }
            EsEvent::NotifyRename(rename) => {
                let mut notification = RawNotification::new(Kind::Rename);
                notification.source_filename = path_string(rename.source().path());
                notification.target_filename = rename_destination(&rename);
                notification
            }
            EsEvent::NotifyKextLoad(kext) => {
                let mut notification = RawNotification::new(Kind::KextLoad);
                notification.driver_name = path_string(kext.identifier());
                notification
            }
            EsEvent::NotifySetuid(setuid) => {
                let mut notification = RawNotification::new(Kind::Setuid);
                notification.user_id = Some(setuid.uid());
                notification
            }
            EsEvent::NotifySudo(sudo) => {
                let mut notification = RawNotification::new(Kind::Sudo);
                notification.user = sudo.to_username().and_then(non_empty);
                notification.user_id = sudo.to_uid();
                notification.command_line = sudo.command().and_then(non_empty);
                notification
            }
            EsEvent::NotifyLoginLogin(login) => {
                let mut notification = RawNotification::new(Kind::Login);
                notification.user = non_empty(login.username());
                notification.user_id = login.uid();
                notification
            }
            _ => return None,
        };

        notification.timestamp = Some(rfc3339(message.time()));
        if notification.process_id.is_none() {
            notification.process_id = Some(actor_token.pid());
        }
        if notification.user_id.is_none() {
            notification.user_id = Some(actor_token.ruid());
        }
        if notification.image.is_none() {
            notification.image = process_image(&actor);
        }
        notification.fill_user_from_id(user_name);
        Some(notification)
    }

    /// `Image` of a process, or `None` for an empty path.
    fn process_image(process: &endpoint_sec::Process<'_>) -> Option<String> {
        path_string(process.executable().path())
    }

    /// Lossy, non-empty string for an `OsStr`.
    fn non_empty(value: &OsStr) -> Option<String> {
        let text = value.to_string_lossy();
        (!text.is_empty()).then(|| text.into_owned())
    }

    /// Lossy string for a path, or `None` for an empty path.
    fn path_string(value: &OsStr) -> Option<String> {
        non_empty(value)
    }

    /// Join exec arguments with spaces (argv[0] included when ES provides it).
    fn join_args<'a>(args: impl Iterator<Item = &'a OsStr>) -> Option<String> {
        let parts: Vec<String> = args.map(|arg| arg.to_string_lossy().into_owned()).collect();
        (!parts.is_empty()).then(|| parts.join(" "))
    }

    /// Full path of a create destination.
    fn create_destination(create: &endpoint_sec::EventCreate<'_>) -> Option<String> {
        use endpoint_sec::EventCreateDestinationFile as Destination;
        match create.destination()? {
            Destination::ExistingFile { file, .. } => path_string(file.path()),
            Destination::NewPath {
                directory,
                filename,
                ..
            } => Some(
                std::path::Path::new(directory.path())
                    .join(filename)
                    .to_string_lossy()
                    .into_owned(),
            ),
            _ => None,
        }
    }

    /// Full path of a rename destination.
    fn rename_destination(rename: &endpoint_sec::EventRename<'_>) -> Option<String> {
        use endpoint_sec::EventRenameDestinationFile as Destination;
        match rename.destination()? {
            Destination::ExistingFile { file, .. } => path_string(file.path()),
            Destination::NewPath {
                directory,
                filename,
                ..
            } => Some(
                std::path::Path::new(directory.path())
                    .join(filename)
                    .to_string_lossy()
                    .into_owned(),
            ),
            _ => None,
        }
    }

    /// RFC 3339 UTC timestamp with microsecond precision.
    fn rfc3339(time: std::time::SystemTime) -> String {
        let datetime: chrono::DateTime<chrono::Utc> = time.into();
        datetime.to_rfc3339_opts(chrono::SecondsFormat::Micros, true)
    }

    /// Create the client, subscribe, and hold it until `stop` is set.
    fn client_loop(
        types: Vec<es_event_type_t>,
        sink: EventSink,
        stop: &AtomicBool,
        ready: oneshot::Sender<Result<(), ConnectError>>,
    ) {
        let handler_sink = sink.clone();
        let handler = move |_client: &mut Client<'_>, message: Message| {
            if let Some(notification) = notification(&message) {
                handler_sink.deliver(notification.to_event());
            }
        };

        let mut client = match Client::new(handler) {
            Ok(client) => client,
            Err(error) => {
                let connect_error = match &error {
                    endpoint_sec::sys::NewClientError::NotEntitled
                    | endpoint_sec::sys::NewClientError::NotPermitted
                    | endpoint_sec::sys::NewClientError::NotPrivileged => ConnectError::NotEntitled,
                    _ => ConnectError::Other(format!(
                        "es_new_client failed ({error:?}) — sign the binary with the \
                         com.apple.developer.endpoint-security.client entitlement \
                         (scripts/macos/sign.sh), run it as root, then approve it in \
                         System Settings > Privacy & Security"
                    )),
                };
                let _ = ready.send(Err(connect_error));
                return;
            }
        };

        if let Err(error) = client.subscribe(&types) {
            let _ = ready.send(Err(ConnectError::Other(format!(
                "es_subscribe failed: {error:?}"
            ))));
            return;
        }
        let _ = ready.send(Ok(()));

        while !stop.load(Ordering::SeqCst) {
            std::thread::sleep(Duration::from_millis(100));
        }
        let _ = client.unsubscribe_all();
        drop(client);
    }

    /// Run the native ES client on its own thread and bridge it to the async
    /// runner. Returns [`NativeOutcome`] so the caller can fall back to
    /// `eslogger` when the client is not entitled.
    pub(super) async fn run(
        kinds: Vec<Kind>,
        tx: mpsc::Sender<Event>,
        mut stop: watch::Receiver<bool>,
    ) -> NativeOutcome {
        init_runtime_version();
        let types = subscription_types(&kinds);
        if types.is_empty() {
            return NativeOutcome::Fatal(ProducerError::Message(
                "no Endpoint Security event kind is available on this macOS version".to_string(),
            ));
        }

        let sink = EventSink {
            tx,
            dropped: Arc::new(AtomicU64::new(0)),
            warned: Arc::new(AtomicBool::new(false)),
        };
        let stop_flag = Arc::new(AtomicBool::new(false));
        let finished = Arc::new(AtomicBool::new(false));
        let (ready_tx, ready_rx) = oneshot::channel();

        let handle = match std::thread::Builder::new()
            .name("macos-endpoint-security".to_string())
            .spawn({
                let stop_flag = Arc::clone(&stop_flag);
                let finished = Arc::clone(&finished);
                move || {
                    client_loop(types, sink, &stop_flag, ready_tx);
                    finished.store(true, Ordering::SeqCst);
                }
            }) {
            Ok(handle) => handle,
            Err(error) => {
                return NativeOutcome::Fatal(ProducerError::Message(format!(
                    "failed to spawn the Endpoint Security thread: {error}"
                )));
            }
        };

        match ready_rx.await {
            Ok(Ok(())) => info!("macOS Endpoint Security client connected"),
            Ok(Err(ConnectError::NotEntitled)) => {
                stop_flag.store(true, Ordering::SeqCst);
                let _ = tokio::task::spawn_blocking(|| handle.join()).await;
                return NativeOutcome::Fallback(
                    "not entitled — the binary lacks the \
                     com.apple.developer.endpoint-security.client entitlement"
                        .to_string(),
                );
            }
            Ok(Err(ConnectError::Other(error))) => {
                stop_flag.store(true, Ordering::SeqCst);
                let _ = tokio::task::spawn_blocking(|| handle.join()).await;
                return NativeOutcome::Fatal(ProducerError::Message(error));
            }
            Err(_) => {
                stop_flag.store(true, Ordering::SeqCst);
                let _ = tokio::task::spawn_blocking(|| handle.join()).await;
                return NativeOutcome::Fatal(ProducerError::Message(
                    "the Endpoint Security thread exited before connecting".to_string(),
                ));
            }
        }

        while !*stop.borrow() && !finished.load(Ordering::SeqCst) {
            tokio::select! {
                changed = stop.changed() => {
                    if changed.is_err() {
                        break;
                    }
                }
                () = tokio::time::sleep(Duration::from_millis(250)) => {}
            }
        }

        stop_flag.store(true, Ordering::SeqCst);
        let _ = tokio::task::spawn_blocking(|| handle.join()).await;
        NativeOutcome::Served
    }
}

/// macOS-only `eslogger` backend: spawn Apple's entitled ES client and forward
/// its NDJSON to the runner channel.
#[cfg(target_os = "macos")]
mod eslogger {
    use tokio::io::{AsyncBufReadExt, BufReader};
    use tokio::process::Command;
    use tokio::sync::{mpsc, watch};
    use tracing::{debug, info};

    use super::RawNotification;
    use crate::types::{Event, ProducerError};

    /// Apple's first-party Endpoint Security client binary.
    const ESLOGGER: &str = "/usr/bin/eslogger";

    /// Render the captured stderr for the error returned on an early exit.
    fn stderr_detail(lines: &[String]) -> String {
        if lines.is_empty() {
            String::new()
        } else {
            format!("; eslogger stderr: {}", lines.join("; "))
        }
    }

    /// Drain the child's stderr so entitlement/permission errors can be
    /// reported when `eslogger` exits before the capture is stopped.
    async fn drain_stderr(stderr: tokio::process::ChildStderr) -> Vec<String> {
        let mut lines = BufReader::new(stderr).lines();
        let mut captured = Vec::new();
        while let Ok(Some(line)) = lines.next_line().await {
            debug!("eslogger: {line}");
            captured.push(line);
        }
        captured
    }

    /// Parse one `eslogger` NDJSON line into a sigmacatch [`Event`].
    fn parse_line(line: &str) -> Option<Event> {
        let doc: serde_json::Value = serde_json::from_str(line).ok()?;
        let mut notification = RawNotification::from_eslogger_json(&doc)?;
        notification.fill_user_from_id(super::user_name);
        Some(notification.to_event())
    }

    /// Spawn `eslogger` for the requested kinds and forward its NDJSON to
    /// `tx` until `stop` is set.
    pub(super) async fn run(
        kinds: Vec<super::Kind>,
        tx: mpsc::Sender<Event>,
        mut stop: watch::Receiver<bool>,
    ) -> Result<(), ProducerError> {
        let event_names: Vec<String> = kinds
            .iter()
            .filter_map(|k| k.eslogger_name().map(str::to_string))
            .collect();
        if event_names.is_empty() {
            return Err(ProducerError::Message(
                "no Endpoint Security event kind maps to an eslogger subscription".to_string(),
            ));
        }

        let mut child = Command::new(ESLOGGER)
            .args(&event_names)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .map_err(|e| ProducerError::Message(format!("failed to spawn {ESLOGGER}: {e}")))?;

        let stderr = child.stderr.take().expect("stderr is piped");
        let stderr_task = tokio::spawn(drain_stderr(stderr));

        let stdout = child.stdout.take().expect("stdout is piped");
        let mut lines = BufReader::new(stdout).lines();

        info!(
            events = event_names.join(","),
            "Endpoint Security eslogger fallback started"
        );

        // An EOF before `stop` means eslogger died. Remember why so a dead
        // source surfaces as a producer error instead of an empty capture.
        let mut early_exit = None;
        while !*stop.borrow() {
            tokio::select! {
                _ = stop.changed() => break,
                line = lines.next_line() => {
                    match line {
                        Ok(Some(line)) => {
                            if let Some(event) = parse_line(&line)
                                && tx.send(event).await.is_err()
                            {
                                break; // receiver dropped
                            }
                        }
                        Ok(None) => {
                            early_exit = Some("eslogger closed its stdout before the capture was stopped".to_string());
                            break;
                        }
                        Err(e) => {
                            early_exit = Some(format!("eslogger stdout read error: {e}"));
                            break;
                        }
                    }
                }
            }
        }

        let _ = child.start_kill();
        let status = child.wait().await;
        let stderr_lines = stderr_task.await.unwrap_or_default();

        if let Some(reason) = early_exit {
            let status = status
                .map(|status| status.to_string())
                .unwrap_or_else(|e| format!("unknown ({e})"));
            return Err(ProducerError::Message(format!(
                "{reason} (status: {status}){}",
                stderr_detail(&stderr_lines)
            )));
        }
        Ok(())
    }

    #[cfg(test)]
    mod tests {
        use super::stderr_detail;

        #[test]
        fn stderr_detail_reports_captured_lines() {
            assert_eq!(stderr_detail(&[]), "");
            assert_eq!(
                stderr_detail(&["bad event".to_string(), "second line".to_string()]),
                "; eslogger stderr: bad event; second line"
            );
        }
    }
}

/// Resolve a numeric uid to an account name, with a per-process cache.
#[cfg(target_os = "macos")]
fn user_name(uid: u32) -> Option<String> {
    use std::sync::{Mutex, OnceLock};

    static CACHE: OnceLock<Mutex<HashMap<u32, Option<String>>>> = OnceLock::new();
    let cache = CACHE.get_or_init(|| Mutex::new(HashMap::new()));

    if let Some(cached) = cache.lock().ok().and_then(|cache| cache.get(&uid).cloned()) {
        return cached;
    }

    let resolved = resolve_user_name(uid);
    if let Ok(mut cache) = cache.lock() {
        cache.insert(uid, resolved.clone());
    }
    resolved
}

/// `getpwuid_r` wrapper; `None` when the uid has no passwd entry.
#[cfg(target_os = "macos")]
fn resolve_user_name(uid: u32) -> Option<String> {
    use std::ffi::CStr;

    let mut passwd = std::mem::MaybeUninit::<libc::passwd>::uninit();
    let mut buffer = vec![0u8; 16 * 1024];
    let mut result: *mut libc::passwd = std::ptr::null_mut();

    // SAFETY: every pointer is valid for the call: `passwd` and `result` are
    // stack slots, `buffer` owns `buffer.len()` writable bytes. The return
    // code is checked before `passwd` is assumed initialised.
    let code = unsafe {
        libc::getpwuid_r(
            uid,
            passwd.as_mut_ptr(),
            buffer.as_mut_ptr().cast(),
            buffer.len(),
            &mut result,
        )
    };
    if code != 0 || result.is_null() {
        return None;
    }

    // SAFETY: `getpwuid_r` returned 0 and set `result`, so `passwd` is
    // initialised and `pw_name` points to a NUL-terminated string inside
    // `buffer`, which is still alive.
    let passwd = unsafe { passwd.assume_init() };
    let name = unsafe { CStr::from_ptr(passwd.pw_name) }
        .to_string_lossy()
        .into_owned();
    (!name.is_empty()).then_some(name)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rule::SigmahqRules;

    fn sample_exec() -> RawNotification {
        RawNotification {
            kind: Kind::Exec,
            timestamp: Some("2026-11-21T10:00:00.000000Z".to_string()),
            image: Some("/bin/zsh".to_string()),
            command_line: Some("zsh -c id".to_string()),
            parent_image: Some("/usr/bin/sshd".to_string()),
            process_id: Some(4242),
            parent_process_id: Some(4000),
            user: Some("frack113".to_string()),
            user_id: Some(501),
            ..RawNotification::default()
        }
    }

    #[test]
    fn exec_maps_to_sigma_field_names() {
        let event = sample_exec().to_event();
        let json = &event.event_json;

        assert_eq!(json["product"], "macos");
        assert_eq!(json["category"], "process_creation");
        assert_eq!(json["Image"], "/bin/zsh");
        assert_eq!(json["CommandLine"], "zsh -c id");
        assert_eq!(json["ParentImage"], "/usr/bin/sshd");
        assert_eq!(json["ProcessId"], 4242);
        assert_eq!(json["ParentProcessId"], 4000);
        assert_eq!(json["User"], "frack113");
        assert_eq!(json["UserId"], 501);
        assert_eq!(json["Provider"], PROVIDER);
        assert_eq!(json["EventType"], "exec");

        // The raw view stays free of injected logsource fields.
        assert!(event.event_json_raw.get("product").is_none());
        assert!(event.event_json_raw.get("category").is_none());
        assert!(!event.event_raw.is_empty());
    }

    #[test]
    fn file_event_maps_target_filename() {
        let raw = RawNotification {
            kind: Kind::Create,
            image: Some("/bin/mkdir".to_string()),
            target_filename: Some("/Library/StartupItems/evil.plist".to_string()),
            process_id: Some(7),
            ..RawNotification::default()
        };
        let event = raw.to_event();

        assert_eq!(event.event_json["category"], "file_event");
        assert_eq!(
            event.event_json["TargetFilename"],
            "/Library/StartupItems/evil.plist"
        );
        assert_eq!(event.event_json["Image"], "/bin/mkdir");
    }

    #[test]
    fn rename_maps_source_and_target() {
        let raw = RawNotification {
            kind: Kind::Rename,
            source_filename: Some("/tmp/a".to_string()),
            target_filename: Some("/tmp/b".to_string()),
            ..RawNotification::default()
        };
        let event = raw.to_event();

        assert_eq!(event.event_json["category"], "file_rename");
        assert_eq!(event.event_json["SourceFilename"], "/tmp/a");
        assert_eq!(event.event_json["TargetFilename"], "/tmp/b");
    }

    #[test]
    fn kinds_without_taxonomy_category_fail_open() {
        for kind in [Kind::Setuid, Kind::Sudo, Kind::Login] {
            let event = RawNotification::new(kind).to_event();
            assert!(
                event.event_json.get("category").is_none(),
                "{kind:?} must not inject a category"
            );
            assert_eq!(event.event_json["EventType"], kind.as_str());
        }
    }

    #[test]
    fn kext_load_maps_driver_name() {
        let raw = RawNotification {
            kind: Kind::KextLoad,
            driver_name: Some("com.example.driver".to_string()),
            ..RawNotification::default()
        };
        let event = raw.to_event();

        assert_eq!(event.event_json["category"], "driver_load");
        assert_eq!(event.event_json["DriverName"], "com.example.driver");
    }

    #[test]
    fn default_kinds_avoid_high_volume_file_events() {
        assert!(DEFAULT_KINDS.contains(&Kind::Exec));
        assert!(DEFAULT_KINDS.contains(&Kind::Create));
        assert!(!DEFAULT_KINDS.contains(&Kind::Open));
        assert!(!DEFAULT_KINDS.contains(&Kind::Write));
    }

    #[test]
    fn collector_kind_contract() {
        let engine = DetectionEngine::new(&SigmahqRules::default()).unwrap();
        let collector = MacosEsCollector::new();

        assert_eq!(collector.name(), "macos-es");
        assert!(collector.mode().contains("Endpoint Security"));
        assert!(collector.channels(&engine, &HashMap::new()).is_none());
        assert!(collector.live_capture());
        assert_eq!(collector.rule_product(), "macos");
        assert!(matches!(collector.regression_format(), DataFormat::Json));
    }

    #[test]
    fn with_kinds_overrides_defaults() {
        let collector = MacosEsCollector::with_kinds(vec![Kind::Exec]);
        assert_eq!(collector.kinds, vec![Kind::Exec]);
        assert_eq!(collector.backend, Backend::Auto);
    }

    // ─── eslogger NDJSON parser ──────────────────────────────────────────────

    /// Minimal `eslogger` `exec` document in the exact shape Apple's client
    /// emits (see `eslogger exec`).
    fn eslogger_exec() -> Value {
        serde_json::json!({
            "time": "2026-11-21T10:00:00.000000Z",
            "process": {
                "executable": { "path": "/usr/bin/sshd" },
                "audit_token": { "pid": 4000, "ruid": 0, "euid": 0 },
                "ppid": 1
            },
            "event": {
                "exec": {
                    "args": ["zsh", "-c", "id"],
                    "target": {
                        "executable": { "path": "/bin/zsh" },
                        "audit_token": { "pid": 4242, "ruid": 501, "euid": 501 }
                    }
                }
            }
        })
    }

    #[test]
    fn eslogger_exec_maps_to_sigma_fields() {
        let raw = RawNotification::from_eslogger_json(&eslogger_exec()).expect("exec parses");
        assert_eq!(raw.kind, Kind::Exec);
        assert_eq!(raw.image.as_deref(), Some("/bin/zsh"));
        assert_eq!(raw.command_line.as_deref(), Some("zsh -c id"));
        assert_eq!(raw.parent_image.as_deref(), Some("/usr/bin/sshd"));
        assert_eq!(raw.process_id, Some(4242));
        assert_eq!(raw.parent_process_id, Some(4000));
        assert_eq!(raw.user_id, Some(501));
        assert_eq!(
            raw.timestamp.as_deref(),
            Some("2026-11-21T10:00:00.000000Z")
        );

        let event = raw.to_event();
        assert_eq!(event.event_json["product"], "macos");
        assert_eq!(event.event_json["category"], "process_creation");
        assert_eq!(event.event_json["Image"], "/bin/zsh");
        assert_eq!(event.event_json["CommandLine"], "zsh -c id");
        assert_eq!(event.event_json["ParentImage"], "/usr/bin/sshd");
    }

    #[test]
    fn eslogger_create_existing_file() {
        let doc = serde_json::json!({
            "time": "2026-11-21T10:00:00.000000Z",
            "process": {
                "executable": { "path": "/bin/touch" },
                "audit_token": { "pid": 7, "ruid": 501, "euid": 501 },
                "ppid": 5
            },
            "event": {
                "create": {
                    "destination_type": 0,
                    "destination": {
                        "existing_file": { "path": "/tmp/a.txt" }
                    }
                }
            }
        });
        let raw = RawNotification::from_eslogger_json(&doc).expect("create parses");
        assert_eq!(raw.kind, Kind::Create);
        assert_eq!(raw.image.as_deref(), Some("/bin/touch"));
        assert_eq!(raw.process_id, Some(7));
        assert_eq!(raw.parent_process_id, Some(5));
        assert_eq!(raw.target_filename.as_deref(), Some("/tmp/a.txt"));
    }

    #[test]
    fn eslogger_rename_new_path() {
        let doc = serde_json::json!({
            "time": "2026-11-21T10:00:00.000000Z",
            "process": {
                "executable": { "path": "/bin/mv" },
                "audit_token": { "pid": 9, "ruid": 501, "euid": 501 },
                "ppid": 5
            },
            "event": {
                "rename": {
                    "destination_type": 1,
                    "source": { "path": "/tmp/a.txt" },
                    "destination": {
                        "new_path": {
                            "dir": { "path": "/tmp" },
                            "filename": "b.txt"
                        }
                    }
                }
            }
        });
        let raw = RawNotification::from_eslogger_json(&doc).expect("rename parses");
        assert_eq!(raw.kind, Kind::Rename);
        assert_eq!(raw.source_filename.as_deref(), Some("/tmp/a.txt"));
        assert_eq!(raw.target_filename.as_deref(), Some("/tmp/b.txt"));
    }

    #[test]
    fn eslogger_unlink_maps_target() {
        let doc = serde_json::json!({
            "time": "2026-11-21T10:00:00.000000Z",
            "process": {
                "executable": { "path": "/bin/rm" },
                "audit_token": { "pid": 11, "ruid": 0, "euid": 0 },
                "ppid": 5
            },
            "event": {
                "unlink": {
                    "target": { "path": "/tmp/b.txt" },
                    "parent_dir": { "path": "/tmp" }
                }
            }
        });
        let raw = RawNotification::from_eslogger_json(&doc).expect("unlink parses");
        assert_eq!(raw.kind, Kind::Unlink);
        assert_eq!(raw.image.as_deref(), Some("/bin/rm"));
        assert_eq!(raw.process_id, Some(11));
        assert_eq!(raw.target_filename.as_deref(), Some("/tmp/b.txt"));
    }

    #[test]
    fn eslogger_unknown_event_is_ignored() {
        let doc = serde_json::json!({
            "time": "2026-11-21T10:00:00.000000Z",
            "event": { "mmap": { "address": 0 } }
        });
        assert!(RawNotification::from_eslogger_json(&doc).is_none());
    }

    #[test]
    fn eslogger_kind_names_match_eslogger() {
        assert_eq!(Kind::Exec.eslogger_name(), Some("exec"));
        assert_eq!(Kind::Create.eslogger_name(), Some("create"));
        assert_eq!(Kind::Rename.eslogger_name(), Some("rename"));
        assert_eq!(Kind::Unlink.eslogger_name(), Some("unlink"));
        assert_eq!(Kind::Setuid.eslogger_name(), Some("setuid"));
        assert_eq!(Kind::Sudo.eslogger_name(), Some("sudo"));
        assert_eq!(Kind::KextLoad.eslogger_name(), Some("kextload"));
        assert_eq!(Kind::Login.eslogger_name(), Some("login_login"));
    }

    #[test]
    fn user_resolves_from_id_only_when_absent() {
        let mut raw = RawNotification::from_eslogger_json(&eslogger_exec()).expect("exec parses");
        raw.fill_user_from_id(|uid| Some(format!("user-{uid}")));
        assert_eq!(raw.user.as_deref(), Some("user-501"));
        assert_eq!(raw.to_event().event_json["User"], "user-501");

        raw.user = Some("explicit".to_string());
        raw.fill_user_from_id(|_| Some("overwritten".to_string()));
        assert_eq!(raw.user.as_deref(), Some("explicit"));
    }
}
