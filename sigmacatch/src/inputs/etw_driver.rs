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

use crate::inputs::etw_event::filetime_to_utc;
use crate::inputs::etw_process::{ImageCache, ProcessFacts, enrich};
use crate::inputs::etw_sysmon::{
    SignatureFields, driver_load_xml, event_xml, file_create_xml, image_load_xml,
    process_access_xml, process_start_xml, process_terminate_xml, sysmon_utc,
};
use crate::inputs::signature::Signature;
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

// SAFETY: the handle is only used from the producer's task; the raw pointer is
// not shared across threads.
unsafe impl Send for Device {}

impl Drop for Device {
    fn drop(&mut self) {
        // SAFETY: the handle came from `CreateFileW` exactly once.
        unsafe {
            let _ = CloseHandle(self.handle);
        }
    }
}

/// Upper bound on the bytes hashed for one file; larger content is hashed
/// from the start only.
pub const HASH_LIMIT: usize = crate::inputs::nt_file::HASH_LIMIT;

/// Creation time of the file at an NT path, in Sysmon's `UtcTime` spelling.
fn creation_time(path: &str) -> Option<String> {
    let ticks = crate::inputs::nt_file::creation_ticks(path)?;
    let at = crate::inputs::etw_event::filetime_to_utc(ticks)?;
    Some(sysmon_utc(at))
}

/// SHA1 of the first [`HASH_LIMIT`] bytes of the file at an NT path, the way
/// Sysmon spells it (`SHA1=…`), or `None` when it cannot be read.
fn sha1_of_nt_path(path: &str) -> Option<String> {
    let bytes = crate::inputs::nt_file::read_prefix(path, HASH_LIMIT)?;
    use sha1::{Digest, Sha1};
    let mut hasher = Sha1::new();
    hasher.update(&bytes);
    let digest = hasher.finalize();
    let hex: String = digest.iter().map(|byte| format!("{byte:02x}")).collect();
    Some(format!("SHA1={hex}"))
}

/// Delay before a created file is inspected for a PE header: the writer has
/// usually finished by then, which a create callback cannot know.
const PE_CHECK_DELAY: std::time::Duration = std::time::Duration::from_millis(300);

/// True when the bytes start with the PE signature.
fn is_pe(bytes: &[u8]) -> bool {
    bytes.len() >= 2 && bytes[0] == b'M' && bytes[1] == b'Z'
}

/// `Hashes` of a process image, whichever path shape it carries.
fn image_hashes(image: &str) -> Option<String> {
    crate::inputs::nt_file::hashes_of(image.strip_prefix(r"\??\").unwrap_or(image))
}

/// Turns a stream of [`SensorEvent`] records into [`Event`]s, keeping the
/// pid → facts cache that fills `ParentImage`/`ParentCommandLine`.
pub struct Mapper {
    computer: String,
    cache: HashMap<u32, ProcessFacts>,
    /// Image paths shared with the other producers (see [`ImageCache`]).
    images: ImageCache,
    /// `Hashes` per image path: hashing every DLL load again would cost more
    /// than the events are worth.
    hashes: HashMap<String, Option<String>>,
    /// Authenticode facts per image path, for the same reason.
    signatures: HashMap<String, Option<Signature>>,
    /// Version resource per image path.
    versions: HashMap<String, Option<crate::inputs::version_info::VersionInfo>>,
    /// Upper bound on both caches before they are cleared.
    cache_limit: usize,
}

impl Default for Mapper {
    fn default() -> Self {
        Self::new()
    }
}

impl Mapper {
    /// Create a mapper that reports for this host.
    pub fn new() -> Self {
        Self::with_images(ImageCache::new())
    }

    /// Create a mapper that publishes its pid → image map to `images`.
    pub fn with_images(images: ImageCache) -> Self {
        let computer = std::env::var("COMPUTERNAME").unwrap_or_default();
        Self {
            computer,
            cache: HashMap::new(),
            images,
            hashes: HashMap::new(),
            signatures: HashMap::new(),
            versions: HashMap::new(),
            cache_limit: 512,
        }
    }

    /// Map one record into a detection event, or `None` for an unknown kind.
    pub fn map(&mut self, event: &SensorEvent) -> Option<Event> {
        match event.kind {
            kind::PROCESS_CREATE => self.map_create(event),
            kind::PROCESS_EXIT => self.map_exit(event),
            kind::PROCESS_ACCESS => self.map_access(event),
            kind::IMAGE_LOAD => self.map_image_load(event, false),
            kind::DRIVER_LOAD => self.map_image_load(event, true),
            kind::FILE_CREATE => self.map_file_create(event),
            kind::FILE_RENAME => self.map_file_rename(event),
            kind::FILE_TRUNCATE => self.map_file_simple(event, 506, true),
            kind::FILE_DELETE => self.map_file_simple(event, 23, false),
            kind::FILE_DELETE_DETECTED => self.map_file_simple(event, 26, false),
            kind::FILE_SET_SECURITY => self.map_file_security(event),
            kind::FILE_CREATION_TIME => self.map_file_creation_time(event),
            kind::RAW_READ => self.map_raw_read(event),
            kind::PIPE_CREATE => self.map_pipe(event, 17, None),
            kind::PIPE_CONNECT => self.map_pipe(event, 18, Some("connect")),
            kind::FILE_STREAM => self.map_file_stream(event),
            kind::FILE_OPEN => self.map_file_open(event),
            kind::FILE_WRITE => self.map_file_write(event),
            kind::PROCESS_REMOTE_THREAD => self.map_remote_thread(event),
            kind::REGISTRY_RENAME => self.map_registry_rename(event),
            _ => None,
        }
    }

    /// Event time from the kernel record, falling back to "now".
    fn event_time(event: &SensorEvent) -> chrono::DateTime<chrono::Utc> {
        filetime_to_utc(event.timestamp as i64).unwrap_or_else(chrono::Utc::now)
    }

    /// `Hashes` of an image path, computed once per path.
    fn image_hashes(&mut self, image: &str) -> Option<String> {
        if let Some(cached) = self.hashes.get(image) {
            return cached.clone();
        }
        let computed = crate::inputs::nt_file::hashes_of(image);
        if self.hashes.len() >= self.cache_limit {
            self.hashes.clear();
        }
        self.hashes.insert(image.to_string(), computed.clone());
        computed
    }

    /// Authenticode facts of an image path, computed once per path.
    fn image_signature(&mut self, image: &str) -> Option<Signature> {
        if let Some(cached) = self.signatures.get(image) {
            return cached.clone();
        }
        let computed = crate::inputs::nt_file::dos_path_of_nt(image)
            .and_then(|dos| crate::inputs::signature::of_file(&dos));
        if self.signatures.len() >= self.cache_limit {
            self.signatures.clear();
        }
        self.signatures.insert(image.to_string(), computed.clone());
        computed
    }

    /// Version resource of an image path, read once per path.
    fn image_version(&mut self, image: &str) -> Option<crate::inputs::version_info::VersionInfo> {
        if let Some(cached) = self.versions.get(image) {
            return cached.clone();
        }
        let computed = crate::inputs::nt_file::dos_path_of_nt(image)
            .and_then(|dos| crate::inputs::version_info::of_file(&dos));
        if self.versions.len() >= self.cache_limit {
            self.versions.clear();
        }
        self.versions.insert(image.to_string(), computed.clone());
        computed
    }

    /// Token user of a process: cached creation-time facts first, then the
    /// live process.
    fn process_user(&self, pid: u32) -> Option<String> {
        self.cache
            .get(&pid)
            .and_then(|facts| facts.user.clone())
            .or_else(|| enrich(pid).and_then(|facts| facts.user))
    }

    /// Image of the process that issued a file/registry event: the cached
    /// creation-time facts first, then the map the other producers publish,
    /// then the live process. A long-lived shell that predates the capture has
    /// no creation event, and would otherwise leave `Image` empty on every
    /// event it produces.
    fn file_image(&self, pid: u32) -> Option<String> {
        self.cache
            .get(&pid)
            .and_then(|f| f.image.clone())
            .or_else(|| self.images.get(pid))
            .or_else(|| enrich(pid).and_then(|facts| facts.image))
    }

    fn map_file_rename(&mut self, event: &SensorEvent) -> Option<Event> {
        let old = wide(&event.primary, event.primary_length);
        let new = wide(&event.secondary, event.secondary_length);
        if old.is_empty() || new.is_empty() {
            return None;
        }
        let image = self.file_image(event.pid);
        let xml = event_xml(
            &self.computer,
            503,
            Self::event_time(event),
            event.pid,
            image.as_deref(),
            &[("TargetFilename", &new), ("SourceFilename", &old)],
        );
        Event::from_xml_injected(&xml, "windows", Some("sysmon")).ok()
    }

    fn map_file_simple(&mut self, event: &SensorEvent, id: u16, with_size: bool) -> Option<Event> {
        let path = wide(&event.primary, event.primary_length);
        if path.is_empty() {
            return None;
        }
        let image = self.file_image(event.pid);
        let size = event.detail.to_string();
        // Sysmon reports the hashes of a deleted file; the content is often
        // still there when the disposition is reported, so this is best
        // effort — an unreadable file simply leaves the field out.
        let hashes = (id == 23 || id == 26)
            .then(|| self.image_hashes(&path))
            .flatten();
        let mut fields: Vec<(&str, &str)> = vec![("TargetFilename", &path)];
        if with_size {
            fields.push(("Size", &size));
        }
        if let Some(hashes) = hashes.as_deref() {
            fields.push(("Hashes", hashes));
        }
        let xml = event_xml(
            &self.computer,
            id,
            Self::event_time(event),
            event.pid,
            image.as_deref(),
            &fields,
        );
        Event::from_xml_injected(&xml, "windows", Some("sysmon")).ok()
    }

    fn map_file_security(&mut self, event: &SensorEvent) -> Option<Event> {
        let path = wide(&event.primary, event.primary_length);
        if path.is_empty() {
            return None;
        }
        let image = self.file_image(event.pid);
        let id = if event.detail == 0 { 504 } else { 505 };
        let xml = event_xml(
            &self.computer,
            id,
            Self::event_time(event),
            event.pid,
            image.as_deref(),
            &[("TargetFilename", &path)],
        );
        Event::from_xml_injected(&xml, "windows", Some("sysmon")).ok()
    }

    /// EID 2: the file's creation time was rewritten (`touch -t`, `SetFileTime`).
    fn map_file_creation_time(&mut self, event: &SensorEvent) -> Option<Event> {
        let path = wide(&event.primary, event.primary_length);
        if path.is_empty() {
            return None;
        }
        let image = self.file_image(event.pid);
        let at = Self::event_time(event);
        let previous = filetime_to_utc(event.value_a as i64).map(sysmon_utc);
        // A zero new value means the caller asked for "now" (`ChangeTime` set
        // to -1), which the kernel does not echo back.
        let created = if event.value_b == 0 {
            Some(sysmon_utc(at))
        } else {
            filetime_to_utc(event.value_b as i64).map(sysmon_utc)
        };
        let mut fields: Vec<(&str, &str)> = vec![("TargetFilename", &path)];
        if let Some(previous) = previous.as_deref() {
            fields.push(("PreviousCreationUtcTime", previous));
        }
        if let Some(created) = created.as_deref() {
            fields.push(("CreationUtcTime", created));
        }
        let xml = event_xml(&self.computer, 2, at, event.pid, image.as_deref(), &fields);
        Event::from_xml_injected(&xml, "windows", Some("sysmon")).ok()
    }

    /// EID 9: a raw read of a volume device (`\\.\C:` style).
    fn map_raw_read(&mut self, event: &SensorEvent) -> Option<Event> {
        let device = wide(&event.primary, event.primary_length);
        if device.is_empty() {
            return None;
        }
        let image = self.file_image(event.pid);
        let xml = event_xml(
            &self.computer,
            9,
            Self::event_time(event),
            event.pid,
            image.as_deref(),
            &[("Device", &device)],
        );
        Event::from_xml_injected(&xml, "windows", Some("sysmon")).ok()
    }

    /// EID 17 (pipe created) and EID 18 (pipe connected). Sysmon prefixes the
    /// relative name NPFS reports with a single backslash, and EID 18 also
    /// carries `EventType`.
    fn map_pipe(
        &mut self,
        event: &SensorEvent,
        id: u16,
        event_type: Option<&str>,
    ) -> Option<Event> {
        let mut pipe = wide(&event.primary, event.primary_length);
        if pipe.is_empty() {
            return None;
        }
        if !pipe.starts_with('\\') {
            pipe.insert(0, '\\');
        }
        let image = self.file_image(event.pid);
        let mut fields: Vec<(&str, &str)> = Vec::new();
        if let Some(event_type) = event_type {
            fields.push(("EventType", event_type));
        }
        fields.push(("PipeName", &pipe));
        let xml = event_xml(
            &self.computer,
            id,
            Self::event_time(event),
            event.pid,
            image.as_deref(),
            &fields,
        );
        Event::from_xml_injected(&xml, "windows", Some("sysmon")).ok()
    }

    /// EID 14: a registry key was renamed. The driver reports the old full
    /// path and the new leaf, which is joined onto the old parent here.
    fn map_registry_rename(&mut self, event: &SensorEvent) -> Option<Event> {
        let old = wide(&event.primary, event.primary_length);
        let leaf = wide(&event.secondary, event.secondary_length);
        if old.is_empty() || leaf.is_empty() {
            return None;
        }
        let parent = old
            .rsplit_once('\\')
            .map_or(old.as_str(), |(parent, _)| parent);
        let new = format!("{parent}\\{leaf}");
        let image = self.file_image(event.pid);
        let old_object = crate::inputs::registry_format::abbreviate(&old);
        let new_name = crate::inputs::registry_format::abbreviate(&new);
        let xml = event_xml(
            &self.computer,
            14,
            Self::event_time(event),
            event.pid,
            image.as_deref(),
            &[
                ("EventType", "RenameKey"),
                ("TargetObject", &old_object),
                ("NewName", &new_name),
            ],
        );
        Event::from_xml_injected(&xml, "windows", Some("sysmon")).ok()
    }

    /// EID 8: a thread was created in another process. `StartAddress` is not
    /// reachable from the thread notify callback, so those fields are absent.
    fn map_remote_thread(&mut self, event: &SensorEvent) -> Option<Event> {
        let source_image = self.file_image(event.pid);
        let target_image = self.file_image(event.parent_pid);
        let source_id = event.pid.to_string();
        let target_id = event.parent_pid.to_string();
        let thread_id = event.detail.to_string();
        let unknown = "-";
        let source = source_image.as_deref().unwrap_or(unknown);
        let target = target_image.as_deref().unwrap_or(unknown);
        let xml = event_xml(
            &self.computer,
            8,
            Self::event_time(event),
            event.pid,
            None,
            &[
                ("SourceProcessId", &source_id),
                ("SourceImage", source),
                ("TargetProcessId", &target_id),
                ("TargetImage", target),
                ("NewThreadId", &thread_id),
            ],
        );
        Event::from_xml_injected(&xml, "windows", Some("sysmon")).ok()
    }

    /// EID 510 (extension): an uncached write reached a file. `Size` carries
    /// the write length, not the file size.
    fn map_file_write(&mut self, event: &SensorEvent) -> Option<Event> {
        let path = wide(&event.primary, event.primary_length);
        if path.is_empty() {
            return None;
        }
        let image = self.file_image(event.pid);
        let size = event.detail.to_string();
        let xml = event_xml(
            &self.computer,
            510,
            Self::event_time(event),
            event.pid,
            image.as_deref(),
            &[("TargetFilename", &path), ("Size", &size)],
        );
        Event::from_xml_injected(&xml, "windows", Some("sysmon")).ok()
    }

    /// EID 509 (extension): an existing file was opened for writing.
    fn map_file_open(&mut self, event: &SensorEvent) -> Option<Event> {
        let path = wide(&event.primary, event.primary_length);
        if path.is_empty() {
            return None;
        }
        let image = self.file_image(event.pid);
        let xml = event_xml(
            &self.computer,
            509,
            Self::event_time(event),
            event.pid,
            image.as_deref(),
            &[("TargetFilename", &path)],
        );
        Event::from_xml_injected(&xml, "windows", Some("sysmon")).ok()
    }

    /// EID 15: an alternate data stream was created. `TargetFilename` carries
    /// the stream (`file.txt:stream:$DATA`) and `Hash` its content, read and
    /// hashed here: the kernel does not read file data.
    fn map_file_stream(&mut self, event: &SensorEvent) -> Option<Event> {
        let path = wide(&event.primary, event.primary_length);
        if path.is_empty() {
            return None;
        }
        let image = self.file_image(event.pid);
        let created = creation_time(&path);
        let mut fields: Vec<(&str, &str)> = vec![("TargetFilename", &path)];
        if let Some(created) = created.as_deref() {
            fields.push(("CreationUtcTime", created));
        }
        let hash = sha1_of_nt_path(&path);
        if let Some(hash) = hash.as_deref() {
            fields.push(("Hash", hash));
        }
        let xml = event_xml(
            &self.computer,
            15,
            Self::event_time(event),
            event.pid,
            image.as_deref(),
            &fields,
        );
        Event::from_xml_injected(&xml, "windows", Some("sysmon")).ok()
    }

    fn map_file_create(&mut self, event: &SensorEvent) -> Option<Event> {
        let target = wide(&event.primary, event.primary_length);
        if target.is_empty() {
            return None;
        }
        let image = self.file_image(event.pid);
        let created = creation_time(&target);
        let xml = file_create_xml(
            &self.computer,
            Self::event_time(event),
            event.pid,
            image.as_deref(),
            &target,
            created.as_deref(),
        );
        Event::from_xml_injected(&xml, "windows", Some("sysmon")).ok()
    }

    fn map_image_load(&mut self, event: &SensorEvent, driver: bool) -> Option<Event> {
        let image_loaded = wide(&event.primary, event.primary_length);
        let at = Self::event_time(event);
        let xml = if driver {
            let hashes = self.image_hashes(&image_loaded);
            let signature = self.image_signature(&image_loaded);
            let fields = signature.as_ref().map(|signature| SignatureFields {
                signed: signature.signed,
                name: signature.name.as_deref(),
                status: signature.status,
            });
            driver_load_xml(
                &self.computer,
                at,
                &image_loaded,
                hashes.as_deref(),
                fields.as_ref(),
            )
        } else {
            // Cloned before the two `&mut self` calls below.
            let process_image = self
                .cache
                .get(&event.pid)
                .and_then(|facts| facts.image.clone());
            let hashes = self.image_hashes(&image_loaded);
            let signature = self.image_signature(&image_loaded);
            let fields = signature.as_ref().map(|signature| SignatureFields {
                signed: signature.signed,
                name: signature.name.as_deref(),
                status: signature.status,
            });
            let version = self.image_version(&image_loaded);
            let user = self.process_user(event.pid);
            image_load_xml(
                &self.computer,
                at,
                event.pid,
                process_image.as_deref(),
                &image_loaded,
                hashes.as_deref(),
                fields.as_ref(),
                version.as_ref(),
                user.as_deref(),
            )
        };
        Event::from_xml_injected(&xml, "windows", Some("sysmon")).ok()
    }

    fn map_access(&mut self, event: &SensorEvent) -> Option<Event> {
        let source_image = self
            .cache
            .get(&event.pid)
            .and_then(|facts| facts.image.as_deref())
            .map(str::to_string);
        let target_image = self
            .cache
            .get(&event.parent_pid)
            .and_then(|facts| facts.image.as_deref())
            .map(str::to_string);
        let xml = process_access_xml(
            &self.computer,
            event.pid,
            source_image.as_deref(),
            event.parent_pid,
            target_image.as_deref(),
            event.detail,
            Self::event_time(event),
        );
        Event::from_xml_injected(&xml, "windows", Some("sysmon")).ok()
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
        facts.created = facts
            .created
            .or_else(|| filetime_to_utc(event.timestamp as i64));
        let parent = self.cache.get(&facts.parent_pid).cloned();
        if let Some(image) = facts.image.as_deref() {
            self.images.insert(event.pid, image);
        }
        // Sysmon reports the hashes of the process image; the kernel does not
        // hash, so this is done here, from the image on disk.
        let hashes = facts.image.as_deref().and_then(|image| image_hashes(image));
        facts.hashes = hashes;
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
        let xml = process_terminate_xml(&self.computer, &facts, Self::event_time(event));
        Event::from_xml_injected(&xml, "windows", Some("sysmon")).ok()
    }
}

/// Copy `length` UTF-16 units out of a fixed record field.
fn wide(field: &[u16], length: u16) -> String {
    let units = (length as usize).min(field.len());
    String::from_utf16_lossy(&field[..units])
}

// ---------------------------------------------------------------------------
// Async producer: the kernel sensor as an `EventProducer`.
// ---------------------------------------------------------------------------

/// True when the driver is loaded and speaks our protocol version.
pub fn is_available() -> bool {
    Device::open()
        .map(|device| device.version() == Some(SIGMACATCH_PROTOCOL_VERSION))
        .unwrap_or(false)
}

/// Async producer draining the kernel sensor into detection events.
pub struct EventCollector {
    /// Image paths published to the other producers (see [`ImageCache`]).
    images: ImageCache,
}

impl EventCollector {
    /// Create the producer, sharing `images` with the ETW mappers.
    pub fn new(images: ImageCache) -> Self {
        Self { images }
    }
}

impl Default for EventCollector {
    fn default() -> Self {
        Self::new(ImageCache::new())
    }
}

#[async_trait::async_trait]
impl crate::types::EventProducer for EventCollector {
    async fn run(
        self: Box<Self>,
        tx: tokio::sync::mpsc::Sender<crate::types::Event>,
        mut stop: tokio::sync::watch::Receiver<bool>,
    ) -> Result<(), crate::types::ProducerError> {
        let Some(device) = Device::open() else {
            tracing::info!("kernel sensor not loaded — driver path disabled");
            return Ok(());
        };
        if device.version() != Some(SIGMACATCH_PROTOCOL_VERSION) {
            tracing::warn!(
                "kernel sensor protocol mismatch (driver {:?}, collector {}) — driver path disabled",
                device.version(),
                SIGMACATCH_PROTOCOL_VERSION
            );
            return Ok(());
        }

        let mut mapper = Mapper::with_images(self.images.clone());
        let mut events = Vec::new();

        // EID 29 (FileExecutableDetected): a PE written to disk. The create
        // callback sees the file before its content exists, so the header is
        // inspected shortly after, when the writer has usually finished.
        let (pe_tx, pe_rx) = std::sync::mpsc::channel::<(u32, String)>();
        let pe_worker = {
            let tx = tx.clone();
            let images = self.images.clone();
            let computer = std::env::var("COMPUTERNAME").unwrap_or_default();
            std::thread::Builder::new()
                .name("sigmacatch-pe-check".into())
                .spawn(move || {
                    for (pid, path) in pe_rx {
                        std::thread::sleep(PE_CHECK_DELAY);
                        let Some(header) = crate::inputs::nt_file::read_prefix(&path, 2) else {
                            continue;
                        };
                        if !is_pe(&header) {
                            continue;
                        }
                        let image = images.get(pid);
                        let mut fields: Vec<(&str, &str)> = vec![("TargetFilename", &path)];
                        let hash = sha1_of_nt_path(&path);
                        if let Some(hash) = hash.as_deref() {
                            fields.push(("Hashes", hash));
                        }
                        let xml = event_xml(
                            &computer,
                            29,
                            chrono::Utc::now(),
                            pid,
                            image.as_deref(),
                            &fields,
                        );
                        if let Ok(event) =
                            crate::types::Event::from_xml_injected(&xml, "windows", Some("sysmon"))
                            && tx.blocking_send(event).is_err()
                        {
                            break;
                        }
                    }
                })
                .ok()
        };

        loop {
            if *stop.borrow() {
                break;
            }
            match device.read_events(&mut events) {
                Ok(_) => {
                    for record in &events {
                        if record.kind == kind::FILE_CREATE {
                            let path = wide(&record.primary, record.primary_length);
                            if !path.is_empty() {
                                let _ = pe_tx.send((record.pid, path));
                            }
                        }
                        if let Some(event) = mapper.map(record)
                            && tx.send(event).await.is_err()
                        {
                            return Ok(());
                        }
                    }
                }
                Err(error) => tracing::warn!("kernel sensor read failed: {error:#}"),
            }
            tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        }
        drop(pe_tx);
        if let Some(worker) = pe_worker {
            let _ = worker.join();
        }
        let _ = &mut stop;
        Ok(())
    }
}
