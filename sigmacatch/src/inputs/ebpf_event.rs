// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 sigmacatch contributors

//! Enrichment of kernel ring buffer records into native Linux JSON events.
//!
//! Events are emitted as flat Sigma-field objects (no Sysmon/XML wrapper)
//! with `product: linux` and the matching `category` injected for detection.
//! The JSON shape follows the internal eBPF taxonomy
//! (`sigmacatch/ebpf_taxonomy.json`) mapping kernel-captured fields to Sigma
//! fields so Linux rules can match directly.
//!
//! Hashes are `-` for now when the image is unreadable — in-kernel SHA256
//! is out of scope; userspace hashing with cache is used when possible.

use std::collections::{HashMap, VecDeque};
use std::fs;
use std::path::Path;
use std::time::SystemTime;

use crate::ebpf_common::{
    DnsEvent, DriverLoadEvent, ExecEvent, FileCreateEvent, FileDeleteEvent, ListenEvent, NetEvent,
    PipeConnectEvent, PipeCreateEvent, ProcessAccessEvent, ProcessTamperingEvent, RawAccessEvent,
};
use crate::types::Event;
use chrono::Utc;
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

/// Bounded memoization of image hashes keyed by resolved path, invalidated
/// by mtime change.
const HASH_CACHE_CAP: usize = 4096;

/// Embedded internal taxonomy mapping (eBPF/kernel → Sigma fields).
pub const EBPF_TAXONOMY_JSON: &str = include_str!("../../ebpf_taxonomy.json");

/// What the builder remembers about a process seen through exec events.
struct ParentInfo {
    guid: String,
    image: String,
    cmdline: String,
    user: String,
}

/// Stateful renderer: monotonic record ids, per-boot process cache,
/// passwd lookups and the image-hash memoization.
pub struct EventBuilder {
    hostname: String,
    parents: HashMap<u32, ParentInfo>,
    users: HashMap<u32, String>,
    hashes: HashMap<String, (SystemTime, String)>,
    hash_order: VecDeque<String>,
}

impl Default for EventBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl EventBuilder {
    /// Builder primed with this host's hostname and a best-effort snapshot of
    /// already-running processes so exits/identity lookups for pre-existing
    /// pids do not degrade to unknown `-` fields.
    pub fn new() -> Self {
        let hostname = fs::read_to_string("/proc/sys/kernel/hostname")
            .map(|s| s.trim().to_string())
            .unwrap_or_else(|_| "localhost".to_string());
        let mut builder = Self {
            hostname,
            parents: HashMap::new(),
            users: HashMap::new(),
            hashes: HashMap::new(),
            hash_order: VecDeque::new(),
        };
        builder.seed_from_proc();
        builder
    }

    /// Best-effort process table seeding from `/proc`.
    fn seed_from_proc(&mut self) {
        let Ok(entries) = fs::read_dir("/proc") else {
            return;
        };
        for entry in entries.flatten() {
            let name = entry.file_name();
            let pid = match name.to_str().and_then(|s| s.parse::<u32>().ok()) {
                Some(pid) => pid,
                None => continue,
            };
            if self.parents.contains_key(&pid) {
                continue;
            }
            let Some(info) = Self::read_proc_info(pid, &mut self.users) else {
                continue;
            };
            self.parents.insert(pid, info);
        }
    }

    fn read_proc_info(pid: u32, users: &mut HashMap<u32, String>) -> Option<ParentInfo> {
        let image = fs::read_link(format!("/proc/{pid}/exe"))
            .ok()
            .map(|p| p.to_string_lossy().into_owned())
            .unwrap_or_else(|| {
                fs::read_to_string(format!("/proc/{pid}/comm"))
                    .map(|s| s.trim().to_string())
                    .unwrap_or_default()
            });
        if image.is_empty() {
            return None;
        }
        let cmdline = fs::read(format!("/proc/{pid}/cmdline"))
            .ok()
            .map(|raw| {
                raw.split(|&b| b == 0)
                    .filter(|part| !part.is_empty())
                    .map(|part| String::from_utf8_lossy(part))
                    .collect::<Vec<_>>()
                    .join(" ")
            })
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| image.clone());
        let uid = fs::read_to_string(format!("/proc/{pid}/status"))
            .ok()
            .and_then(|s| {
                s.lines()
                    .find_map(|l| l.strip_prefix("Uid:"))
                    .and_then(|rest| rest.split_whitespace().next()?.parse::<u32>().ok())
            })
            .unwrap_or(0);
        let user = if let Some(name) = users.get(&uid) {
            name.clone()
        } else {
            let name = lookup_user(uid).unwrap_or_else(|| uid.to_string());
            users.insert(uid, name.clone());
            name
        };
        Some(ParentInfo {
            guid: new_guid(),
            image,
            cmdline,
            user,
        })
    }

    /// Build a process_creation (EID 1) event for a kernel exec record.
    pub fn exec_event(&mut self, ev: &ExecEvent) -> Event {
        let now = Utc::now();
        let guid = new_guid();
        let image = ev.image_str().to_string();
        let cmdline = full_cmdline(ev);
        let user = self.user_name(ev.uid);
        let ppid = read_ppid(ev.pid);
        let parent_info = ppid.as_ref().and_then(|p| self.parents.get(p));

        let (parent_guid, parent_pid, parent_image, parent_cmdline, parent_user) =
            match (&ppid, parent_info) {
                (Some(ppid), Some(info)) => (
                    info.guid.clone(),
                    ppid.to_string(),
                    info.image.clone(),
                    info.cmdline.clone(),
                    info.user.clone(),
                ),
                _ => (
                    NULL_GUID.to_string(),
                    "-".to_string(),
                    "-".to_string(),
                    "-".to_string(),
                    "-".to_string(),
                ),
            };

        let mut m = base_event("process_creation", &now, &self.hostname);
        insert_str(&mut m, "UtcTime", &utc_time(&now));
        insert_str(&mut m, "ProcessGuid", &guid);
        insert_str(&mut m, "ProcessId", &ev.pid.to_string());
        insert_str(&mut m, "Image", &image);
        insert_str(&mut m, "FileVersion", "-");
        insert_str(&mut m, "Description", "-");
        insert_str(&mut m, "Product", "-");
        insert_str(&mut m, "Company", "-");
        insert_str(&mut m, "OriginalFileName", "-");
        insert_str(&mut m, "CommandLine", &cmdline);
        insert_str(
            &mut m,
            "CurrentDirectory",
            &read_cwd(ev.pid).unwrap_or_else(|| "-".to_string()),
        );
        insert_str(&mut m, "User", &user);
        insert_str(&mut m, "LogonGuid", NULL_GUID);
        insert_str(&mut m, "LogonId", "0");
        insert_str(
            &mut m,
            "TerminalSessionId",
            &read_session_id(ev.pid).unwrap_or(0).to_string(),
        );
        insert_str(&mut m, "IntegrityLevel", "no level");
        insert_str(&mut m, "Hashes", &self.image_hash(ev.pid, &image));
        insert_str(&mut m, "ParentProcessGuid", &parent_guid);
        insert_str(&mut m, "ParentProcessId", &parent_pid);
        insert_str(&mut m, "ParentImage", &parent_image);
        insert_str(&mut m, "ParentCommandLine", &parent_cmdline);
        insert_str(&mut m, "ParentUser", &parent_user);

        self.parents.insert(
            ev.pid,
            ParentInfo {
                guid,
                image,
                cmdline,
                user,
            },
        );
        to_json_event(m, "process_creation")
    }

    /// Build a process_termination (EID 5) event; `None` when the process is
    /// unknown to us (no Image available).
    pub fn exit_event(&mut self, pid: u32) -> Option<Event> {
        let info = self.parents.remove(&pid)?;
        let now = Utc::now();
        let mut m = base_event("process_termination", &now, &self.hostname);
        insert_str(&mut m, "UtcTime", &utc_time(&now));
        insert_str(&mut m, "ProcessGuid", &info.guid);
        insert_str(&mut m, "ProcessId", &pid.to_string());
        insert_str(&mut m, "Image", &info.image);
        insert_str(&mut m, "User", &info.user);
        Some(to_json_event(m, "process_termination"))
    }

    /// Build a network_connection (EID 3) event.
    pub fn net_event(&mut self, ev: &NetEvent) -> Event {
        let now = Utc::now();
        let (guid, image) = match self.parents.get(&ev.pid) {
            Some(info) => (info.guid.clone(), info.image.clone()),
            None => (NULL_GUID.to_string(), "-".to_string()),
        };
        let user = self.user_name(ev.uid);
        let is_v6 = ev.family == 10;
        let dest_ip = format_addr(&ev.addr, is_v6);
        let dest_port = u16::from_be(ev.port_be);
        let dest_port_s = dest_port.to_string();
        let (source_ip, source_port_s) =
            resolve_source_endpoint(ev.pid, is_v6, &ev.addr, dest_port).unwrap_or_else(|| {
                (
                    if is_v6 { "::" } else { "0.0.0.0" }.to_string(),
                    "0".to_string(),
                )
            });

        let mut m = base_event("network_connection", &now, &self.hostname);
        insert_str(&mut m, "UtcTime", &utc_time(&now));
        insert_str(&mut m, "ProcessGuid", &guid);
        insert_str(&mut m, "ProcessId", &ev.pid.to_string());
        insert_str(&mut m, "Image", &image);
        insert_str(&mut m, "User", &user);
        insert_str(&mut m, "Protocol", "tcp");
        insert_str(&mut m, "Initiated", "true");
        insert_str(&mut m, "SourceIsIpv6", &is_v6.to_string());
        insert_str(&mut m, "SourceIp", &source_ip);
        insert_str(&mut m, "SourceHostname", "-");
        insert_str(&mut m, "SourcePort", &source_port_s);
        insert_str(&mut m, "SourcePortName", "-");
        insert_str(&mut m, "DestinationIsIpv6", &is_v6.to_string());
        insert_str(&mut m, "DestinationIp", &dest_ip);
        insert_str(&mut m, "DestinationHostname", "-");
        insert_str(&mut m, "DestinationPort", &dest_port_s);
        insert_str(&mut m, "DestinationPortName", "-");
        to_json_event(m, "network_connection")
    }

    /// Build a network_listen (extension EID 500) event.
    pub fn listen_event(&mut self, ev: &ListenEvent) -> Event {
        let now = Utc::now();
        let (guid, image) = match self.parents.get(&ev.pid) {
            Some(info) => (info.guid.clone(), info.image.clone()),
            None => (NULL_GUID.to_string(), "-".to_string()),
        };
        let user = self.user_name(ev.uid);
        let is_v6 = ev.family == 10;
        let bind_ip = format_addr(&ev.addr, is_v6);
        let bind_port = u16::from_be(ev.port_be).to_string();
        let (dest_ip, dest_v6) = if is_v6 {
            ("::".to_string(), "true")
        } else {
            ("0.0.0.0".to_string(), "false")
        };

        let mut m = base_event("network_connection", &now, &self.hostname);
        insert_str(&mut m, "UtcTime", &utc_time(&now));
        insert_str(&mut m, "ProcessGuid", &guid);
        insert_str(&mut m, "ProcessId", &ev.pid.to_string());
        insert_str(&mut m, "Image", &image);
        insert_str(&mut m, "User", &user);
        insert_str(&mut m, "Protocol", "tcp");
        insert_str(&mut m, "Initiated", "false");
        insert_str(&mut m, "SourceIsIpv6", &is_v6.to_string());
        insert_str(&mut m, "SourceIp", &bind_ip);
        insert_str(&mut m, "SourceHostname", "-");
        insert_str(&mut m, "SourcePort", &bind_port);
        insert_str(&mut m, "SourcePortName", "-");
        insert_str(&mut m, "DestinationIsIpv6", &dest_v6);
        insert_str(&mut m, "DestinationIp", &dest_ip);
        insert_str(&mut m, "DestinationHostname", "-");
        insert_str(&mut m, "DestinationPort", "0");
        insert_str(&mut m, "DestinationPortName", "-");
        to_json_event(m, "network_connection")
    }

    /// Build a file_create (EID 11, category file_event) event.
    pub fn file_create_event(&mut self, ev: &FileCreateEvent) -> Event {
        let now = Utc::now();
        let guid = self
            .parents
            .get(&ev.pid)
            .map(|info| info.guid.clone())
            .unwrap_or_else(new_guid);
        let image = self
            .parents
            .get(&ev.pid)
            .map(|info| info.image.clone())
            .unwrap_or_else(|| "-".to_string());
        let user = self.user_name(ev.uid);
        let target = resolve_target(ev);
        let mut m = base_event("file_event", &now, &self.hostname);
        insert_str(&mut m, "UtcTime", &utc_time(&now));
        insert_str(&mut m, "ProcessGuid", &guid);
        insert_str(&mut m, "ProcessId", &ev.pid.to_string());
        insert_str(&mut m, "Image", &image);
        insert_str(&mut m, "TargetFilename", &target);
        insert_str(&mut m, "CreationUtcTime", &utc_time(&now));
        insert_str(&mut m, "User", &user);
        to_json_event(m, "file_event")
    }

    /// Build a file_delete (EID 23) event.
    pub fn file_delete_event(&mut self, ev: &FileDeleteEvent) -> Event {
        let now = Utc::now();
        let (guid, image) = match self.parents.get(&ev.pid) {
            Some(info) => (info.guid.clone(), info.image.clone()),
            None => (NULL_GUID.to_string(), "-".to_string()),
        };
        let user = self.user_name(ev.uid);
        let target = resolve_target_path(ev.pid, ev.dirfd, ev.path_str());
        let mut m = base_event("file_delete", &now, &self.hostname);
        insert_str(&mut m, "UtcTime", &utc_time(&now));
        insert_str(&mut m, "ProcessGuid", &guid);
        insert_str(&mut m, "ProcessId", &ev.pid.to_string());
        insert_str(&mut m, "User", &user);
        insert_str(&mut m, "Image", &image);
        insert_str(&mut m, "TargetFilename", &target);
        insert_str(&mut m, "Hashes", "-");
        insert_str(&mut m, "IsExecutable", "false");
        insert_str(&mut m, "Archived", "false");
        to_json_event(m, "file_delete")
    }

    /// Build a process_access (EID 10) event.
    pub fn process_access_event(&mut self, ev: &ProcessAccessEvent) -> Event {
        let now = Utc::now();
        let (src_guid, src_image) = self.resolve_process_info(ev.source_pid);
        let (tgt_guid, tgt_image) = self.resolve_process_info(ev.target_pid);
        let source_user = self.user_name(ev.source_uid);
        let granted = format!("0x{:x}", ev.request);
        let mut m = base_event("process_access", &now, &self.hostname);
        insert_str(&mut m, "UtcTime", &utc_time(&now));
        insert_str(&mut m, "SourceProcessGUID", &src_guid);
        insert_str(&mut m, "SourceProcessId", &ev.source_pid.to_string());
        insert_str(&mut m, "SourceThreadId", &ev.source_tid.to_string());
        insert_str(&mut m, "SourceImage", &src_image);
        insert_str(&mut m, "TargetProcessGUID", &tgt_guid);
        insert_str(&mut m, "TargetProcessId", &ev.target_pid.to_string());
        insert_str(&mut m, "TargetImage", &tgt_image);
        insert_str(&mut m, "GrantedAccess", &granted);
        insert_str(&mut m, "CallTrace", "-");
        insert_str(&mut m, "SourceUser", &source_user);
        to_json_event(m, "process_access")
    }

    fn resolve_process_info(&mut self, pid: u32) -> (String, String) {
        if let Some(info) = self.parents.get(&pid) {
            return (info.guid.clone(), info.image.clone());
        }
        let image = fs::read_link(format!("/proc/{pid}/exe"))
            .ok()
            .map(|p| p.to_string_lossy().into_owned())
            .unwrap_or_else(|| "-".to_string());
        (NULL_GUID.to_string(), image)
    }

    /// Build a raw_access_thread (EID 9) event.
    pub fn raw_access_event(&mut self, ev: &RawAccessEvent) -> Event {
        let now = Utc::now();
        let (guid, image) = self.resolve_process_info(ev.pid);
        let device = resolve_target_path(ev.pid, ev.dirfd, ev.path_str());
        let mut m = base_event("raw_access_thread", &now, &self.hostname);
        insert_str(&mut m, "UtcTime", &utc_time(&now));
        insert_str(&mut m, "ProcessGuid", &guid);
        insert_str(&mut m, "ProcessId", &ev.pid.to_string());
        insert_str(&mut m, "Image", &image);
        insert_str(&mut m, "Device", &device);
        to_json_event(m, "raw_access_thread")
    }

    /// Build a pipe_created (EID 17) event.
    pub fn pipe_create_event(&mut self, ev: &PipeCreateEvent) -> Event {
        let now = Utc::now();
        let (guid, image) = self.resolve_process_info(ev.pid);
        let user = self.user_name(ev.uid);
        let raw = ev.pipe_name_str();
        let pipe_name = if raw == "-" || raw.is_empty() {
            raw.to_string()
        } else {
            resolve_target_path(ev.pid, ev.dirfd, raw)
        };
        let mut m = base_event("pipe_created", &now, &self.hostname);
        insert_str(&mut m, "UtcTime", &utc_time(&now));
        insert_str(&mut m, "ProcessGuid", &guid);
        insert_str(&mut m, "ProcessId", &ev.pid.to_string());
        insert_str(&mut m, "PipeName", &pipe_name);
        insert_str(&mut m, "Image", &image);
        insert_str(&mut m, "User", &user);
        to_json_event(m, "pipe_created")
    }

    /// Build a pipe_connected (EID 18) event.
    pub fn pipe_connect_event(&mut self, ev: &PipeConnectEvent) -> Event {
        let now = Utc::now();
        let (guid, image) = self.resolve_process_info(ev.pid);
        let user = self.user_name(ev.uid);
        let raw = ev.pipe_name_str();
        let pipe_name = if raw.is_empty() {
            "-".to_string()
        } else {
            resolve_target_path(ev.pid, ev.dirfd, raw)
        };
        let mut m = base_event("pipe_created", &now, &self.hostname);
        insert_str(&mut m, "UtcTime", &utc_time(&now));
        insert_str(&mut m, "ProcessGuid", &guid);
        insert_str(&mut m, "ProcessId", &ev.pid.to_string());
        insert_str(&mut m, "PipeName", &pipe_name);
        insert_str(&mut m, "Image", &image);
        insert_str(&mut m, "User", &user);
        to_json_event(m, "pipe_created")
    }

    /// Build a driver_load (EID 6) event.
    pub fn driver_load_event(&mut self, ev: &DriverLoadEvent) -> Event {
        let now = Utc::now();
        let (guid, image) = self.resolve_process_info(ev.pid);
        let user = self.user_name(ev.uid);
        let image_loaded = if ev.fd >= 0 {
            fs::read_link(format!("/proc/{}/fd/{}", ev.pid, ev.fd))
                .ok()
                .map(|p| p.to_string_lossy().into_owned())
                .unwrap_or_else(|| "-".to_string())
        } else {
            "-".to_string()
        };
        let mut m = base_event("driver_load", &now, &self.hostname);
        insert_str(&mut m, "UtcTime", &utc_time(&now));
        insert_str(&mut m, "ProcessGuid", &guid);
        insert_str(&mut m, "ProcessId", &ev.pid.to_string());
        insert_str(&mut m, "Image", &image);
        insert_str(&mut m, "ImageLoaded", &image_loaded);
        insert_str(&mut m, "Hashes", "-");
        insert_str(&mut m, "Signed", "false");
        insert_str(&mut m, "Signature", "-");
        insert_str(&mut m, "SignatureStatus", "Unavailable");
        insert_str(&mut m, "User", &user);
        to_json_event(m, "driver_load")
    }

    /// Build a process_tampering (EID 25) event.
    pub fn process_tampering_event(&mut self, ev: &ProcessTamperingEvent) -> Event {
        let now = Utc::now();
        let (guid, image) = self.resolve_process_info(ev.source_pid);
        let user = self.user_name(ev.uid);
        let mut m = base_event("process_tampering", &now, &self.hostname);
        insert_str(&mut m, "UtcTime", &utc_time(&now));
        insert_str(&mut m, "ProcessGuid", &guid);
        insert_str(&mut m, "ProcessId", &ev.source_pid.to_string());
        insert_str(&mut m, "Image", &image);
        insert_str(&mut m, "Type", "CrossProcessMemoryWrite");
        insert_str(&mut m, "User", &user);
        to_json_event(m, "process_tampering")
    }

    /// Build a dns_query (EID 22) event.
    pub fn dns_event(&mut self, ev: &DnsEvent) -> Option<Event> {
        let end = ev.payload_len as usize;
        if end > ev.payload.len() {
            return None;
        }
        let query_name = parse_query_name(&ev.payload[..end])?;

        let now = Utc::now();
        let (guid, image) = match self.parents.get(&ev.pid) {
            Some(info) => (info.guid.clone(), info.image.clone()),
            None => (new_guid(), "-".to_string()),
        };
        let user = self.user_name(ev.uid);
        let mut m = base_event("dns_query", &now, &self.hostname);
        insert_str(&mut m, "UtcTime", &utc_time(&now));
        insert_str(&mut m, "ProcessGuid", &guid);
        insert_str(&mut m, "ProcessId", &ev.pid.to_string());
        insert_str(&mut m, "Image", &image);
        insert_str(&mut m, "User", &user);
        insert_str(&mut m, "QueryName", &query_name);
        insert_str(&mut m, "QueryStatus", "0");
        insert_str(&mut m, "QueryResults", "-");
        Some(to_json_event(m, "dns_query"))
    }

    fn user_name(&mut self, uid: u32) -> String {
        if let Some(name) = self.users.get(&uid) {
            return name.clone();
        }
        let name = lookup_user(uid).unwrap_or_else(|| uid.to_string());
        self.users.insert(uid, name.clone());
        name
    }

    fn image_hash(&mut self, pid: u32, image: &str) -> String {
        let resolved = fs::read_link(format!("/proc/{pid}/exe"))
            .map(|p| p.to_string_lossy().into_owned())
            .unwrap_or_else(|_| image.to_string());
        match self.cached_sha256(&resolved) {
            Some(hex) => format!("SHA256={hex}"),
            None => "-".to_string(),
        }
    }

    fn cached_sha256(&mut self, path: &str) -> Option<String> {
        let mtime = fs::metadata(path).ok()?.modified().ok()?;
        if let Some((seen_at, hash)) = self.hashes.get(path)
            && *seen_at == mtime
        {
            return Some(hash.clone());
        }
        let hash = compute_sha256(Path::new(path))?;
        if self.hashes.len() >= HASH_CACHE_CAP
            && let Some(evicted) = self.hash_order.pop_front()
        {
            self.hashes.remove(&evicted);
        }
        self.hash_order.push_back(path.to_string());
        self.hashes.insert(path.to_string(), (mtime, hash.clone()));
        Some(hash)
    }
}

/// Compute SHA256 of a regular file.
fn compute_sha256(path: &Path) -> Option<String> {
    use std::io::Read;

    let mut file = fs::File::open(path).ok()?;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 8192];
    loop {
        let n = file.read(&mut buf).ok()?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Some(hex::encode(hasher.finalize()))
}

const NULL_GUID: &str = "{00000000-0000-0000-0000-000000000000}";

fn base_event(category: &str, now: &chrono::DateTime<Utc>, hostname: &str) -> Map<String, Value> {
    let mut m = Map::new();
    insert_str(&mut m, "Computer", hostname);
    insert_str(&mut m, "EventTime", &now.to_rfc3339());
    insert_str(&mut m, "EventCategory", category);
    m
}

fn insert_str(m: &mut Map<String, Value>, k: &str, v: &str) {
    m.insert(k.to_string(), Value::String(v.to_string()));
}

/// Build the final Event: flat Sigma-field JSON, with logsource injected
/// (product: linux, category) and no Sysmon/service dependency.
fn to_json_event(fields: Map<String, Value>, category: &str) -> Event {
    let json = Value::Object(fields);
    let raw_bytes = serde_json::to_vec(&json).unwrap_or_default();
    // Use the same JSON for detection/raw views; inject linux logsource.
    let mut det = json.clone();
    if let Some(m) = det.as_object_mut() {
        m.insert("product".into(), Value::String("linux".into()));
        m.insert("category".into(), Value::String(category.into()));
    }
    Event {
        event_json_raw: std::sync::Arc::new(json),
        event_json: std::sync::Arc::new(det),
        event_raw: std::sync::Arc::new(raw_bytes),
        event_json_raw_all: None,
    }
}

/// Extract the question name from a raw DNS wire payload.
pub fn parse_query_name(payload: &[u8]) -> Option<String> {
    if payload.len() < 13 {
        return None;
    }
    let flags = u16::from_be_bytes([payload[2], payload[3]]);
    if flags & 0x8000 != 0 {
        return None;
    }
    let qdcount = u16::from_be_bytes([payload[4], payload[5]]);
    if qdcount == 0 {
        return None;
    }
    let mut pos = 12usize;
    let mut parts = Vec::new();
    loop {
        if pos >= payload.len() || parts.len() > 16 {
            return None;
        }
        let label = payload[pos];
        if label == 0 {
            break;
        }
        if label & 0xC0 != 0 || pos + 1 + label as usize > payload.len() {
            return None;
        }
        pos += 1;
        let chunk = String::from_utf8_lossy(&payload[pos..pos + label as usize]).to_string();
        parts.push(chunk);
        pos += label as usize;
    }
    if parts.is_empty() {
        return None;
    }
    Some(parts.join("."))
}

fn resolve_target_path(pid: u32, dirfd: i32, raw: &str) -> String {
    if raw.starts_with('/') || raw.is_empty() {
        return raw.to_string();
    }
    let base = if dirfd >= 0 {
        fs::read_link(format!("/proc/{pid}/fd/{dirfd}"))
    } else {
        fs::read_link(format!("/proc/{pid}/cwd"))
    }
    .map(|p| p.to_string_lossy().into_owned())
    .unwrap_or_default();
    match base.as_str() {
        "" => raw.to_string(),
        b => format!("{b}/{raw}"),
    }
}

fn resolve_target(ev: &FileCreateEvent) -> String {
    resolve_target_path(ev.pid, ev.dirfd, ev.path_str())
}

fn format_addr(addr: &[u8; 16], is_v6: bool) -> String {
    if is_v6 {
        std::net::Ipv6Addr::from(*addr).to_string()
    } else {
        format!("{}.{}.{}.{}", addr[0], addr[1], addr[2], addr[3])
    }
}

fn resolve_source_endpoint(
    pid: u32,
    is_v6: bool,
    dest_addr: &[u8; 16],
    dest_port: u16,
) -> Option<(String, String)> {
    let table = if is_v6 { "tcp6" } else { "tcp" };
    let path = format!("/proc/{pid}/net/{table}");
    let content = fs::read_to_string(path).ok()?;
    resolve_source_endpoint_from_proc(&content, is_v6, dest_addr, dest_port)
}

fn resolve_source_endpoint_from_proc(
    content: &str,
    is_v6: bool,
    dest_addr: &[u8; 16],
    dest_port: u16,
) -> Option<(String, String)> {
    let mut fallback = None;
    for line in content.lines().skip(1) {
        let Some(entry) = parse_proc_net_line(line, is_v6) else {
            continue;
        };
        if entry.remote_port != dest_port || !proc_addr_eq(&entry.remote_addr, dest_addr, is_v6) {
            continue;
        }
        if entry.state == 0x0A {
            continue;
        }
        let local = (
            format_proc_addr(&entry.local_addr, is_v6),
            entry.local_port.to_string(),
        );
        if entry.state == 0x01 {
            return Some(local);
        }
        if fallback.is_none() {
            fallback = Some(local);
        }
    }
    fallback
}

fn proc_addr_eq(parsed: &[u8; 16], dest: &[u8; 16], is_v6: bool) -> bool {
    if is_v6 {
        parsed == dest
    } else {
        parsed[..4] == dest[..4]
    }
}

fn format_proc_addr(addr: &[u8; 16], is_v6: bool) -> String {
    if is_v6 {
        std::net::Ipv6Addr::from(*addr).to_string()
    } else {
        format!("{}.{}.{}.{}", addr[0], addr[1], addr[2], addr[3])
    }
}

struct ProcNetLine {
    local_addr: [u8; 16],
    local_port: u16,
    remote_addr: [u8; 16],
    remote_port: u16,
    state: u8,
}

fn parse_proc_net_line(line: &str, is_v6: bool) -> Option<ProcNetLine> {
    let mut fields = line.split_whitespace();
    let _sl = fields.next()?;
    let local = fields.next()?;
    let remote = fields.next()?;
    let st = fields.next()?;
    let (local_addr, local_port) = parse_proc_endpoint(local, is_v6)?;
    let (remote_addr, remote_port) = parse_proc_endpoint(remote, is_v6)?;
    let state = u8::from_str_radix(st, 16).ok()?;
    Some(ProcNetLine {
        local_addr,
        local_port,
        remote_addr,
        remote_port,
        state,
    })
}

fn parse_proc_endpoint(token: &str, is_v6: bool) -> Option<([u8; 16], u16)> {
    let (addr_hex, port_hex) = token.split_once(':')?;
    let port = u16::from_str_radix(port_hex, 16).ok()?;
    let addr = if is_v6 {
        parse_proc_ipv6(addr_hex)?
    } else {
        parse_proc_ipv4(addr_hex)?
    };
    Some((addr, port))
}

fn parse_proc_ipv4(hex: &str) -> Option<[u8; 16]> {
    if hex.len() != 8 {
        return None;
    }
    let v = u32::from_str_radix(hex, 16).ok()?;
    let b = v.to_le_bytes();
    let mut out = [0u8; 16];
    out[..4].copy_from_slice(&b);
    Some(out)
}

fn parse_proc_ipv6(hex: &str) -> Option<[u8; 16]> {
    if hex.len() != 32 {
        return None;
    }
    let mut out = [0u8; 16];
    for (i, chunk) in (0..4).enumerate() {
        let start = chunk * 8;
        let v = u32::from_str_radix(&hex[start..start + 8], 16).ok()?;
        out[i * 4..i * 4 + 4].copy_from_slice(&v.to_le_bytes());
    }
    Some(out)
}

fn utc_time(now: &chrono::DateTime<Utc>) -> String {
    now.format("%Y-%m-%d %H:%M:%S%.3f").to_string()
}

fn new_guid() -> String {
    format!("{{{}}}", uuid::Uuid::new_v4())
}

fn full_cmdline(ev: &ExecEvent) -> String {
    if let Ok(raw) = fs::read(format!("/proc/{}/cmdline", ev.pid)) {
        let joined = raw
            .split(|&b| b == 0)
            .filter(|part| !part.is_empty())
            .map(|part| String::from_utf8_lossy(part))
            .collect::<Vec<_>>()
            .join(" ");
        if !joined.is_empty() {
            return joined;
        }
    }
    let arg0 = ev.arg0_str();
    let image = ev.image_str();
    match (arg0.is_empty(), image.is_empty()) {
        (true, true) => String::new(),
        (true, false) => image.to_string(),
        (false, true) => arg0.to_string(),
        (false, false) => format!("{image} {arg0}"),
    }
}


fn lookup_user(uid: u32) -> Option<String> {
    let passwd = fs::read_to_string("/etc/passwd").ok()?;
    passwd.lines().find_map(|line| {
        let mut parts = line.split(':');
        let name = parts.next()?;
        let _password = parts.next()?;
        match parts.next()?.parse::<u32>() {
            Ok(u) if u == uid => Some(name.to_string()),
            _ => None,
        }
    })
}

fn read_ppid(pid: u32) -> Option<u32> {
    let stat = fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let after_comm = stat.rsplit(')').next()?;
    let mut fields = after_comm.split_whitespace();
    fields.next()?;
    fields.next()?.parse().ok()
}

fn read_cwd(pid: u32) -> Option<String> {
    fs::read_link(format!("/proc/{pid}/cwd"))
        .ok()
        .map(|p| p.to_string_lossy().into_owned())
}

fn read_session_id(pid: u32) -> Option<u32> {
    fs::read_to_string(format!("/proc/{pid}/sessionid"))
        .ok()?
        .trim()
        .parse()
        .ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ebpf_common::{EVENT_EXEC, ExecEvent, IMAGE_LEN, ARG0_LEN, NetEvent, EVENT_NET};

    const FAKE_PID: u32 = u32::MAX;

    fn sample_exec(pid: u32) -> ExecEvent {
        let mut ev = ExecEvent {
            kind: EVENT_EXEC,
            pid,
            uid: 0,
            gid: 0,
            _pad0: 0,
            comm: *b"bash\0\0\0\0\0\0\0\0\0\0\0\0",
            image: [0; IMAGE_LEN],
            arg0: [0; ARG0_LEN],
            _pad1: 0,
        };
        ev.image[..12].copy_from_slice(b"/usr/bin/id\0");
        ev.arg0[..12].copy_from_slice(b"/usr/bin/id\0");
        ev
    }

    fn sample_net(family: u16, port_be: u16, addr: [u8; 16]) -> NetEvent {
        NetEvent {
            kind: EVENT_NET,
            pid: FAKE_PID,
            uid: 0,
            gid: 0,
            family,
            _pad0: 0,
            port_be,
            _pad1: 0,
            addr,
            comm: *b"curl\0\0\0\0\0\0\0\0\0\0\0\0",
        }
    }

    #[test]
    fn exec_event_emits_native_linux_json() {
        let mut b = EventBuilder::new();
        let event = b.exec_event(&sample_exec(FAKE_PID));
        assert_eq!(event.event_json["product"], "linux");
        assert_eq!(event.event_json["category"], "process_creation");
        assert!(event.event_json.get("service").is_none(), "no sysmon service");
        assert_eq!(event.event_json["Image"], "/usr/bin/id");
        assert_eq!(event.event_json["CommandLine"], "/usr/bin/id /usr/bin/id");
        assert_eq!(event.event_json["ProcessId"], FAKE_PID.to_string());
        assert_eq!(event.event_json["User"], "root");
        // raw is JSON bytes of the event
        let raw: serde_json::Value = serde_json::from_slice(&event.event_raw).unwrap();
        assert_eq!(raw["Image"], "/usr/bin/id");
        assert_eq!(raw["EventCategory"], "process_creation");
    }

    #[test]
    fn net_event_emits_native_linux_json() {
        let mut b = EventBuilder::new();
        let _ = b.exec_event(&sample_exec(FAKE_PID));
        let addr = [127, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        let event = b.net_event(&sample_net(2, 22u16.to_be(), addr));
        assert_eq!(event.event_json["product"], "linux");
        assert_eq!(event.event_json["category"], "network_connection");
        assert_eq!(event.event_json["DestinationIp"], "127.0.0.1");
        assert_eq!(event.event_json["DestinationPort"], "22");
        assert_eq!(event.event_json["Protocol"], "tcp");
        assert_eq!(event.event_json["Initiated"], "true");
    }

    #[test]
    fn taxonomy_file_is_embedded_and_valid_json() {
        let v: serde_json::Value = serde_json::from_str(EBPF_TAXONOMY_JSON).unwrap();
        assert_eq!(v["version"], 1);
        assert!(v["events"]["process_creation"].is_object());
        assert_eq!(v["events"]["process_creation"]["sigma_category"], "process_creation");
    }
}
