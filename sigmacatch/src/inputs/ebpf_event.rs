// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 sigmacatch contributors

//! Enrichment of kernel ring buffer records into Sysmon-schema events.
//!
//! The rendered XML is byte-compatible with what Sysmon-for-Linux writes to
//! syslog (golden samples: spec `stories/1-golden-samples/`); it then flows
//! through the exact same parsing pipeline as the legacy tail
//! (`parse_winevt_xml[_raw]` + logsource injection), so the matching engine
//! sees identical events from both sources.
//!
//! Hashes are `-` for now — in-kernel SHA256 is a dedicated follow-up step.

use std::collections::HashMap;
use std::collections::VecDeque;
use std::fs;
use std::path::Path;
use std::time::SystemTime;

use crate::ebpf_common::{
    DnsEvent, DriverLoadEvent, ExecEvent, FileCreateEvent, FileDeleteEvent, ListenEvent, NetEvent,
    ProcessAccessEvent,
};
use crate::types::Event;
use chrono::Utc;
use sha2::{Digest, Sha256};

const PROVIDER_GUID: &str = "{ff032593-a8d3-4f13-b0d6-01fc615a0f97}";
const CHANNEL: &str = "Linux-Sysmon/Operational";
const NULL_GUID: &str = "{00000000-0000-0000-0000-000000000000}";

/// Bounded memoization of image hashes keyed by resolved path, invalidated
/// by mtime change (pattern: rustinel IOC hash cache / SysmonForLinux).
const HASH_CACHE_CAP: usize = 4096;

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
    record_id: u64,
    hostname: String,
    exec_pid: u32,
    euid: u32,
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
            record_id: 0,
            hostname,
            exec_pid: std::process::id(),
            euid: read_euid(),
            parents: HashMap::new(),
            users: HashMap::new(),
            hashes: HashMap::new(),
            hash_order: VecDeque::new(),
        };
        builder.seed_from_proc();
        builder
    }

    /// Best-effort process table seeding from `/proc`. Synthetic GUIDs are
    /// generated for processes we did not observe starting; real exec events
    /// overwrite these entries when the same pid is seen again.
    fn seed_from_proc(&mut self) {
        let Ok(entries) = fs::read_dir("/proc") else {
            return;
        };
        for entry in entries.flatten() {
            let name = entry.file_name();
            let Some(pid) = name.to_str().and_then(|s| s.parse::<u32>().ok()) else {
                continue;
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

    /// Build the EID 1 (process_create) event for a kernel exec record.
    pub fn exec_event(&mut self, ev: &ExecEvent) -> Event {
        let now = Utc::now();
        let guid = new_guid();
        let image = ev.image_str().to_string();
        let cmdline = full_cmdline(ev);
        let user = self.user_name(ev.uid);
        let ppid = read_ppid(ev.pid);
        let parent_info = ppid.as_ref().and_then(|p| self.parents.get(p));

        // Parent fields mirror sysmon: unknown parents render as "-" / null
        // guid exactly like golden samples captured before our first exec.
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

        let xml = format!(
            "<Event><System>{system}</System><EventData>{data}</EventData></Event>",
            system = system_block(
                1,
                5,
                TASK_PROCESS_CREATE,
                &mut self.record_id,
                now,
                &self.hostname,
                self.exec_pid,
                self.euid,
            ),
            data = [
                data("RuleName", "-"),
                data("UtcTime", &utc_time(&now)),
                data("ProcessGuid", &guid),
                data("ProcessId", &ev.pid.to_string()),
                data("Image", &image),
                data("FileVersion", "-"),
                data("Description", "-"),
                data("Product", "-"),
                data("Company", "-"),
                data("OriginalFileName", "-"),
                data("CommandLine", &cmdline),
                data(
                    "CurrentDirectory",
                    &read_cwd(ev.pid).unwrap_or_else(|| "-".to_string()),
                ),
                data("User", &user),
                data("LogonGuid", NULL_GUID),
                data("LogonId", "0"),
                data(
                    "TerminalSessionId",
                    &read_session_id(ev.pid).unwrap_or(0).to_string(),
                ),
                data("IntegrityLevel", "no level"),
                data("Hashes", &self.image_hash(ev.pid, &image)),
                data("ParentProcessGuid", &parent_guid),
                data("ParentProcessId", &parent_pid),
                data("ParentImage", &parent_image),
                data("ParentCommandLine", &parent_cmdline),
                data("ParentUser", &parent_user),
            ]
            .concat(),
        );

        self.parents.insert(
            ev.pid,
            ParentInfo {
                guid,
                image,
                cmdline,
                user,
            },
        );
        to_event(xml)
    }

    /// Build the EID 5 (process_terminate) event; `None` when the process is
    /// unknown to us (no Image available — matches nothing useful anyway).
    pub fn exit_event(&mut self, pid: u32) -> Option<Event> {
        let info = self.parents.remove(&pid)?;
        let now = Utc::now();
        let xml = format!(
            "<Event><System>{system}</System><EventData>{data}</EventData></Event>",
            system = system_block(
                5,
                3,
                TASK_PROCESS_TERMINATE,
                &mut self.record_id,
                now,
                &self.hostname,
                self.exec_pid,
                self.euid,
            ),
            data = [
                data("RuleName", "-"),
                data("UtcTime", &utc_time(&now)),
                data("ProcessGuid", &info.guid),
                data("ProcessId", &pid.to_string()),
                data("Image", &info.image),
                data("User", &info.user),
            ]
            .concat(),
        );
        Some(to_event(xml))
    }

    /// Build the EID 3 (network_connection) event for a kernel connect
    /// record. Process identity comes from our exec cache; unknown processes
    /// render `-` fields exactly like sysmon does for untracked parents.
    ///
    /// Source endpoint enrichment is best-effort: `sys_enter_connect` runs
    /// before the local address/port is always assigned, so we resolve the
    /// local endpoint from `/proc/<pid>/net/tcp{,6}` by matching the remote
    /// destination. On any ambiguity, race or read failure we fall back to
    /// the previous neutral values (`0.0.0.0`/`::`, port `0`).
    pub fn net_event(&mut self, ev: &NetEvent) -> Event {
        let now = Utc::now();
        let (guid, image, _) = match self.parents.get(&ev.pid) {
            Some(info) => (info.guid.clone(), info.image.clone(), info.user.clone()),
            None => (NULL_GUID.to_string(), "-".to_string(), String::new()),
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

        let xml = format!(
            "<Event><System>{system}</System><EventData>{data}</EventData></Event>",
            system = system_block(
                3,
                5,
                TASK_NETWORK_CONNECT,
                &mut self.record_id,
                now,
                &self.hostname,
                self.exec_pid,
                self.euid,
            ),
            data = [
                data("RuleName", "-"),
                data("UtcTime", &utc_time(&now)),
                data("ProcessGuid", &guid),
                data("ProcessId", &ev.pid.to_string()),
                data("Image", &image),
                data("User", &user),
                data("Protocol", "tcp"),
                data("Initiated", "true"),
                data("SourceIsIpv6", &is_v6.to_string()),
                data("SourceIp", &source_ip),
                data("SourceHostname", "-"),
                data("SourcePort", &source_port_s),
                data("SourcePortName", "-"),
                data("DestinationIsIpv6", &is_v6.to_string()),
                data("DestinationIp", &dest_ip),
                data("DestinationHostname", "-"),
                data("DestinationPort", &dest_port_s),
                data("DestinationPortName", "-"),
            ]
            .concat(),
        );
        to_event(xml)
    }

    /// Build the extension EID 500 (network_listen) event for a socket that
    /// entered the listening state. This is a sigmacatch extension (not part
    /// of SigmaHQ's Linux Sysmon taxonomy v2.1.0): local bound endpoint is
    /// reported as `Source*`, destination fields are neutral because a passive
    /// listener has no peer.
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

        let xml = format!(
            "<Event><System>{system}</System><EventData>{data}</EventData></Event>",
            system = system_block(
                500,
                1,
                TASK_NETWORK_LISTEN,
                &mut self.record_id,
                now,
                &self.hostname,
                self.exec_pid,
                self.euid,
            ),
            data = [
                data("RuleName", "-"),
                data("UtcTime", &utc_time(&now)),
                data("ProcessGuid", &guid),
                data("ProcessId", &ev.pid.to_string()),
                data("Image", &image),
                data("User", &user),
                data("Protocol", "tcp"),
                data("Initiated", "false"),
                data("SourceIsIpv6", &is_v6.to_string()),
                data("SourceIp", &bind_ip),
                data("SourceHostname", "-"),
                data("SourcePort", &bind_port),
                data("SourcePortName", "-"),
                data("DestinationIsIpv6", dest_v6),
                data("DestinationIp", &dest_ip),
                data("DestinationHostname", "-"),
                data("DestinationPort", "0"),
                data("DestinationPortName", "-"),
            ]
            .concat(),
        );
        to_event(xml)
    }

    /// Build the EID 11 (file_create) event for a kernel openat(O_CREAT)
    /// record. Relative paths are resolved against the opener's dirfd/cwd
    /// while it is still alive; otherwise the raw kernel path is kept.
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
        let xml = format!(
            "<Event><System>{system}</System><EventData>{data}</EventData></Event>",
            system = system_block(
                11,
                2,
                TASK_FILE_CREATE,
                &mut self.record_id,
                now,
                &self.hostname,
                self.exec_pid,
                self.euid,
            ),
            data = [
                data("RuleName", "-"),
                data("UtcTime", &utc_time(&now)),
                data("ProcessGuid", &guid),
                data("ProcessId", &ev.pid.to_string()),
                data("Image", &image),
                data("TargetFilename", &target),
                data("CreationUtcTime", &utc_time(&now)),
                data("User", &user),
            ]
            .concat(),
        );
        to_event(xml)
    }

    /// Build the EID 23 (file_delete) event for a kernel unlink/unlinkat
    /// record. Relative paths are resolved against the deleter's dirfd/cwd
    /// while it is still alive; hashes/archiving metadata are unavailable from
    /// the syscall tracepoint and reported as `-`/`false`.
    pub fn file_delete_event(&mut self, ev: &FileDeleteEvent) -> Event {
        let now = Utc::now();
        let (guid, image) = match self.parents.get(&ev.pid) {
            Some(info) => (info.guid.clone(), info.image.clone()),
            None => (NULL_GUID.to_string(), "-".to_string()),
        };
        let user = self.user_name(ev.uid);
        let target = resolve_target_path(ev.pid, ev.dirfd, ev.path_str());
        let xml = format!(
            "<Event><System>{system}</System><EventData>{data}</EventData></Event>",
            system = system_block(
                23,
                5,
                TASK_FILE_DELETE,
                &mut self.record_id,
                now,
                &self.hostname,
                self.exec_pid,
                self.euid,
            ),
            data = [
                data("RuleName", "-"),
                data("UtcTime", &utc_time(&now)),
                data("ProcessGuid", &guid),
                data("ProcessId", &ev.pid.to_string()),
                data("User", &user),
                data("Image", &image),
                data("TargetFilename", &target),
                data("Hashes", "-"),
                data("IsExecutable", "false"),
                data("Archived", "false"),
            ]
            .concat(),
        );
        to_event(xml)
    }

    /// Build the EID 10 (process_access) event for a kernel ptrace record.
    /// `GrantedAccess` reflects the ptrace request code in hex; `CallTrace`
    /// is unavailable from a tracepoint and reported as `-`.
    pub fn process_access_event(&mut self, ev: &ProcessAccessEvent) -> Event {
        let now = Utc::now();
        let (src_guid, src_image) = self.resolve_process_info(ev.source_pid);
        let (tgt_guid, tgt_image) = self.resolve_process_info(ev.target_pid);
        let source_user = self.user_name(ev.source_uid);
        let granted = format!("0x{:x}", ev.request);
        let xml = format!(
            "<Event><System>{system}</System><EventData>{data}</EventData></Event>",
            system = system_block(
                10,
                3,
                TASK_PROCESS_ACCESS,
                &mut self.record_id,
                now,
                &self.hostname,
                self.exec_pid,
                self.euid,
            ),
            data = [
                data("RuleName", "-"),
                data("UtcTime", &utc_time(&now)),
                data("SourceProcessGUID", &src_guid),
                data("SourceProcessId", &ev.source_pid.to_string()),
                data("SourceThreadId", &ev.source_tid.to_string()),
                data("SourceImage", &src_image),
                data("TargetProcessGUID", &tgt_guid),
                data("TargetProcessId", &ev.target_pid.to_string()),
                data("TargetImage", &tgt_image),
                data("GrantedAccess", &granted),
                data("CallTrace", "-"),
                data("SourceUser", &source_user),
            ]
            .concat(),
        );
        to_event(xml)
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

    /// Build the EID 6 (driver_load / kernel module load) event for a
    /// `finit_module` syscall. `ImageLoaded` is resolved from the module fd;
    /// signature/hash metadata is unavailable and reported with safe defaults.
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
        let xml = format!(
            "<Event><System>{system}</System><EventData>{data}</EventData></Event>",
            system = system_block(
                6,
                3,
                TASK_DRIVER_LOAD,
                &mut self.record_id,
                now,
                &self.hostname,
                self.exec_pid,
                self.euid,
            ),
            data = [
                data("RuleName", "-"),
                data("UtcTime", &utc_time(&now)),
                data("ProcessGuid", &guid),
                data("ProcessId", &ev.pid.to_string()),
                data("Image", &image),
                data("ImageLoaded", &image_loaded),
                data("Hashes", "-"),
                data("Signed", "false"),
                data("Signature", "-"),
                data("SignatureStatus", "Unavailable"),
                data("User", &user),
            ]
            .concat(),
        );
        to_event(xml)
    }

    /// Build the extension EID 22 (dns_query) event for a kernel DNS record.
    /// Field order follows the Windows Sysmon EID 22 schema (no golden exists
    /// for Linux — sysmon-for-linux does not emit this event); QueryResults is
    /// always `-` because responses are not observed.
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
        let xml = format!(
            "<Event><System>{system}</System><EventData>{data}</EventData></Event>",
            system = system_block(
                22,
                5,
                TASK_DNS_QUERY,
                &mut self.record_id,
                now,
                &self.hostname,
                self.exec_pid,
                self.euid,
            ),
            data = [
                data("RuleName", "-"),
                data("UtcTime", &utc_time(&now)),
                data("ProcessGuid", &guid),
                data("ProcessId", &ev.pid.to_string()),
                data("Image", &image),
                data("User", &user),
                data("QueryName", &query_name),
                data("QueryStatus", "0"),
                data("QueryResults", "-"),
            ]
            .concat(),
        );
        Some(to_event(xml))
    }

    fn user_name(&mut self, uid: u32) -> String {
        if let Some(name) = self.users.get(&uid) {
            return name.clone();
        }
        let name = lookup_user(uid).unwrap_or_else(|| uid.to_string());
        self.users.insert(uid, name.clone());
        name
    }

    /// Sysmon `Hashes` value for the executed image: `SHA256=<hex>`, or `-`
    /// when neither `/proc/<pid>/exe` nor the recorded path is readable.
    ///
    /// Resolution prefers the proc symlink: it stays valid after unlink and
    /// dedupes hardlink/bind-mount aliases through its canonical target.
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

/// Streaming SHA256 of a regular file; `None` when unreadable (deleted,
/// permission, I/O error). Oversized images are hashed anyway — execs are
/// rare enough that the cost is acceptable and sysmon does not cap either.
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

#[allow(clippy::too_many_arguments)]
fn system_block(
    event_id: u32,
    version: u8,
    task: u32,
    record_id: &mut u64,
    now: chrono::DateTime<Utc>,
    hostname: &str,
    exec_pid: u32,
    euid: u32,
) -> String {
    *record_id += 1;
    format!(
        "<Provider Name=\"Linux-Sysmon\" Guid=\"{PROVIDER_GUID}\"/>\
         <EventID>{event_id}</EventID>\
         <Version>{version}</Version>\
         <Level>4</Level>\
         <Task>{task}</Task>\
         <Opcode>0</Opcode>\
         <Keywords>0x8000000000000000</Keywords>\
         <TimeCreated SystemTime=\"{}\"/>\
         <EventRecordID>{record_id}</EventRecordID>\
         <Correlation/>\
         <Execution ProcessID=\"{exec_pid}\" ThreadID=\"{exec_pid}\"/>\
         <Channel>{CHANNEL}</Channel>\
         <Computer>{hostname}</Computer>\
         <Security UserId=\"{euid}\"/>",
        now.format("%Y-%m-%dT%H:%M:%S%.9fZ"),
    )
}

/// Extract the question name from a raw DNS wire payload (query direction
/// only: response flag and compression pointers are rejected). Bounded walk:
/// ≤16 labels of the header-anchored question section.
pub fn parse_query_name(payload: &[u8]) -> Option<String> {
    if payload.len() < 13 {
        return None;
    }
    let flags = u16::from_be_bytes([payload[2], payload[3]]);
    if flags & 0x8000 != 0 {
        return None; // response, not query
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

const TASK_PROCESS_CREATE: u32 = 1;
const TASK_PROCESS_TERMINATE: u32 = 5;
const TASK_NETWORK_CONNECT: u32 = 3;
const TASK_DRIVER_LOAD: u32 = 6;
const TASK_PROCESS_ACCESS: u32 = 10;
const TASK_FILE_CREATE: u32 = 11;
const TASK_DNS_QUERY: u32 = 22;
const TASK_FILE_DELETE: u32 = 23;
const TASK_NETWORK_LISTEN: u32 = 500;

/// Absolute TargetFilename: kernel-relative paths are resolved through the
/// process's `/proc` handles while it is alive; dead processes keep the raw
/// path (best effort, same trade-off as rustinel's command line).
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

/// Dotted quad for v4, compressed RFC-5952 for v6.
fn format_addr(addr: &[u8; 16], is_v6: bool) -> String {
    if is_v6 {
        std::net::Ipv6Addr::from(*addr).to_string()
    } else {
        format!("{}.{}.{}.{}", addr[0], addr[1], addr[2], addr[3])
    }
}

/// Best-effort local endpoint for a connect event, resolved from the
/// process's `/proc/<pid>/net/tcp{,6}` table by matching the remote
/// destination. Returns `None` on any read/parse/ambiguity failure so the
/// caller can keep the neutral fallback.
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

/// Parse a `/proc/net/tcp` or `tcp6` table and return the local endpoint of a
/// socket whose remote address/port matches `dest`. Prefers `ESTABLISHED`
/// (`01`) but accepts any non-`LISTEN` socket with a matching remote, since
/// `sys_enter_connect` may be observed around state transitions.
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
        // 0A = LISTEN (no remote); never a connect endpoint.
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

/// Parse one data line of `/proc/net/tcp{,6}`.
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

fn data(name: &str, value: &str) -> String {
    format!("<Data Name=\"{}\">{}</Data>", escape(name), escape(value))
}

fn escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

fn new_guid() -> String {
    format!("{{{}}}", uuid::Uuid::new_v4())
}

/// Full command line: `/proc/<pid>/cmdline` when the process is still alive
/// (NULs joined with spaces), else the race-free kernel capture
/// `image arg0`.
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

/// Render + parse through the legacy pipeline so engine inputs are
/// indistinguishable from tailed-sysmon events.
fn to_event(xml: String) -> Event {
    let (json_raw, json) =
        crate::types::parse_winevt_xml_both(&xml).expect("rendered XML must always parse");
    Event::new_injected(json_raw, json, xml.into_bytes(), "linux", None)
}

fn read_euid() -> u32 {
    fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|s| {
            s.lines()
                .find_map(|l| l.strip_prefix("Uid:"))
                .and_then(|rest| rest.split_whitespace().nth(1)?.parse::<u32>().ok())
        })
        .unwrap_or(0)
}

fn lookup_user(uid: u32) -> Option<String> {
    let passwd = fs::read_to_string("/etc/passwd").ok()?;
    passwd.lines().find_map(|line| {
        let mut parts = line.split(':');
        let name = parts.next()?;
        let _password = parts.next()?; // "x" on modern systems
        match parts.next()?.parse::<u32>() {
            Ok(u) if u == uid => Some(name.to_string()),
            _ => None,
        }
    })
}

/// Parent pid from `/proc/<pid>/stat` (field 4, after the comm parenthesis).
fn read_ppid(pid: u32) -> Option<u32> {
    let stat = fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let after_comm = stat.rsplit(')').next()?;
    let mut fields = after_comm.split_whitespace();
    fields.next()?; // state
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
    use crate::ebpf_common::{ARG0_LEN, EVENT_EXEC, EVENT_NET, IMAGE_LEN, NetEvent};

    // PID that cannot belong to a real process: way past kernel pid_max
    // (<= 4194304), so /proc/<pid> lookups always fall back to the
    // kernel-captured fields — deterministic on any host, including CI.
    pub(super) const FAKE_PID: u32 = u32::MAX;

    pub(super) fn sample_net(family: u16, port_be: u16, addr: [u8; 16]) -> NetEvent {
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

    pub(super) fn sample_exec(pid: u32) -> ExecEvent {
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

    #[test]
    fn eid1_matches_golden_shape_and_order() {
        let mut builder = EventBuilder::new();
        let event = builder.exec_event(&sample_exec(FAKE_PID));
        let xml = String::from_utf8(event.event_raw.as_ref().clone()).expect("utf8 xml");

        // Golden structure markers.
        assert!(xml.starts_with("<Event><System>"));
        assert!(xml.ends_with("</EventData></Event>"));
        assert!(xml.contains("<EventID>1</EventID>"));
        assert!(xml.contains("<Version>5</Version>"));
        assert!(xml.contains("<Task>1</Task>"));
        assert!(xml.contains("<Channel>Linux-Sysmon/Operational</Channel>"));
        assert!(xml.contains("<Data Name=\"Image\">/usr/bin/id</Data>"));
        // /proc/<pid>/cmdline is unreadable for the fake pid: kernel fallback.
        assert!(xml.contains("<Data Name=\"CommandLine\">/usr/bin/id /usr/bin/id</Data>"));
        assert!(xml.contains("<Data Name=\"User\">root</Data>"));
        // Real /usr/bin/id exists on the test host: a full hash is expected.
        let hashes = xml
            .split("<Data Name=\"Hashes\">")
            .nth(1)
            .and_then(|rest| rest.split("</Data>").next())
            .expect("Hashes field");
        assert!(
            hashes.starts_with("SHA256=") && hashes.len() == 7 + 64,
            "{hashes}"
        );
        assert!(xml.contains("<Data Name=\"IntegrityLevel\">no level</Data>"));

        // Field order must match the golden sample byte-for-byte layout.
        let order = [
            "RuleName",
            "UtcTime",
            "ProcessGuid",
            "ProcessId",
            "Image",
            "FileVersion",
            "Description",
            "Product",
            "Company",
            "OriginalFileName",
            "CommandLine",
            "CurrentDirectory",
            "User",
            "LogonGuid",
            "LogonId",
            "TerminalSessionId",
            "IntegrityLevel",
            "Hashes",
            "ParentProcessGuid",
            "ParentProcessId",
            "ParentImage",
            "ParentCommandLine",
            "ParentUser",
        ];
        let mut last = 0;
        for field in order {
            let pos = xml.find(&format!("Name=\"{field}\"")).expect(field);
            assert!(pos > last, "field {field} out of order");
            last = pos;
        }

        // Round-trip through the legacy parsing pipeline.
        assert_eq!(event.event_json["product"], "linux");
        assert_eq!(event.event_json["service"], "sysmon");
        assert_eq!(event.event_json["category"], "process_creation");
    }

    #[test]
    fn eid1_unknown_parent_renders_null_fields() {
        let mut builder = EventBuilder::new();
        let event = builder.exec_event(&sample_exec(FAKE_PID));
        let xml = String::from_utf8(event.event_raw.as_ref().clone()).expect("utf8");
        assert!(xml.contains(
            "<Data Name=\"ParentProcessGuid\">{00000000-0000-0000-0000-000000000000}</Data>"
        ));
        assert!(xml.contains("<Data Name=\"ParentImage\">-</Data>"));
        assert!(xml.contains("<Data Name=\"ParentProcessId\">-</Data>"));
    }

    #[test]
    fn unreadable_image_falls_back_to_dash() {
        let mut ev = sample_exec(FAKE_PID);
        let missing = b"/sigmacatch/no/such/binary\0";
        ev.image[..missing.len()].copy_from_slice(missing);
        let mut builder = EventBuilder::new();
        let event = builder.exec_event(&ev);
        let xml = String::from_utf8(event.event_raw.as_ref().clone()).expect("utf8");
        assert!(xml.contains("<Data Name=\"Hashes\">-</Data>"));
        // CommandLine still falls back to image arg0 even when unhashable.
        assert!(
            xml.contains(
                "<Data Name=\"CommandLine\">/sigmacatch/no/such/binary /usr/bin/id</Data>"
            )
        );
    }

    #[test]
    fn hash_cache_invalidates_on_mtime_change() {
        let mut builder = EventBuilder::new();
        let path = "/etc/hostname";
        let first = builder.cached_sha256(path).expect("hashable");
        // Stale entry with an impossible mtime must be recomputed.
        builder
            .hashes
            .insert(path.to_string(), (SystemTime::UNIX_EPOCH, "stale".into()));
        assert_ne!(builder.cached_sha256(path), Some("stale".to_string()));
        assert_eq!(builder.cached_sha256(path), Some(first));
    }

    #[test]
    fn exit_requires_known_process() {
        let mut builder = EventBuilder::new();
        assert!(builder.exit_event(999_999).is_none());
    }

    #[test]
    fn eid5_after_exec_carries_cached_image() {
        let mut builder = EventBuilder::new();
        let _exec = builder.exec_event(&sample_exec(FAKE_PID));
        let event = builder.exit_event(FAKE_PID).expect("known process exits");
        let xml = String::from_utf8(event.event_raw.as_ref().clone()).expect("utf8");

        assert!(xml.contains("<EventID>5</EventID>"));
        assert!(xml.contains("<Version>3</Version>"));
        assert!(xml.contains("<Task>5</Task>"));
        assert!(xml.contains("<Data Name=\"Image\">/usr/bin/id</Data>"));
        assert!(!xml.contains("CommandLine"));
        assert_eq!(event.event_json["service"], "sysmon");
        assert_eq!(event.event_json["category"], "process_termination");
    }

    #[test]
    fn cmdline_is_xml_escaped() {
        let mut ev = sample_exec(FAKE_PID);
        let evil = b"/bin/echo <script>&amp;\0";
        ev.arg0[..evil.len()].copy_from_slice(evil);
        // image stays clean; the escaped content must come from arg0.
        let mut builder = EventBuilder::new();
        let event = builder.exec_event(&ev);
        let xml = String::from_utf8(event.event_raw.as_ref().clone()).expect("utf8");
        assert!(xml.contains("&lt;script&gt;&amp;amp;"));
        assert!(
            !xml[xml.find("<Data Name=\"CommandLine\"").expect("cmdline")..].contains("<script>")
        );
    }

    #[test]
    fn seed_from_proc_is_best_effort() {
        let mut users = HashMap::new();
        assert!(EventBuilder::read_proc_info(FAKE_PID, &mut users).is_none());
        // Must not panic even if /proc is partially unreadable.
        let builder = EventBuilder::new();
        let _ = builder.parents.len();
    }
}

#[cfg(test)]
mod net_tests {
    use super::tests::{FAKE_PID, sample_exec, sample_net};
    use super::*;

    #[test]
    fn eid3_ipv4_matches_golden_shape_and_order() {
        let mut builder = EventBuilder::new();
        // Seed the process cache so Image/ProcessGuid resolve.
        let _ = builder.exec_event(&sample_exec(FAKE_PID));

        let addr = [127, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        let event = builder.net_event(&sample_net(2, 22u16.to_be(), addr));
        let xml = String::from_utf8(event.event_raw.as_ref().clone()).expect("utf8");

        assert!(xml.contains("<EventID>3</EventID>"));
        assert!(xml.contains("<Version>5</Version>"));
        assert!(xml.contains("<Task>3</Task>"));
        assert!(xml.contains("<Data Name=\"Protocol\">tcp</Data>"));
        assert!(xml.contains("<Data Name=\"Initiated\">true</Data>"));
        assert!(xml.contains("<Data Name=\"SourceIsIpv6\">false</Data>"));
        assert!(xml.contains("<Data Name=\"SourceIp\">0.0.0.0</Data>"));
        assert!(xml.contains("<Data Name=\"DestinationIp\">127.0.0.1</Data>"));
        assert!(xml.contains("<Data Name=\"DestinationPort\">22</Data>"));
        assert!(xml.contains("<Data Name=\"Image\">/usr/bin/id</Data>"));
        assert!(xml.contains("<Data Name=\"User\">root</Data>"));

        let order = [
            "RuleName",
            "UtcTime",
            "ProcessGuid",
            "ProcessId",
            "Image",
            "User",
            "Protocol",
            "Initiated",
            "SourceIsIpv6",
            "SourceIp",
            "SourceHostname",
            "SourcePort",
            "SourcePortName",
            "DestinationIsIpv6",
            "DestinationIp",
            "DestinationHostname",
            "DestinationPort",
            "DestinationPortName",
        ];
        let mut last = 0;
        for field in order {
            let pos = xml.find(&format!("Name=\"{field}\"")).expect(field);
            assert!(pos > last, "field {field} out of order");
            last = pos;
        }

        assert_eq!(event.event_json["service"], "sysmon");
        assert_eq!(event.event_json["category"], "network_connection");
    }

    #[test]
    fn eid3_ipv6_and_unknown_process() {
        let mut builder = EventBuilder::new();
        let addr: [u8; 16] = std::net::Ipv6Addr::LOCALHOST.octets();
        let event = builder.net_event(&sample_net(10, 8080u16.to_be(), addr));
        let xml = String::from_utf8(event.event_raw.as_ref().clone()).expect("utf8");

        assert!(xml.contains("<Data Name=\"DestinationIsIpv6\">true</Data>"));
        assert!(xml.contains("<Data Name=\"DestinationIp\">::1</Data>"));
        assert!(xml.contains("<Data Name=\"DestinationPort\">8080</Data>"));
        assert!(xml.contains("<Data Name=\"SourceIsIpv6\">true</Data>"));
        // Unknown process: sysmon-style null guid + dash image.
        assert!(
            xml.contains(
                "<Data Name=\"ProcessGuid\">{00000000-0000-0000-0000-000000000000}</Data>"
            )
        );
        assert!(xml.contains("<Data Name=\"Image\">-</Data>"));
        assert_eq!(event.event_json["category"], "network_connection");
    }

    #[test]
    fn resolve_source_endpoint_from_tcp_table() {
        // dest 127.0.0.1 (0100007F LE hex) port 22 (0016), local 10.0.2.15 (0F02000A) port 45678 (B26E)
        let table = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n\
   0: 0100007F:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 1 1 0 100 0 0 10 0\n\
   5: 0F02000A:B26E 0100007F:0016 01 00000000:00000000 00:00000000 00000000  1000        0 12345 1 0 20 4 30 10 -1\n";
        let mut dest = [0u8; 16];
        dest[..4].copy_from_slice(&[127, 0, 0, 1]);
        let (src_ip, src_port) =
            resolve_source_endpoint_from_proc(table, false, &dest, 22).expect("resolved");
        assert_eq!(src_ip, "10.0.2.15");
        assert_eq!(src_port, "45678");
    }

    #[test]
    fn resolve_source_endpoint_from_tcp6_table() {
        // dest ::1 port 8080 (1F90), local ::1 port 50000 (C350), ESTABLISHED
        let table = "  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n\
   0: 00000000000000000000000001000000:C350 00000000000000000000000001000000:1F90 01 00000000:00000000 00:00000000 00000000     0        0 99 1 0 20 4 30 10 -1\n";
        let dest = std::net::Ipv6Addr::LOCALHOST.octets();
        let (src_ip, src_port) =
            resolve_source_endpoint_from_proc(table, true, &dest, 8080).expect("resolved");
        assert_eq!(src_ip, "::1");
        assert_eq!(src_port, "50000");
    }

    #[test]
    fn resolve_source_endpoint_falls_back_when_unmatched() {
        let table = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n\
   0: 0100007F:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 1 1 0 100 0 0 10 0\n";
        let mut dest = [0u8; 16];
        dest[..4].copy_from_slice(&[127, 0, 0, 1]);
        assert!(resolve_source_endpoint_from_proc(table, false, &dest, 22).is_none());
    }
}

#[cfg(test)]
mod file_tests {
    use super::tests::{FAKE_PID, sample_exec};
    use super::*;
    use crate::ebpf_common::{AT_FDCWD, EVENT_FILE, PATH_LEN};

    fn sample_file(pid: u32) -> FileCreateEvent {
        let mut ev = FileCreateEvent {
            kind: EVENT_FILE,
            pid,
            uid: 0,
            gid: 0,
            dirfd: AT_FDCWD,
            _pad0: 0,
            path: [0; PATH_LEN],
            comm: *b"touch\0\0\0\0\0\0\0\0\0\0\0",
        };
        let p = b"/etc/doas.conf\0";
        ev.path[..p.len()].copy_from_slice(p);
        ev
    }

    #[test]
    fn eid11_matches_golden_shape_and_order() {
        let mut builder = EventBuilder::new();
        let _ = builder.exec_event(&sample_exec(FAKE_PID));
        let event = builder.file_create_event(&sample_file(FAKE_PID));
        let xml = String::from_utf8(event.event_raw.as_ref().clone()).expect("utf8");

        assert!(xml.contains("<EventID>11</EventID>"));
        assert!(xml.contains("<Version>2</Version>"));
        assert!(xml.contains("<Task>11</Task>"));
        assert!(xml.contains("<Data Name=\"TargetFilename\">/etc/doas.conf</Data>"));
        // CreationUtcTime mirrors UtcTime for freshly created files.
        let utc = xml
            .split("<Data Name=\"UtcTime\">")
            .nth(1)
            .and_then(|rest| rest.split("</Data>").next())
            .expect("UtcTime");
        assert!(xml.contains(&format!("<Data Name=\"CreationUtcTime\">{utc}</Data>")));
        assert!(xml.contains("<Data Name=\"Image\">/usr/bin/id</Data>"));
        assert_eq!(event.event_json["service"], "sysmon");
        assert_eq!(event.event_json["category"], "file_event");

        let order = [
            "RuleName",
            "UtcTime",
            "ProcessGuid",
            "ProcessId",
            "Image",
            "TargetFilename",
            "CreationUtcTime",
            "User",
        ];
        let mut last = 0;
        for field in order {
            let pos = xml.find(&format!("Name=\"{field}\"")).expect(field);
            assert!(pos > last, "field {field} out of order");
            last = pos;
        }
    }

    #[test]
    fn relative_path_resolves_against_cwd() {
        let mut builder = EventBuilder::new();
        let _ = builder.exec_event(&sample_exec(std::process::id()));
        let mut ev = sample_file(std::process::id());
        ev.dirfd = AT_FDCWD;
        let rel = b"sigmacatch_rel_test.txt\0";
        ev.path[..rel.len()].copy_from_slice(rel);
        let event = builder.file_create_event(&ev);
        let xml = String::from_utf8(event.event_raw.as_ref().clone()).expect("utf8");
        let cwd = std::env::current_dir()
            .unwrap()
            .to_string_lossy()
            .into_owned();
        assert!(xml.contains(&format!(
            "<Data Name=\"TargetFilename\">{cwd}/sigmacatch_rel_test.txt</Data>"
        )));
    }

    #[test]
    fn dead_opener_keeps_raw_relative_path() {
        let mut builder = EventBuilder::new();
        let mut ev = sample_file(999_999);
        ev.dirfd = 5;
        let rel = b"sub/file.conf\0";
        ev.path[..rel.len()].copy_from_slice(rel);
        let event = builder.file_create_event(&ev);
        let xml = String::from_utf8(event.event_raw.as_ref().clone()).expect("utf8");
        assert!(xml.contains("<Data Name=\"TargetFilename\">sub/file.conf</Data>"));
    }
}

#[cfg(test)]
mod file_delete_tests {
    use super::tests::{FAKE_PID, sample_exec};
    use super::*;
    use crate::ebpf_common::{AT_FDCWD, EVENT_FILE_DELETE, PATH_LEN};

    fn sample_delete(pid: u32) -> FileDeleteEvent {
        let mut ev = FileDeleteEvent {
            kind: EVENT_FILE_DELETE,
            pid,
            uid: 0,
            gid: 0,
            dirfd: AT_FDCWD,
            _pad0: 0,
            path: [0; PATH_LEN],
            comm: [0; 16],
        };
        let p = b"/etc/doas.conf\0";
        ev.path[..p.len()].copy_from_slice(p);
        ev.comm[..2].copy_from_slice(b"rm");
        ev
    }

    #[test]
    fn eid23_shape_order_and_category() {
        let mut builder = EventBuilder::new();
        let _ = builder.exec_event(&sample_exec(FAKE_PID));
        let event = builder.file_delete_event(&sample_delete(FAKE_PID));
        let xml = String::from_utf8(event.event_raw.as_ref().clone()).expect("utf8");

        assert!(xml.contains("<EventID>23</EventID>"));
        assert!(xml.contains("<Version>5</Version>"));
        assert!(xml.contains("<Task>23</Task>"));
        assert!(xml.contains("<Data Name=\"TargetFilename\">/etc/doas.conf</Data>"));
        assert!(xml.contains("<Data Name=\"Hashes\">-</Data>"));
        assert!(xml.contains("<Data Name=\"IsExecutable\">false</Data>"));
        assert!(xml.contains("<Data Name=\"Archived\">false</Data>"));
        assert!(xml.contains("<Data Name=\"Image\">/usr/bin/id</Data>"));
        assert_eq!(event.event_json["service"], "sysmon");
        assert_eq!(event.event_json["category"], "file_delete");

        let order = [
            "RuleName",
            "UtcTime",
            "ProcessGuid",
            "ProcessId",
            "User",
            "Image",
            "TargetFilename",
            "Hashes",
            "IsExecutable",
            "Archived",
        ];
        let mut last = 0;
        for field in order {
            let pos = xml.find(&format!("Name=\"{field}\"")).expect(field);
            assert!(pos > last, "field {field} out of order");
            last = pos;
        }
    }

    #[test]
    fn eid23_unknown_process_falls_back() {
        let mut builder = EventBuilder::new();
        let event = builder.file_delete_event(&sample_delete(999_999));
        let xml = String::from_utf8(event.event_raw.as_ref().clone()).expect("utf8");
        assert!(xml.contains("<EventID>23</EventID>"));
        assert!(xml.contains("<Data Name=\"Image\">-</Data>"));
        assert!(
            xml.contains(
                "<Data Name=\"ProcessGuid\">{00000000-0000-0000-0000-000000000000}</Data>"
            )
        );
        assert_eq!(event.event_json["category"], "file_delete");
    }
}

#[cfg(test)]
mod dns_tests {
    use super::tests::{FAKE_PID, sample_exec};
    use super::*;
    use crate::ebpf_common::{DNS_PAYLOAD_LEN, DnsEvent, EVENT_DNS};

    /// Wire bytes for a query of `name` type A (header id=0x1234).
    fn dns_query_wire(name: &str) -> Vec<u8> {
        let mut out = vec![0x12, 0x34, 0x01, 0x00, 0, 1, 0, 1, 0, 0, 0, 0];
        for label in name.split('.') {
            out.push(label.len() as u8);
            out.extend_from_slice(label.as_bytes());
        }
        out.push(0);
        out.extend([0, 1, 0, 1]); // QTYPE=A, QCLASS=IN
        out
    }

    fn sample_dns(pid: u32, wire: &[u8]) -> DnsEvent {
        let mut ev = DnsEvent {
            kind: EVENT_DNS,
            pid,
            uid: 0,
            gid: 0,
            payload_len: wire.len() as u32,
            _pad0: 0,
            comm: *b"dig\0\0\0\0\0\0\0\0\0\0\0\0\0",
            payload: [0; DNS_PAYLOAD_LEN],
        };
        let n = wire.len().min(DNS_PAYLOAD_LEN);
        ev.payload[..n].copy_from_slice(&wire[..n]);
        ev
    }

    #[test]
    fn query_name_extraction() {
        let wire = dns_query_wire("story6.sigmacatch.test");
        assert_eq!(
            parse_query_name(&wire).as_deref(),
            Some("story6.sigmacatch.test")
        );
        // Single label.
        assert_eq!(
            parse_query_name(&dns_query_wire("localhost")).as_deref(),
            Some("localhost")
        );
    }

    #[test]
    fn malformed_payloads_are_rejected() {
        let mut response = dns_query_wire("x.test");
        response[2] = 0x81; // QR=1 → response
        assert_eq!(parse_query_name(&response), None);
        assert_eq!(parse_query_name(&[0u8; 10]), None); // too short
        let mut compressed = dns_query_wire("a.b");
        compressed[14] |= 0xC0; // second label length becomes a pointer
        assert_eq!(parse_query_name(&compressed), None);
    }

    #[test]
    fn eid22_xml_fields_and_category() {
        let wire = dns_query_wire("story6.sigmacatch.test");
        let mut builder = EventBuilder::new();
        let _ = builder.exec_event(&sample_exec(FAKE_PID));
        let event = builder
            .dns_event(&sample_dns(FAKE_PID, &wire))
            .expect("valid");

        let xml = String::from_utf8(event.event_raw.as_ref().clone()).expect("utf8");
        for field in [
            "RuleName",
            "UtcTime",
            "ProcessGuid",
            "ProcessId",
            "Image",
            "User",
            "QueryName",
            "QueryStatus",
            "QueryResults",
        ] {
            assert!(
                xml.contains(&format!("Name=\"{field}\"")),
                "{field} missing"
            );
        }
        assert!(xml.contains("<Data Name=\"QueryName\">story6.sigmacatch.test</Data>"));
        assert!(xml.contains("<Data Name=\"QueryStatus\">0</Data>"));
        assert!(xml.contains("<EventID>22</EventID>"));
        assert_eq!(event.event_json["service"], "sysmon");
        assert_eq!(event.event_json["category"], "dns_query");
    }

    #[test]
    fn non_query_payload_returns_none() {
        let mut builder = EventBuilder::new();
        // Truncated garbage (len < header).
        assert!(
            builder
                .dns_event(&sample_dns(FAKE_PID, &[1, 2, 3]))
                .is_none()
        );
    }
}

#[cfg(test)]
mod listen_tests {
    use super::tests::{FAKE_PID, sample_exec};
    use super::*;
    use crate::ebpf_common::{EVENT_LISTEN, ListenEvent};

    fn sample_listen(family: u16, port_be: u16, addr: [u8; 16]) -> ListenEvent {
        ListenEvent {
            kind: EVENT_LISTEN,
            pid: FAKE_PID,
            uid: 0,
            gid: 0,
            family,
            _pad0: 0,
            port_be,
            _pad1: 0,
            addr,
            comm: *b"nginx\0\0\0\0\0\0\0\0\0\0\0",
        }
    }

    #[test]
    fn eid500_ipv4_shape_and_category() {
        let mut builder = EventBuilder::new();
        let _ = builder.exec_event(&sample_exec(FAKE_PID));

        let addr = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        let event = builder.listen_event(&sample_listen(2, 8080u16.to_be(), addr));
        let xml = String::from_utf8(event.event_raw.as_ref().clone()).expect("utf8");

        assert!(xml.contains("<EventID>500</EventID>"));
        assert!(xml.contains("<Task>500</Task>"));
        assert!(xml.contains("<Data Name=\"Protocol\">tcp</Data>"));
        assert!(xml.contains("<Data Name=\"Initiated\">false</Data>"));
        assert!(xml.contains("<Data Name=\"SourceIsIpv6\">false</Data>"));
        assert!(xml.contains("<Data Name=\"SourceIp\">0.0.0.0</Data>"));
        assert!(xml.contains("<Data Name=\"SourcePort\">8080</Data>"));
        assert!(xml.contains("<Data Name=\"DestinationIp\">0.0.0.0</Data>"));
        assert!(xml.contains("<Data Name=\"DestinationPort\">0</Data>"));
        assert!(xml.contains("<Data Name=\"Image\">/usr/bin/id</Data>"));
        assert_eq!(event.event_json["service"], "sysmon");
        assert_eq!(event.event_json["category"], "network_listen");
    }

    #[test]
    fn eid500_ipv6_unknown_process_falls_back() {
        let mut builder = EventBuilder::new();
        let addr = std::net::Ipv6Addr::UNSPECIFIED.octets();
        let event = builder.listen_event(&sample_listen(10, 443u16.to_be(), addr));
        let xml = String::from_utf8(event.event_raw.as_ref().clone()).expect("utf8");

        assert!(xml.contains("<Data Name=\"SourceIsIpv6\">true</Data>"));
        assert!(xml.contains("<Data Name=\"SourceIp\">::</Data>"));
        assert!(xml.contains("<Data Name=\"SourcePort\">443</Data>"));
        assert!(xml.contains("<Data Name=\"DestinationIsIpv6\">true</Data>"));
        assert!(xml.contains("<Data Name=\"DestinationIp\">::</Data>"));
        assert!(
            xml.contains(
                "<Data Name=\"ProcessGuid\">{00000000-0000-0000-0000-000000000000}</Data>"
            )
        );
        assert!(xml.contains("<Data Name=\"Image\">-</Data>"));
        assert_eq!(event.event_json["category"], "network_listen");
    }
}

#[cfg(test)]
mod process_access_tests {
    use super::tests::{FAKE_PID, sample_exec};
    use super::*;
    use crate::ebpf_common::{EVENT_PROCESS_ACCESS, ProcessAccessEvent};

    fn sample_access(source_pid: u32, target_pid: u32, request: u64) -> ProcessAccessEvent {
        ProcessAccessEvent {
            kind: EVENT_PROCESS_ACCESS,
            source_pid,
            source_tid: source_pid,
            source_uid: 0,
            source_gid: 0,
            _pad0: 0,
            target_pid,
            _pad1: 0,
            request,
            comm: *b"strace\0\0\0\0\0\0\0\0\0\0",
        }
    }

    #[test]
    fn eid10_shape_order_and_category() {
        let mut builder = EventBuilder::new();
        let target = 42_424u32;
        let _ = builder.exec_event(&sample_exec(FAKE_PID));
        let mut target_ev = sample_exec(target);
        target_ev.image[..11].copy_from_slice(b"/usr/bin/ls");
        let _ = builder.exec_event(&target_ev);

        let event = builder.process_access_event(&sample_access(FAKE_PID, target, 16));
        let xml = String::from_utf8(event.event_raw.as_ref().clone()).expect("utf8");

        assert!(xml.contains("<EventID>10</EventID>"));
        assert!(xml.contains("<Version>3</Version>"));
        assert!(xml.contains("<Task>10</Task>"));
        assert!(xml.contains(&format!("<Data Name=\"SourceProcessId\">{FAKE_PID}</Data>")));
        assert!(xml.contains(&format!("<Data Name=\"TargetProcessId\">{target}</Data>")));
        assert!(xml.contains("<Data Name=\"SourceImage\">/usr/bin/id</Data>"));
        assert!(xml.contains("<Data Name=\"TargetImage\">/usr/bin/ls</Data>"));
        assert!(xml.contains("<Data Name=\"GrantedAccess\">0x10</Data>"));
        assert!(xml.contains("<Data Name=\"CallTrace\">-</Data>"));
        assert!(xml.contains("<Data Name=\"SourceUser\">"));
        assert_eq!(event.event_json["service"], "sysmon");
        assert_eq!(event.event_json["category"], "process_access");

        let order = [
            "RuleName",
            "UtcTime",
            "SourceProcessGUID",
            "SourceProcessId",
            "SourceThreadId",
            "SourceImage",
            "TargetProcessGUID",
            "TargetProcessId",
            "TargetImage",
            "GrantedAccess",
            "CallTrace",
            "SourceUser",
        ];
        let mut last = 0;
        for field in order {
            let pos = xml.find(&format!("Name=\"{field}\"")).expect(field);
            assert!(pos > last, "field {field} out of order");
            last = pos;
        }
    }

    #[test]
    fn eid10_unknown_processes_fall_back() {
        let mut builder = EventBuilder::new();
        let event = builder.process_access_event(&sample_access(999_997, 999_998, 1));
        let xml = String::from_utf8(event.event_raw.as_ref().clone()).expect("utf8");
        assert!(xml.contains("<EventID>10</EventID>"));
        assert!(xml.contains("<Data Name=\"SourceImage\">-</Data>"));
        assert!(xml.contains(
            "<Data Name=\"SourceProcessGUID\">{00000000-0000-0000-0000-000000000000}</Data>"
        ));
        assert_eq!(event.event_json["category"], "process_access");
    }
}

#[cfg(test)]
mod driver_load_tests {
    use super::tests::{FAKE_PID, sample_exec};
    use super::*;
    use crate::ebpf_common::{DriverLoadEvent, EVENT_DRIVER_LOAD};

    fn sample_driver(pid: u32) -> DriverLoadEvent {
        DriverLoadEvent {
            kind: EVENT_DRIVER_LOAD,
            pid,
            uid: 0,
            gid: 0,
            fd: -1,
            _pad0: 0,
            comm: *b"modprobe\0\0\0\0\0\0\0\0",
        }
    }

    #[test]
    fn eid6_shape_order_and_category() {
        let mut builder = EventBuilder::new();
        let _ = builder.exec_event(&sample_exec(FAKE_PID));
        let event = builder.driver_load_event(&sample_driver(FAKE_PID));
        let xml = String::from_utf8(event.event_raw.as_ref().clone()).expect("utf8");

        assert!(xml.contains("<EventID>6</EventID>"));
        assert!(xml.contains("<Version>3</Version>"));
        assert!(xml.contains("<Task>6</Task>"));
        assert!(xml.contains("<Data Name=\"Image\">/usr/bin/id</Data>"));
        assert!(xml.contains("<Data Name=\"ImageLoaded\">-</Data>"));
        assert!(xml.contains("<Data Name=\"Hashes\">-</Data>"));
        assert!(xml.contains("<Data Name=\"Signed\">false</Data>"));
        assert!(xml.contains("<Data Name=\"SignatureStatus\">Unavailable</Data>"));
        assert_eq!(event.event_json["service"], "sysmon");
        assert_eq!(event.event_json["category"], "driver_load");

        let order = [
            "RuleName",
            "UtcTime",
            "ProcessGuid",
            "ProcessId",
            "Image",
            "ImageLoaded",
            "Hashes",
            "Signed",
            "Signature",
            "SignatureStatus",
            "User",
        ];
        let mut last = 0;
        for field in order {
            let pos = xml.find(&format!("Name=\"{field}\"")).expect(field);
            assert!(pos > last, "field {field} out of order");
            last = pos;
        }
    }

    #[test]
    fn eid6_unknown_process_falls_back() {
        let mut builder = EventBuilder::new();
        let event = builder.driver_load_event(&sample_driver(999_996));
        let xml = String::from_utf8(event.event_raw.as_ref().clone()).expect("utf8");
        assert!(xml.contains("<EventID>6</EventID>"));
        assert!(xml.contains("<Data Name=\"Image\">-</Data>"));
        assert!(
            xml.contains(
                "<Data Name=\"ProcessGuid\">{00000000-0000-0000-0000-000000000000}</Data>"
            )
        );
        assert_eq!(event.event_json["category"], "driver_load");
    }
}
