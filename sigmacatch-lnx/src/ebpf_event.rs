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

use chrono::Utc;
use sha2::{Digest, Sha256};
use sigmacatch_ebpf_common::{DnsEvent, ExecEvent, FileCreateEvent, NetEvent};
use sigmacatch_types::Event;

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
    /// Builder primed with this host's hostname.
    pub fn new() -> Self {
        let hostname = fs::read_to_string("/proc/sys/kernel/hostname")
            .map(|s| s.trim().to_string())
            .unwrap_or_else(|_| "localhost".to_string());
        Self {
            record_id: 0,
            hostname,
            exec_pid: std::process::id(),
            euid: read_euid(),
            parents: HashMap::new(),
            users: HashMap::new(),
            hashes: HashMap::new(),
            hash_order: VecDeque::new(),
        }
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
                user: user.clone(),
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
    pub fn net_event(&mut self, ev: &NetEvent) -> Event {
        let now = Utc::now();
        let (guid, image, _) = match self.parents.get(&ev.pid) {
            Some(info) => (info.guid.clone(), info.image.clone(), info.user.clone()),
            None => (NULL_GUID.to_string(), "-".to_string(), String::new()),
        };
        let user = self.user_name(ev.uid);
        let is_v6 = ev.family == 10;
        let dest_ip = format_addr(&ev.addr, is_v6);
        let port = u16::from_be(ev.port_be).to_string();
        let source_ip = if is_v6 { "::" } else { "0.0.0.0" };

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
                data("SourceIp", source_ip),
                data("SourceHostname", "-"),
                data("SourcePort", "0"),
                data("SourcePortName", "-"),
                data("DestinationIsIpv6", &is_v6.to_string()),
                data("DestinationIp", &dest_ip),
                data("DestinationHostname", "-"),
                data("DestinationPort", &port),
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
    let mut file = fs::File::open(path).ok()?;
    let mut hasher = Sha256::new();
    std::io::copy(&mut file, &mut hasher).ok()?;
    Some(format!("{:x}", hasher.finalize()))
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
const TASK_FILE_CREATE: u32 = 11;
const TASK_DNS_QUERY: u32 = 22;

/// Absolute TargetFilename: kernel-relative paths are resolved through the
/// opener's `/proc` handles while it is alive; dead openers keep the raw
/// path (best effort, same trade-off as rustinel's command line).
fn resolve_target(ev: &FileCreateEvent) -> String {
    let raw = ev.path_str();
    if raw.starts_with('/') || raw.is_empty() {
        return raw.to_string();
    }
    let base = if ev.dirfd >= 0 {
        fs::read_link(format!("/proc/{}/fd/{}", ev.pid, ev.dirfd))
    } else {
        fs::read_link(format!("/proc/{}/cwd", ev.pid))
    }
    .map(|p| p.to_string_lossy().into_owned())
    .unwrap_or_default();
    match base.as_str() {
        "" => raw.to_string(),
        b => format!("{b}/{raw}"),
    }
}

/// Dotted quad for v4, compressed RFC-5952 for v6.
fn format_addr(addr: &[u8; 16], is_v6: bool) -> String {
    if is_v6 {
        std::net::Ipv6Addr::from(*addr).to_string()
    } else {
        format!("{}.{}.{}.{}", addr[0], addr[1], addr[2], addr[3])
    }
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
    let json_raw =
        sigmacatch_types::parse_winevt_xml_raw(&xml).expect("rendered XML must always parse");
    let json = sigmacatch_types::parse_winevt_xml(&xml).expect("rendered XML must always parse");
    let mut event = Event::new(json_raw, json, xml.into_bytes());
    event.inject_logsource_fields_for("linux", None);
    event
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
    use sigmacatch_ebpf_common::{ARG0_LEN, EVENT_EXEC, EVENT_NET, IMAGE_LEN, NetEvent};

    pub(super) fn sample_net(family: u16, port_be: u16, addr: [u8; 16]) -> NetEvent {
        NetEvent {
            kind: EVENT_NET,
            pid: 4242,
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
        let event = builder.exec_event(&sample_exec(4242));
        let xml = String::from_utf8(event.event_raw.clone()).expect("utf8 xml");

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
        let event = builder.exec_event(&sample_exec(4242));
        let xml = String::from_utf8(event.event_raw).expect("utf8");
        assert!(xml.contains(
            "<Data Name=\"ParentProcessGuid\">{00000000-0000-0000-0000-000000000000}</Data>"
        ));
        assert!(xml.contains("<Data Name=\"ParentImage\">-</Data>"));
        assert!(xml.contains("<Data Name=\"ParentProcessId\">-</Data>"));
    }

    #[test]
    fn unreadable_image_falls_back_to_dash() {
        let mut ev = sample_exec(4242);
        let missing = b"/sigmacatch/no/such/binary\0";
        ev.image[..missing.len()].copy_from_slice(missing);
        let mut builder = EventBuilder::new();
        let event = builder.exec_event(&ev);
        let xml = String::from_utf8(event.event_raw).expect("utf8");
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
        let _exec = builder.exec_event(&sample_exec(4242));
        let event = builder.exit_event(4242).expect("known process exits");
        let xml = String::from_utf8(event.event_raw).expect("utf8");

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
        let mut ev = sample_exec(4242);
        let evil = b"/bin/echo <script>&amp;\0";
        ev.arg0[..evil.len()].copy_from_slice(evil);
        // image stays clean; the escaped content must come from arg0.
        let mut builder = EventBuilder::new();
        let event = builder.exec_event(&ev);
        let xml = String::from_utf8(event.event_raw).expect("utf8");
        assert!(xml.contains("&lt;script&gt;&amp;amp;"));
        assert!(
            !xml[xml.find("<Data Name=\"CommandLine\"").expect("cmdline")..].contains("<script>")
        );
    }
}

#[cfg(test)]
mod net_tests {
    use super::tests::{sample_exec, sample_net};
    use super::*;

    #[test]
    fn eid3_ipv4_matches_golden_shape_and_order() {
        let mut builder = EventBuilder::new();
        // Seed the process cache so Image/ProcessGuid resolve.
        let _ = builder.exec_event(&sample_exec(4242));

        let addr = [127, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        let event = builder.net_event(&sample_net(2, 22u16.to_be(), addr));
        let xml = String::from_utf8(event.event_raw).expect("utf8");

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
        let xml = String::from_utf8(event.event_raw).expect("utf8");

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
}

#[cfg(test)]
mod file_tests {
    use super::tests::sample_exec;
    use super::*;
    use sigmacatch_ebpf_common::{AT_FDCWD, EVENT_FILE, PATH_LEN};

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
        let _ = builder.exec_event(&sample_exec(4242));
        let event = builder.file_create_event(&sample_file(4242));
        let xml = String::from_utf8(event.event_raw).expect("utf8");

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
        let xml = String::from_utf8(event.event_raw).expect("utf8");
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
        let xml = String::from_utf8(event.event_raw).expect("utf8");
        assert!(xml.contains("<Data Name=\"TargetFilename\">sub/file.conf</Data>"));
    }
}

#[cfg(test)]
mod dns_tests {
    use super::tests::sample_exec;
    use super::*;
    use sigmacatch_ebpf_common::{DNS_PAYLOAD_LEN, DnsEvent, EVENT_DNS};

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
        let _ = builder.exec_event(&sample_exec(4242));
        let event = builder.dns_event(&sample_dns(4242, &wire)).expect("valid");

        let xml = String::from_utf8(event.event_raw).expect("utf8");
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
        assert!(builder.dns_event(&sample_dns(4242, &[1, 2, 3])).is_none());
    }
}
