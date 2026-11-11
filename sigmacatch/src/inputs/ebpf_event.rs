// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 sigmacatch contributors

//! Enrichment of kernel ring buffer records into Sysmon-for-Linux compatible events.
//!
//! Events are emitted as nested winevt-shaped JSON (`Event.System`,
//! `Event.EventData`) on channel `Linux-Sysmon/Operational` with logsource fields
//! (`product: linux`, `service: sysmon`, `category`) injected, so the existing
//! Linux detection pipelines (`3_lnx_logsource.yml`, `4_lnx_field_name.yml`) and
//! regression generation work unchanged.
//!
//! The field mapping follows the internal eBPF taxonomy
//! (`sigmacatch/ebpf_taxonomy.json`) from kernel-captured data to Sigma/Sysmon
//! fields.
//!
//! Hashes are `-` when the image is unreadable; userspace SHA256 with mtime-based
//! caching is used when possible.

use std::collections::{HashMap, VecDeque};
use std::fs;
use std::path::Path;
use std::time::SystemTime;

use crate::ebpf_common::{
    CAP_CAPSET, CAP_PRCTL, CHMOD_CHMOD, CHMOD_FCHMOD, CHMOD_FCHMODAT, CHMOD_FCHMODAT2, CHOWN_CHOWN,
    CHOWN_FCHOWN, CHOWN_FCHOWNAT, CHOWN_LCHOWN, CRED_SETEGID, CRED_SETEUID, CRED_SETFSGID,
    CRED_SETFSUID, CRED_SETGID, CRED_SETGROUPS, CRED_SETREGID, CRED_SETRESGID, CRED_SETRESUID,
    CRED_SETREUID, CRED_SETUID, CapabilityChangeEvent, CredentialChangeEvent, DnsEvent,
    DnsResponseEvent, DriverLoadEvent, ExecEvent, ExitEvent, FileChangeEvent, FileChmodEvent,
    FileChownEvent, FileCreateEvent, FileDeleteEvent, FileRenameEvent, FileTruncateEvent,
    ForkEvent, ListenEvent, ModuleUnloadEvent, NetEvent, PipeCreateEvent, ProcessAccessEvent,
    ProcessTamperingEvent, RENAME_RENAME, RENAME_RENAMEAT, RENAME_RENAMEAT2, RawAccessEvent,
    TRUNCATE_FTRUNCATE, TRUNCATE_TRUNCATE, WRITE_PWRITE64, WRITE_PWRITEV, WRITE_PWRITEV2,
    WRITE_WRITE, WRITE_WRITEV,
};
use crate::types::Event;
use chrono::Utc;
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

/// Bounded memoization of image hashes keyed by resolved path, invalidated
/// by mtime change.
const HASH_CACHE_CAP: usize = 4096;

/// Upper bound for the fork-lineage cache. Each entry is a few bytes; the cap
/// matters because threads and non-exec children may never produce a cleanup
/// event on kernels where a tracepoint is unavailable.
const FORK_CACHE_CAP: usize = 16_384;

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
    fork_parents: HashMap<u32, u32>,
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
            fork_parents: HashMap::new(),
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
        let image = if ev.image_str().is_empty() {
            // execveat(..., "", ..., AT_EMPTY_PATH) has no pathname. Prefer the
            // current executable, then argv[0] for short-lived processes whose
            // /proc entry is already gone.
            fs::read_link(format!("/proc/{}/exe", ev.pid))
                .ok()
                .map(|p| p.to_string_lossy().into_owned())
                .filter(|image| !image.is_empty())
                .or_else(|| {
                    let arg0 = ev.arg0_str();
                    (!arg0.is_empty()).then(|| arg0.to_string())
                })
                .unwrap_or_else(|| "-".to_string())
        } else {
            ev.image_str().to_string()
        };
        let cmdline = full_cmdline(ev);
        let user = self.user_name(ev.uid);
        let ppid = read_ppid(ev.pid).or_else(|| self.fork_parents.get(&ev.pid).copied());
        self.fork_parents.remove(&ev.pid);
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

        let (stat_session, tty_nr) = read_stat_session_tty(ev.pid);
        let mut data = Map::new();
        insert_str(&mut data, "UtcTime", &utc_time(&now));
        insert_str(&mut data, "ProcessGuid", &guid);
        insert_str(&mut data, "ProcessId", &ev.pid.to_string());
        insert_str(&mut data, "Image", &image);
        insert_str(&mut data, "FileVersion", "-");
        insert_str(&mut data, "Description", "-");
        insert_str(&mut data, "Product", "-");
        insert_str(&mut data, "Company", "-");
        insert_str(&mut data, "OriginalFileName", "-");
        insert_str(&mut data, "CommandLine", &cmdline);
        insert_str(
            &mut data,
            "CurrentDirectory",
            &read_cwd(ev.pid).unwrap_or_else(|| "-".to_string()),
        );
        insert_str(&mut data, "User", &user);
        insert_str(&mut data, "LogonGuid", NULL_GUID);
        insert_str(&mut data, "LogonId", "0");
        insert_str(
            &mut data,
            "TerminalSessionId",
            &read_session_id(ev.pid).unwrap_or(0).to_string(),
        );
        insert_str(
            &mut data,
            "SessionId",
            &stat_session
                .or_else(|| read_session_id(ev.pid))
                .unwrap_or(0)
                .to_string(),
        );
        insert_str(
            &mut data,
            "TtyNr",
            &tty_nr
                .map(|v| v.to_string())
                .unwrap_or_else(|| "-".to_string()),
        );
        insert_str(&mut data, "Cgroup", &read_cgroup(ev.pid));
        insert_str(&mut data, "NamespacePid", &read_namespace(ev.pid, "pid"));
        insert_str(&mut data, "NamespaceMnt", &read_namespace(ev.pid, "mnt"));
        insert_str(&mut data, "NamespaceNet", &read_namespace(ev.pid, "net"));
        insert_str(&mut data, "NamespaceUser", &read_namespace(ev.pid, "user"));
        insert_str(&mut data, "NamespaceUts", &read_namespace(ev.pid, "uts"));
        insert_str(&mut data, "NamespaceIpc", &read_namespace(ev.pid, "ipc"));
        insert_str(
            &mut data,
            "NamespaceCgroup",
            &read_namespace(ev.pid, "cgroup"),
        );
        insert_str(&mut data, "IntegrityLevel", "no level");
        insert_str(&mut data, "Hashes", &self.image_hash(ev.pid, &image));
        insert_str(&mut data, "ParentProcessGuid", &parent_guid);
        insert_str(&mut data, "ParentProcessId", &parent_pid);
        insert_str(&mut data, "ParentImage", &parent_image);
        insert_str(&mut data, "ParentCommandLine", &parent_cmdline);
        insert_str(&mut data, "ParentUser", &parent_user);

        self.parents.insert(
            ev.pid,
            ParentInfo {
                guid,
                image,
                cmdline,
                user,
            },
        );
        to_sysmon_event(1, &self.hostname, &now, data)
    }

    /// Clean up internal lineage for every task exit and build a
    /// process_termination (EID 5) event for group leaders only. `None` when
    /// the task is unknown to us (no Image available) or is a thread.
    pub fn exit_event(&mut self, ev: &ExitEvent) -> Option<Event> {
        // Threads are recorded by sched_process_fork but never appear in
        // `parents`; remove their lineage entry before the group-leader check.
        self.fork_parents.remove(&ev.tid);
        if ev.tid != ev.pid {
            return None;
        }
        let info = self.parents.remove(&ev.pid)?;
        let now = Utc::now();
        let mut data = Map::new();
        insert_str(&mut data, "UtcTime", &utc_time(&now));
        insert_str(&mut data, "ProcessGuid", &info.guid);
        insert_str(&mut data, "ProcessId", &ev.pid.to_string());
        insert_str(&mut data, "Image", &info.image);
        insert_str(&mut data, "User", &info.user);
        Some(to_sysmon_event(5, &self.hostname, &now, data))
    }

    /// Record fork/clone lineage (parent tgid -> child task) for parent
    /// resolution fallback.
    pub fn fork_event(&mut self, ev: &ForkEvent) {
        if self.fork_parents.len() >= FORK_CACHE_CAP
            && !self.fork_parents.contains_key(&ev.child_pid)
            && let Some(victim) = self.fork_parents.keys().next().copied()
        {
            self.fork_parents.remove(&victim);
        }
        self.fork_parents.insert(ev.child_pid, ev.parent_tgid);
    }

    /// Build a network_connection (EID 3) event.
    pub fn net_event(&mut self, ev: &NetEvent) -> Event {
        let now = Utc::now();
        let (guid, image) = match self.parents.get(&ev.pid) {
            Some(info) => (info.guid.clone(), info.image.clone()),
            None => (NULL_GUID.to_string(), "-".to_string()),
        };
        let user = self.user_name(ev.uid);
        let captured_family = matches!(ev.family, 2 | 10);
        let captured_remote = captured_family && ev.port_be != 0;
        let captured_v6 = ev.family == 10;
        let resolved = resolve_socket_endpoints(ev.pid, ev.fd);
        let is_v6 = if captured_family {
            captured_v6
        } else {
            resolved.as_ref().is_some_and(|endpoints| endpoints.is_v6)
        };
        let zero_ip = if is_v6 { "::" } else { "0.0.0.0" };
        let initiated = ev.initiated != 0;

        let (source_ip, source_port_s, dest_ip, dest_port_s) = if initiated {
            let (dest_ip, dest_port) = if captured_remote {
                (format_addr(&ev.addr, captured_v6), u16::from_be(ev.port_be))
            } else {
                resolved
                    .as_ref()
                    .map(|endpoints| (endpoints.remote_ip.clone(), endpoints.remote_port))
                    .unwrap_or_else(|| (zero_ip.to_string(), 0))
            };
            let source = resolved
                .as_ref()
                .map(|endpoints| (endpoints.local_ip.clone(), endpoints.local_port))
                .or_else(|| {
                    if captured_remote {
                        resolve_source_endpoint(
                            ev.pid,
                            captured_v6,
                            &ev.addr,
                            u16::from_be(ev.port_be),
                        )
                        .map(|(ip, port)| (ip, port.parse::<u16>().unwrap_or(0)))
                    } else {
                        None
                    }
                })
                .unwrap_or_else(|| (zero_ip.to_string(), 0));
            (
                source.0,
                source.1.to_string(),
                dest_ip,
                dest_port.to_string(),
            )
        } else {
            let (source_ip, source_port) = if captured_remote {
                (format_addr(&ev.addr, captured_v6), u16::from_be(ev.port_be))
            } else {
                resolved
                    .as_ref()
                    .map(|endpoints| (endpoints.remote_ip.clone(), endpoints.remote_port))
                    .unwrap_or_else(|| (zero_ip.to_string(), 0))
            };
            let (dest_ip, dest_port) = resolved
                .as_ref()
                .map(|endpoints| (endpoints.local_ip.clone(), endpoints.local_port))
                .unwrap_or_else(|| (zero_ip.to_string(), 0));
            (
                source_ip,
                source_port.to_string(),
                dest_ip,
                dest_port.to_string(),
            )
        };

        let mut data = Map::new();
        insert_str(&mut data, "UtcTime", &utc_time(&now));
        insert_str(&mut data, "ProcessGuid", &guid);
        insert_str(&mut data, "ProcessId", &ev.pid.to_string());
        insert_str(&mut data, "Image", &image);
        insert_str(&mut data, "User", &user);
        insert_str(&mut data, "Protocol", "tcp");
        insert_str(
            &mut data,
            "Initiated",
            if initiated { "true" } else { "false" },
        );
        insert_str(&mut data, "SourceIsIpv6", &is_v6.to_string());
        insert_str(&mut data, "SourceIp", &source_ip);
        insert_str(&mut data, "SourceHostname", "-");
        insert_str(&mut data, "SourcePort", &source_port_s);
        insert_str(&mut data, "SourcePortName", "-");
        insert_str(&mut data, "DestinationIsIpv6", &is_v6.to_string());
        insert_str(&mut data, "DestinationIp", &dest_ip);
        insert_str(&mut data, "DestinationHostname", "-");
        insert_str(&mut data, "DestinationPort", &dest_port_s);
        insert_str(&mut data, "DestinationPortName", "-");
        to_sysmon_event(3, &self.hostname, &now, data)
    }

    /// Build a network_listen event (EID 500, Sysmon extension) with
    /// `Initiated=false`.
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

        let mut data = Map::new();
        insert_str(&mut data, "UtcTime", &utc_time(&now));
        insert_str(&mut data, "ProcessGuid", &guid);
        insert_str(&mut data, "ProcessId", &ev.pid.to_string());
        insert_str(&mut data, "Image", &image);
        insert_str(&mut data, "User", &user);
        insert_str(&mut data, "Protocol", "tcp");
        insert_str(&mut data, "Initiated", "false");
        insert_str(&mut data, "SourceIsIpv6", &is_v6.to_string());
        insert_str(&mut data, "SourceIp", &bind_ip);
        insert_str(&mut data, "SourceHostname", "-");
        insert_str(&mut data, "SourcePort", &bind_port);
        insert_str(&mut data, "SourcePortName", "-");
        insert_str(&mut data, "DestinationIsIpv6", dest_v6);
        insert_str(&mut data, "DestinationIp", &dest_ip);
        insert_str(&mut data, "DestinationHostname", "-");
        insert_str(&mut data, "DestinationPort", "0");
        insert_str(&mut data, "DestinationPortName", "-");
        to_sysmon_event(500, &self.hostname, &now, data)
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
        let mut data = Map::new();
        insert_str(&mut data, "UtcTime", &utc_time(&now));
        insert_str(&mut data, "ProcessGuid", &guid);
        insert_str(&mut data, "ProcessId", &ev.pid.to_string());
        insert_str(&mut data, "Image", &image);
        insert_str(&mut data, "TargetFilename", &target);
        insert_str(&mut data, "CreationUtcTime", &utc_time(&now));
        insert_str(&mut data, "User", &user);
        to_sysmon_event(11, &self.hostname, &now, data)
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
        let mut data = Map::new();
        insert_str(&mut data, "UtcTime", &utc_time(&now));
        insert_str(&mut data, "ProcessGuid", &guid);
        insert_str(&mut data, "ProcessId", &ev.pid.to_string());
        insert_str(&mut data, "User", &user);
        insert_str(&mut data, "Image", &image);
        insert_str(&mut data, "TargetFilename", &target);
        insert_str(&mut data, "Hashes", "-");
        insert_str(&mut data, "IsExecutable", "false");
        insert_str(&mut data, "Archived", "false");
        to_sysmon_event(23, &self.hostname, &now, data)
    }

    /// Build a file_rename (EID 503, extension) event.
    pub fn file_rename_event(&mut self, ev: &FileRenameEvent) -> Event {
        let now = Utc::now();
        let (guid, image) = match self.parents.get(&ev.pid) {
            Some(info) => (info.guid.clone(), info.image.clone()),
            None => (NULL_GUID.to_string(), "-".to_string()),
        };
        let user = self.user_name(ev.uid);
        let source = if ev.old_path_str().starts_with('/') {
            ev.old_path_str().to_string()
        } else {
            resolve_target_path(ev.pid, ev.old_dirfd, ev.old_path_str())
        };
        let target = if ev.new_path_str().starts_with('/') {
            ev.new_path_str().to_string()
        } else {
            resolve_target_path(ev.pid, ev.new_dirfd, ev.new_path_str())
        };
        let mut data = Map::new();
        insert_str(&mut data, "UtcTime", &utc_time(&now));
        insert_str(&mut data, "ProcessGuid", &guid);
        insert_str(&mut data, "ProcessId", &ev.pid.to_string());
        insert_str(&mut data, "Image", &image);
        insert_str(&mut data, "User", &user);
        insert_str(&mut data, "TargetFilename", &target);
        insert_str(&mut data, "SourceFilename", &source);
        insert_str(&mut data, "Syscall", rename_syscall_name(ev.syscall));
        insert_str(&mut data, "Flags", &ev.flags.to_string());
        insert_str(&mut data, "Result", &ev.result.to_string());
        to_sysmon_event(503, &self.hostname, &now, data)
    }

    /// Build a file_chmod (EID 504, extension) event.
    pub fn file_chmod_event(&mut self, ev: &FileChmodEvent) -> Event {
        let now = Utc::now();
        let (guid, image) = match self.parents.get(&ev.pid) {
            Some(info) => (info.guid.clone(), info.image.clone()),
            None => (NULL_GUID.to_string(), "-".to_string()),
        };
        let user = self.user_name(ev.uid);
        let target = resolve_target_or_fd(ev.pid, ev.dirfd, ev.path_str(), ev.fd);
        let mut data = Map::new();
        insert_str(&mut data, "UtcTime", &utc_time(&now));
        insert_str(&mut data, "ProcessGuid", &guid);
        insert_str(&mut data, "ProcessId", &ev.pid.to_string());
        insert_str(&mut data, "Image", &image);
        insert_str(&mut data, "User", &user);
        insert_str(&mut data, "TargetFilename", &target);
        insert_str(&mut data, "Syscall", chmod_syscall_name(ev.syscall));
        insert_str(&mut data, "Mode", &format!("0o{:o}", ev.mode));
        insert_str(&mut data, "Flags", &ev.flags.to_string());
        insert_str(&mut data, "Result", &ev.result.to_string());
        to_sysmon_event(504, &self.hostname, &now, data)
    }

    /// Build a file_chown (EID 505, extension) event.
    pub fn file_chown_event(&mut self, ev: &FileChownEvent) -> Event {
        let now = Utc::now();
        let (guid, image) = match self.parents.get(&ev.pid) {
            Some(info) => (info.guid.clone(), info.image.clone()),
            None => (NULL_GUID.to_string(), "-".to_string()),
        };
        let user = self.user_name(ev.uid);
        let target = resolve_target_or_fd(ev.pid, ev.dirfd, ev.path_str(), ev.fd);
        let mut data = Map::new();
        insert_str(&mut data, "UtcTime", &utc_time(&now));
        insert_str(&mut data, "ProcessGuid", &guid);
        insert_str(&mut data, "ProcessId", &ev.pid.to_string());
        insert_str(&mut data, "Image", &image);
        insert_str(&mut data, "User", &user);
        insert_str(&mut data, "TargetFilename", &target);
        insert_str(&mut data, "Syscall", chown_syscall_name(ev.syscall));
        insert_str(&mut data, "Owner", &ev.owner.to_string());
        insert_str(&mut data, "Group", &ev.group.to_string());
        insert_str(&mut data, "Flags", &ev.flags.to_string());
        insert_str(&mut data, "Result", &ev.result.to_string());
        to_sysmon_event(505, &self.hostname, &now, data)
    }

    /// Build a file_truncate (EID 506, extension) event.
    pub fn file_truncate_event(&mut self, ev: &FileTruncateEvent) -> Event {
        let now = Utc::now();
        let (guid, image) = match self.parents.get(&ev.pid) {
            Some(info) => (info.guid.clone(), info.image.clone()),
            None => (NULL_GUID.to_string(), "-".to_string()),
        };
        let user = self.user_name(ev.uid);
        let target = resolve_target_or_fd(ev.pid, -100, ev.path_str(), ev.fd);
        let mut data = Map::new();
        insert_str(&mut data, "UtcTime", &utc_time(&now));
        insert_str(&mut data, "ProcessGuid", &guid);
        insert_str(&mut data, "ProcessId", &ev.pid.to_string());
        insert_str(&mut data, "Image", &image);
        insert_str(&mut data, "User", &user);
        insert_str(&mut data, "TargetFilename", &target);
        insert_str(&mut data, "Syscall", truncate_syscall_name(ev.syscall));
        insert_str(&mut data, "Length", &ev.length.to_string());
        insert_str(&mut data, "Result", &ev.result.to_string());
        to_sysmon_event(506, &self.hostname, &now, data)
    }

    /// Build a file_change (EID 2) event for a successful write to a regular
    /// file. Writes to sockets, pipes and terminals are not file changes and
    /// are discarded.
    pub fn file_change_event(&mut self, ev: &FileChangeEvent) -> Option<Event> {
        if ev.fd < 0 {
            return None;
        }
        let fd_path = format!("/proc/{}/fd/{}", ev.pid, ev.fd);
        let path = fs::read_link(&fd_path).ok()?;
        if !fs::metadata(&fd_path).ok()?.is_file() {
            return None;
        }
        let target = path.to_string_lossy().into_owned();
        let now = Utc::now();
        let (guid, image) = match self.parents.get(&ev.pid) {
            Some(info) => (info.guid.clone(), info.image.clone()),
            None => (NULL_GUID.to_string(), "-".to_string()),
        };
        let user = self.user_name(ev.uid);
        let mut data = Map::new();
        insert_str(&mut data, "UtcTime", &utc_time(&now));
        insert_str(&mut data, "ProcessGuid", &guid);
        insert_str(&mut data, "ProcessId", &ev.pid.to_string());
        insert_str(&mut data, "Image", &image);
        insert_str(&mut data, "TargetFilename", &target);
        insert_str(&mut data, "User", &user);
        insert_str(&mut data, "Syscall", write_syscall_name(ev.syscall));
        insert_str(&mut data, "BytesWritten", &ev.bytes_written.to_string());
        Some(to_sysmon_event(2, &self.hostname, &now, data))
    }

    /// Build a module_unload (EID 507, extension) event.
    pub fn module_unload_event(&mut self, ev: &ModuleUnloadEvent) -> Event {
        let now = Utc::now();
        let (guid, image) = match self.parents.get(&ev.pid) {
            Some(info) => (info.guid.clone(), info.image.clone()),
            None => (NULL_GUID.to_string(), "-".to_string()),
        };
        let user = self.user_name(ev.uid);
        let mut data = Map::new();
        insert_str(&mut data, "UtcTime", &utc_time(&now));
        insert_str(&mut data, "ProcessGuid", &guid);
        insert_str(&mut data, "ProcessId", &ev.pid.to_string());
        insert_str(&mut data, "Image", &image);
        insert_str(&mut data, "User", &user);
        insert_str(&mut data, "ModuleName", ev.name_str());
        insert_str(&mut data, "Flags", &ev.flags.to_string());
        insert_str(&mut data, "Result", &ev.result.to_string());
        to_sysmon_event(507, &self.hostname, &now, data)
    }

    /// Build a process_access (EID 10) event.
    pub fn process_access_event(&mut self, ev: &ProcessAccessEvent) -> Event {
        let now = Utc::now();
        let (src_guid, src_image) = self.resolve_process_info(ev.source_pid);
        let (tgt_guid, tgt_image) = self.resolve_process_info(ev.target_pid);
        let source_user = self.user_name(ev.source_uid);
        let granted = format!("0x{:x}", ev.request);
        let mut data = Map::new();
        insert_str(&mut data, "UtcTime", &utc_time(&now));
        insert_str(&mut data, "SourceProcessGUID", &src_guid);
        insert_str(&mut data, "SourceProcessId", &ev.source_pid.to_string());
        insert_str(&mut data, "SourceThreadId", &ev.source_tid.to_string());
        insert_str(&mut data, "SourceImage", &src_image);
        insert_str(&mut data, "TargetProcessGUID", &tgt_guid);
        insert_str(&mut data, "TargetProcessId", &ev.target_pid.to_string());
        insert_str(&mut data, "TargetImage", &tgt_image);
        insert_str(&mut data, "GrantedAccess", &granted);
        insert_str(&mut data, "CallTrace", "-");
        insert_str(&mut data, "SourceUser", &source_user);
        to_sysmon_event(10, &self.hostname, &now, data)
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
        let mut data = Map::new();
        insert_str(&mut data, "UtcTime", &utc_time(&now));
        insert_str(&mut data, "ProcessGuid", &guid);
        insert_str(&mut data, "ProcessId", &ev.pid.to_string());
        insert_str(&mut data, "Image", &image);
        insert_str(&mut data, "Device", &device);
        to_sysmon_event(9, &self.hostname, &now, data)
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
        let mut data = Map::new();
        insert_str(&mut data, "UtcTime", &utc_time(&now));
        insert_str(&mut data, "ProcessGuid", &guid);
        insert_str(&mut data, "ProcessId", &ev.pid.to_string());
        insert_str(&mut data, "PipeName", &pipe_name);
        insert_str(&mut data, "Image", &image);
        insert_str(&mut data, "User", &user);
        to_sysmon_event(17, &self.hostname, &now, data)
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
        let mut data = Map::new();
        insert_str(&mut data, "UtcTime", &utc_time(&now));
        insert_str(&mut data, "ProcessGuid", &guid);
        insert_str(&mut data, "ProcessId", &ev.pid.to_string());
        insert_str(&mut data, "Image", &image);
        insert_str(&mut data, "ImageLoaded", &image_loaded);
        insert_str(&mut data, "Hashes", "-");
        insert_str(&mut data, "Signed", "false");
        insert_str(&mut data, "Signature", "-");
        insert_str(&mut data, "SignatureStatus", "Unavailable");
        insert_str(&mut data, "User", &user);
        to_sysmon_event(6, &self.hostname, &now, data)
    }

    /// Build a process_tampering (EID 25) event.
    pub fn process_tampering_event(&mut self, ev: &ProcessTamperingEvent) -> Event {
        let now = Utc::now();
        let (guid, image) = self.resolve_process_info(ev.source_pid);
        let user = self.user_name(ev.uid);
        let mut data = Map::new();
        insert_str(&mut data, "UtcTime", &utc_time(&now));
        insert_str(&mut data, "ProcessGuid", &guid);
        insert_str(&mut data, "ProcessId", &ev.source_pid.to_string());
        insert_str(&mut data, "Image", &image);
        insert_str(&mut data, "Type", "CrossProcessMemoryWrite");
        insert_str(&mut data, "User", &user);
        to_sysmon_event(25, &self.hostname, &now, data)
    }

    /// Build a credential_change (EID 501, extension) event.
    pub fn credential_change_event(&mut self, ev: &CredentialChangeEvent) -> Event {
        let now = Utc::now();
        let (guid, image) = self.resolve_process_info(ev.pid);
        let user = self.user_name(ev.uid);
        let syscall = cred_syscall_name(ev.syscall);
        let mut data = Map::new();
        insert_str(&mut data, "UtcTime", &utc_time(&now));
        insert_str(&mut data, "ProcessGuid", &guid);
        insert_str(&mut data, "ProcessId", &ev.pid.to_string());
        insert_str(&mut data, "Image", &image);
        insert_str(&mut data, "User", &user);
        insert_str(&mut data, "Syscall", syscall);
        insert_str(&mut data, "TargetUid0", &ev.arg0.to_string());
        insert_str(&mut data, "TargetUid1", &ev.arg1.to_string());
        insert_str(&mut data, "TargetUid2", &ev.arg2.to_string());
        insert_str(&mut data, "GroupCount", &ev.groups_count.to_string());
        insert_str(&mut data, "Result", &ev.result.to_string());
        to_sysmon_event(501, &self.hostname, &now, data)
    }

    /// Build a capability_change (EID 502, extension) event.
    pub fn capability_change_event(&mut self, ev: &CapabilityChangeEvent) -> Event {
        let now = Utc::now();
        let (guid, image) = self.resolve_process_info(ev.pid);
        let user = self.user_name(ev.uid);
        let syscall = cap_syscall_name(ev.syscall);
        let mut data = Map::new();
        insert_str(&mut data, "UtcTime", &utc_time(&now));
        insert_str(&mut data, "ProcessGuid", &guid);
        insert_str(&mut data, "ProcessId", &ev.pid.to_string());
        insert_str(&mut data, "Image", &image);
        insert_str(&mut data, "User", &user);
        insert_str(&mut data, "Syscall", syscall);
        insert_str(&mut data, "Option", &ev.option.to_string());
        insert_str(&mut data, "Arg2", &ev.arg2.to_string());
        insert_str(&mut data, "Arg3", &ev.arg3.to_string());
        insert_str(&mut data, "Arg4", &ev.arg4.to_string());
        insert_str(&mut data, "Result", &ev.result.to_string());
        to_sysmon_event(502, &self.hostname, &now, data)
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
        let mut data = Map::new();
        insert_str(&mut data, "UtcTime", &utc_time(&now));
        insert_str(&mut data, "ProcessGuid", &guid);
        insert_str(&mut data, "ProcessId", &ev.pid.to_string());
        insert_str(&mut data, "Image", &image);
        insert_str(&mut data, "User", &user);
        insert_str(&mut data, "QueryName", &query_name);
        insert_str(&mut data, "QueryStatus", "0");
        insert_str(&mut data, "QueryResults", "-");
        Some(to_sysmon_event(22, &self.hostname, &now, data))
    }

    /// Build a dns_response (EID 508, extension) event.
    pub fn dns_response_event(&mut self, ev: &DnsResponseEvent) -> Option<Event> {
        let end = ev.payload_len as usize;
        if end > ev.payload.len() {
            return None;
        }
        if ev.source_valid == 0 && socket_remote_port(ev.pid, ev.fd) != Some(53) {
            return None;
        }
        let (query_name, rcode) = dns_query_name_and_rcode(&ev.payload[..end])?;

        let now = Utc::now();
        let (guid, image) = match self.parents.get(&ev.pid) {
            Some(info) => (info.guid.clone(), info.image.clone()),
            None => (new_guid(), "-".to_string()),
        };
        let user = self.user_name(ev.uid);
        let mut data = Map::new();
        insert_str(&mut data, "UtcTime", &utc_time(&now));
        insert_str(&mut data, "ProcessGuid", &guid);
        insert_str(&mut data, "ProcessId", &ev.pid.to_string());
        insert_str(&mut data, "Image", &image);
        insert_str(&mut data, "User", &user);
        insert_str(&mut data, "QueryName", &query_name);
        // dns_response extension: QueryStatus carries the DNS RCODE (0 = success,
        // 3 = NXDOMAIN, 2 = SERVFAIL, ...), unlike the Windows Win32 status.
        insert_str(&mut data, "QueryStatus", &rcode.to_string());
        insert_str(&mut data, "QueryResults", "-");
        Some(to_sysmon_event(508, &self.hostname, &now, data))
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

fn insert_str(m: &mut Map<String, Value>, k: &str, v: &str) {
    m.insert(k.to_string(), Value::String(v.to_string()));
}

/// Build a Sysmon-for-Linux compatible nested event (`Event.System`,
/// `Event.EventData`) so the existing linux detection pipelines (which add
/// `Event.System.EventID` conditions and map fields to `Event.EventData.*`)
/// can match eBPF-captured events. Logsource fields are injected from the
/// `Linux-Sysmon/Operational` channel like the legacy sysmon tail.
fn to_sysmon_event(
    event_id: u32,
    hostname: &str,
    now: &chrono::DateTime<Utc>,
    data: Map<String, Value>,
) -> Event {
    let mut system = Map::new();
    let mut provider = Map::new();
    let mut provider_attrs = Map::new();
    provider_attrs.insert("Name".into(), Value::String("Linux-Sysmon".into()));
    provider.insert("#attributes".into(), Value::Object(provider_attrs));
    system.insert("Provider".into(), Value::Object(provider));
    system.insert("EventID".into(), Value::Number(event_id.into()));
    system.insert(
        "TimeCreated".into(),
        serde_json::json!({ "#attributes": { "SystemTime": now.to_rfc3339() } }),
    );
    system.insert("Computer".into(), Value::String(hostname.to_string()));
    system.insert(
        "Channel".into(),
        Value::String("Linux-Sysmon/Operational".into()),
    );

    let mut event = Map::new();
    event.insert("System".into(), Value::Object(system));
    event.insert("EventData".into(), Value::Object(data));

    let mut root = Map::new();
    root.insert("Event".into(), Value::Object(event));
    let json = Value::Object(root);
    let raw_bytes = serde_json::to_vec(&json).unwrap_or_default();
    Event::new_injected(json.clone(), json, raw_bytes, "linux", None)
}

/// Extract the question name from a raw DNS wire payload (query or response).
pub fn parse_query_name(payload: &[u8]) -> Option<String> {
    dns_query_name_and_rcode(payload).map(|(name, _)| name)
}

/// Extract the first question name and the response RCODE from a DNS payload.
fn dns_query_name_and_rcode(payload: &[u8]) -> Option<(String, u8)> {
    if payload.len() < 12 {
        return None;
    }
    let qdcount = u16::from_be_bytes([payload[4], payload[5]]);
    if qdcount == 0 {
        return None;
    }
    let name = parse_dns_name(payload, 12)?;
    Some((name, payload[3] & 0x0f))
}

/// Parse a possibly-compressed DNS name. Compression pointers are followed
/// with a bounded visited set so malformed packets cannot loop.
fn parse_dns_name(payload: &[u8], start: usize) -> Option<String> {
    let mut pos = start;
    let mut parts = Vec::new();
    let mut visited = [usize::MAX; 32];
    let mut jumps = 0usize;
    let mut wire_len = 0usize;
    loop {
        if pos >= payload.len() || parts.len() > 127 || wire_len > 255 {
            return None;
        }
        let label = payload[pos];
        if label & 0xC0 == 0xC0 {
            if pos + 1 >= payload.len() || jumps >= visited.len() {
                return None;
            }
            let target = (((label & 0x3f) as usize) << 8) | payload[pos + 1] as usize;
            if target >= payload.len() || visited[..jumps].contains(&target) {
                return None;
            }
            visited[jumps] = target;
            jumps += 1;
            pos = target;
            continue;
        }
        if label & 0xC0 != 0 || pos + 1 + label as usize > payload.len() {
            return None;
        }
        if label == 0 {
            break;
        }
        pos += 1;
        let chunk = String::from_utf8_lossy(&payload[pos..pos + label as usize]).to_string();
        wire_len += 1 + label as usize;
        parts.push(chunk);
        pos += label as usize;
    }
    if parts.is_empty() {
        return None;
    }
    Some(parts.join("."))
}

struct SocketEndpoints {
    local_ip: String,
    local_port: u16,
    remote_ip: String,
    remote_port: u16,
    is_v6: bool,
}

/// Resolve both endpoints of a socket through `/proc/<pid>/fd/<fd>` and the
/// matching inode row in `/proc/<pid>/net/{tcp,tcp6}`. This covers connected
/// UDP sockets and `accept(..., NULL, NULL)`, where no user `sockaddr` was
/// captured in the kernel.
fn resolve_socket_endpoints(pid: u32, fd: i32) -> Option<SocketEndpoints> {
    if fd < 0 {
        return None;
    }
    let inode = socket_inode(pid, fd)?;
    for (is_v6, table) in [
        (false, "tcp"),
        (true, "tcp6"),
        (false, "udp"),
        (true, "udp6"),
    ] {
        let path = format!("/proc/{pid}/net/{table}");
        let Ok(content) = fs::read_to_string(path) else {
            continue;
        };
        for line in content.lines().skip(1) {
            let Some(entry) = parse_proc_net_line(line, is_v6) else {
                continue;
            };
            if entry.inode == inode {
                return Some(SocketEndpoints {
                    local_ip: format_proc_addr(&entry.local_addr, is_v6),
                    local_port: entry.local_port,
                    remote_ip: format_proc_addr(&entry.remote_addr, is_v6),
                    remote_port: entry.remote_port,
                    is_v6,
                });
            }
        }
    }
    None
}

fn socket_remote_port(pid: u32, fd: i32) -> Option<u16> {
    resolve_socket_endpoints(pid, fd).map(|endpoints| endpoints.remote_port)
}

fn socket_inode(pid: u32, fd: i32) -> Option<u64> {
    let link = fs::read_link(format!("/proc/{pid}/fd/{fd}")).ok()?;
    let link = link.to_string_lossy();
    link.strip_prefix("socket:[")?
        .strip_suffix(']')?
        .parse()
        .ok()
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
    inode: u64,
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
    // tx_queue:rx_queue, tr:tm->when, retrnsmt, uid, timeout, inode.
    let inode = fields.nth(5)?.parse().ok()?;
    Some(ProcNetLine {
        local_addr,
        local_port,
        remote_addr,
        remote_port,
        state,
        inode,
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
    let kernel_cmdline = ev.cmdline_string();
    if !kernel_cmdline.is_empty() {
        return kernel_cmdline;
    }
    let image = ev.image_str();
    if image.is_empty() {
        String::new()
    } else {
        image.to_string()
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

fn read_cgroup(pid: u32) -> String {
    fs::read_to_string(format!("/proc/{pid}/cgroup"))
        .ok()
        .and_then(|s| {
            s.lines()
                .find(|l| l.starts_with("0::"))
                .or_else(|| s.lines().next())
                .map(|l| l.trim().to_string())
        })
        .unwrap_or_else(|| "-".to_string())
}

fn read_namespace(pid: u32, name: &str) -> String {
    fs::read_link(format!("/proc/{pid}/ns/{name}"))
        .ok()
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_else(|| "-".to_string())
}

fn read_stat_session_tty(pid: u32) -> (Option<u32>, Option<u32>) {
    let stat = match fs::read_to_string(format!("/proc/{pid}/stat")) {
        Ok(s) => s,
        Err(_) => return (None, None),
    };
    let after_comm = match stat.rsplit(')').next() {
        Some(s) => s,
        None => return (None, None),
    };
    let mut fields = after_comm.split_whitespace();
    // state
    let _ = fields.next();
    // ppid
    let _ = fields.next();
    // pgrp
    let _ = fields.next();
    let session = fields.next().and_then(|v| v.parse().ok());
    let tty_nr = fields.next().and_then(|v| v.parse().ok());
    (session, tty_nr)
}

fn cred_syscall_name(id: u32) -> &'static str {
    match id {
        CRED_SETUID => "setuid",
        CRED_SETEUID => "seteuid",
        CRED_SETREUID => "setreuid",
        CRED_SETRESUID => "setresuid",
        CRED_SETFSUID => "setfsuid",
        CRED_SETGID => "setgid",
        CRED_SETEGID => "setegid",
        CRED_SETREGID => "setregid",
        CRED_SETRESGID => "setresgid",
        CRED_SETFSGID => "setfsgid",
        CRED_SETGROUPS => "setgroups",
        _ => "unknown",
    }
}

fn cap_syscall_name(id: u32) -> &'static str {
    match id {
        CAP_CAPSET => "capset",
        CAP_PRCTL => "prctl",
        _ => "unknown",
    }
}

fn rename_syscall_name(id: u32) -> &'static str {
    match id {
        RENAME_RENAME => "rename",
        RENAME_RENAMEAT => "renameat",
        RENAME_RENAMEAT2 => "renameat2",
        _ => "unknown",
    }
}

fn chmod_syscall_name(id: u32) -> &'static str {
    match id {
        CHMOD_CHMOD => "chmod",
        CHMOD_FCHMOD => "fchmod",
        CHMOD_FCHMODAT => "fchmodat",
        CHMOD_FCHMODAT2 => "fchmodat2",
        _ => "unknown",
    }
}

fn chown_syscall_name(id: u32) -> &'static str {
    match id {
        CHOWN_CHOWN => "chown",
        CHOWN_LCHOWN => "lchown",
        CHOWN_FCHOWN => "fchown",
        CHOWN_FCHOWNAT => "fchownat",
        _ => "unknown",
    }
}

fn truncate_syscall_name(id: u32) -> &'static str {
    match id {
        TRUNCATE_TRUNCATE => "truncate",
        TRUNCATE_FTRUNCATE => "ftruncate",
        _ => "unknown",
    }
}

fn write_syscall_name(id: u32) -> &'static str {
    match id {
        WRITE_WRITE => "write",
        WRITE_PWRITE64 => "pwrite64",
        WRITE_WRITEV => "writev",
        WRITE_PWRITEV => "pwritev",
        WRITE_PWRITEV2 => "pwritev2",
        _ => "unknown",
    }
}

fn resolve_target_or_fd(pid: u32, dirfd: i32, raw: &str, fd: i32) -> String {
    if !raw.is_empty() {
        if raw.starts_with('/') {
            return raw.to_string();
        }
        return resolve_target_path(pid, dirfd, raw);
    }
    if fd >= 0 {
        return fs::read_link(format!("/proc/{pid}/fd/{fd}"))
            .ok()
            .map(|p| p.to_string_lossy().into_owned())
            .unwrap_or_else(|| "-".to_string());
    }
    "-".to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ebpf_common::{
        ARG0_LEN, ARG1_LEN, ARG2_LEN, DnsResponseEvent, EVENT_DNS_RESPONSE, EVENT_EXEC,
        EVENT_FILE_CHANGE, EVENT_FORK, EVENT_NET, ExecEvent, ExitEvent, FileChangeEvent, IMAGE_LEN,
        NetEvent,
    };
    use std::net::{TcpListener, TcpStream, UdpSocket};
    use std::os::fd::AsRawFd;
    use std::os::unix::net::UnixStream;

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
            arg1: [0; ARG1_LEN],
            arg2: [0; ARG2_LEN],
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
            fd: -1,
            family,
            _pad0: 0,
            port_be,
            initiated: 1,
            _pad1: 0,
            _pad2: 0,
            addr,
            comm: *b"curl\0\0\0\0\0\0\0\0\0\0\0\0",
        }
    }

    #[test]
    fn exec_event_emits_sysmon_linux_json() {
        let mut b = EventBuilder::new();
        let event = b.exec_event(&sample_exec(FAKE_PID));
        assert_eq!(event.event_json["product"], "linux");
        assert_eq!(event.event_json["service"], "sysmon");
        assert_eq!(event.event_json["category"], "process_creation");
        assert_eq!(event.event_json["Event"]["System"]["EventID"], 1);
        assert_eq!(
            event.event_json["Event"]["System"]["Channel"],
            "Linux-Sysmon/Operational"
        );
        assert_eq!(
            event.event_json["Event"]["EventData"]["Image"],
            "/usr/bin/id"
        );
        assert_eq!(
            event.event_json["Event"]["EventData"]["CommandLine"],
            "/usr/bin/id"
        );
        assert_eq!(
            event.event_json["Event"]["EventData"]["ProcessId"],
            FAKE_PID.to_string()
        );
        assert_eq!(event.event_json["Event"]["EventData"]["User"], "root");
        let raw: serde_json::Value = serde_json::from_slice(&event.event_raw).unwrap();
        assert_eq!(raw["Event"]["EventData"]["Image"], "/usr/bin/id");
        assert_eq!(raw["Event"]["System"]["EventID"], 1);
    }

    #[test]
    fn net_event_emits_sysmon_linux_json() {
        let mut b = EventBuilder::new();
        let _ = b.exec_event(&sample_exec(FAKE_PID));
        let addr = [127, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        let event = b.net_event(&sample_net(2, 22u16.to_be(), addr));
        assert_eq!(event.event_json["product"], "linux");
        assert_eq!(event.event_json["service"], "sysmon");
        assert_eq!(event.event_json["category"], "network_connection");
        assert_eq!(event.event_json["Event"]["System"]["EventID"], 3);
        assert_eq!(
            event.event_json["Event"]["EventData"]["DestinationIp"],
            "127.0.0.1"
        );
        assert_eq!(
            event.event_json["Event"]["EventData"]["DestinationPort"],
            "22"
        );
        assert_eq!(event.event_json["Event"]["EventData"]["Protocol"], "tcp");
        assert_eq!(event.event_json["Event"]["EventData"]["Initiated"], "true");
    }

    #[test]
    fn exec_event_falls_back_to_argv0_when_image_is_empty() {
        let mut ev = sample_exec(FAKE_PID);
        ev.image = [0; IMAGE_LEN];
        let mut b = EventBuilder::new();
        let event = b.exec_event(&ev);
        assert_eq!(
            event.event_json["Event"]["EventData"]["Image"],
            "/usr/bin/id"
        );
    }

    #[test]
    fn fork_lineage_resolves_parent_and_is_cleaned_on_exit() {
        let mut b = EventBuilder::new();
        let parent_pid = FAKE_PID - 2;
        let child_pid = FAKE_PID - 1;
        let parent = b.exec_event(&sample_exec(parent_pid));
        assert_eq!(
            parent.event_json["Event"]["EventData"]["Image"],
            "/usr/bin/id"
        );

        b.fork_event(&ForkEvent {
            kind: EVENT_FORK,
            parent_tgid: parent_pid,
            child_pid,
            _pad0: 0,
        });
        assert_eq!(b.fork_parents.get(&child_pid), Some(&parent_pid));

        let child = b.exec_event(&sample_exec(child_pid));
        assert_eq!(
            child.event_json["Event"]["EventData"]["ParentProcessId"],
            parent_pid.to_string()
        );
        assert_eq!(
            child.event_json["Event"]["EventData"]["ParentImage"],
            "/usr/bin/id"
        );
        assert!(!b.fork_parents.contains_key(&child_pid));

        b.fork_event(&ForkEvent {
            kind: EVENT_FORK,
            parent_tgid: parent_pid,
            child_pid,
            _pad0: 0,
        });
        assert!(
            b.exit_event(&ExitEvent {
                kind: 2,
                pid: parent_pid,
                tid: child_pid,
                _pad0: 0,
            })
            .is_none()
        );
        assert!(!b.fork_parents.contains_key(&child_pid));
    }

    #[test]
    fn fork_lineage_cache_is_bounded() {
        let mut b = EventBuilder::new();
        for pid in 0..(FORK_CACHE_CAP as u32 + 16) {
            b.fork_event(&ForkEvent {
                kind: EVENT_FORK,
                parent_tgid: 1,
                child_pid: pid,
                _pad0: 0,
            });
        }
        assert_eq!(b.fork_parents.len(), FORK_CACHE_CAP);
    }

    #[test]
    fn file_change_event_keeps_regular_files_only() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("target");
        let file = fs::File::create(&path).unwrap();
        let mut b = EventBuilder::new();
        let event = b
            .file_change_event(&FileChangeEvent {
                kind: EVENT_FILE_CHANGE,
                pid: std::process::id(),
                uid: 0,
                gid: 0,
                syscall: WRITE_WRITE,
                fd: file.as_raw_fd(),
                bytes_written: 1,
                comm: [0; 16],
            })
            .expect("regular file write must be emitted");
        assert_eq!(
            event.event_json["Event"]["EventData"]["TargetFilename"],
            path.to_string_lossy().as_ref()
        );

        let (socket, _peer) = UnixStream::pair().unwrap();
        assert!(
            b.file_change_event(&FileChangeEvent {
                kind: EVENT_FILE_CHANGE,
                pid: std::process::id(),
                uid: 0,
                gid: 0,
                syscall: WRITE_WRITE,
                fd: socket.as_raw_fd(),
                bytes_written: 1,
                comm: [0; 16],
            })
            .is_none()
        );
    }

    #[test]
    fn accepted_socket_without_sockaddr_resolves_both_endpoints() {
        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let listen_port = listener.local_addr().unwrap().port();
        let client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let client_port = client.local_addr().unwrap().port();
        let (accepted, _) = listener.accept().unwrap();

        let mut b = EventBuilder::new();
        let event = b.net_event(&NetEvent {
            kind: EVENT_NET,
            pid: std::process::id(),
            uid: 0,
            gid: 0,
            fd: accepted.as_raw_fd(),
            family: 0,
            _pad0: 0,
            port_be: 0,
            initiated: 0,
            _pad1: 0,
            _pad2: 0,
            addr: [0; 16],
            comm: [0; 16],
        });
        assert_eq!(event.event_json["Event"]["EventData"]["Initiated"], "false");
        assert_eq!(
            event.event_json["Event"]["EventData"]["SourcePort"],
            client_port.to_string()
        );
        assert_eq!(
            event.event_json["Event"]["EventData"]["DestinationPort"],
            listen_port.to_string()
        );
    }

    #[test]
    fn dns_response_reports_rcode_in_query_status() {
        let mut payload = [0u8; 256];
        payload[2] = 0x81;
        payload[3] = 0x83; // response, NXDOMAIN (RCODE 3)
        payload[5] = 1; // QDCOUNT
        payload[12..17].copy_from_slice(b"\x03www\x00");
        payload[17..21].copy_from_slice(&[0, 1, 0, 1]);

        let mut b = EventBuilder::new();
        let event = b
            .dns_response_event(&DnsResponseEvent {
                kind: EVENT_DNS_RESPONSE,
                pid: FAKE_PID,
                uid: 0,
                gid: 0,
                payload_len: 21,
                fd: -1,
                source_port_be: 53u16.to_be(),
                source_valid: 1,
                _pad0: 0,
                _pad1: 0,
                comm: [0; 16],
                payload,
            })
            .expect("valid DNS response");
        assert_eq!(event.event_json["Event"]["EventData"]["QueryName"], "www");
        assert_eq!(event.event_json["Event"]["EventData"]["QueryStatus"], "3");
    }

    #[test]
    fn dns_response_without_source_address_rejects_non_dns_socket() {
        let receiver = UdpSocket::bind(("127.0.0.1", 0)).unwrap();
        let sender = UdpSocket::bind(("127.0.0.1", 0)).unwrap();
        sender.connect(receiver.local_addr().unwrap()).unwrap();

        let mut payload = [0u8; 256];
        payload[2] = 0x81;
        payload[3] = 0x80;
        payload[5] = 1;
        payload[12..17].copy_from_slice(b"\x03www\x00");
        payload[17..21].copy_from_slice(&[0, 1, 0, 1]);

        let mut b = EventBuilder::new();
        assert!(
            b.dns_response_event(&DnsResponseEvent {
                kind: EVENT_DNS_RESPONSE,
                pid: std::process::id(),
                uid: 0,
                gid: 0,
                payload_len: 21,
                fd: sender.as_raw_fd(),
                source_port_be: 0,
                source_valid: 0,
                _pad0: 0,
                _pad1: 0,
                comm: [0; 16],
                payload,
            })
            .is_none()
        );
    }

    #[test]
    fn taxonomy_file_is_embedded_and_valid_json() {
        let v: serde_json::Value = serde_json::from_str(EBPF_TAXONOMY_JSON).unwrap();
        assert_eq!(v["version"], 1);
        assert!(v["events"]["process_creation"].is_object());
        assert_eq!(
            v["events"]["process_creation"]["sigma_category"],
            "process_creation"
        );
    }
}
