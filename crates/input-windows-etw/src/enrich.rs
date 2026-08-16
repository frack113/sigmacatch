// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 sigmacatch contributors

//! Assembly-time enrichment of synthesized ETW events (AD-6/7/8/9).
//!
//! Runs on the *renamed* field map of each record, in the single translation
//! point required by AD-8: kernel fields are renamed by `field_maps`, then this
//! module (a) translates NT device paths to Win32 (paths), (b) correlates
//! `FileObject`→name for Read/Write/Close (filekey), (c) attaches the process
//! context (`Image`/`ParentImage`/`CommandLine`/`User`) via the PID table with
//! a `CreateTime` PID-reuse guard, and (d) shapes the events that are
//! masqueraded as Sysmon with Sysmon-style fields: `UtcTime`, `ProcessGuid`
//! (machine GUID + create time + PID, MD5) and — for process creation —
//! version info + hashes of the image and the full parent context.
//!
//! Everything is fail-open: an unknown PID, an unreadable MachineGuid, a
//! failed PEB/token query or an unhashable image yields an absent field,
//! never a lost event.

use std::collections::HashMap;
use std::sync::Mutex;

use ferrisetw::EventRecord;

use crate::filekey::FileKeyTable;
use crate::filetime_quad_to_sysmon_utc;
use crate::paths;
use crate::pe::PeInfo;
use crate::process_query;
use crate::process_table::{ProcessEnrichment, ProcessTable};
use crate::sysmon;

/// Max PE metadata entries cached by path (bounds RAM).
const MAX_PE_CACHE_ENTRIES: usize = 512;

/// Kernel-File internals stripped from the final EventData of a Sysmon-shaped
/// file event (they have no Sysmon equivalent and would leak kernel objects).
const KERNEL_FILE_INTERNALS: [&str; 12] = [
    "FileObject",
    "FileKey",
    "Irp",
    "ThreadId",
    "CreateOptions",
    "CreateAttributes",
    "ShareAccess",
    "ByteOffset",
    "IOSize",
    "IOFlags",
    "ExtraInformation",
    "InfoClass",
];

/// Parent context resolved live for process-creation events (AD-6 fallback):
/// the parent is not always seeded in the table, so the missing pieces are
/// queried on demand and cached back into the table under the CreateTime guard.
struct ParentContext {
    create_time: i64,
    image: Option<String>,
    command_line: Option<String>,
    user: Option<String>,
}

/// Bounded LRU cache of PE metadata, keyed by normalized image path.
struct PeCache {
    map: HashMap<String, (PeInfo, u64)>,
    next_seq: u64,
}

impl PeCache {
    fn new() -> Self {
        Self {
            map: HashMap::new(),
            next_seq: 0,
        }
    }

    fn get(&mut self, path: &str) -> Option<PeInfo> {
        self.map.get_mut(path).map(|(info, seq)| {
            self.next_seq = self.next_seq.wrapping_add(1);
            *seq = self.next_seq;
            info.clone()
        })
    }

    fn insert(&mut self, path: String, info: PeInfo) {
        self.next_seq = self.next_seq.wrapping_add(1);
        self.map.insert(path, (info, self.next_seq));
        self.evict();
    }

    fn evict(&mut self) {
        while self.map.len() > MAX_PE_CACHE_ENTRIES {
            let oldest = self
                .map
                .iter()
                .min_by_key(|(_, (_, seq))| *seq)
                .map(|(k, _)| k.clone());
            if let Some(k) = oldest {
                self.map.remove(&k);
            } else {
                break;
            }
        }
    }
}

/// Shared enrichment state, locked once per synthesized event. All provider
/// callbacks run on the single trace thread, so the mutex is uncontended.
pub struct EnrichState {
    mounts: Vec<(String, String)>,
    process_table: ProcessTable,
    filekey: FileKeyTable,
    /// `HKLM\...\MachineGuid`, the seed of the Sysmon ProcessGuid algorithm.
    machine_guid: Option<String>,
    pe_cache: PeCache,
}

impl EnrichState {
    pub fn new() -> Self {
        let mounts = paths::build_mounts();
        let process_table = crate::process_table::snapshot();
        for (i, (prefix, replacement)) in mounts.iter().enumerate() {
            tracing::info!("mount[{i}]: prefix={prefix:?} replacement={replacement:?}");
        }
        let machine_guid = sysmon::read_machine_guid();
        match &machine_guid {
            Some(g) => tracing::info!("MachineGuid: {g}"),
            None => tracing::warn!("MachineGuid unreadable — ProcessGuid fields will be absent"),
        }
        tracing::info!(
            "ETW enrichment state: {} mounts, {} processes",
            mounts.len(),
            process_table.len()
        );
        Self {
            mounts,
            process_table,
            filekey: FileKeyTable::new(),
            machine_guid,
            pe_cache: PeCache::new(),
        }
    }

    /// Apply AD-6/7/8/9 enrichment to the renamed fields of one record.
    ///
    /// `event_id` is the *raw* ETW EventID (not the synthesized Sysmon ID): the
    /// arms below select on the provider's native events, which all collapse to
    /// the same Sysmon EventID once mapped.
    pub fn enrich(
        &mut self,
        provider_name: &str,
        event_id: u16,
        record: &EventRecord,
        fields: &mut HashMap<String, String>,
    ) {
        let pid = record.process_id();
        let ts = record.raw_timestamp();
        match provider_name {
            "Microsoft-Windows-Kernel-Process" => self.enrich_process(event_id, pid, ts, fields),
            "Microsoft-Windows-Kernel-File" => self.enrich_file(event_id, pid, ts, fields),
            // Network, Registry and DNS events carry no PID in the payload — the
            // record's process is the caller; enrich it like the other Sysmon EIDs.
            "Microsoft-Windows-Kernel-Network"
            | "Microsoft-Windows-Kernel-Registry"
            | "Microsoft-Windows-DNS-Client" => {
                fields
                    .entry("ProcessId".to_string())
                    .or_insert_with(|| pid.to_string());
                self.enrich_sysmon_common(pid, ts, fields);
            }
            _ => {}
        }
    }
}

impl EnrichState {
    fn normalize_path(&self, p: &str) -> String {
        let out = paths::normalize(p, &self.mounts);
        if out == p && p.starts_with("\\Device\\") {
            tracing::info!("untranslated NT device path: {p}");
        }
        out
    }

    fn enrich_process(
        &mut self,
        event_id: u16,
        pid: u32,
        ts: i64,
        fields: &mut HashMap<String, String>,
    ) {
        fields
            .entry("ProcessId".to_string())
            .or_insert_with(|| pid.to_string());
        match event_id {
            1 => self.enrich_process_start(pid, ts, fields),
            2 => self.enrich_process_stop(pid, fields),
            10 => {
                self.enrich_image_load(fields);
                self.enrich_sysmon_common(pid, ts, fields);
            }
            _ => {}
        }
    }

    /// Full Sysmon EventID 1 (process creation): identity, hashes/version of the
    /// image, PEB/token enrichment and the live-resolved parent context.
    fn enrich_process_start(&mut self, pid: u32, ts: i64, fields: &mut HashMap<String, String>) {
        let image = fields.remove("Image").map(|i| self.normalize_path(&i));
        let parent_pid = fields
            .get("ParentProcessId")
            .and_then(|s| s.parse::<u32>().ok());
        let etw_create_time = fields
            .remove("CreateTime")
            .and_then(|s| s.parse::<i64>().ok());

        // A just-started PID is the newest truth (AD-6): replace any recycled
        // entry *before* recording the CreateTime, so the stale enrichment of
        // the previous incarnation never leaks here.
        self.process_table
            .on_process_start(pid, image.clone(), parent_pid);
        if let Some(ct) = etw_create_time {
            self.process_table.set_create_time(pid, ct);
        }

        // Lazy PEB/token enrichment (also validates the CreateTime identity).
        self.ensure_enriched(pid);
        let create_time =
            etw_create_time.or_else(|| self.process_table.get(pid).and_then(|p| p.create_time));

        fields.insert("UtcTime".to_string(), filetime_quad_to_sysmon_utc(ts));
        fields.insert("RuleName".to_string(), String::new());
        if let Some(ct) = create_time {
            fields.insert(
                "CreationUtcTime".to_string(),
                filetime_quad_to_sysmon_utc(ct),
            );
            if let Some(mg) = &self.machine_guid {
                fields.insert("ProcessGuid".to_string(), sysmon::process_guid(mg, ct, pid));
            }
        }

        if let Some(img) = &image {
            fields.insert("Image".to_string(), img.clone());
            self.insert_pe_fields(img, fields);
        }

        if let Some(enrichment) = self.cached_enrichment(pid) {
            if let Some(cl) = enrichment.command_line {
                fields.insert("CommandLine".to_string(), cl);
            }
            if let Some(u) = enrichment.user {
                fields.insert("User".to_string(), u);
            }
            if let Some(cd) = enrichment.current_directory {
                fields.insert("CurrentDirectory".to_string(), cd);
            }
            if let Some(il) = enrichment.integrity_level {
                fields.insert("IntegrityLevel".to_string(), il);
            }
            if let Some(li) = enrichment.logon_id {
                fields.insert("LogonId".to_string(), li);
            }
        }

        if let Some(ppid) = parent_pid {
            self.enrich_parent(ppid, fields);
        }
    }

    fn enrich_process_stop(&mut self, pid: u32, fields: &mut HashMap<String, String>) {
        if let Some(img) = fields.get("Image").cloned() {
            fields.insert("Image".to_string(), self.normalize_path(&img));
        } else if let Some(img) = self.process_table.get(pid).and_then(|p| p.image.clone()) {
            fields.insert("Image".to_string(), img);
        }
        self.process_table.on_process_exit(pid);
    }

    fn enrich_image_load(&mut self, fields: &mut HashMap<String, String>) {
        if let Some(img) = fields.get("Image").cloned() {
            let img = self.normalize_path(&img);
            fields.insert("Image".to_string(), img.clone());
            fields.insert("ImageLoaded".to_string(), img);
        }
    }

    /// Hash + version info of the image into the fields, cache-first (AD: the
    /// image is hashed at most once per path).
    fn insert_pe_fields(&mut self, image: &str, fields: &mut HashMap<String, String>) {
        let info = self.pe_cache.get(image).or_else(|| {
            let info = crate::pe::pe_info(image)?;
            self.pe_cache.insert(image.to_string(), info.clone());
            Some(info)
        });
        let Some(info) = info else { return };
        if !info.sha256.is_empty() {
            fields.insert(
                "Hashes".to_string(),
                sysmon::format_hashes(&info.sha256, &info.md5, &info.sha1, &info.imphash),
            );
        }
        if let Some(v) = info.file_version {
            fields.insert("FileVersion".to_string(), v);
        }
        if let Some(v) = info.description {
            fields.insert("Description".to_string(), v);
        }
        if let Some(v) = info.product {
            fields.insert("Product".to_string(), v);
        }
        if let Some(v) = info.company {
            fields.insert("Company".to_string(), v);
        }
        if let Some(v) = info.original_filename {
            fields.insert("OriginalFileName".to_string(), v);
        }
    }

    /// Parent context: table-first, live queries for the missing pieces, cached
    /// back under the CreateTime guard so sibling events reuse them.
    fn parent_context(&mut self, ppid: u32) -> Option<ParentContext> {
        if ppid == 0 {
            return None;
        }
        self.ensure_enriched(ppid);
        let (cached_image, cached_ct, cached_cl, cached_user) = match self.process_table.get(ppid) {
            Some(e) => (
                e.image.clone(),
                e.create_time,
                e.enrichment.command_line.clone(),
                e.enrichment.user.clone(),
            ),
            None => (None, None, None, None),
        };
        let create_time = cached_ct.or_else(|| process_query::query_create_time(ppid))?;
        let image = cached_image.or_else(|| process_query::query_image_path(ppid));
        if let Some(img) = &image {
            self.process_table
                .upsert_snapshot(ppid, Some(img.clone()), create_time);
        }
        let command_line = cached_cl.or_else(|| process_query::query_command_line(ppid));
        let user = cached_user.or_else(|| process_query::query_user_name(ppid));
        Some(ParentContext {
            create_time,
            image,
            command_line,
            user,
        })
    }

    fn enrich_parent(&mut self, ppid: u32, fields: &mut HashMap<String, String>) {
        let Some(parent) = self.parent_context(ppid) else {
            return;
        };
        if let Some(mg) = &self.machine_guid {
            fields.insert(
                "ParentProcessGuid".to_string(),
                sysmon::process_guid(mg, parent.create_time, ppid),
            );
        }
        if let Some(img) = &parent.image {
            fields.insert("ParentImage".to_string(), img.clone());
        }
        if let Some(cl) = &parent.command_line {
            fields.insert("ParentCommandLine".to_string(), cl.clone());
        }
        if let Some(u) = &parent.user {
            fields.insert("ParentUser".to_string(), u.clone());
        }
    }

    fn enrich_file(
        &mut self,
        event_id: u16,
        pid: u32,
        ts: i64,
        fields: &mut HashMap<String, String>,
    ) {
        fields
            .entry("ProcessId".to_string())
            .or_insert_with(|| pid.to_string());
        // Only the raw events that map to Sysmon 11/23 get the Sysmon shaping;
        // the rest (NameCreate/NameDelete/Read/Cleanup/Close) exist to maintain
        // the FileObject→name table.
        let sysmon_shaped = matches!(event_id, 12 | 16 | 26 | 27);
        match event_id {
            // NameCreate/NameDelete (10/11): name-bearing, keyed by FileKey.
            10 | 11 => {
                if let Some(name) = fields
                    .get("TargetFilename")
                    .cloned()
                    .map(|n| self.normalize_path(&n))
                {
                    if let Some(fk) = fields.get("FileKey").cloned() {
                        self.filekey.insert(fk, name.clone());
                    }
                    fields.insert("TargetFilename".to_string(), name);
                }
                if event_id == 11 {
                    if let Some(fk) = fields.get("FileKey") {
                        self.filekey.purge(fk);
                    }
                }
            }
            // Create (12): name-bearing, keyed by FileObject (+ FileKey alias).
            12 => {
                let name = fields
                    .get("TargetFilename")
                    .cloned()
                    .map(|n| self.normalize_path(&n));
                if let Some(fo) = fields.get("FileObject").cloned() {
                    if let Some(n) = &name {
                        self.filekey.insert(fo, n.clone());
                    }
                }
                if let Some(fk) = fields.get("FileKey").cloned() {
                    if let Some(n) = &name {
                        self.filekey.insert(fk, n.clone());
                    }
                }
                if let Some(n) = name {
                    fields.insert("TargetFilename".to_string(), n);
                }
            }
            // Cleanup/Read/Write (13/15/16): no name in the payload — resolve
            // it through the FileObject table (AD-9).
            13 | 15 | 16 => {
                let key = fields.get("FileObject").or_else(|| fields.get("FileKey"));
                if let Some(key) = key {
                    if let Some(name) = self.filekey.resolve(key) {
                        fields.insert("TargetFilename".to_string(), name.to_string());
                    }
                }
            }
            // Close (14): resolve the name, then purge the object.
            14 => {
                let key = fields
                    .get("FileObject")
                    .or_else(|| fields.get("FileKey"))
                    .cloned();
                if let Some(key) = &key {
                    if let Some(name) = self.filekey.resolve(key) {
                        fields.insert("TargetFilename".to_string(), name.to_string());
                    }
                    self.filekey.purge(key);
                }
            }
            // DeletePath/RenamePath/SetLinkPath (26/27/28): FilePath → Sysmon 23.
            26..=28 => {
                if let Some(p) = fields.get("TargetFilename").cloned() {
                    fields.insert("TargetFilename".to_string(), self.normalize_path(&p));
                }
            }
            _ => return,
        }
        if !sysmon_shaped {
            return; // table maintenance only
        }
        // Kernel internals never reach the Sysmon-shaped EventData.
        for k in KERNEL_FILE_INTERNALS {
            fields.remove(k);
        }
        self.enrich_sysmon_common(pid, ts, fields);
    }

    /// Minimal Sysmon shaping shared by every Sysmon-masqueraded EID except
    /// process creation: `RuleName` (empty), `UtcTime`, `ProcessGuid` and the
    /// PID context (Image/CommandLine/User).
    fn enrich_sysmon_common(&mut self, pid: u32, ts: i64, fields: &mut HashMap<String, String>) {
        fields.insert("RuleName".to_string(), String::new());
        fields.insert("UtcTime".to_string(), filetime_quad_to_sysmon_utc(ts));
        self.ensure_enriched(pid);
        if let Some(ct) = self.process_table.get(pid).and_then(|p| p.create_time) {
            if let Some(mg) = &self.machine_guid {
                fields.insert("ProcessGuid".to_string(), sysmon::process_guid(mg, ct, pid));
            }
        }
        self.enrich_pid_context(pid, fields);
    }

    /// Attach Image/CommandLine/User of `pid` to the event (cache-first).
    fn enrich_pid_context(&mut self, pid: u32, fields: &mut HashMap<String, String>) {
        self.ensure_enriched(pid);
        if let Some(info) = self.process_table.get(pid) {
            if let Some(img) = &info.image {
                fields.insert("Image".to_string(), img.clone());
            }
            if let Some(cl) = &info.enrichment.command_line {
                fields.insert("CommandLine".to_string(), cl.clone());
            }
            if let Some(u) = &info.enrichment.user {
                fields.insert("User".to_string(), u.clone());
            }
        }
    }

    fn cached_enrichment(&self, pid: u32) -> Option<ProcessEnrichment> {
        self.process_table
            .get(pid)
            .map(|info| info.enrichment.clone())
    }

    /// Lazy PEB/token enrichment with the CreateTime PID-reuse guard (AD-7).
    ///
    /// Cache-first: at most one successful read per PID identity. On a CreateTime
    /// change the cache is recomputed — never the previous process's data.
    fn ensure_enriched(&mut self, pid: u32) {
        if pid == 0 {
            return;
        }
        let Some(create_time) = process_query::query_create_time(pid) else {
            return; // fail-open: process gone/unreadable, retried on next event
        };
        if let Some(entry) = self.process_table.get(pid) {
            if entry.create_time == Some(create_time)
                && (entry.enrichment.command_line.is_some()
                    || entry.enrichment.user.is_some()
                    || entry.enrichment.integrity_level.is_some())
            {
                return;
            }
        }
        let command_line = process_query::query_command_line(pid);
        let user = process_query::query_user_name(pid);
        let current_directory = process_query::query_current_directory(pid);
        let integrity_level = process_query::query_integrity_level(pid);
        let logon_id = process_query::query_logon_id(pid);
        self.process_table.cache_enrichment(
            pid,
            create_time,
            ProcessEnrichment {
                command_line,
                user,
                current_directory,
                integrity_level,
                logon_id,
            },
        );
    }
}

/// Shared state holder used by the collector (mutexed for the trace thread).
pub type SharedEnrich = Mutex<EnrichState>;
