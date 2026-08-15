// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 sigmacatch contributors

//! PID → process context table (AD-6/AD-7).
//!
//! Feeds the synthesis of every Sysmon-shaped ETW event with `Image`,
//! `ParentProcessId`, `CommandLine` and `User` for the PID that produced the
//! record. Seeded from a startup snapshot and Kernel-Process events 1/2, and
//! enriched lazily (PEB/token) by [`crate::process_query`] via
//! [`ProcessTable::cache_enrichment`].
//!
//! `CreateTime` (FILETIME 100ns since 1601) is the **PID-reuse guard**: an
//! entry whose `create_time` differs from a freshly queried one belongs to a
//! recycled PID — the cached `CommandLine`/`User` are dropped and recomputed,
//! never carried over from the previous process.

use std::collections::HashMap;

/// Lazy PEB/token enrichment of a process entry (AD-7), all fail-open.
#[derive(Debug, Clone, Default)]
pub struct ProcessEnrichment {
    pub command_line: Option<String>,
    /// Token owner user (`DOMAIN\user`).
    pub user: Option<String>,
    pub current_directory: Option<String>,
    /// Token integrity label (e.g. `High`).
    pub integrity_level: Option<String>,
    /// Token logon id (`0x…`).
    pub logon_id: Option<String>,
}

#[derive(Debug, Clone, Default)]
pub struct ProcessInfo {
    /// Executable path (Win32 form) or process name.
    pub image: Option<String>,
    pub parent_pid: Option<u32>,
    /// Cached PEB/token enrichment (AD-7). Validated against `create_time`.
    pub enrichment: ProcessEnrichment,
    /// FILETIME quad (100ns since 1601); `None` until queried via
    /// `GetProcessTimes` or set from a Kernel-Process event.
    pub create_time: Option<i64>,
}

#[derive(Debug, Default)]
pub struct ProcessTable {
    map: HashMap<u32, ProcessInfo>,
}

impl ProcessTable {
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a fresh process from a Kernel-Process event 1 (ProcessStart).
    ///
    /// A just-started PID is the newest truth and always wins: PID reuse is
    /// settled here (the entry is replaced, so no stale `CommandLine`/`User`
    /// from the previous incarnation is carried over). `create_time` is left
    /// `None` until validated via `GetProcessTimes`.
    pub fn on_process_start(&mut self, pid: u32, image: Option<String>, parent_pid: Option<u32>) {
        self.map.insert(
            pid,
            ProcessInfo {
                image,
                parent_pid,
                ..Default::default()
            },
        );
    }

    /// Drop a process on Kernel-Process event 2 (ProcessStop).
    pub fn on_process_exit(&mut self, pid: u32) {
        self.map.remove(&pid);
    }

    /// Insert a snapshot entry (startup seed). Keeps existing enrichment when
    /// the CreateTime is unchanged (same process identity); replaces the entry
    /// when it differs (PID was reused since the snapshot).
    pub fn upsert_snapshot(&mut self, pid: u32, image: Option<String>, create_time: i64) {
        match self.map.get_mut(&pid) {
            Some(entry) if entry.create_time == Some(create_time) => {
                if entry.image.is_none() {
                    entry.image = image;
                }
            }
            _ => {
                self.map.insert(
                    pid,
                    ProcessInfo {
                        image,
                        create_time: Some(create_time),
                        ..Default::default()
                    },
                );
            }
        }
    }

    /// Cache lazily queried enrichment (AD-7), guarded by `create_time`.
    ///
    /// Call with the process's *current* CreateTime (from `GetProcessTimes`)
    /// right after querying. If the cached CreateTime differs, the PID was
    /// reused since the last query — the stale enrichment of the previous
    /// process is replaced.
    pub fn cache_enrichment(&mut self, pid: u32, create_time: i64, enrichment: ProcessEnrichment) {
        let entry = self.map.entry(pid).or_default();
        match entry.create_time {
            Some(old) if old != create_time => {
                entry.create_time = Some(create_time);
                entry.enrichment = enrichment;
            }
            _ => {
                entry.create_time = Some(create_time);
                let cached = &mut entry.enrichment;
                if cached.command_line.is_none() {
                    cached.command_line = enrichment.command_line;
                }
                if cached.user.is_none() {
                    cached.user = enrichment.user;
                }
                if cached.current_directory.is_none() {
                    cached.current_directory = enrichment.current_directory;
                }
                if cached.integrity_level.is_none() {
                    cached.integrity_level = enrichment.integrity_level;
                }
                if cached.logon_id.is_none() {
                    cached.logon_id = enrichment.logon_id;
                }
            }
        }
    }

    /// Record a CreateTime seen on the ETW stream (Kernel-Process event 1).
    pub fn set_create_time(&mut self, pid: u32, create_time: i64) {
        self.map.entry(pid).or_default().create_time = Some(create_time);
    }

    pub fn get(&self, pid: u32) -> Option<&ProcessInfo> {
        self.map.get(&pid)
    }

    pub fn get_mut(&mut self, pid: u32) -> Option<&mut ProcessInfo> {
        self.map.get_mut(&pid)
    }

    pub fn len(&self) -> usize {
        self.map.len()
    }
}

/// Startup seed of the table (AD-6): `EnumProcesses` + `OpenProcess` +
/// `GetProcessTimes` + `QueryFullProcessImageNameW` + `NtQueryInformationProcess`.
/// Fail-open: processes that cannot be opened are skipped, never an error.
#[cfg(windows)]
pub fn snapshot() -> ProcessTable {
    use crate::process_query::{query_create_time, query_image_path, query_parent_pid};
    use windows::Win32::System::ProcessStatus::EnumProcesses;

    let mut table = ProcessTable::new();
    let mut pids = vec![0u32; 16384];
    let mut needed = 0u32;
    if unsafe {
        EnumProcesses(
            pids.as_mut_ptr(),
            (pids.len() * std::mem::size_of::<u32>()) as u32,
            &mut needed,
        )
    }
    .is_err()
    {
        return table;
    }
    let count = (needed as usize) / std::mem::size_of::<u32>();

    let mut rows: Vec<(u32, Option<String>, i64, Option<u32>)> = Vec::with_capacity(count);
    for &pid in &pids[..count] {
        if pid == 0 {
            continue;
        }
        if let (Some(image), Some(create_time)) = (query_image_path(pid), query_create_time(pid)) {
            rows.push((pid, Some(image), create_time, query_parent_pid(pid)));
        }
    }

    // Parent images are resolved live at enrichment time via
    // `table.get(parent_pid)`, so only the parent PID is stored here.
    for (pid, image, create_time, parent_pid) in rows {
        table.upsert_snapshot(pid, image, create_time);
        if let Some(ppid) = parent_pid {
            if let Some(entry) = table.get_mut(pid) {
                entry.parent_pid = Some(ppid);
            }
        }
    }
    table
}

#[cfg(test)]
mod tests {
    use super::*;

    fn enrichment(command_line: Option<&str>, user: Option<&str>) -> ProcessEnrichment {
        ProcessEnrichment {
            command_line: command_line.map(|s| s.to_string()),
            user: user.map(|s| s.to_string()),
            ..Default::default()
        }
    }

    #[test]
    fn test_on_process_start_replaces_reused_pid() {
        let mut t = ProcessTable::new();
        t.upsert_snapshot(100, Some("C:\\old.exe".to_string()), 111);
        t.cache_enrichment(100, 111, enrichment(Some("old --cmd"), Some("OLD\\u")));

        // Same PID restarted: ProcessStart is the newest truth.
        t.on_process_start(100, Some("C:\\new.exe".to_string()), Some(1));
        let e = t.get(100).unwrap();
        assert_eq!(e.image.as_deref(), Some("C:\\new.exe"));
        assert_eq!(e.enrichment.command_line, None); // stale enrichment dropped
        assert_eq!(e.enrichment.user, None);
    }

    #[test]
    fn test_cache_enrichment_create_time_guard() {
        let mut t = ProcessTable::new();
        t.upsert_snapshot(42, Some("C:\\a.exe".to_string()), 1000);
        t.cache_enrichment(42, 1000, enrichment(Some("a --x"), Some("DOM\\a")));

        // PID reused: CreateTime differs → enrichment replaced, not kept.
        t.cache_enrichment(42, 2000, enrichment(Some("b --y"), Some("DOM\\b")));
        let e = t.get(42).unwrap();
        assert_eq!(e.create_time, Some(2000));
        assert_eq!(e.enrichment.command_line.as_deref(), Some("b --y"));
        assert_eq!(e.enrichment.user.as_deref(), Some("DOM\\b"));
    }

    #[test]
    fn test_cache_enrichment_same_create_time_keeps_first() {
        let mut t = ProcessTable::new();
        t.upsert_snapshot(7, Some("C:\\x.exe".to_string()), 500);
        t.cache_enrichment(7, 500, enrichment(Some("first"), None));
        t.cache_enrichment(7, 500, enrichment(Some("second"), Some("DOM\\u")));
        let e = t.get(7).unwrap();
        assert_eq!(e.enrichment.command_line.as_deref(), Some("first")); // kept
        assert_eq!(e.enrichment.user.as_deref(), Some("DOM\\u")); // filled in
    }

    #[test]
    fn test_cache_enrichment_extra_fields_guard() {
        let mut t = ProcessTable::new();
        t.upsert_snapshot(42, Some("C:\\a.exe".to_string()), 1000);
        let mut extra = enrichment(Some("a --x"), Some("DOM\\a"));
        extra.current_directory = Some("C:\\a\\".to_string());
        extra.integrity_level = Some("High".to_string());
        extra.logon_id = Some("0x1f2".to_string());
        t.cache_enrichment(42, 1000, extra);

        // Same identity: existing fields kept, missing ones filled in.
        t.cache_enrichment(42, 1000, enrichment(Some("z"), Some("Z\\z")));
        let e = t.get(42).unwrap();
        assert_eq!(e.enrichment.command_line.as_deref(), Some("a --x"));
        assert_eq!(e.enrichment.current_directory.as_deref(), Some("C:\\a\\"));
        assert_eq!(e.enrichment.integrity_level.as_deref(), Some("High"));
        assert_eq!(e.enrichment.logon_id.as_deref(), Some("0x1f2"));

        // PID reused: everything replaced.
        t.cache_enrichment(42, 2000, enrichment(Some("b --y"), Some("DOM\\b")));
        let e = t.get(42).unwrap();
        assert_eq!(e.enrichment.current_directory, None);
        assert_eq!(e.enrichment.integrity_level, None);
        assert_eq!(e.enrichment.logon_id, None);
    }

    #[test]
    fn test_upsert_snapshot_same_identity_keeps_enrichment() {
        let mut t = ProcessTable::new();
        t.cache_enrichment(9, 100, enrichment(Some("cmd"), Some("D\\u")));
        // Snapshot with the same CreateTime must not wipe the enrichment.
        t.upsert_snapshot(9, Some("C:\\img.exe".to_string()), 100);
        let e = t.get(9).unwrap();
        assert_eq!(e.image.as_deref(), Some("C:\\img.exe"));
        assert_eq!(e.enrichment.command_line.as_deref(), Some("cmd"));
    }

    #[test]
    fn test_on_process_exit() {
        let mut t = ProcessTable::new();
        t.on_process_start(5, Some("C:\\x.exe".to_string()), None);
        t.on_process_exit(5);
        assert!(t.get(5).is_none());
    }

    #[test]
    fn test_fail_open_unknown_pid() {
        let t = ProcessTable::new();
        assert!(t.get(999).is_none());
    }
}
