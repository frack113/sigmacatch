// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 sigmacatch contributors

//! FileObject → FileName correlation (AD-9).
//!
//! Kernel-File events 15 (Read) and 16 (Write) do **not** carry a file name —
//! only a `FileObject`/`FileKey` (an opaque pointer identifying the open file).
//! The name is resolved through this table, which is fed by the events that do
//! carry one (10 NameCreate, 11 NameDelete, 12 Create) and purged when the
//! file is closed (14 Close) or deleted (11 NameDelete).
//!
//! Bounded (LRU): an attacker flooding new file objects cannot grow RAM
//! unboundedly — the oldest entries are evicted. Fail-open: an unknown key
//! simply yields no `TargetFilename` (norme at startup: a Read/Write may
//! precede the first naming event for a file opened before the trace).

use std::collections::HashMap;

/// Maximum number of tracked file objects (bounds the table's RAM).
const MAX_ENTRIES: usize = 4096;

#[derive(Debug, Default)]
pub struct FileKeyTable {
    map: HashMap<String, (String, u64)>,
    next_seq: u64,
}

impl FileKeyTable {
    pub fn new() -> Self {
        Self::default()
    }

    /// Record that `file_object` names `file_name`. Moves the entry to the
    /// front of the LRU order.
    pub fn insert(&mut self, file_object: String, file_name: String) {
        if file_object.is_empty() || file_name.is_empty() {
            return;
        }
        self.next_seq = self.next_seq.wrapping_add(1);
        self.map.insert(file_object, (file_name, self.next_seq));
        self.evict();
    }

    /// Resolve a file object (or FileKey alias) to its name.
    pub fn resolve(&self, file_object: &str) -> Option<&str> {
        self.map.get(file_object).map(|(name, _)| name.as_str())
    }

    /// Forget a file object on Close (14) / NameDelete (11).
    pub fn purge(&mut self, file_object: &str) {
        self.map.remove(file_object);
    }

    /// Keep the table within `MAX_ENTRIES`, evicting the least recently
    /// touched entries.
    fn evict(&mut self) {
        while self.map.len() > MAX_ENTRIES {
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

    #[cfg_attr(not(test), allow(dead_code))]
    pub fn len(&self) -> usize {
        self.map.len()
    }

    #[cfg_attr(not(test), allow(dead_code))]
    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_resolve_and_purge() {
        let mut t = FileKeyTable::new();
        t.insert(
            "0xffffc0001234".to_string(),
            "C:\\Windows\\System32\\WER.dll".to_string(),
        );
        assert_eq!(
            t.resolve("0xffffc0001234"),
            Some("C:\\Windows\\System32\\WER.dll")
        );
        // Close (14) purges the object.
        t.purge("0xffffc0001234");
        assert!(t.resolve("0xffffc0001234").is_none());
    }

    #[test]
    fn test_alias_resolution() {
        let mut t = FileKeyTable::new();
        t.insert("key".to_string(), "C:\\x.dll".to_string());
        // Read/Write events may carry FileKey while the table was keyed by
        // FileObject; both are aliases of the same open-file identity.
        t.insert("obj".to_string(), "C:\\x.dll".to_string());
        assert_eq!(t.resolve("obj"), Some("C:\\x.dll"));
    }

    #[test]
    fn test_fail_open_unknown_key() {
        let t = FileKeyTable::new();
        assert!(t.resolve("0xdeadbeef").is_none());
    }

    #[test]
    fn test_empty_inputs_ignored() {
        let mut t = FileKeyTable::new();
        t.insert(String::new(), "C:\\x".to_string());
        t.insert("k".to_string(), String::new());
        assert!(t.is_empty());
    }

    #[test]
    fn test_lru_bounded() {
        let mut t = FileKeyTable::new();
        for i in 0..5000 {
            t.insert(format!("k{i}"), format!("C:\\f{i}.dll"));
        }
        assert!(t.len() <= MAX_ENTRIES);
        // The oldest entries were evicted.
        assert!(t.resolve("k0").is_none());
        // The newest survive.
        assert!(t.resolve("k4999").is_some());
    }
}
