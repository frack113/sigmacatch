// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 sigmacatch contributors

//! `Microsoft-Windows-Kernel-Registry` → Sysmon EID 12/13/14.
//!
//! The provider delivers `SetValueKey`/`DeleteValueKey`/`DeleteKey` with an
//! **empty `KeyName`**: the path only comes with the matching
//! `CreateKey`/`OpenKey` record, keyed by the `KeyObject` handle, and is
//! released by `CloseKey`. [`RegistryMapper`] keeps that cache so a write can
//! be reported with the key it landed on.
//!
//! Paths arrive in native form (`\REGISTRY\MACHINE\SOFTWARE\...`) and are
//! reported the way Sysmon reports `TargetObject`, with the hive abbreviations
//! Sigma rules are written against (`HKLM`, `HKU`).
//!
//! `Details` is the value *data* (Sysmon EID 13 semantics, which the rules
//! match on), not the value name. It only arrives when the session asked the
//! provider for `CapturedData`; see `sigmacatch_input_etw::TraceSession::enable_provider`.

use std::collections::HashMap;

use crate::etw_event::{DecodedEvent, PropertyValue};
use crate::registry_format::{abbreviate, format_value_data, from_hex};

/// `Kernel-Registry` event ids, measured with `etw_dump` on the test VM.
const CREATE_KEY: u16 = 1;
const OPEN_KEY: u16 = 2;
const DELETE_KEY: u16 = 3;
const SET_VALUE_KEY: u16 = 5;
const DELETE_VALUE_KEY: u16 = 6;
const CLOSE_KEY: u16 = 13;

/// `STATUS_SUCCESS`: the open/create failed otherwise and must not seed the
/// path cache.
const STATUS_SUCCESS: u64 = 0;

/// One Sysmon registry event, before rendering.
#[derive(Debug, PartialEq, Eq)]
pub struct RegistryEvent {
    /// Sysmon event id: 12 (create/delete key), 13 (set/delete value),
    /// 14 (rename key).
    pub event_id: u16,
    /// Sysmon `EventType`.
    pub event_type: &'static str,
    /// Sysmon `TargetObject`, in hive-abbreviated form.
    pub target_object: String,
    /// Sysmon `Details`: the value data, when the provider delivered it.
    pub details: Option<String>,
}

/// Key-handle → path cache, plus the event mapping.
#[derive(Default)]
pub struct RegistryMapper {
    /// `KeyObject` → native key path.
    paths: HashMap<u64, String>,
}

impl RegistryMapper {
    /// Create an empty mapper.
    pub fn new() -> Self {
        Self::default()
    }

    /// Observe one `Kernel-Registry` record.
    ///
    /// Returns an event for the operations Sysmon reports, and `None` for the
    /// naming records (`OpenKey`, `CloseKey`) that only feed the cache.
    pub fn observe(&mut self, event: &DecodedEvent) -> Option<RegistryEvent> {
        match event.event_id {
            CREATE_KEY | OPEN_KEY => {
                let key = event.uint("KeyObject")?;
                if event.uint("Status") != Some(STATUS_SUCCESS) || key == 0 {
                    return None;
                }
                let path = self.resolve(event)?;
                self.paths.insert(key, path.clone());
                (event.event_id == CREATE_KEY).then(|| RegistryEvent {
                    event_id: 12,
                    event_type: "CreateKey",
                    target_object: abbreviate(&path),
                    details: None,
                })
            }
            CLOSE_KEY => {
                if let Some(key) = event.uint("KeyObject") {
                    self.paths.remove(&key);
                }
                None
            }
            DELETE_KEY => {
                let path = self.key_path(event)?;
                Some(RegistryEvent {
                    event_id: 12,
                    event_type: "DeleteKey",
                    target_object: abbreviate(&path),
                    details: None,
                })
            }
            SET_VALUE_KEY | DELETE_VALUE_KEY => {
                let path = self.key_path(event)?;
                let value = event.str("ValueName").unwrap_or_default();
                let target_object = if value.is_empty() {
                    abbreviate(&path)
                } else {
                    format!("{}\\{}", abbreviate(&path), value)
                };
                let set = event.event_id == SET_VALUE_KEY;
                Some(RegistryEvent {
                    event_id: 13,
                    event_type: if set { "SetValue" } else { "DeleteValue" },
                    target_object,
                    details: set.then(|| self.value_data(event)).flatten(),
                })
            }
            _ => None,
        }
    }

    /// Key path for a record that carries no name of its own.
    fn key_path(&self, event: &DecodedEvent) -> Option<String> {
        if let Some(name) = event.str("KeyName")
            && !name.is_empty()
        {
            return Some(name.to_string());
        }
        let key = event.uint("KeyObject")?;
        self.paths.get(&key).cloned()
    }

    /// Absolute path of a `CreateKey`/`OpenKey` record.
    ///
    /// `RelativeName` is absolute for a top-level open and relative to
    /// `BaseName` otherwise; the base is itself a cached handle.
    fn resolve(&self, event: &DecodedEvent) -> Option<String> {
        let name = event.str("RelativeName").unwrap_or_default();
        if name.starts_with('\\') {
            return Some(name.to_string());
        }
        let base = event
            .uint("BaseObject")
            .and_then(|base| self.paths.get(&base))?;
        if name.is_empty() {
            Some(base.clone())
        } else {
            Some(format!("{base}\\{name}"))
        }
    }

    /// `Details` for a value write, from the captured value data.
    fn value_data(&self, event: &DecodedEvent) -> Option<String> {
        let data = event.bytes("CapturedData")?;
        let value_type = event.uint("Type").unwrap_or(0) as u32;
        format_value_data(value_type, &data)
    }
}

impl DecodedEvent {
    /// Raw bytes of a binary property (the decoder keeps it hex-encoded).
    pub fn bytes(&self, name: &str) -> Option<Vec<u8>> {
        let PropertyValue::Bin(hex) = &self.get(name)?.value else {
            return None;
        };
        from_hex(hex)
    }
}
