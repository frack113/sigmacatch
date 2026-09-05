// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 sigmacatch contributors

//! Regression data formats: how a matched event becomes the per-rule data
//! file (`<rule_id>.evtx` or `<rule_id>.log`) and how existing data files are
//! validated cheaply during the skip-set scan.

use std::path::Path;

use crate::{RegressionError, Result};
use tracing::warn;

use sigmacatch_types::Alert;

/// Data-file extensions recognized in a rule directory, in validation
/// precedence order. `json` doubles as auxiliary output
/// (`regression.add_json_output`) and as legacy json-only data; `raw` is
/// read for pre-existing non-Winevt data but never generated.
pub(crate) const DATA_EXTENSIONS: [&str; 4] = ["evtx", "log", "raw", "json"];

/// EVTX files start with this 8-byte magic.
const EVTX_MAGIC: &[u8; 8] = b"ElfFile\x00";

/// Upper bound for any generated or scanned data blob — bounds RAM during
/// validation. Larger blobs are treated as broken so the rule is re-captured.
pub(crate) const MAX_DATA_BLOB_SIZE: usize = 64 * 1024 * 1024;

/// Output format of the per-rule regression data file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DataFormat {
    /// Windows Winevt — `.evtx`, re-exported from the live log
    /// (`EvtExportLog`) or synthesized with the pure-Rust writer.
    Evtx,
    /// Raw text lines (auditd) — `.log`, written from the event's original
    /// lines.
    Log,
}

impl DataFormat {
    /// File extension of the regression data file for this format.
    pub fn ext(self) -> &'static str {
        match self {
            Self::Evtx => "evtx",
            Self::Log => "log",
        }
    }

    /// Safety bound on a single data blob (AGENTS.md size limits).
    pub fn max_blob_size(self) -> usize {
        MAX_DATA_BLOB_SIZE
    }

    /// Provider written to `info.yml`. Evtx events carry their provider in
    /// the event XML — an empty one means a malformed event and fails
    /// generation rather than committing wrong contribution metadata (a
    /// Sysmon provider on a Windows rule discredits the whole PR). Log
    /// events use their XML provider when present (Sysmon for Linux writes
    /// winevt XML into syslog); plain text lines (auditd) have none and
    /// fall back to the collector identity.
    pub fn resolve_provider(self, alert: &Alert) -> Result<String> {
        match self {
            Self::Evtx => {
                let provider = alert.provider();
                if provider.is_empty() {
                    return Err(RegressionError::Invalid(
                        "event has no XML provider — refusing to generate with default provider metadata"
                            .to_string(),
                    ));
                }
                Ok(provider.to_string())
            }
            Self::Log => {
                let provider = alert.provider();
                if provider.is_empty() {
                    Ok("auditd".to_string())
                } else {
                    Ok(provider.to_string())
                }
            }
        }
    }

    /// Write the data file for one matched alert.
    pub fn write(self, alert: &Alert, path: &Path) -> Result<()> {
        match self {
            Self::Evtx => {
                crate::evtx::write_evtx(alert.raw_xml(), alert.channel(), alert.record_id(), path)
            }
            Self::Log => {
                if alert.event_raw.len() > self.max_blob_size() {
                    return Err(RegressionError::Invalid(format!(
                        "audit event exceeds {} MiB — refusing to write {}",
                        self.max_blob_size() / 1024 / 1024,
                        path.display()
                    )));
                }
                std::fs::write(path, &alert.event_raw).map_err(|e| {
                    RegressionError::Invalid(format!(
                        "Failed to write log data {}: {e}",
                        path.display()
                    ))
                })
            }
        }
    }

    /// Cheap structural validation used by `regressiondata-check`: stat + magic or
    /// prefix check, no full parse. Deep validation happens once, at write
    /// time (re-parse for EVTX). Broken data returns `false` so the rule is
    /// reported as failed in the check output.
    pub fn cheap_validate(self, path: &Path) -> bool {
        let meta = match std::fs::metadata(path) {
            Ok(m) => m,
            Err(e) => {
                warn!(
                    "cannot stat {} ({}) — excluded from skip-set, will be re-captured",
                    path.display(),
                    e
                );
                return false;
            }
        };
        if meta.len() as usize > self.max_blob_size() {
            warn!(
                "{} exceeds {} MiB — excluded from skip-set, will be re-captured",
                path.display(),
                self.max_blob_size() / 1024 / 1024
            );
            return false;
        }
        if meta.len() == 0 {
            warn!(
                "{} is empty — excluded from skip-set, will be re-captured",
                path.display()
            );
            return false;
        }
        match self {
            Self::Evtx => header_is_evtx(path),
            Self::Log => prefix_is_text(path, meta.len()),
        }
    }
}

/// Read the first bytes of a file (bounded read).
fn read_prefix(path: &Path, len: usize) -> Option<Vec<u8>> {
    use std::io::Read;

    let mut file = std::fs::File::open(path).ok()?;
    let cap = len.min(64 * 1024);
    let mut buf = vec![0u8; cap];
    file.read_exact(&mut buf).ok()?;
    Some(buf)
}

fn header_is_evtx(path: &Path) -> bool {
    match read_prefix(path, EVTX_MAGIC.len()) {
        Some(header) if header.as_slice() == EVTX_MAGIC => true,
        _ => {
            warn!(
                "{} has no EVTX header — excluded from skip-set, will be re-captured",
                path.display()
            );
            false
        }
    }
}

/// A valid `.log` starts with UTF-8 text. A truncated multi-byte character at
/// the read boundary is accepted (only the tail was cut, not corrupted).
fn prefix_is_text(path: &Path, size: u64) -> bool {
    let Some(buf) = read_prefix(path, size as usize) else {
        warn!(
            "{} unreadable — excluded from skip-set, will be re-captured",
            path.display()
        );
        return false;
    };
    match std::str::from_utf8(&buf) {
        Ok(_) => true,
        Err(e) if e.valid_up_to() == buf.len() && buf.len() < size as usize => true,
        Err(_) => {
            warn!(
                "{} is not UTF-8 text — excluded from skip-set, will be re-captured",
                path.display()
            );
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sigmacatch_types::Alert;

    fn bare_alert(event_raw: Vec<u8>) -> Alert {
        Alert {
            rule_id: uuid::Uuid::new_v4(),
            rule_title: "test".to_string(),
            description: None,
            rule_path: None,
            severity: "low".to_string(),
            event_json_raw: serde_json::json!({}),
            event_json: serde_json::json!({}),
            event_raw,
        }
    }

    #[test]
    fn test_ext() {
        assert_eq!(DataFormat::Evtx.ext(), "evtx");
        assert_eq!(DataFormat::Log.ext(), "log");
    }

    #[test]
    fn test_resolve_provider_evtx_requires_xml_provider() {
        assert!(
            DataFormat::Evtx
                .resolve_provider(&bare_alert(Vec::new()))
                .is_err()
        );
    }

    #[test]
    fn test_resolve_provider_log_is_auditd() {
        assert_eq!(
            DataFormat::Log
                .resolve_provider(&bare_alert(Vec::new()))
                .unwrap(),
            "auditd"
        );
    }

    #[test]
    fn test_resolve_provider_log_uses_xml_provider_when_present() {
        let mut alert = bare_alert(Vec::new());
        alert.event_json = serde_json::json!({
            "Event": { "System": { "Provider": { "#attributes": { "Name": "Linux-Sysmon" } } } }
        });
        assert_eq!(
            DataFormat::Log.resolve_provider(&alert).unwrap(),
            "Linux-Sysmon"
        );
    }

    #[test]
    fn test_cheap_validate_evtx_magic() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("x.evtx");

        std::fs::write(&path, b"not-an-evtx").unwrap();
        assert!(!DataFormat::Evtx.cheap_validate(&path));

        std::fs::write(&path, b"ElfFile\x00rest-of-header").unwrap();
        assert!(DataFormat::Evtx.cheap_validate(&path));

        std::fs::write(&path, b"").unwrap();
        assert!(!DataFormat::Evtx.cheap_validate(&path));
    }

    #[test]
    fn test_cheap_validate_log() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("x.log");

        assert!(!DataFormat::Log.cheap_validate(&path), "missing → invalid");

        std::fs::write(&path, b"").unwrap();
        assert!(!DataFormat::Log.cheap_validate(&path), "empty → invalid");

        std::fs::write(&path, b"type=EXECVE msg=audit(1.2:3): argc=2\n").unwrap();
        assert!(DataFormat::Log.cheap_validate(&path));
    }

    #[test]
    fn test_cheap_validate_oversized_blob() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("big.evtx");
        let file = std::fs::File::create(&path).unwrap();
        file.set_len((MAX_DATA_BLOB_SIZE as u64) + 1).unwrap();
        drop(file);
        assert!(!DataFormat::Evtx.cheap_validate(&path));
        assert!(!DataFormat::Log.cheap_validate(&tmp.path().join("missing.log")));
    }

    #[test]
    fn test_log_write_rejects_oversized_event() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("x.log");
        let alert = bare_alert(vec![0u8; MAX_DATA_BLOB_SIZE + 1]);
        assert!(DataFormat::Log.write(&alert, &path).is_err());
        assert!(!path.exists());

        let small = bare_alert(b"type=EXECVE msg=audit(1.2:3)\n".to_vec());
        DataFormat::Log.write(&small, &path).unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), small.event_raw);
    }
}
