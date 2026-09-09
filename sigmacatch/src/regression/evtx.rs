// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 sigmacatch contributors

use crate::regression::{RegressionError, Result};
use std::path::Path;
#[cfg(windows)]
use std::thread::sleep;
#[cfg(windows)]
use std::time::Duration;

/// EVTX file header magic ("ElfFile\0").
#[allow(dead_code)]
const EVTX_MAGIC: &[u8; 8] = b"ElfFile\x00";
/// Chunk header magic ("ElfChnk\0").
#[allow(dead_code)]
const EVTX_CHUNK_MAGIC: &[u8; 8] = b"ElfChnk\x00";
/// Minimum valid EVTX: 4096-byte header + 64 KiB chunk.
#[allow(dead_code)]
const MIN_EVTX_SIZE: u64 = 4096 + 64 * 1024;

/// Total `EvtExportLog` attempts (initial + retries) before giving up.
#[cfg(windows)]
const EVTX_EXPORT_MAX_ATTEMPTS: u32 = 4;

/// Backoff (seconds) between failed `EvtExportLog` attempts.
#[cfg(windows)]
const EVTX_EXPORT_BACKOFF_SECS: [u64; (EVTX_EXPORT_MAX_ATTEMPTS - 1) as usize] = [2, 5, 10];

/// Write a valid EVTX file from a matched event.
///
/// Path selection: events that exist in the live Event Log (Winevt collection,
/// with a record id) are re-exported via `EvtExportLog` (Windows only). Events
/// without a record id are written directly with the pure-Rust EVTX writer
/// (all platforms).
///
/// `EvtExportLog` returns success even for a zero-record match (header-only
/// file), so every successful call is re-parsed; an empty file is retried
/// (the live-log race may be transient) then treated as failure and the
/// `.evtx` is removed. The pure-Rust writer path applies the same re-parse
/// validation but no retry (deterministic writer).
///
/// Implementation details:
///
/// - The pure-Rust EVTX encoder lives in the [`crate::regression::evtx_writer`] module.
/// - Low-level deterministic API: [`crate::regression::evtx_writer::write_evtx_from_xml`]
///   (extracts timestamp from XML, errors if missing/malformed).
/// - Explicit-timestamp API: [`crate::regression::evtx_writer::write_evtx_from_xml_with_time`]
///   (fully deterministic, no fallback).
/// - Validation: [`validate_evtx_structure`] performs a full re-parse via the
///   `evtx` crate to verify structural integrity.
pub fn write_evtx(xml: &str, channel: &str, record_id: Option<u64>, path: &Path) -> Result<()> {
    let rid = record_id.unwrap_or(1);
    if record_id.is_none() {
        write_evtx_pure_rust(xml, channel, rid, path)
    } else {
        write_evtx_winevt(xml, channel, rid, path)
    }
}

/// Re-export a live-log event by record id + channel (`EvtExportLog`) with
/// retry + re-parse validation.
#[cfg(windows)]
fn write_evtx_winevt(_xml: &str, channel: &str, rid: u64, path: &Path) -> Result<()> {
    use windows::Win32::System::EventLog::{
        EvtExportLog, EvtExportLogChannelPath, EvtExportLogOverwrite,
    };
    use windows::core::HSTRING;

    if channel.is_empty() {
        return Err(RegressionError::Export(
            "Cannot export EVTX: empty channel".to_string(),
        ));
    }

    let path = crate::regression::long_path::long_path(path);
    let query = format!("*[System[EventRecordID={}]]", rid);

    for attempt in 0..EVTX_EXPORT_MAX_ATTEMPTS {
        // SAFETY: pure FFI wrapper — the three HSTRING arguments are valid
        // BSTR-compatible wide strings alive for the call; flags select
        // channel-path source + overwrite semantics per the EvtExportLog
        // contract. No pointers retained by the API.
        // SAFETY: `channel`, `query` and `path` are valid NUL-terminated HSTRINGs
        // built above; `EvtExportLog` is a documented Windows API that writes to `path`.
        let result = unsafe {
            EvtExportLog(
                None,
                &HSTRING::from(channel),
                &HSTRING::from(&query),
                &HSTRING::from(path.as_os_str()),
                EvtExportLogChannelPath.0 | EvtExportLogOverwrite.0,
            )
        };

        match result {
            Ok(()) => match exported_has_records(&path) {
                Ok(true) => {
                    tracing::info!(
                        "Wrote EVTX via EvtExportLog: {} (channel={}, rid={})",
                        path.display(),
                        channel,
                        rid
                    );
                    return Ok(());
                }
                Ok(false) => {
                    tracing::warn!(
                        "EvtExportLog succeeded but produced an empty EVTX for {} (channel={}, rid={}, attempt {}): query matched 0 records",
                        path.display(),
                        channel,
                        rid,
                        attempt + 1
                    );
                }
                Err(e) => {
                    tracing::warn!(
                        "EvtExportLog wrote an unreadable EVTX for {} (channel={}, rid={}, attempt {}): {}",
                        path.display(),
                        channel,
                        rid,
                        attempt + 1,
                        e
                    );
                }
            },
            Err(e) => {
                tracing::warn!(
                    "EvtExportLog failed for {} (channel={}, rid={}, attempt {}): {}",
                    path.display(),
                    channel,
                    rid,
                    attempt + 1,
                    e
                );
            }
        }

        if attempt + 1 < EVTX_EXPORT_MAX_ATTEMPTS {
            sleep(Duration::from_secs(
                EVTX_EXPORT_BACKOFF_SECS[attempt as usize],
            ));
        }
    }

    // Remove the header-only `.evtx` so no invalid binary is committed.
    if path.exists() {
        let _ = std::fs::remove_file(&path);
    }

    Err(RegressionError::Export(format!(
        "EvtExportLog produced no records for {} (channel={}, rid={}) after {} attempts — \
         the event likely rotated out of log retention; the rule will be re-captured on a later cycle",
        path.display(),
        channel,
        rid,
        EVTX_EXPORT_MAX_ATTEMPTS
    )))
}

/// Non-Windows has no `EvtExportLog`: error so the rule is skipped this cycle
/// rather than producing a file that does not match the live log.
#[cfg(not(windows))]
fn write_evtx_winevt(_xml: &str, channel: &str, _rid: u64, _path: &Path) -> Result<()> {
    Err(RegressionError::Export(format!(
        "EvtExportLog is not available on non-Windows (channel={channel})"
    )))
}

/// Write a synthesized single-record EVTX from the event XML (pure-Rust
/// writer) with lightweight structural validation. Unlike the live-log
/// export, no retry: the writer is deterministic (same XML → same output),
/// so an identical retry would fail identically.
///
/// Validation is a fast header check (magic + minimum size) rather than a
/// full re-parse — the writer is well-tested and deterministic, so a
/// structural check catches the failure modes that matter (truncated write,
/// wrong format) without the cost of `EvtxParser::from_path`.
fn write_evtx_pure_rust(xml: &str, channel: &str, rid: u64, path: &Path) -> Result<()> {
    let path = crate::regression::long_path::long_path(path);

    let result = crate::regression::evtx_writer::write_evtx_from_xml(xml, rid, &path)
        .map_err(|e| {
            RegressionError::Export(format!("evtx-writer failed for {}: {e}", path.display()))
        })
        .and_then(|_filetime| validate_evtx_structure(&path));

    match result {
        Ok(()) => {
            tracing::info!(
                "Wrote EVTX via evtx-writer: {} (channel={}, rid={})",
                path.display(),
                channel,
                rid
            );
            Ok(())
        }
        Err(e) => {
            if path.exists() {
                let _ = std::fs::remove_file(&path);
            }
            Err(e)
        }
    }
}

/// Verify the exported file contains at least one parseable record. Used only
/// by the `EvtExportLog` re-export path, where the OS (not our deterministic
/// writer) produces the file and a full parse is the only reliable check.
#[cfg(windows)]
fn exported_has_records(path: &Path) -> Result<bool> {
    let path = crate::regression::long_path::long_path(path);
    let events = crate::evtx_reader::parse_evtx_file(&path).map_err(|e| {
        RegressionError::Invalid(format!(
            "Failed to parse exported EVTX {}: {e}",
            path.display()
        ))
    })?;
    Ok(!events.is_empty())
}

/// Full structural validation for EVTX files written by the pure-Rust
/// writer. Re-parses the file via the `evtx` crate to verify complete
/// integrity (headers, chunk checksums, record structure, BinXML).
fn validate_evtx_structure(path: &Path) -> Result<()> {
    let mut parser = evtx::EvtxParser::from_path(path).map_err(|e| {
        RegressionError::Invalid(format!("Failed to parse EVTX {}: {e}", path.display()))
    })?;
    for record in parser.records() {
        record.map_err(|e| {
            RegressionError::Invalid(format!(
                "Failed to read record from EVTX {}: {e}",
                path.display()
            ))
        })?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::regression::evtx_writer::SAMPLE_XML;

    #[test]
    fn test_write_evtx_pure_rust_writes_valid_evtx() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("noid.evtx");
        write_evtx(
            SAMPLE_XML,
            "Microsoft-Windows-TaskScheduler/Operational",
            None,
            &path,
        )
        .unwrap();
        assert!(validate_evtx_structure(&path).is_ok());
    }

    #[test]
    fn test_write_evtx_without_record_id_uses_writer() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("noid.evtx");
        write_evtx(
            SAMPLE_XML,
            "Microsoft-Windows-TaskScheduler/Operational",
            None,
            &path,
        )
        .unwrap();
        assert!(validate_evtx_structure(&path).is_ok());
    }

    #[cfg(windows)]
    #[test]
    fn test_write_evtx_winevt_missing_channel_errors() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("nochannel.evtx");
        let err = write_evtx(SAMPLE_XML, "", Some(1), &path).unwrap_err();
        assert!(err.to_string().contains("empty channel"));
    }

    #[cfg(not(windows))]
    #[test]
    fn test_write_evtx_winevt_unavailable_on_non_windows() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("winevt.evtx");
        let err = write_evtx(SAMPLE_XML, "Some/Channel", Some(1), &path).unwrap_err();
        assert!(err.to_string().contains("not available on non-Windows"));
        assert!(!path.exists());
    }

    #[test]
    fn test_write_evtx_missing_timecreated_errors() {
        let xml = r#"<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Test" Guid="{123}"/>
    <EventID>1</EventID>
    <TimeCreated/>
    <EventRecordID>1</EventRecordID>
    <Channel>Test/Channel</Channel>
    <Computer>TEST</Computer>
    <Security UserID="S-1-5-18"/>
  </System>
  <EventData/>
</Event>"#;
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("missing_time.evtx");
        let err = write_evtx(xml, "Test/Channel", None, &path).unwrap_err();
        assert!(err.to_string().contains("no TimeCreated"));
    }

    #[test]
    fn test_write_evtx_malformed_timecreated_errors() {
        let xml = r#"<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Test" Guid="{123}"/>
    <EventID>1</EventID>
    <TimeCreated SystemTime="not-a-timestamp"/>
    <EventRecordID>1</EventRecordID>
    <Channel>Test/Channel</Channel>
    <Computer>TEST</Computer>
    <Security UserID="S-1-5-18"/>
  </System>
  <EventData/>
</Event>"#;
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("bad_time.evtx");
        let err = write_evtx(xml, "Test/Channel", None, &path).unwrap_err();
        assert!(err.to_string().contains("malformed SystemTime"));
    }
}
