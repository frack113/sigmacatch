// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 sigmacatch contributors

use crate::{RegressionError, Result};
use std::path::Path;
#[cfg(windows)]
use std::thread::sleep;
#[cfg(windows)]
use std::time::Duration;

/// Total `EvtExportLog` attempts (initial + retries) before giving up.
#[cfg(windows)]
const EVTX_EXPORT_MAX_ATTEMPTS: u32 = 4;

/// Backoff (seconds) between failed `EvtExportLog` attempts.
#[cfg(windows)]
const EVTX_EXPORT_BACKOFF_SECS: [u64; (EVTX_EXPORT_MAX_ATTEMPTS - 1) as usize] = [2, 5, 10];

/// Write a valid EVTX file from a matched event.
///
/// Path selection: events that exist in the live Event Log (Winevt collection,
/// `is_etw == false` with a record id) are re-exported via `EvtExportLog`
/// (Windows only). Everything else — ETW-synthesized events (`is_etw == true`,
/// which carry a synthetic record id but never existed in a live log, so
/// `EvtExportLog` would always return an empty export) and record-id-less
/// events — is written directly with the pure-Rust EVTX writer (all
/// platforms).
///
/// `EvtExportLog` returns success even for a zero-record match (header-only
/// file), so every successful call is re-parsed; an empty file is retried
/// (the live-log race may be transient) then treated as failure and the
/// `.evtx` is removed. The ETW writer path applies the same re-parse
/// validation but no retry (deterministic writer — see `write_evtx_etw`).
pub fn write_evtx(
    xml: &str,
    channel: &str,
    record_id: Option<u64>,
    is_etw: bool,
    path: &Path,
) -> Result<()> {
    let rid = record_id.unwrap_or(1);
    if is_etw || record_id.is_none() {
        if !is_etw {
            tracing::warn!(
                "Writing EVTX via pure-Rust writer for a Winevt event without a record id (channel={}) — \
                 record id missing from the event XML",
                channel
            );
        }
        write_evtx_etw(xml, channel, rid, path)
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

    let path = crate::long_path::long_path(path);
    let query = format!("*[System[EventRecordID={}]]", rid);

    for attempt in 0..EVTX_EXPORT_MAX_ATTEMPTS {
        // SAFETY: pure FFI wrapper — the three HSTRING arguments are valid
        // BSTR-compatible wide strings alive for the call; flags select
        // channel-path source + overwrite semantics per the EvtExportLog
        // contract. No pointers retained by the API.
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
/// writer) with the same re-parse validation as `EvtExportLog`. Unlike the
/// live-log export, no retry: the writer is deterministic (same XML → same
/// output), so an identical retry would fail identically.
fn write_evtx_etw(xml: &str, channel: &str, rid: u64, path: &Path) -> Result<()> {
    let path = crate::long_path::long_path(path);

    let result = sigmacatch_evtx_writer::write_evtx_from_xml(xml, rid, &path)
        .map_err(|e| {
            RegressionError::Export(format!("evtx-writer failed for {}: {e}", path.display()))
        })
        .and_then(|()| exported_has_records(&path));

    match result {
        Ok(true) => {
            tracing::info!(
                "Wrote EVTX via evtx-writer: {} (channel={}, rid={})",
                path.display(),
                channel,
                rid
            );
            Ok(())
        }
        Ok(false) => {
            // Remove the invalid `.evtx` so no broken binary is committed.
            if path.exists() {
                let _ = std::fs::remove_file(&path);
            }
            Err(RegressionError::Export(format!(
                "evtx-writer produced an empty EVTX for {} (channel={}, rid={}) — \
                 the rule will be re-captured on a later cycle",
                path.display(),
                channel,
                rid
            )))
        }
        Err(e) => {
            if path.exists() {
                let _ = std::fs::remove_file(&path);
            }
            Err(RegressionError::Export(format!(
                "evtx-writer produced an unreadable EVTX for {} (channel={}, rid={}): {}",
                path.display(),
                channel,
                rid,
                e
            )))
        }
    }
}

/// Verify the exported file contains at least one parseable record.
#[cfg(windows)]
fn exported_has_records(path: &Path) -> Result<bool> {
    let path = crate::long_path::long_path(path);
    let events = input_windows_evtx::parse_evtx_file(&path).map_err(|e| {
        RegressionError::Invalid(format!(
            "Failed to parse exported EVTX {}: {e}",
            path.display()
        ))
    })?;
    Ok(!events.is_empty())
}

/// Non-Windows variant used by the pure-Rust writer path (no `Context`
/// needed there).
#[cfg(not(windows))]
fn exported_has_records(path: &Path) -> Result<bool> {
    let events = input_windows_evtx::parse_evtx_file(path).map_err(|e| {
        RegressionError::Invalid(format!(
            "Failed to parse exported EVTX {}: {e}",
            path.display()
        ))
    })?;
    Ok(!events.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE_XML: &str = r#"<?xml version="1.0" encoding="utf-8" standalone="yes"?>
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-TaskScheduler" Guid="{de7b24ea-73c8-4a09-985d-5bdadcfa9017}"/>
    <EventID>106</EventID>
    <Version>0</Version>
    <Level>4</Level>
    <Task>106</Task>
    <Opcode>0</Opcode>
    <Keywords>0x8020000000000000</Keywords>
    <TimeCreated SystemTime="2026-01-15T10:30:45.1234567Z"/>
    <EventRecordID>1</EventRecordID>
    <Correlation/>
    <Execution ProcessID="1234" ThreadID="5678"/>
    <Channel>Microsoft-Windows-TaskScheduler/Operational</Channel>
    <Computer>WIN-TEST</Computer>
    <Security UserID="S-1-5-18"/>
  </System>
  <EventData>
    <Data Name="TaskName">\MyTask &amp; More</Data>
  </EventData>
</Event>"#;

    #[test]
    fn test_write_evtx_etw_writes_valid_evtx() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("etw.evtx");
        write_evtx(
            SAMPLE_XML,
            "Microsoft-Windows-TaskScheduler/Operational",
            None,
            true,
            &path,
        )
        .unwrap();
        assert!(exported_has_records(&path).unwrap());
    }

    #[test]
    fn test_write_evtx_without_record_id_uses_writer() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("noid.evtx");
        write_evtx(
            SAMPLE_XML,
            "Microsoft-Windows-TaskScheduler/Operational",
            None,
            false,
            &path,
        )
        .unwrap();
        assert!(exported_has_records(&path).unwrap());
    }

    #[cfg(windows)]
    #[test]
    fn test_write_evtx_winevt_missing_channel_errors() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("nochannel.evtx");
        let err = write_evtx(SAMPLE_XML, "", Some(1), false, &path).unwrap_err();
        assert!(err.to_string().contains("empty channel"));
    }

    #[cfg(not(windows))]
    #[test]
    fn test_write_evtx_winevt_unavailable_on_non_windows() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("winevt.evtx");
        let err = write_evtx(SAMPLE_XML, "Some/Channel", Some(1), false, &path).unwrap_err();
        assert!(err.to_string().contains("not available on non-Windows"));
        assert!(!path.exists());
    }
}
