// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 sigmacatch contributors

use anyhow::anyhow;
#[cfg(windows)]
use anyhow::Context;
use anyhow::Result;
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
/// For Winevt-collected events, `EvtExportLog` re-exports the live-log event
/// by record id + channel. For ETW-collected events (indicated by `is_etw`),
/// the event was synthesized from raw ETW data and never existed in the live
/// Event Log; `EvtExportLog` would always return an empty export, so we use
/// the pure-Rust EVTX writer directly instead.
///
/// `EvtExportLog` returns success even for a zero-record match (header-only
/// file), so every successful call is re-parsed; an empty file is retried
/// (the live-log race may be transient) then treated as failure and the
/// `.evtx` is removed.
#[cfg(windows)]
pub fn write_evtx(
    xml: &str,
    channel: &str,
    record_id: Option<u64>,
    is_etw: bool,
    path: &Path,
) -> Result<()> {
    if is_etw {
        let rid = record_id.ok_or_else(|| anyhow!("Cannot write EVTX: no record id"))?;
        sigmacatch_evtx_writer::write_evtx_from_xml(xml, rid, path)?;
        if !exported_has_records(path)? {
            let _ = std::fs::remove_file(path);
            return Err(anyhow!(
                "evtx-writer produced an unreadable EVTX for {} (rid={})",
                path.display(),
                rid
            ));
        }
        tracing::info!(
            "Wrote EVTX via evtx-writer: {} (channel={}, rid={})",
            path.display(),
            channel,
            rid
        );
        return Ok(());
    }

    use windows::core::HSTRING;
    use windows::Win32::System::EventLog::{
        EvtExportLog, EvtExportLogChannelPath, EvtExportLogOverwrite,
    };

    let rid = record_id.ok_or_else(|| anyhow!("Cannot export EVTX: no record id"))?;
    if channel.is_empty() {
        return Err(anyhow!("Cannot export EVTX: empty channel"));
    }

    let path = crate::long_path::long_path(path);
    let query = format!("*[System[EventRecordID={}]]", rid);

    for attempt in 0..EVTX_EXPORT_MAX_ATTEMPTS {
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

    Err(anyhow!(
        "EvtExportLog produced no records for {} (channel={}, rid={}) after {} attempts — \
         the event likely rotated out of log retention; the rule will be re-captured on a later cycle",
        path.display(),
        channel,
        rid,
        EVTX_EXPORT_MAX_ATTEMPTS
    ))
}

/// Verify the exported file contains at least one parseable record.
#[cfg(windows)]
fn exported_has_records(path: &Path) -> Result<bool> {
    let path = crate::long_path::long_path(path);
    let events = input_evtx::parse_evtx_file(&path)
        .with_context(|| format!("Failed to parse exported EVTX {}", path.display()))?;
    Ok(!events.is_empty())
}

/// Non-Windows has no `EvtExportLog` and no EVTX writer: error so the rule
/// is skipped this cycle rather than producing an unreadable file.
#[cfg(not(windows))]
pub fn write_evtx(
    _xml: &str,
    _channel: &str,
    _record_id: Option<u64>,
    _is_etw: bool,
    _path: &Path,
) -> Result<()> {
    Err(anyhow!("EVTX export is not available on non-Windows"))
}
