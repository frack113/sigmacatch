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
/// `EvtExportLog` returns success even when the query matched zero records
/// (header-only file), so every successful call is re-parsed; a file with no
/// records is retried (the live-log race may be transient) then treated as
/// failure. The empty `.evtx` is removed and an error is returned. No `.xml`
/// fallback is written: the SigmaHQ CI runner only accepts `type: evtx`.
#[cfg(windows)]
pub fn write_evtx(_xml: &str, channel: &str, record_id: Option<u64>, path: &Path) -> Result<()> {
    use windows::core::HSTRING;
    use windows::Win32::System::EventLog::{
        EvtExportLog, EvtExportLogChannelPath, EvtExportLogOverwrite,
    };

    let rid = record_id.ok_or_else(|| anyhow!("Cannot export EVTX: no record id"))?;
    if channel.is_empty() {
        return Err(anyhow!("Cannot export EVTX: empty channel"));
    }

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
            Ok(()) => match exported_has_records(path) {
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
        let _ = std::fs::remove_file(path);
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

/// Verify the exported file actually contains at least one parseable record.
#[cfg(windows)]
fn exported_has_records(path: &Path) -> Result<bool> {
    let events = input_evtx::parse_evtx_file(path)
        .with_context(|| format!("Failed to parse exported EVTX {}", path.display()))?;
    Ok(!events.is_empty())
}

/// Non-Windows has no `EvtExportLog`: error so the rule is skipped this cycle
/// rather than producing an unreadable file.
#[cfg(not(windows))]
pub fn write_evtx(_xml: &str, _channel: &str, _record_id: Option<u64>, _path: &Path) -> Result<()> {
    Err(anyhow!(
        "EVTX export via EvtExportLog is Windows-only; no local data on non-Windows"
    ))
}
