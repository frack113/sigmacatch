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

/// Number of `EvtExportLog` attempts before giving up on the re-query.
#[cfg(windows)]
const EVTX_EXPORT_RETRIES: u32 = 3;

/// Backoff (seconds) between `EvtExportLog` attempts.
#[cfg(windows)]
const EVTX_EXPORT_BACKOFF_SECS: [u64; EVTX_EXPORT_RETRIES as usize] = [2, 5, 10];

/// Write a valid EVTX file from a matched event.
///
/// On Windows, uses `EvtExportLog` to re-query the specific event by
/// RecordID and export it to a valid binary `.evtx` file.
///
/// **Why validation + retry instead of an XML fallback:** `EvtExportLog`
/// returns success even when the query matched zero records (Microsoft: "If
/// the query result is empty, the service creates a file that contains header
/// information but no events"). Every successful call is therefore re-parsed;
/// a file with no records is retried with a short backoff (the live-log race
/// may be transient) and finally treated as a failure.
///
/// On failure the empty `.evtx` is removed and an error is returned. The
/// caller skips the rule this cycle (no commit, rule stays loaded) so a fresh
/// event is re-captured on a later cycle. A `.xml` fallback is deliberately
/// NOT written: the SigmaHQ CI runner only accepts `type: evtx` tests, so a
/// committed `.xml` would fail `true-positive-tests`.
///
/// On non-Windows there is no `EvtExportLog` API and no live Winevt collector,
/// so no data is generated — see the `#[cfg(not(windows))]` variant which
/// returns an error instead of the legacy v0.1.0 `.xml` fallback.
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

    for attempt in 0..=EVTX_EXPORT_RETRIES {
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

        if attempt < EVTX_EXPORT_RETRIES {
            sleep(Duration::from_secs(
                EVTX_EXPORT_BACKOFF_SECS[attempt as usize],
            ));
        }
    }

    // Every attempt failed or produced an empty file. Remove the broken
    // header-only `.evtx` so no invalid binary is ever committed.
    if path.exists() {
        let _ = std::fs::remove_file(path);
    }

    Err(anyhow!(
        "EvtExportLog produced no records for {} (channel={}, rid={}) after {} attempts — \
         the event likely rotated out of log retention; the rule will be re-captured on a later cycle",
        path.display(),
        channel,
        rid,
        EVTX_EXPORT_RETRIES + 1
    ))
}

/// Verify the exported file actually contains at least one parseable record.
#[cfg(windows)]
fn exported_has_records(path: &Path) -> Result<bool> {
    let events = input_evtx::parse_evtx_file(path)
        .with_context(|| format!("Failed to parse exported EVTX {}", path.display()))?;
    Ok(!events.is_empty())
}

/// Non-Windows platforms have no `EvtExportLog` API and no live Winevt collector
/// (the channel collector is a Windows-only stub), so there is no valid `.evtx`
/// to produce. Previously this wrote a raw `.xml` fallback, but the Windows-only
/// `EvtExportLog` path is the only one that emits committed regression data and
/// `check_evtx` only validates `type: evtx` data — the `.xml` output was dead code
/// since v0.1.0 and is now removed (see AGENTS.md EVTX invariants). Calling this
/// on a non-Windows host returns an error so the rule is skipped this cycle rather
/// than producing an unreadable `.xml`.
#[cfg(not(windows))]
pub fn write_evtx(_xml: &str, _channel: &str, _record_id: Option<u64>, _path: &Path) -> Result<()> {
    Err(anyhow!(
        "EVTX export via EvtExportLog is Windows-only; no local data on non-Windows"
    ))
}
