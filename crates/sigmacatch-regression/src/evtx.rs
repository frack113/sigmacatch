// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 sigmacatch contributors

#[cfg(windows)]
use anyhow::anyhow;
use anyhow::{Context, Result};
use std::path::Path;
#[cfg(windows)]
use std::thread::sleep;
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
/// NOT written on Windows: the SigmaHQ CI runner only accepts `type: evtx`
/// tests, so a committed `.xml` would fail `true-positive-tests`.
///
/// Non-Windows platforms still write `.xml` for local tooling (`check_evtx`).
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

/// Non-Windows fallback: write raw XML as `.xml` for local tooling only
/// (`check_evtx`). Never committed by the Windows pipeline.
#[cfg(not(windows))]
pub fn write_evtx(xml: &str, _channel: &str, _record_id: Option<u64>, path: &Path) -> Result<()> {
    let xml_path = path.with_extension("xml");
    std::fs::write(&xml_path, xml)
        .with_context(|| format!("Failed to write XML: {}", xml_path.display()))?;
    tracing::info!("Wrote XML (non-Windows): {}", xml_path.display());
    Ok(())
}
