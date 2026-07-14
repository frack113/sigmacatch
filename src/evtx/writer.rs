use anyhow::{Context, Result};
use std::path::Path;

/// Write a valid EVTX file from a matched event.
///
/// On Windows, uses `EvtExportLog` to re-query the specific event by
/// RecordID and export it to a valid binary `.evtx` file.
///
/// Falls back to writing raw XML as `.xml` (not `.evtx`) if:
/// - RecordID or channel are unavailable
/// - EvtExportLog fails (event may have rotated out of retention)
/// - Non-Windows platform
///
/// **Known limitation:** `EvtExportLog` re-queries the live event log. If the
/// event has rotated out of the channel's retention window between collection
/// and export, the call will fail silently (ERROR_EVT_QUERY_RESULT_STALE).
/// This is inherent to the architecture — we store XML, not binary event data.
#[cfg(windows)]
pub fn write_evtx(xml: &str, channel: &str, record_id: Option<u64>, path: &Path) -> Result<()> {
    use windows::core::HSTRING;
    use windows::Win32::System::EventLog::{
        EvtExportLog, EvtExportLogChannelPath, EvtExportLogOverwrite,
    };

    if let Some(rid) = record_id {
        if !channel.is_empty() {
            let query = format!("*[System[EventRecordID={}]]", rid);
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
                Ok(()) => {
                    tracing::info!(
                        "Wrote EVTX via EvtExportLog: {} (channel={}, rid={})",
                        path.display(),
                        channel,
                        rid
                    );
                    return Ok(());
                }
                Err(e) => {
                    tracing::warn!(
                        "EvtExportLog failed for {} (rid={}): {} — event may have rotated out of log retention, writing XML fallback",
                        path.display(),
                        rid,
                        e
                    );
                }
            }
        }
    }

    // Fallback: write raw XML as .xml (not .evtx — invalid binary would break downstream tools)
    let xml_path = path.with_extension("xml");
    std::fs::write(&xml_path, xml)
        .with_context(|| format!("Failed to write XML fallback: {}", xml_path.display()))?;
    tracing::warn!(
        "Wrote XML fallback (not valid EVTX): {} — use EvtExportLog on Windows for binary EVTX",
        xml_path.display()
    );
    Ok(())
}

/// Non-Windows fallback: write raw XML as .xml (no Windows API available).
#[cfg(not(windows))]
pub fn write_evtx(xml: &str, _channel: &str, _record_id: Option<u64>, path: &Path) -> Result<()> {
    let xml_path = path.with_extension("xml");
    std::fs::write(&xml_path, xml)
        .with_context(|| format!("Failed to write XML: {}", xml_path.display()))?;
    tracing::info!("Wrote XML (non-Windows): {}", xml_path.display());
    Ok(())
}
