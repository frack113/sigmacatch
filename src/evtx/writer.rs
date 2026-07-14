use anyhow::{Context, Result};
use std::path::Path;

/// Write a valid EVTX file from a matched event.
///
/// On Windows, uses `EvtExportLog` to re-query the specific event by
/// RecordID and export it to a valid binary `.evtx` file. Falls back to
/// writing the raw XML stub if the event is no longer in the log or if
/// the channel/record_id are unavailable.
///
/// On non-Windows, writes the raw XML as a stub (valid EVTX requires the
/// Windows Event Log binary format).
#[cfg(windows)]
pub fn write_evtx(xml: &str, channel: &str, record_id: Option<u64>, path: &Path) -> Result<()> {
    use windows::core::HSTRING;
    use windows::Win32::System::EventLog::{
        EvtExportLog, EvtExportLogChannelPath, EvtExportLogOverwrite,
    };

    // Try to export a valid EVTX via the Windows API
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
                        "EvtExportLog failed for {} (rid={}): {} — writing XML stub",
                        path.display(),
                        rid,
                        e
                    );
                }
            }
        }
    }

    // Fallback: write raw XML
    std::fs::write(path, xml)
        .with_context(|| format!("Failed to write EVTX file: {}", path.display()))?;
    tracing::warn!("Wrote EVTX (XML stub, not valid binary): {}", path.display());
    Ok(())
}

/// Non-Windows fallback: write raw XML (no Windows API available).
#[cfg(not(windows))]
pub fn write_evtx(xml: &str, _channel: &str, _record_id: Option<u64>, path: &Path) -> Result<()> {
    std::fs::write(path, xml)
        .with_context(|| format!("Failed to write EVTX file: {}", path.display()))?;
    tracing::info!("Wrote XML (non-Windows): {}", path.display());
    Ok(())
}
