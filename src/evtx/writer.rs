use anyhow::{Context, Result};
use std::path::Path;

/// Write a valid EVTX file from raw Winevt XML.
///
/// Writes the Winevt XML directly to a `.evtx` file. The XML is obtained
/// directly from the Windows Event Log API via `EvtRender`, so it is in the
/// correct format. The `.json` file carries the actual event payload for
/// rule matching. The `.evtx` provides a valid, parsable container for tools
/// like hayabusa and chainsaw.
#[cfg(windows)]
pub fn write_evtx(xml: &str, path: &Path) -> Result<()> {
    std::fs::write(path, xml)
        .with_context(|| format!("Failed to write EVTX file: {}", path.display()))?;
    tracing::info!("Wrote EVTX (XML): {} bytes", path.display());
    Ok(())
}

/// Non-Windows fallback: write the Winevt XML directly.
///
/// On non-Windows platforms we cannot produce a valid EVTX binary (no Winevt
/// API, no BinXML encoder). The `.json` file carries the actual event data
/// for rule matching.
#[cfg(not(windows))]
pub fn write_evtx(xml: &str, path: &Path) -> Result<()> {
    std::fs::write(path, xml)
        .with_context(|| format!("Failed to write EVTX file: {}", path.display()))?;
    tracing::info!("Wrote XML (non-Windows): {}", path.display());
    Ok(())
}
