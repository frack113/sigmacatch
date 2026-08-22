// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 sigmacatch contributors

//! Multi-channel Windows Event Log collector that sends events into an mpsc channel.
//!
//! # API
//! - `EventCollector::new(channels)` → creates collector for specified channels
//! - Implements `EventProducer` trait — calls `run(tx)` to collect and send events

use std::sync::Arc;

use async_trait::async_trait;
use sigmacatch_types::{Event, EventProducer};
use tokio::sync::mpsc;
use tokio::sync::watch;
use tokio::task::JoinSet;
use tracing::info;

/// Timeout in ms for each EvtNext call. Kept short so the collector can
/// respond to shutdown signals within a bounded window even while blocked
/// inside the native Winevt API.
#[cfg(windows)]
const EVT_NEXT_TIMEOUT_MS: u32 = 1000;

/// Maximum events to collect per channel before the initial drain is capped.
#[cfg(windows)]
const MAX_EVENTS: usize = 100_000;

/// Backoff in ms when EvtNext returns a real error.
#[cfg(windows)]
const ERROR_BACKOFF_MS: u64 = 5_000;

/// Idle poll interval in ms when a channel has no new events (normal state).
/// Kept short so the collector checks the shutdown signal frequently.
#[cfg(windows)]
const IDLE_POLL_MS: u64 = 100;

/// Number of consecutive empty incremental cycles before probing for a record-id rollover.
#[cfg(windows)]
const ROLLOVER_CHECK_CYCLES: u32 = 30;

/// Minimum interval between per-channel collection progress logs.
#[cfg(windows)]
const COLLECT_LOG_INTERVAL_MS: u64 = 10_000;

/// Interval between "still alive" heartbeats when a channel has no new events.
#[cfg(windows)]
const IDLE_LOG_INTERVAL_SECS: u64 = 60;

/// Multi-channel Windows Event Log collector.
///
/// Spawns one task per channel. Each task continuously polls for new events
/// via the Winevt API until the receiver is dropped.
pub struct EventCollector {
    channels: Vec<String>,
}

impl EventCollector {
    /// Create a new collector for all configured channels.
    pub fn new(channels: Vec<String>) -> Self {
        Self { channels }
    }
}

#[async_trait]
impl EventProducer for EventCollector {
    async fn run(
        self: Box<Self>,
        tx: mpsc::Sender<Event>,
        stop: watch::Receiver<bool>,
    ) -> anyhow::Result<()> {
        let tx = Arc::new(tx);
        let mut handles = JoinSet::new();

        for channel in &self.channels {
            let tx = Arc::clone(&tx);
            let stop = stop.clone();
            let channel = channel.to_string();

            handles.spawn(async move {
                Self::collect_channel(channel, tx, stop).await;
            });
        }

        while let Some(res) = handles.join_next().await {
            if let Err(e) = res {
                tracing::warn!("Collector task failed: {e}");
            }
        }

        info!("EventCollector stopped");
        Ok(())
    }
}

impl EventCollector {
    /// Collect events from a single channel via Winevt API (continuous).
    #[cfg(windows)]
    async fn collect_channel(
        channel: String,
        tx: Arc<mpsc::Sender<Event>>,
        stop: watch::Receiver<bool>,
    ) {
        let ch = channel.clone();
        let result = tokio::task::spawn_blocking(move || {
            Self::collect_continuous(&ch, &tx, &stop);
        })
        .await;

        if let Err(e) = result {
            tracing::warn!("Channel '{channel}' collector panicked: {e}");
        }
    }

    /// Continuous event collection from a single channel using Winevt API.
    ///
    /// Polls the channel in a loop, using XPath `*[System[EventRecordID > {last}]]`
    /// to fetch only new events. Events are sent through `tx` as they arrive.
    /// Returns when `stop` is set, `tx.blocking_send()` fails (receiver dropped),
    /// or an unrecoverable error occurs.
    #[cfg(windows)]
    fn collect_continuous(channel: &str, tx: &mpsc::Sender<Event>, stop: &watch::Receiver<bool>) {
        use windows::Win32::System::EventLog::{EVT_HANDLE, EvtClose};

        let _com_guard = match Self::init_com() {
            Ok(g) => g,
            Err(e) => {
                tracing::warn!("CoInitializeEx failed for channel '{channel}': {e}");
                return;
            }
        };

        let mut last_record_id: u64 = 0;
        let mut empty_cycles: u32 = 0;
        let mut sent_lifetime: u64 = 0;
        let mut is_initial_drain = true;
        let drain_start = std::time::Instant::now();
        let mut last_log = std::time::Instant::now();
        let mut last_idle_log = std::time::Instant::now();

        while !*stop.borrow() {
            let channel_wide = str_to_wide(channel);
            let query_wide = if last_record_id == 0 {
                str_to_wide("*")
            } else {
                str_to_wide(&format!("*[System[EventRecordID > {}]]", last_record_id))
            };

            let query_handle = match Self::evt_query(&channel_wide, &query_wide) {
                Ok(h) => h,
                Err(e) => {
                    if Self::is_channel_not_found(&e) {
                        tracing::error!(
                            "Channel '{channel}' not found — excluding permanently (role/service not installed)"
                        );
                        return;
                    }
                    tracing::warn!("EvtQuery failed for channel '{channel}': {e}");
                    std::thread::sleep(std::time::Duration::from_millis(ERROR_BACKOFF_MS));
                    continue;
                }
            };

            let mut event_handles: Vec<isize> = vec![0; 32];
            let mut total_sent: usize = 0;
            let mut cycle_fetched: usize = 0;
            loop {
                if *stop.borrow() {
                    break;
                }

                let events_fetched = match Self::evt_next(query_handle, &mut event_handles) {
                    Ok(n) => n,
                    Err(e) => {
                        if Self::is_idle_error(&e) {
                            break; // normal idle timeout / no more items — re-query
                        }
                        tracing::warn!("EvtNext failed for channel '{channel}': {e}");
                        std::thread::sleep(std::time::Duration::from_millis(ERROR_BACKOFF_MS));
                        break;
                    }
                };
                if events_fetched == 0 {
                    break;
                }
                cycle_fetched += events_fetched as usize;

                for i in 0..events_fetched as usize {
                    let handle_value = event_handles[i];
                    if handle_value == 0 {
                        event_handles[i] = 0;
                        continue;
                    }

                    let event_handle = EVT_HANDLE(handle_value);
                    let render_result = Self::render_event(event_handle);
                    unsafe {
                        let _ = EvtClose(event_handle);
                    }
                    event_handles[i] = 0;

                    if let Some(event) = render_result {
                        if let Some(rid) = event
                            .record_id()
                            .or_else(|| Self::extract_record_id_from_raw(&event.event_raw))
                        {
                            if rid > last_record_id {
                                last_record_id = rid;
                            }
                        }
                        if tx.blocking_send(event).is_err() {
                            // Receiver dropped — close remaining handles and exit
                            for handle in event_handles
                                .iter_mut()
                                .take(events_fetched as usize)
                                .skip(i + 1)
                            {
                                if *handle != 0 {
                                    unsafe {
                                        let _ = EvtClose(EVT_HANDLE(*handle));
                                    }
                                    *handle = 0;
                                }
                            }
                            unsafe {
                                let _ = EvtClose(query_handle);
                            }
                            return;
                        }
                        total_sent += 1;
                        if total_sent >= MAX_EVENTS {
                            // Zero out unprocessed handles in the current batch to
                            // avoid leaking Winevt handles on break.
                            for handle in event_handles
                                .iter_mut()
                                .take(events_fetched as usize)
                                .skip(i + 1)
                            {
                                if *handle != 0 {
                                    unsafe {
                                        let _ = EvtClose(EVT_HANDLE(*handle));
                                    }
                                    *handle = 0;
                                }
                            }
                            tracing::warn!(
                                "Channel '{channel}' reached MAX_EVENTS ({MAX_EVENTS}), stopping initial drain"
                            );
                            break;
                        }
                    }
                }
            }

            unsafe {
                let _ = EvtClose(query_handle);
            }

            if total_sent == 0 {
                empty_cycles += 1;
                if cycle_fetched > 0 {
                    tracing::warn!(
                        "Channel '{channel}': fetched {cycle_fetched} events but 0 sent — events dropped during render/parse"
                    );
                }
                if is_initial_drain {
                    tracing::info!(
                        "Channel '{channel}': initial query OK — 0 events (channel exists but empty)"
                    );
                    is_initial_drain = false;
                } else if last_idle_log.elapsed()
                    >= std::time::Duration::from_secs(IDLE_LOG_INTERVAL_SECS)
                {
                    tracing::info!("Channel '{channel}': still alive — 0 new events since startup");
                    last_idle_log = std::time::Instant::now();
                }
                if empty_cycles >= ROLLOVER_CHECK_CYCLES {
                    empty_cycles = 0;
                    let max_record_id = Self::probe_max_record_id(channel);
                    if should_reset_after_idle(max_record_id, last_record_id) {
                        tracing::warn!(
                            "Channel '{channel}' record-id rollover detected (last={last_record_id}, max={max_record_id}); resetting to 0"
                        );
                        last_record_id = 0;
                    }
                }
                std::thread::sleep(std::time::Duration::from_millis(IDLE_POLL_MS));
                if *stop.borrow() {
                    break;
                }
            } else {
                empty_cycles = 0;
                sent_lifetime += total_sent as u64;
                if is_initial_drain {
                    tracing::info!(
                        "Channel '{channel}': initial drain collected {total_sent} events in {:?}",
                        drain_start.elapsed()
                    );
                    is_initial_drain = false;
                    last_log = std::time::Instant::now();
                } else if last_log.elapsed()
                    >= std::time::Duration::from_millis(COLLECT_LOG_INTERVAL_MS)
                {
                    tracing::info!(
                        "Channel '{channel}': {sent_lifetime} events collected so far (recent cycle: {total_sent})"
                    );
                    last_log = std::time::Instant::now();
                }
            }

            if *stop.borrow() {
                break;
            }
        }

        if sent_lifetime > 0 {
            tracing::info!(
                "Channel '{channel}': collector stopped after collecting {sent_lifetime} events"
            );
        }
    }

    /// True when `EvtNext` failed due to normal idle conditions (ERROR_TIMEOUT,
    /// ERROR_NO_MORE_ITEMS) — not an actual error worth logging.
    #[cfg(windows)]
    fn is_idle_error(e: &windows::core::Error) -> bool {
        use windows::Win32::Foundation::{ERROR_NO_MORE_ITEMS, ERROR_TIMEOUT};

        let code = e.code().0;
        code == windows::core::HRESULT::from_win32(ERROR_TIMEOUT.0).0
            || code == windows::core::HRESULT::from_win32(ERROR_NO_MORE_ITEMS.0).0
    }

    /// ERROR_EVT_CHANNEL_NOT_FOUND — the channel does not exist on this
    /// machine (the corresponding role/service is not installed). This is
    /// permanent, so the channel should be excluded rather than retried.
    #[cfg(windows)]
    fn is_channel_not_found(e: &windows::core::Error) -> bool {
        use windows::Win32::Foundation::ERROR_EVT_CHANNEL_NOT_FOUND;

        let code = e.code().0;
        code == windows::core::HRESULT::from_win32(ERROR_EVT_CHANNEL_NOT_FOUND.0).0
    }

    /// Extract the event record id directly from the raw rendered XML as a
    /// fallback when the structured parse did not carry it (avoids re-fetching
    /// duplicates on the next incremental query).
    #[cfg(windows)]
    fn extract_record_id_from_raw(raw: &[u8]) -> Option<u64> {
        const MARKER: &str = "<EventRecordID>";
        const END: &str = "</EventRecordID>";
        let s = std::str::from_utf8(raw).ok()?;
        let start = s.find(MARKER)? + MARKER.len();
        let rest = &s[start..];
        let end = rest.find(END)?;
        rest[..end].trim().parse().ok()
    }

    /// Probe the current maximum record id of the channel via a reverse-direction
    /// query (first result is the newest event). Returns 0 when the channel is
    /// empty or the query fails.
    #[cfg(windows)]
    fn probe_max_record_id(channel: &str) -> u64 {
        use windows::Win32::System::EventLog::{
            EVT_HANDLE, EvtClose, EvtNext, EvtQueryReverseDirection,
        };

        let channel_wide = str_to_wide(channel);
        let query_wide = str_to_wide("*");

        let query_handle =
            match Self::evt_query_flags(&channel_wide, &query_wide, EvtQueryReverseDirection.0) {
                Ok(h) => h,
                Err(_) => return 0,
            };

        let mut event_handles = [0isize; 1];
        let mut events_fetched: u32 = 0;
        let mut max_record_id: u64 = 0;

        let result = unsafe {
            EvtNext(
                query_handle,
                &mut event_handles,
                EVT_NEXT_TIMEOUT_MS,
                0,
                &mut events_fetched,
            )
        };

        if result.is_ok() && events_fetched > 0 && event_handles[0] != 0 {
            let event_handle = EVT_HANDLE(event_handles[0]);
            if let Some(event) = Self::render_event(event_handle) {
                max_record_id = event.record_id().unwrap_or(0);
            }
            unsafe {
                let _ = EvtClose(event_handle);
            }
        }

        unsafe {
            let _ = EvtClose(query_handle);
        }
        max_record_id
    }

    /// Query events from a channel with the given XPath query.
    #[cfg(windows)]
    fn evt_query(
        channel_wide: &[u16],
        query_wide: &[u16],
    ) -> Result<windows::Win32::System::EventLog::EVT_HANDLE, windows::core::Error> {
        use windows::Win32::System::EventLog::EvtQueryChannelPath;
        Self::evt_query_flags(channel_wide, query_wide, EvtQueryChannelPath.0)
    }

    /// Query events from a channel with the given XPath query and flags.
    #[cfg(windows)]
    fn evt_query_flags(
        channel_wide: &[u16],
        query_wide: &[u16],
        flags: u32,
    ) -> Result<windows::Win32::System::EventLog::EVT_HANDLE, windows::core::Error> {
        use windows::Win32::System::EventLog::EvtQuery;
        use windows::core::PCWSTR;

        let path = PCWSTR::from_raw(channel_wide.as_ptr());
        let query = PCWSTR::from_raw(query_wide.as_ptr());

        unsafe { EvtQuery(None, path, query, flags) }
    }

    /// Initialize COM apartment for the current thread.
    #[cfg(windows)]
    fn init_com() -> Result<ComGuard, String> {
        use windows::Win32::System::Com::{COINIT_APARTMENTTHREADED, CoInitializeEx};

        let hr = unsafe { CoInitializeEx(None, COINIT_APARTMENTTHREADED) };

        if hr.is_ok() {
            Ok(ComGuard)
        } else {
            Err(format!("CoInitializeEx failed: {hr}"))
        }
    }

    /// Fetch the next batch of events.
    #[cfg(windows)]
    fn evt_next(
        query_handle: windows::Win32::System::EventLog::EVT_HANDLE,
        event_handles: &mut [isize],
    ) -> Result<u32, windows::core::Error> {
        use windows::Win32::System::EventLog::EvtNext;

        let mut events_fetched: u32 = 0;

        unsafe {
            EvtNext(
                query_handle,
                event_handles,
                EVT_NEXT_TIMEOUT_MS,
                0,
                &mut events_fetched,
            )?;
        }

        Ok(events_fetched)
    }

    /// Render event handle to XML and parse into an Event.
    #[cfg(windows)]
    fn render_event(event_handle: windows::Win32::System::EventLog::EVT_HANDLE) -> Option<Event> {
        use windows::Win32::Foundation::ERROR_INSUFFICIENT_BUFFER;
        use windows::Win32::System::EventLog::{EvtRender, EvtRenderEventXml};

        // Size-probe: EvtRender fails with ERROR_INSUFFICIENT_BUFFER and
        // reports the required size through `buffer_size` — normal, not a failure.
        let mut buffer_size: u32 = 0;
        let result = unsafe {
            EvtRender(
                None,
                event_handle,
                EvtRenderEventXml.0,
                0,
                Some(std::ptr::null_mut()),
                &mut buffer_size,
                std::ptr::null_mut(),
            )
        };

        let insufficient_buffer = matches!(
            result.as_ref().err(),
            Some(e) if e.code() == windows::core::HRESULT::from_win32(ERROR_INSUFFICIENT_BUFFER.0)
        );

        if (result.is_err() && !insufficient_buffer) || buffer_size == 0 {
            return None;
        }

        let mut buffer: Vec<u8> = vec![0u8; buffer_size as usize];
        let mut bytes_used: u32 = 0;
        let result = unsafe {
            EvtRender(
                None,
                event_handle,
                EvtRenderEventXml.0,
                buffer_size,
                Some(buffer.as_mut_ptr().cast()),
                &mut bytes_used,
                std::ptr::null_mut(),
            )
        };

        if result.is_err() || bytes_used == 0 {
            return None;
        }

        // EvtRender writes a null-terminated UTF-16LE string (not UTF-8).
        let mut units: Vec<u16> = buffer[..bytes_used as usize]
            .chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .collect();
        if units.last() == Some(&0) {
            units.pop();
        }
        let xml_str = String::from_utf16_lossy(&units);

        let mut event = Event::from_xml(&xml_str).ok()?;
        event.inject_logsource_fields();
        Some(event)
    }

    /// Non-Windows stub: continuous collection is a no-op.
    #[cfg(not(windows))]
    async fn collect_channel(
        _channel: String,
        _tx: Arc<mpsc::Sender<Event>>,
        _stop: watch::Receiver<bool>,
    ) {
    }
}

/// COM initialization guard — calls `CoUninitialize` on drop.
#[cfg(windows)]
struct ComGuard;

#[cfg(windows)]
impl Drop for ComGuard {
    fn drop(&mut self) {
        use windows::Win32::System::Com::CoUninitialize;
        unsafe { CoUninitialize() };
    }
}

/// Convert a string to a null-terminated wide string for the Winevt API.
#[cfg(windows)]
fn str_to_wide(s: &str) -> Vec<u16> {
    let mut v: Vec<u16> = s.encode_utf16().collect();
    v.push(0);
    v
}

/// Decide whether an idle channel needs its record-id cursor reset.
///
/// A genuine rollover (log cleared) means the channel's newest record id is
/// strictly below the last id we processed — new events restart at low ids.
/// `max == last` is the normal idle state (no new events) and must NOT reset,
/// otherwise the whole log is re-fetched on every idle probe.
#[cfg_attr(not(windows), allow(dead_code))]
fn should_reset_after_idle(max_record_id: u64, last_record_id: u64) -> bool {
    max_record_id > 0 && max_record_id < last_record_id
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_no_reset_when_log_grew() {
        assert!(!should_reset_after_idle(200, 100));
    }

    #[test]
    fn test_no_reset_when_idle() {
        assert!(!should_reset_after_idle(1152, 1152));
    }

    #[test]
    fn test_reset_on_genuine_rollover() {
        assert!(should_reset_after_idle(7, 31545));
    }

    #[test]
    fn test_no_reset_when_channel_empty() {
        assert!(!should_reset_after_idle(0, 31545));
    }
}
