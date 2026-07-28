// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 sigmacatch contributors

//! `EventCollector` — multi-channel Winevt collector that sends events into an mpsc channel.

use std::sync::Arc;

use async_trait::async_trait;
use sigmacatch_types::{Event, EventProducer};
use tokio::sync::mpsc;
use tokio::task::JoinSet;
use tracing::info;

use crate::mapping::channel_list::ALL_CHANNELS;

/// Maximum events to collect per channel before stopping.
#[allow(dead_code)]
const MAX_EVENTS: usize = 100_000;
/// Timeout in ms for each EvtNext call.
#[allow(dead_code)]
const EVT_NEXT_TIMEOUT_MS: u32 = 5000;
/// Idle timeout per channel: if a channel returns no events for this duration,
/// it is considered exhausted (prevents 5s per-channel waste on empty logs).
#[allow(dead_code)]
const CHANNEL_IDLE_TIMEOUT_MS: u32 = 10_000;

/// Multi-channel Windows Event Log collector.
///
/// Spawns one task per channel. Each task collects events via Winevt
/// API and sends them into the provided `mpsc::Sender<Event>`.
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
    async fn run(self, tx: mpsc::Sender<Event>) -> anyhow::Result<()> {
        let channels = if self.channels.is_empty() {
            ALL_CHANNELS.iter().map(|s| s.to_string()).collect()
        } else {
            self.channels.clone()
        };

        let tx = Arc::new(tx);
        let mut handles = JoinSet::new();

        for channel in &channels {
            let tx = Arc::clone(&tx);
            let channel = channel.to_string();

            handles.spawn(async move {
                Self::collect_channel(channel, tx).await;
            });
        }

        // Wait for all tasks to complete
        while let Some(res) = handles.join_next().await {
            if let Err(e) = res {
                tracing::warn!("Collector task failed: {e}");
            }
        }

        info!("EventCollector stopped — all channels collected");
        Ok(())
    }
}

impl EventCollector {
    /// Collect events from a single channel via Winevt API.
    #[cfg(windows)]
    async fn collect_channel(channel: String, tx: Arc<mpsc::Sender<Event>>) {
        let channel_name = channel.clone();
        let result =
            tokio::task::spawn_blocking(move || Self::collect_events_blocking(&channel_name)).await;

        match result {
            Ok(events) => {
                let count = events.len();
                for event in events {
                    if tx.send(event).await.is_err() {
                        tracing::warn!("Channel '{channel}' — receiver dropped, stopping");
                        return;
                    }
                }
                info!("Collected {count} events from channel '{channel}'");
            }
            Err(e) => {
                tracing::warn!("Failed to collect from channel '{channel}': {e}");
            }
        }
    }

    /// Collect events from a single channel via Winevt API (blocking).
    #[cfg(windows)]
    fn collect_events_blocking(channel: &str) -> Vec<Event> {
        use windows::Win32::System::EventLog::{EvtClose, EVT_HANDLE};

        // Initialize COM for the thread
        let _com_guard = match Self::init_com() {
            Ok(g) => g,
            Err(e) => {
                tracing::warn!("CoInitializeEx failed for channel '{channel}': {e}");
                return Vec::new();
            }
        };

        // Convert channel name to wide string for Winevt API
        let channel_wide = channel_to_wide(channel);

        // Query events from channel (deferred query)
        let query_handle = match Self::evt_query(&channel_wide) {
            Ok(h) => h,
            Err(e) => {
                tracing::warn!("EvtQuery failed for channel '{channel}': {e}");
                return Vec::new();
            }
        };

        let mut events = Vec::new();
        let mut event_handles: Vec<isize> = vec![0; 32];
        let mut idle_count: u32 = 0;

        while events.len() < MAX_EVENTS {
            let events_fetched = match Self::evt_next(query_handle, &mut event_handles) {
                Ok(n) => n,
                Err(e) => {
                    tracing::warn!("EvtNext failed for channel '{channel}': {e}");
                    break;
                }
            };

            if events_fetched == 0 {
                idle_count += 1;
                if idle_count > CHANNEL_IDLE_TIMEOUT_MS / 10 {
                    tracing::debug!("Channel '{channel}' idle, stopping");
                    break;
                }
                continue;
            }

            idle_count = 0;

            for i in 0..events_fetched {
                let handle_value = event_handles[i as usize];
                if handle_value == 0 {
                    continue;
                }

                let event_handle = EVT_HANDLE(handle_value);
                Self::render_and_push(event_handle, channel, &mut events);

                // Close event handle
                unsafe {
                    let _ = EvtClose(event_handle);
                }
            }

            // Reset event handles for next batch
            for handle in event_handles.iter_mut() {
                *handle = 0;
            }
        }

        // Close query handle
        unsafe {
            let _ = EvtClose(query_handle);
        }

        // COM guard drops here, calling CoUninitialize
        events
    }

    /// Initialize COM apartment for the current thread.
    #[cfg(windows)]
    fn init_com() -> Result<ComGuard, String> {
        use windows::Win32::System::Com::{CoInitializeEx, COINIT_APARTMENTTHREADED};

        let hr = unsafe { CoInitializeEx(None, COINIT_APARTMENTTHREADED) };

        if hr.is_ok() {
            Ok(ComGuard)
        } else {
            Err(format!("CoInitializeEx failed: {hr}"))
        }
    }

    /// Query events from a channel.
    #[cfg(windows)]
    fn evt_query(
        channel_wide: &[u16],
    ) -> Result<windows::Win32::System::EventLog::EVT_HANDLE, String> {
        use windows::core::PCWSTR;
        use windows::Win32::System::EventLog::{EvtQuery, EvtQueryChannelPath};

        let path = PCWSTR::from_raw(channel_wide.as_ptr());
        let query = PCWSTR::from_raw(b"*\0".as_ptr() as *const u16);

        let handle = unsafe { EvtQuery(None, path, query, EvtQueryChannelPath.0) };

        match handle {
            Ok(h) => Ok(h),
            Err(e) => Err(format!("EvtQuery failed: {e}")),
        }
    }

    /// Fetch the next batch of events.
    #[cfg(windows)]
    fn evt_next(
        query_handle: windows::Win32::System::EventLog::EVT_HANDLE,
        event_handles: &mut [isize],
    ) -> Result<u32, String> {
        use windows::Win32::System::EventLog::EvtNext;

        let mut events_fetched: u32 = 0;

        let result = unsafe {
            EvtNext(
                query_handle,
                event_handles,
                EVT_NEXT_TIMEOUT_MS,
                0,
                &mut events_fetched,
            )
        };

        match result {
            Ok(()) => Ok(events_fetched),
            Err(e) => Err(format!("EvtNext failed: {e}")),
        }
    }

    /// Render event handle to XML and parse into Event.
    #[cfg(windows)]
    fn render_and_push(
        event_handle: windows::Win32::System::EventLog::EVT_HANDLE,
        _channel: &str,
        events: &mut Vec<Event>,
    ) {
        use windows::Win32::System::EventLog::{EvtRender, EvtRenderEventXml};

        // First call to get required buffer size
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

        if result.is_err() || buffer_size == 0 {
            return;
        }

        // Allocate and render
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
            return;
        }

        // Parse XML to Event
        let xml_str = match String::from_utf8(buffer[..bytes_used as usize].to_vec()) {
            Ok(s) => s,
            Err(_) => return,
        };

        if let Ok(mut event) = Event::from_xml(&xml_str) {
            event.inject_logsource_fields();
            events.push(event);
        }
    }

    /// Non-Windows stub: returns empty events.
    #[cfg(not(windows))]
    async fn collect_channel(_channel: String, _tx: Arc<mpsc::Sender<Event>>) {
        // stub on non-Windows
    }

    #[cfg(not(windows))]
    #[allow(dead_code)]
    fn collect_events_blocking(_channel: &str) -> Vec<Event> {
        Vec::new()
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

/// Convert a channel name to a null-terminated wide string.
#[cfg(windows)]
fn channel_to_wide(channel: &str) -> Vec<u16> {
    let mut v: Vec<u16> = channel.encode_utf16().collect();
    v.push(0);
    v
}
