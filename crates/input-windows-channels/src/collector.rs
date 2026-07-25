// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 sigmacatch contributors

//! `EventCollector` — multi-channel Winevt collector with internal FIFO.

use std::collections::VecDeque;
use std::sync::Arc;

use sigmacatch_types::Event;
use tokio::sync::{mpsc, Mutex};
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
/// On `start()`, spawns one task per channel (95 tasks). Each task
/// collects events via Winevt API and pushes into the shared FIFO.
///
/// `get_events()` pops all entries from the FIFO.
/// `stop()` signals all collector tasks to shutdown and waits for them.
pub struct EventCollector {
    fifo: Arc<Mutex<VecDeque<Event>>>,
    tx: Option<mpsc::Sender<Event>>,
    handles: JoinSet<Result<(), String>>,
}

impl EventCollector {
    /// Launch collection on all 95 channels.
    ///
    /// Spawns one task per channel. Each task collects events via Winevt
    /// API and pushes into the shared FIFO.
    pub fn start() -> Self {
        let fifo = Arc::new(Mutex::new(VecDeque::new()));
        let (tx, mut rx) = mpsc::channel::<Event>(1024);

        let handles = {
            let mut set = JoinSet::new();

            for channel in ALL_CHANNELS {
                let fifo = Arc::clone(&fifo);
                let tx = tx.clone();
                let channel = channel.to_string();

                set.spawn(async move {
                    Self::collect_channel(channel, Arc::clone(&fifo), tx).await;
                    Ok(())
                });
            }

            // Drop the original sender so rx closes when all tasks finish
            drop(tx);

            set
        };

        // Spawn a background task that drains the channel receiver into the FIFO
        let fifo_for_drain = Arc::clone(&fifo);
        let _drain_task = tokio::spawn(async move {
            while let Some(event) = rx.recv().await {
                let mut fifo = fifo_for_drain.lock().await;
                fifo.push_back(event);
            }
        });

        info!("EventCollector started on {} channels", ALL_CHANNELS.len());

        Self {
            fifo,
            tx: None,
            handles,
        }
    }

    /// Pop all events from the FIFO.
    pub async fn get_events(&self) -> Vec<Event> {
        let mut fifo = self.fifo.lock().await;
        fifo.drain(..).collect()
    }

    /// Signal all collector tasks to shutdown and wait for them.
    pub async fn stop(&mut self) {
        // Drop tx to signal tasks to stop
        self.tx.take();

        // Wait for all tasks to complete
        while let Some(res) = self.handles.join_next().await {
            if let Err(e) = res {
                tracing::warn!("Collector task failed: {e}");
            }
        }

        info!("EventCollector stopped");
    }

    /// Collect events from a single channel via Winevt API.
    #[cfg(windows)]
    async fn collect_channel(
        channel: String,
        fifo: Arc<Mutex<VecDeque<Event>>>,
        _tx: mpsc::Sender<Event>,
    ) {
        let channel_name = channel.clone();
        let result =
            tokio::task::spawn_blocking(move || Self::collect_events_blocking(&channel_name)).await;

        match result {
            Ok(events) => {
                let mut fifo = fifo.lock().await;
                for event in events {
                    fifo.push_back(event);
                }
                info!("Collected {} events from channel '{channel}'", fifo.len());
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
        channel: &str,
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
            event.channel = Some(channel.to_string());
            events.push(event);
        }
    }

    /// Non-Windows stub: returns empty events.
    #[cfg(not(windows))]
    async fn collect_channel(
        channel: String,
        _fifo: Arc<Mutex<VecDeque<Event>>>,
        _tx: mpsc::Sender<Event>,
    ) {
        tracing::info!("Channel '{channel}' — stub on non-Windows platform (collects 0 events)");
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

impl Drop for EventCollector {
    fn drop(&mut self) {
        // Drop tx to signal shutdown; JoinSet::shutdown() cancels remaining tasks.
        self.tx.take();
        // `shutdown()` returns a future but Drop can't await — tasks will
        // be cancelled when the JoinSet is dropped at the end of this function.
        std::mem::drop(self.handles.shutdown());
    }
}
