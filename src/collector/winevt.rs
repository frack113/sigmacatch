// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 sigmacatch contributors

#[cfg(windows)]
use tracing::{debug, error, info};
#[allow(dead_code)]
#[cfg(windows)]
use windows::core::{HSTRING, PCWSTR};
#[cfg(windows)]
use windows::Win32::Foundation::{GetLastError, RPC_E_CHANGED_MODE, S_OK};
#[cfg(windows)]
use windows::Win32::System::Com::{CoInitializeEx, CoUninitialize, COINIT_APARTMENTTHREADED};
#[cfg(windows)]
use windows::Win32::System::EventLog::{
    EvtClose, EvtNext, EvtQuery, EvtRender, EvtRenderEventXml, EVT_HANDLE,
};
#[cfg(windows)]
use windows::Win32::System::Threading::INFINITE;

use anyhow::Result;
use tokio::sync::mpsc as tokio_mpsc;

/// WinevtCollector — stub non-Windows (pas de collecte Event Log)
#[cfg(not(windows))]
#[allow(dead_code)]
pub struct WinevtCollector;

#[cfg(not(windows))]
impl WinevtCollector {
    #[allow(dead_code)]
    pub fn new(_channel_name: impl Into<String>) -> Self {
        Self
    }

    #[allow(dead_code)]
    pub async fn stream(self, _tx: tokio_mpsc::Sender<WinevtEvent>) -> Result<()> {
        #[cfg(not(windows))]
        use tracing::info;
        info!("WinevtCollector: non-Windows platform, returning empty events");
        Ok(())
    }
}

/// WinevtCollector — Windows (Event Log API)
#[cfg(windows)]
pub struct WinevtCollector {
    channel: String,
}

#[cfg(windows)]
impl WinevtCollector {
    pub fn new(channel: impl Into<String>) -> Self {
        Self {
            channel: channel.into(),
        }
    }

    pub async fn stream(self, tx: tokio_mpsc::Sender<WinevtEvent>) -> Result<()> {
        info!("Starting winevt collection on channel: {}", self.channel);
        let result = tokio::task::spawn_blocking({
            let channel = self.channel.clone();
            move || collect_events(&channel)
        })
        .await;
        let events = match result {
            Ok(Ok(events)) => events,
            Ok(Err(e)) => {
                error!(
                    "Error collecting events from channel '{}': {}",
                    self.channel, e
                );
                Vec::new()
            }
            Err(_) => {
                error!("Collector task panicked for channel '{}'", self.channel);
                Vec::new()
            }
        };
        info!(
            "Channel '{}' collected {} events",
            self.channel,
            events.len()
        );
        for event in events {
            if tx.send(event).await.is_err() {
                break;
            }
        }
        info!("WinevtCollector '{}' completed", self.channel);
        Ok(())
    }
}

#[cfg(windows)]
fn collect_events(channel: &str) -> Result<Vec<WinevtEvent>> {
    let co_init_result = unsafe { CoInitializeEx(None, COINIT_APARTMENTTHREADED) };
    let com_initialized = co_init_result == S_OK || co_init_result == RPC_E_CHANGED_MODE;

    let mut events = Vec::new();

    let query_handle = unsafe {
        let query_hstring = HSTRING::from(channel);
        EvtQuery(
            None,
            PCWSTR(query_hstring.as_ptr()),
            PCWSTR(HSTRING::from("*").as_ptr()),
            0x00000001,
        )
    };

    let query = match query_handle {
        Ok(q) => q.0 as isize,
        Err(_) => {
            let last_error = unsafe { GetLastError().0 };
            error!(
                "EvtQuery failed for channel '{}': HRESULT=0x{:08X} — channel may not exist, inaccessible, or no events match",
                channel, last_error
            );
            if com_initialized {
                unsafe {
                    CoUninitialize();
                }
            }
            return Ok(events);
        }
    };

    let mut event_handles: [isize; 32] = [0; 32];
    let mut returned: u32 = 0;
    let mut event_count: u64 = 0;

    loop {
        let result = unsafe {
            EvtNext(
                EVT_HANDLE(query),
                &mut event_handles,
                INFINITE,
                0,
                &mut returned,
            )
        };

        if result.is_err() || returned == 0 {
            break;
        }

        for i in 0..returned {
            let event_handle = event_handles[i as usize];
            if event_handle == 0 {
                continue;
            }
            match render_event_to_xml(EVT_HANDLE(event_handle)) {
                Ok(Some(event)) => {
                    event_count += 1;
                    events.push(event);
                }
                Ok(None) => {}
                Err(e) => {
                    debug!("Failed to render event: {}", e);
                }
            }
        }

        for i in 0..returned {
            if event_handles[i as usize] != 0 {
                unsafe {
                    let _ = EvtClose(EVT_HANDLE(event_handles[i as usize]));
                    event_handles[i as usize] = 0;
                }
            }
        }
    }

    unsafe {
        let _ = EvtClose(EVT_HANDLE(query));
    }

    if com_initialized {
        unsafe {
            CoUninitialize();
        }
    }

    info!("Channel '{}' collected {} events", channel, event_count);

    Ok(events)
}

#[cfg(windows)]
fn render_event_to_xml(event_handle: EVT_HANDLE) -> Result<Option<WinevtEvent>> {
    let mut buffer: Vec<u16> = vec![0u16; 32768];
    let mut buffer_used: u32 = 0;
    let mut value_count: u32 = 0;

    let result = unsafe {
        EvtRender(
            None,
            event_handle,
            EvtRenderEventXml.0,
            buffer.len() as u32,
            Some(buffer.as_mut_ptr() as *mut std::ffi::c_void),
            &mut buffer_used,
            &mut value_count,
        )
    };

    if result.is_err() {
        let last_error = unsafe { GetLastError().0 };
        if last_error == 122u32 {
            let needed = (buffer_used as usize).max(65536) * 2;
            buffer.resize(needed, 0);
            let result = unsafe {
                EvtRender(
                    None,
                    event_handle,
                    EvtRenderEventXml.0,
                    buffer.len() as u32,
                    Some(buffer.as_mut_ptr() as *mut std::ffi::c_void),
                    &mut buffer_used,
                    &mut value_count,
                )
            };
            if result.is_err() {
                return Ok(None);
            }
        } else {
            return Ok(None);
        }
    }

    if buffer_used == 0 {
        return Ok(None);
    }

    let xml_len = (buffer_used as usize).saturating_sub(1);
    let xml_slice = &buffer[..xml_len];
    let mut xml_str: String = String::from_utf16_lossy(xml_slice);
    xml_str.truncate(xml_str.find('\0').unwrap_or(xml_str.len()));
    let xml_str = xml_str.trim().to_string();

    if let Some(json) = parse_event_xml(&xml_str) {
        let event = WinevtEvent::from_json(json, xml_str);
        Ok(Some(event))
    } else {
        Ok(Some(WinevtEvent {
            channel: String::new(),
            event_id: 0,
            raw_xml: xml_str,
            event_json: None,
        }))
    }
}

#[cfg(windows)]
fn parse_event_xml(xml: &str) -> Option<serde_json::Value> {
    let parser = crate::parser::XmlParser {};
    parser.parse(xml).ok()
}

#[allow(dead_code)]
#[derive(Debug, Clone)]
pub struct WinevtEvent {
    pub channel: String,
    pub event_id: u32,
    pub raw_xml: String,
    pub event_json: Option<serde_json::Value>,
}

#[allow(dead_code)]
impl WinevtEvent {
    pub fn from_json(json: serde_json::Value, raw_xml: String) -> Self {
        let event_id = json
            .get("EventID_num")
            .and_then(|v| v.as_u64())
            .unwrap_or(0) as u32;
        let channel = json
            .get("Channel")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        Self {
            event_id,
            channel,
            raw_xml,
            event_json: Some(json),
        }
    }
}
