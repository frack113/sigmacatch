// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 sigmacatch contributors

//! Singleton Winevt event collector with FIFO queue.
//!
//! Collects events from a predefined set of Windows event channels
//! and makes them available via `get_events()` as batched `Option<Vec<Event>>`.
//!
//! # Usage
//!
//! ```ignore
//! use input_winevt_channel::{init, run, get_events};
//!
//! init(get_all_channels());
//! run();
//!
//! loop {
//!     if let Some(events) = get_events() {
//!         for event in events {
//!             // process event
//!         }
//!     }
//!     std::thread::sleep(std::time::Duration::from_millis(100));
//! }
//! ```

use sigmacatch_types::Event;
use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, LazyLock, Mutex};

// ─── Channel mapping (131 lines YAML → 54 unique channels) ──────────────

/// Maximum events collected per channel.
#[allow(dead_code)]
const MAX_EVENTS: u64 = 100_000;

/// Embedded channel-to-service mapping from `channel_mapping.yml`.
/// Used as the authoritative source for channel discovery.
pub static CHANNEL_TO_SERVICE: phf::Map<&'static str, &'static str> = phf::phf_map! {
    "Application" => "application",
    "System" => "system",
    "Security" => "security",
    "Microsoft-Windows-Sysmon/Operational" => "sysmon",
    "DNS Server" => "dns-server",
    "Microsoft-Windows-DNS-Server/Analytical" => "dns-server-analytic",
    "Microsoft-Windows-DNS-Server/Audit" => "dns-server-audit",
    "Microsoft-Windows-DNS Client Events/Operational" => "dns-client",
    "Microsoft-Windows-DHCP-Server/Operational" => "dhcp",
    "Microsoft-Windows-DriverFrameworks-UserMode/Operational" => "driver-framework",
    "Microsoft-Windows-Hyper-V-Worker" => "hyper-v-worker",
    "Microsoft-IIS-Configuration/Operational" => "iis-configuration",
    "Microsoft-Windows-Kernel-EventTracing" => "kernel-event-tracing",
    "Microsoft-Windows-Kernel-ShimEngine/Operational" => "kernel-shimengine",
    "Microsoft-Windows-Kernel-ShimEngine/Diagnostic" => "kernel-shimengine",
    "Microsoft-Windows-LDAP-Client/Debug" => "ldap",
    "Microsoft-Windows-LSA/Operational" => "lsa-server",
    "Microsoft-Windows-NTLM/Operational" => "ntlm",
    "Microsoft-Windows-Ntfs/Operational" => "ntfs",
    "OpenSSH/Operational" => "openssh",
    "Microsoft-Windows-PrintService/Admin" => "printservice-admin",
    "Microsoft-Windows-PrintService/Operational" => "printservice-operational",
    "Microsoft-Windows-AppLocker/EXE and DLL" => "applocker",
    "Microsoft-Windows-AppLocker/MSI and Script" => "applocker",
    "Microsoft-Windows-AppLocker/Packaged app-Deployment" => "applocker",
    "Microsoft-Windows-AppLocker/Packaged app-Execution" => "applocker",
    "Microsoft-Windows-AppModel-Runtime/Admin" => "appmodel-runtime",
    "Microsoft-Windows-AppXDeploymentServer/Operational" => "appxdeployment-server",
    "Microsoft-Windows-AppxPackaging/Operational" => "appxpackaging-om",
    "Microsoft-Windows-Application-Experience/Program-Telemetry" => "application-experience",
    "Microsoft-Windows-Application-Experience/Program-Compatibility-Assistant" => "application-experience",
    "Microsoft-Windows-BitLocker/BitLocker Management" => "bitlocker",
    "Microsoft-Windows-Bits-Client/Operational" => "bits-client",
    "Microsoft-Windows-CAPI2/Operational" => "capi2",
    "Microsoft-Windows-CertificateServicesClient-Lifecycle-System/Operational" => "certificateservicesclient-lifecycle-system",
    "Microsoft-Windows-CodeIntegrity/Operational" => "codeintegrity-operational",
    "Microsoft-Windows-SENSE/Operational" => "sense",
    "Microsoft-ServiceBus-Client/Operational" => "servicebus-client",
    "Microsoft-ServiceBus-Client/Admin" => "servicebus-client",
    "Microsoft-Windows-Shell-Core/Operational" => "shell-core",
    "Microsoft-Windows-Security-Mitigations/Kernel Mode" => "security-mitigations",
    "Microsoft-Windows-Security-Mitigations/User Mode" => "security-mitigations",
    "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational" => "terminalservices-localsessionmanager",
    "Microsoft-Windows-VHDMP/Operational" => "vhdmp",
    "Microsoft-Windows-Windows Defender/Operational" => "windefend",
    "Microsoft-Windows-Windows Firewall With Advanced Security/Firewall" => "firewall-as",
    "Microsoft-Windows-Diagnosis-Scripted/Operational" => "diagnosis-scripted",
    "MSExchange Management" => "msexchange-management",
    "Microsoft-Windows-SmbClient/Security" => "smbclient-security",
    "Windows PowerShell" => "powershell-classic",
    "Microsoft-Windows-PowerShell/Operational" => "powershell",
    "PowerShellCore/Operational" => "powershell",
    "Microsoft-Windows-TaskScheduler/Operational" => "taskscheduler",
    "Microsoft-Windows-WMI-Activity/Operational" => "wmi",
};

/// Returns all channels from the embedded mapping, sorted.
pub fn get_all_channels() -> Vec<String> {
    let mut channels: Vec<String> = CHANNEL_TO_SERVICE
        .keys()
        .copied()
        .map(String::from)
        .collect();
    channels.sort();
    channels
}

// ─── Singleton Collector ─────────────────────────────────────────────────

struct Collector {
    channels: Vec<String>,
    initialized: bool,
    running: AtomicBool,
    events: Arc<Mutex<VecDeque<Event>>>,
    task_handles: Arc<Mutex<Vec<tokio::task::JoinHandle<()>>>>,
}

impl Collector {
    fn new() -> Self {
        Self {
            channels: Vec::new(),
            initialized: false,
            running: AtomicBool::new(false),
            events: Arc::new(Mutex::new(VecDeque::new())),
            task_handles: Arc::new(Mutex::new(Vec::new())),
        }
    }

    fn init(&mut self, channels: Vec<String>) {
        self.channels = channels;
        self.initialized = true;
        tracing::info!(
            "input-winevt-channel initialized with {} channels",
            self.channels.len()
        );
    }

    fn is_initialized(&self) -> bool {
        self.initialized
    }

    fn run(&self) {
        if !self.is_initialized() {
            tracing::warn!("input-winevt-channel: not initialized, call init() first");
            return;
        }

        if self.running.load(Ordering::SeqCst) {
            tracing::warn!("input-winevt-channel: already running");
            return;
        }

        self.running.store(true, Ordering::SeqCst);

        let channels = self.channels.clone();
        let events = Arc::clone(&self.events);
        let task_handles = Arc::clone(&self.task_handles);

        for channel in &channels {
            let channel_clone = channel.clone();
            let channel_log = channel.clone();
            let channel_events = Arc::clone(&events);
            let handles_clone = Arc::clone(&task_handles);
            let handle = tokio::spawn(async move {
                let result =
                    tokio::task::spawn_blocking(move || collect_events_on_channel(&channel_clone))
                        .await;

                match result {
                    Ok(Ok(event_list)) => {
                        tracing::info!(
                            "Channel '{}' collected {} events",
                            channel_log,
                            event_list.len()
                        );
                        let mut queue = channel_events.lock().unwrap();
                        for event in event_list {
                            queue.push_back(event);
                        }
                    }
                    Ok(Err(e)) => {
                        tracing::error!(
                            "Error collecting events from channel '{}': {}",
                            channel_log,
                            e
                        );
                    }
                    Err(e) => {
                        tracing::error!(
                            "Collector task panicked for channel '{}': {}",
                            channel_log,
                            e
                        );
                    }
                }
            });

            handles_clone.lock().unwrap().push(handle);
        }

        tracing::info!(
            "input-winevt-channel: {} collection tasks started",
            channels.len()
        );
    }

    fn stop(&self) {
        self.running.store(false, Ordering::SeqCst);
        let mut handles = self.task_handles.lock().unwrap();
        let to_abort: Vec<_> = handles.drain(..).collect();
        for handle in to_abort {
            handle.abort();
        }
        tracing::info!("input-winevt-channel: all collection tasks stopped");
    }

    fn get_events(&self) -> Option<Vec<Event>> {
        let mut queue = self.events.lock().unwrap();
        if queue.is_empty() {
            None
        } else {
            Some(queue.drain(..).collect())
        }
    }
}

/// Static singleton collector instance.
static COLLECTOR: LazyLock<Mutex<Collector>> = LazyLock::new(|| Mutex::new(Collector::new()));

// ─── Public API ──────────────────────────────────────────────────────────

/// Initialize the collector with a list of channels.
pub fn init(channels: Vec<String>) {
    let mut collector = COLLECTOR.lock().unwrap();
    collector.init(channels);
}

/// Check if the collector has been initialized.
pub fn is_initialized() -> bool {
    COLLECTOR.lock().unwrap().is_initialized()
}

/// Start collecting events in the background.
pub fn run() {
    COLLECTOR.lock().unwrap().run();
}

/// Stop all collection tasks.
pub fn stop() {
    COLLECTOR.lock().unwrap().stop();
}

/// Get events from the FIFO queue (drains the queue).
/// Returns `Some(vec)` if events are available, `None` if empty.
pub fn get_events() -> Option<Vec<Event>> {
    COLLECTOR.lock().unwrap().get_events()
}

// ─── Winevt Collection (cfg(windows)) ────────────────────────────────────

#[cfg(windows)]
fn collect_events_on_channel(channel: &str) -> Result<Vec<Event>, String> {
    use windows::core::{HSTRING, PCWSTR};
    use windows::Win32::Foundation::{GetLastError, RPC_E_CHANGED_MODE, S_OK};
    use windows::Win32::System::Com::{CoInitializeEx, CoUninitialize, COINIT_APARTMENTTHREADED};
    use windows::Win32::System::EventLog::{
        EvtClose, EvtNext, EvtQuery, EvtRender, EvtRenderEventXml, EVT_HANDLE,
    };

    let co_init_result = unsafe { CoInitializeEx(None, COINIT_APARTMENTTHREADED) };
    let com_initialized = co_init_result == S_OK || co_init_result == RPC_E_CHANGED_MODE;

    let mut events = Vec::new();
    let mut event_count: u64 = 0;

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
            tracing::warn!(
                "EvtQuery failed for channel '{}': HRESULT=0x{:08X} — channel may not exist, inaccessible, or no events match",
                channel,
                last_error
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

    loop {
        let result = unsafe {
            EvtNext(
                EVT_HANDLE(query),
                &mut event_handles,
                5000,
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

            if event_count >= MAX_EVENTS {
                tracing::info!(
                    "Max events limit ({}) reached for channel '{}', stopping collection",
                    MAX_EVENTS,
                    channel
                );
                break;
            }

            match render_event_to_xml(EVT_HANDLE(event_handle)) {
                Ok(Some(event)) => {
                    event_count += 1;
                    events.push(event);
                }
                Ok(None) => {}
                Err(e) => {
                    tracing::debug!("Failed to render event: {}", e);
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

        if event_count >= MAX_EVENTS {
            break;
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

    tracing::info!("Channel '{}' collected {} events", channel, event_count);
    Ok(events)
}

#[cfg(windows)]
fn render_event_to_xml(event_handle: EVT_HANDLE) -> Result<Option<Event>, String> {
    use windows::Win32::Foundation::{GetLastError, S_OK};
    use windows::Win32::System::EventLog::{EvtRender, EvtRenderEventXml};

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
                return Err(format!(
                    "EvtRender failed after resize: 0x{:08X}",
                    last_error
                ));
            }
        } else {
            return Err(format!("EvtRender failed: 0x{:08X}", last_error));
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

    match Event::from_xml(&xml_str) {
        Ok(event) => Ok(Some(event)),
        Err(e) => Err(format!("Event::from_xml failed: {}", e)),
    }
}

// ─── Stub (cfg(not(windows))) ────────────────────────────────────────────

#[cfg(not(windows))]
fn collect_events_on_channel(_channel: &str) -> Result<Vec<Event>, String> {
    tracing::info!("input-winevt-channel: non-Windows platform, no events collected");
    Ok(Vec::new())
}

// ─── Tests ───────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_all_channels_returns_sorted_channels() {
        let channels = get_all_channels();
        assert!(!channels.is_empty());

        // Verify sorted order
        for i in 1..channels.len() {
            assert!(channels[i - 1] <= channels[i], "channels not sorted");
        }
    }

    #[test]
    fn test_get_all_channels_contains_key_channels() {
        let channels = get_all_channels();
        assert!(channels.contains(&"Security".to_string()));
        assert!(channels.contains(&"System".to_string()));
        assert!(channels.contains(&"Application".to_string()));
        assert!(channels.contains(&"Microsoft-Windows-Sysmon/Operational".to_string()));
    }

    #[test]
    fn test_channel_to_service_contains_all_channels() {
        let channels = get_all_channels();
        for channel in &channels {
            assert!(
                CHANNEL_TO_SERVICE.contains_key(channel.as_str()),
                "channel '{}' not in CHANNEL_TO_SERVICE",
                channel
            );
        }
    }

    #[test]
    fn test_channel_to_service_count() {
        assert_eq!(CHANNEL_TO_SERVICE.len(), 54);
    }

    #[test]
    fn test_collector_accessible() {
        let collector = COLLECTOR.lock().unwrap();
        let _ = collector.is_initialized();
    }

    #[test]
    fn test_collector_init() {
        let mut collector = COLLECTOR.lock().unwrap();
        let channels = vec!["Security".to_string(), "System".to_string()];
        collector.init(channels.clone());
        assert!(collector.is_initialized());
        assert_eq!(collector.channels, channels);
    }

    #[test]
    fn test_collector_get_events_empty() {
        let collector = COLLECTOR.lock().unwrap();
        assert!(collector.get_events().is_none());
    }

    #[test]
    fn test_collector_get_events_with_data() {
        let mut collector = COLLECTOR.lock().unwrap();
        collector.init(vec!["Security".to_string()]);

        // Manually add an event to the queue
        let mut queue = collector.events.lock().unwrap();
        queue.push_back(Event::new(
            serde_json::json!({
                "Event": {
                    "System": {
                        "Channel": "Security",
                        "EventID": 4624
                    }
                }
            }),
            Vec::new(),
        ));
        drop(queue);

        let events = collector.get_events().unwrap();
        assert_eq!(events.len(), 1);
    }

    #[test]
    fn test_collector_get_events_drains_queue() {
        let collector = COLLECTOR.lock().unwrap();
        let first = collector.get_events();
        let second = collector.get_events();
        assert!(first.is_none());
        assert!(second.is_none());
    }

    #[test]
    fn test_channel_mapping_sysmon() {
        assert_eq!(
            CHANNEL_TO_SERVICE.get("Microsoft-Windows-Sysmon/Operational"),
            Some(&"sysmon")
        );
    }

    #[test]
    fn test_channel_mapping_applocker_channels() {
        let applocker_channels: Vec<&str> = CHANNEL_TO_SERVICE
            .keys()
            .filter(|k| k.starts_with("Microsoft-Windows-AppLocker"))
            .copied()
            .collect();
        assert!(applocker_channels.len() >= 4);
        for channel in &applocker_channels {
            assert_eq!(CHANNEL_TO_SERVICE.get(*channel), Some(&"applocker"));
        }
    }

    #[test]
    fn test_channel_mapping_security_login() {
        assert_eq!(CHANNEL_TO_SERVICE.get("Security"), Some(&"security"));
    }
}
