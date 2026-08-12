// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 sigmacatch contributors

//! ETW event collector (Windows) that sends events into an mpsc channel.
//!
//! # API
//! - `EventCollector::new()` → creates the collector
//! - Implements `EventProducer` trait — calls `run(tx, stop)` to collect and send events
//!
//! Windows collection subscribes to the providers from [`providers::PROVIDERS`]
//! via ferrisetw (one `UserTrace`, real-time). Each decoded `EVENT_RECORD` is
//! masqueraded as a Winevt-shaped XML event: opcode is mapped to a Sysmon
//! EventID, ETW field names are renamed via `field_maps`, and a synthetic
//! channel is chosen so that the existing `inject_logsource_fields()` pipeline
//! routes the event correctly. The trace loop runs in `spawn_blocking`;
//! stopping is done from outside by name (`stop_trace_by_name`).
//! Non-Windows → silent stub.

use async_trait::async_trait;
use sigmacatch_types::{Event, EventProducer};
#[cfg(windows)]
use std::collections::HashMap;
#[cfg(windows)]
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use tokio::sync::mpsc;
use tokio::sync::watch;
#[cfg(windows)]
use tracing::{error, info, warn};

#[cfg(any(windows, test))]
mod providers;
#[cfg(windows)]
use providers::PROVIDERS;

#[cfg(any(windows, test))]
mod field_maps;
#[cfg(any(windows, test))]
mod mapper;

/// Name of the ETW trace session (also used to stop it by name).
#[cfg_attr(not(windows), allow(dead_code))]
const SESSION: &str = "sigmacatch-etw";

/// ETW event collector.
pub struct EventCollector;

impl Default for EventCollector {
    fn default() -> Self {
        Self::new()
    }
}

impl EventCollector {
    /// Create a new collector.
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl EventProducer for EventCollector {
    async fn run(
        self: Box<Self>,
        tx: mpsc::Sender<Event>,
        stop: watch::Receiver<bool>,
    ) -> anyhow::Result<()> {
        Self::collect_events(&self, tx, stop).await
    }
}

impl EventCollector {
    /// Start the ETW trace and collect events until `stop` is set or the
    /// receiver is dropped. The blocking `process()` loop runs in
    /// `spawn_blocking`; the trace is stopped externally by name.
    #[cfg(windows)]
    async fn collect_events(
        &self,
        tx: mpsc::Sender<Event>,
        mut stop: watch::Receiver<bool>,
    ) -> anyhow::Result<()> {
        use ferrisetw::provider::Provider;
        use ferrisetw::trace::{stop_trace_by_name, TraceTrait, UserTrace};
        use ferrisetw::GUID;

        // Purge any orphaned session from a previous run (otherwise the
        // session name is already taken and start() fails).
        let _ = stop_trace_by_name(SESSION);
        info!("ETW collector starting (session '{SESSION}')");

        let mut builder = UserTrace::new().named(SESSION.to_string());
        for seed in PROVIDERS {
            let tx = tx.clone();
            let provider = Provider::by_guid(GUID::from(seed.guid))
                .level(seed.level)
                .any(seed.keywords)
                .add_callback(move |record, schema_locator| {
                    handle_event(record, schema_locator, seed.name, &tx);
                })
                .build();
            builder = builder.enable(provider);
        }

        let trace_task = tokio::task::spawn_blocking(move || {
            let (mut trace, _handle) = builder
                .start()
                .map_err(|e| anyhow::anyhow!("ETW trace start failed: {e:?}"))?;
            trace
                .process()
                .map_err(|e| anyhow::anyhow!("ETW trace processing failed: {e:?}"))
        });

        let stopper = tokio::spawn(async move {
            tokio::select! {
                _ = stop.changed() => {}
                _ = tx.closed() => {}
            }
            let _ = stop_trace_by_name(SESSION);
        });

        let res = match trace_task.await {
            Ok(inner) => {
                if let Err(e) = &inner {
                    error!("{e}");
                }
                inner
            }
            Err(e) => {
                error!("ETW trace task panicked: {e}");
                Err(anyhow::anyhow!("ETW trace task panicked: {e}"))
            }
        };
        stopper.abort();
        info!("ETW collector stopped");
        res
    }

    /// Non-Windows stub: silent no-op.
    #[cfg(not(windows))]
    async fn collect_events(
        &self,
        _tx: mpsc::Sender<Event>,
        _stop: watch::Receiver<bool>,
    ) -> anyhow::Result<()> {
        Ok(())
    }
}

/// Decode a single ETW record into an `Event` and send it through `tx`.
///
/// Runs on the `process()` thread (the record is not `Send`): synthesize the
/// full Winevt-shaped XML (masquerading as Sysmon/Ps/WMI/etc.), parse it,
/// inject the logsource fields, then `blocking_send`. When the receiver is
/// gone, stop the trace to end the loop.
#[cfg(windows)]
fn handle_event(
    record: &ferrisetw::EventRecord,
    schema_locator: &ferrisetw::SchemaLocator,
    provider_name: &'static str,
    tx: &mpsc::Sender<Event>,
) {
    let raw_eid = record.event_id();
    let (sysmon_eid, channel) = match mapper::map_to_sysmon_id(
        record.opcode(),
        raw_eid,
        u128::from(record.provider_id()),
    ) {
        Some(eid) => (eid, mapper::synthetic_channel_for_sysmon_eid(eid)),
        None => (raw_eid, "sigmacatch/etw-unmapped"),
    };
    let kind = field_maps::provider_kind_for_name(provider_name);
    let xml = synthesize_winevt_xml(
        record,
        schema_locator,
        sysmon_eid,
        channel,
        provider_name,
        kind,
    );
    let mut event = match Event::from_xml(&xml) {
        Ok(e) => e,
        Err(e) => {
            warn!("ETW parse error for provider '{provider_name}': {e}");
            return;
        }
    };
    event.inject_logsource_fields();
    if tx.blocking_send(event).is_err() {
        warn!("ETW receiver dropped — stopping trace");
        let _ = ferrisetw::trace::stop_trace_by_name(SESSION);
    }
}

/// Synthesize a full Winevt-shaped XML event from an ETW record.
///
/// The XML mirrors the shape produced by `EvtRender` so that
/// `sigmacatch_types::parse_winevt_xml` and `inject_logsource_fields()` work
/// without modification.
#[cfg(windows)]
fn synthesize_winevt_xml(
    record: &ferrisetw::EventRecord,
    schema_locator: &ferrisetw::SchemaLocator,
    sysmon_eid: u16,
    channel: &str,
    provider_name: &str,
    kind: Option<field_maps::ProviderKind>,
) -> String {
    static NEXT_RECORD_ID: AtomicU64 = AtomicU64::new(0);
    static SCHEMA_WARNED: AtomicBool = AtomicBool::new(false);

    let record_id = NEXT_RECORD_ID.fetch_add(1, Ordering::Relaxed) + 1;
    let time_created = filetime_to_iso8601(record.raw_timestamp());
    let provider_guid_fmt = format!("{{{:?}}}", record.provider_id());

    // Parse only the ETW fields mapped to Sysmon/Sigma names and rename them.
    // Unmapped fields are ignored (spec sanitization); unknown providers yield
    // an empty EventData. `Schema::properties()` is pub(crate) upstream, so
    // the field map is the source of known names instead.
    let mut etw_fields: HashMap<String, String> = HashMap::new();
    if let Some(kind) = kind {
        match schema_locator.event_schema(record) {
            Ok(schema) => {
                let parser = ferrisetw::parser::Parser::create(record, &schema);
                let mapping = field_maps::field_map_for_provider(kind);
                for etw_name in mapping.etw_names() {
                    if let Some(value) = parse_etw_property(&parser, etw_name) {
                        etw_fields.insert(etw_name.to_string(), value);
                    }
                }
            }
            Err(_) if !SCHEMA_WARNED.swap(true, Ordering::Relaxed) => {
                warn!("ETW schema lookup failed for provider '{provider_name}', EventData will be empty");
            }
            Err(_) => {}
        }
    }
    let renamed = match kind {
        Some(kind) => field_maps::rename_fields(&etw_fields, kind),
        None => etw_fields,
    };

    // Build the EventData XML fragment in deterministic order.
    let mut event_data_lines: Vec<String> = renamed
        .iter()
        .map(|(name, value)| {
            format!(
                "        <Data Name=\"{}\">{}</Data>",
                escape_xml(name),
                escape_xml(value)
            )
        })
        .collect();
    event_data_lines.sort();
    let event_data = if event_data_lines.is_empty() {
        String::new()
    } else {
        format!("\n{}\n      ", event_data_lines.join("\n"))
    };

    format!(
        r#"<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
      <System>
        <Provider Name="{provider_name}" Guid="{provider_guid_fmt}"/>
        <EventID>{sysmon_eid}</EventID>
        <Version>5</Version>
        <Level>4</Level>
        <Task>1</Task>
        <Opcode>0</Opcode>
        <Keywords>0x8000000000000000</Keywords>
        <TimeCreated SystemTime="{time_created}"/>
        <EventRecordID>{record_id}</EventRecordID>
        <Channel>{channel}</Channel>
        <Computer>localhost</Computer>
      </System>
      <EventData>
{event_data}
      </EventData>
    </Event>"#
    )
}

/// Parse a single ETW property into its plain-text representation.
///
/// Tries the scalar types the subscribed providers emit (strings, IP
/// addresses, integers, bools); returns `None` when the property is absent or
/// of an unsupported type. ferrisetw's `TryParse<String>` panics on
/// `InTypeCountedString` — a known upstream limitation, no public property-type
/// API exists to guard against it.
#[cfg(windows)]
fn parse_etw_property(parser: &ferrisetw::parser::Parser<'_, '_>, name: &str) -> Option<String> {
    if let Ok(s) = parser.try_parse::<String>(name) {
        return (!s.is_empty()).then_some(s);
    }
    if let Ok(ip) = parser.try_parse::<std::net::IpAddr>(name) {
        return Some(ip.to_string());
    }
    if let Ok(n) = parser.try_parse::<u8>(name) {
        return Some(n.to_string());
    }
    if let Ok(n) = parser.try_parse::<u16>(name) {
        return Some(n.to_string());
    }
    if let Ok(n) = parser.try_parse::<u32>(name) {
        return Some(n.to_string());
    }
    if let Ok(n) = parser.try_parse::<u64>(name) {
        return Some(n.to_string());
    }
    if let Ok(b) = parser.try_parse::<bool>(name) {
        return Some(b.to_string());
    }
    None
}

/// Escape a string for a Winevt XML text/attribute value.
#[cfg(windows)]
fn escape_xml(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

/// FILETIME (100ns intervals since 1601-01-01 UTC) → ISO 8601 UTC string with
/// 7 fractional digits, matching the Winevt `TimeCreated` format.
#[cfg_attr(not(windows), allow(dead_code))]
fn filetime_to_iso8601(filetime: i64) -> String {
    const FILETIME_TO_UNIX_EPOCH_100NS: i64 = 116_444_736_000_000_000;

    let total = filetime - FILETIME_TO_UNIX_EPOCH_100NS;
    let (secs, subsec_100ns) = (total.div_euclid(10_000_000), total.rem_euclid(10_000_000));
    let (days, secs_of_day) = (secs.div_euclid(86_400), secs.rem_euclid(86_400));
    let (year, month, day) = civil_from_days(days);
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}.{subsec_100ns:07}Z",
        secs_of_day / 3_600,
        (secs_of_day % 3_600) / 60,
        secs_of_day % 60,
    )
}

/// Days since 1970-01-01 → civil (year, month, day) via the days-from-civil
/// algorithm (Howard Hinnant).
#[cfg_attr(not(windows), allow(dead_code))]
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_session_name_constant() {
        assert_eq!(SESSION, "sigmacatch-etw");
    }

    #[test]
    fn test_filetime_to_iso8601_epoch() {
        assert_eq!(
            filetime_to_iso8601(116_444_736_000_000_000),
            "1970-01-01T00:00:00.0000000Z"
        );
    }

    #[test]
    fn test_filetime_to_iso8601_known_date() {
        assert_eq!(
            filetime_to_iso8601(133_485_408_000_000_000),
            "2024-01-01T00:00:00.0000000Z"
        );
    }

    #[test]
    fn test_filetime_to_iso8601_subseconds() {
        assert_eq!(
            filetime_to_iso8601(133_485_408_000_000_001),
            "2024-01-01T00:00:00.0000001Z"
        );
    }

    #[test]
    fn test_synthesize_winevt_xml_parses() {
        // Build a minimal XML that mimics what synthesize_winevt_xml produces.
        let xml = r#"<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
      <System>
        <Provider Name="Microsoft-Windows-Kernel-Process" Guid="{22FB2CD6-0E7B-422B-A0C7-2FAD1FD0E716}"/>
        <EventID>1</EventID>
        <Version>5</Version>
        <Level>4</Level>
        <Task>1</Task>
        <Opcode>0</Opcode>
        <Keywords>0x8000000000000000</Keywords>
        <TimeCreated SystemTime="2024-01-01T00:00:00.0000000Z"/>
        <EventRecordID>5</EventRecordID>
        <Channel>Microsoft-Windows-Sysmon/Operational</Channel>
        <Computer>localhost</Computer>
      </System>
      <EventData>
        <Data Name="Image">C:\Windows\System32\cmd.exe</Data>
        <Data Name="CommandLine">cmd.exe /c whoami</Data>
      </EventData>
    </Event>"#;

        let mut event = Event::from_xml(xml).expect("winevt XML must parse");
        assert_eq!(event.record_id(), Some(5));

        event.inject_logsource_fields();
        let system = &event.event_json["Event"]["System"];
        assert_eq!(system["EventID"], 1);
        assert_eq!(
            system["Provider"]["#attributes"]["Name"],
            "Microsoft-Windows-Kernel-Process"
        );
        assert_eq!(event.event_json["product"], "windows");
        assert_eq!(event.event_json["service"], "sysmon");
        assert_eq!(event.event_json["category"], "process_creation");
        let ed = &event.event_json["Event"]["EventData"];
        assert_eq!(ed["Image"], "C:\\Windows\\System32\\cmd.exe");
        assert_eq!(ed["CommandLine"], "cmd.exe /c whoami");
        assert_eq!(event.event_raw, xml.as_bytes());
    }

    #[test]
    fn test_synthesize_winevt_xml_powershell_channel() {
        let xml = r#"<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
      <System>
        <Provider Name="Microsoft-Windows-PowerShell" Guid="{A0C1853B-5C40-4B15-8766-3CF1C58F985A}"/>
        <EventID>4104</EventID>
        <Version>5</Version>
        <Level>4</Level>
        <Task>1</Task>
        <Opcode>0</Opcode>
        <Keywords>0x8000000000000000</Keywords>
        <TimeCreated SystemTime="2024-01-01T00:00:00.0000000Z"/>
        <EventRecordID>10</EventRecordID>
        <Channel>Microsoft-Windows-PowerShell/Operational</Channel>
        <Computer>localhost</Computer>
      </System>
      <EventData>
        <Data Name="ScriptBlockText">Get-Process</Data>
      </EventData>
    </Event>"#;

        let mut event = Event::from_xml(xml).expect("winevt XML must parse");
        event.inject_logsource_fields();
        assert_eq!(event.event_json["service"], "powershell");
        assert_eq!(event.event_json["category"], "ps_script");
    }

    #[test]
    fn test_synthesize_winevt_xml_empty_eventdata() {
        let xml = r#"<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
      <System>
        <Provider Name="Microsoft-Windows-Kernel-Process" Guid="{22FB2CD6-0E7B-422B-A0C7-2FAD1FD0E716}"/>
        <EventID>1</EventID>
        <Version>5</Version>
        <Level>4</Level>
        <Task>1</Task>
        <Opcode>0</Opcode>
        <Keywords>0x8000000000000000</Keywords>
        <TimeCreated SystemTime="2024-01-01T00:00:00.0000000Z"/>
        <EventRecordID>1</EventRecordID>
        <Channel>Microsoft-Windows-Sysmon/Operational</Channel>
        <Computer>localhost</Computer>
      </System>
      <EventData>
      </EventData>
    </Event>"#;

        let mut event = Event::from_xml(xml).expect("winevt XML must parse");
        event.inject_logsource_fields();
        assert_eq!(event.event_json["product"], "windows");
        assert_eq!(event.event_json["service"], "sysmon");
    }

    #[test]
    fn test_event_collector_constructible() {
        let _ = EventCollector::new();
    }

    #[test]
    fn test_mapper_process_start() {
        use mapper::map_to_sysmon_id;
        const KERNEL_PROCESS: u128 = 0x22fb2cd6_0e7b_422b_a0c7_2fad1fd0e716;
        assert_eq!(map_to_sysmon_id(1, 0, KERNEL_PROCESS), Some(1));
    }

    #[test]
    fn test_mapper_network_tcp() {
        use mapper::map_to_sysmon_id;
        const KERNEL_NETWORK: u128 = 0x7dd42a49_5329_4832_8dfd_43d979153a88;
        assert_eq!(map_to_sysmon_id(12, 0, KERNEL_NETWORK), Some(3));
    }

    #[test]
    fn test_mapper_file_create() {
        use mapper::map_to_sysmon_id;
        const KERNEL_FILE: u128 = 0xedd08927_9cc4_4e65_b970_c2560fb5c289;
        assert_eq!(map_to_sysmon_id(0, 12, KERNEL_FILE), Some(11));
    }

    #[test]
    fn test_mapper_powershell() {
        use mapper::map_to_sysmon_id;
        const POWERSHELL: u128 = 0xa0c1853b_5c40_4b15_8766_3cf1c58f985a;
        assert_eq!(map_to_sysmon_id(0, 0, POWERSHELL), Some(4104));
    }

    #[test]
    fn test_field_maps_process() {
        use field_maps::{rename_fields, ProviderKind};
        use std::collections::HashMap;

        let mut fields = HashMap::new();
        fields.insert("ImageName".to_string(), "cmd.exe".to_string());
        fields.insert("Unmapped".to_string(), "keep".to_string());
        fields.insert("EmptyField".to_string(), "".to_string());

        let renamed = rename_fields(&fields, ProviderKind::Process);

        assert_eq!(renamed.get("Image").map(|v| v.as_str()), Some("cmd.exe"));
        assert_eq!(renamed.get("Unmapped").map(|v| v.as_str()), Some("keep"));
        assert!(!renamed.contains_key("EmptyField"));
        assert!(!renamed.contains_key("ImageName"));
    }

    #[test]
    fn test_channel_synthetic() {
        use mapper::synthetic_channel_for_sysmon_eid;
        assert_eq!(
            synthetic_channel_for_sysmon_eid(1),
            "Microsoft-Windows-Sysmon/Operational"
        );
        assert_eq!(
            synthetic_channel_for_sysmon_eid(3),
            "Microsoft-Windows-Sysmon/Operational"
        );
        assert_eq!(
            synthetic_channel_for_sysmon_eid(11),
            "Microsoft-Windows-Sysmon/Operational"
        );
        assert_eq!(
            synthetic_channel_for_sysmon_eid(4104),
            "Microsoft-Windows-PowerShell/Operational"
        );
        assert_eq!(synthetic_channel_for_sysmon_eid(7045), "System");
        assert_eq!(
            synthetic_channel_for_sysmon_eid(106),
            "Microsoft-Windows-TaskScheduler/Operational"
        );
    }
}
