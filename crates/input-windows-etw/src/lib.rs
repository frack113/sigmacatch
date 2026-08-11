// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 sigmacatch contributors

//! ETW event collector (Windows) that sends events into an mpsc channel.
//!
//! # API
//! - `EventCollector::new()` → creates the collector
//! - Implements `EventProducer` trait — calls `run(tx, stop)` to collect and send events
//!
//! Windows collection subscribes to the providers from [`providers::PROVIDERS`]
//! via ferrisetw (one `UserTrace`, real-time), decodes each event into the
//! minimal `System`-only XML and sends it through the channel. The trace loop
//! runs in `spawn_blocking`; stopping is done from outside by name
//! (`stop_trace_by_name`). Non-Windows → silent stub.

use async_trait::async_trait;
use sigmacatch_types::{Event, EventProducer};
use tokio::sync::mpsc;
use tokio::sync::watch;
#[cfg(windows)]
use tracing::{error, info, warn};

#[cfg(any(windows, test))]
mod providers;
#[cfg(windows)]
use providers::PROVIDERS;

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
    async fn run(self, tx: mpsc::Sender<Event>, stop: watch::Receiver<bool>) -> anyhow::Result<()> {
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
                .add_callback(move |record, _locator| {
                    handle_event(record, seed.name, seed.guid, &tx);
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
/// minimal `System`-only XML, parse it, inject the logsource fields, then
/// `blocking_send`. When the receiver is gone, stop the trace to end the loop.
#[cfg(windows)]
fn handle_event(
    record: &ferrisetw::EventRecord,
    provider_name: &'static str,
    provider_guid: &'static str,
    tx: &mpsc::Sender<Event>,
) {
    let xml = synthesize_minimal_xml(
        provider_name,
        provider_guid,
        record.event_id(),
        &filetime_to_iso8601(record.raw_timestamp()),
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

/// Synthesize the minimal Winevt-shaped XML for an ETW event: `System` only
/// (Provider name/Guid, EventID, TimeCreated). The full channel/EventData
/// synthesis is Story 1.3.
#[cfg_attr(not(windows), allow(dead_code))]
fn synthesize_minimal_xml(
    provider_name: &str,
    provider_guid: &str,
    event_id: u16,
    time_created: &str,
) -> String {
    format!(
        r#"<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="{provider_name}" Guid="{{{provider_guid}}}"/>
    <EventID>{event_id}</EventID>
    <TimeCreated SystemTime="{time_created}"/>
  </System>
</Event>"#
    )
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
    fn test_synthesize_minimal_xml_parses() {
        let xml = synthesize_minimal_xml(
            "Microsoft-Windows-Kernel-Process",
            "22fb2cd6-0e7b-422b-a0c7-2fad1fd0e716",
            5,
            "2024-01-01T00:00:00.0000000Z",
        );
        let mut event = Event::from_xml(&xml).expect("minimal XML must parse");
        assert_eq!(event.record_id(), None);

        event.inject_logsource_fields();
        let system = &event.event_json["Event"]["System"];
        assert_eq!(system["EventID"], 5);
        assert_eq!(
            system["Provider"]["#attributes"]["Name"],
            "Microsoft-Windows-Kernel-Process"
        );
        assert_eq!(event.event_json["product"], "windows");
        assert_eq!(event.event_json["service"], "process");
        assert_eq!(event.event_raw, xml.as_bytes());
    }

    #[test]
    fn test_synthesize_minimal_xml_no_service_mapping() {
        let xml = synthesize_minimal_xml(
            "Microsoft-Windows-Kernel-EventTracing",
            "b675ec37-bdb6-4648-bc92-f3fdc84dc3da",
            1,
            "2024-01-01T00:00:00.0000000Z",
        );
        let mut event = Event::from_xml(&xml).unwrap();
        event.inject_logsource_fields();
        assert_eq!(event.event_json["product"], "windows");
        assert_eq!(event.event_json.get("service"), None);
    }

    #[test]
    fn test_synthesize_minimal_xml_etw_provider_services() {
        for (provider, service) in [
            ("Microsoft-Windows-WMI-Activity", "wmi"),
            ("Microsoft-Windows-TaskScheduler", "taskscheduler"),
            ("Microsoft-Windows-Kernel-File", "file"),
            ("Microsoft-Windows-DNS-Client", "dns"),
        ] {
            let xml = synthesize_minimal_xml(
                provider,
                "00000000-0000-0000-0000-000000000000",
                1,
                "2024-01-01T00:00:00.0000000Z",
            );
            let mut event = Event::from_xml(&xml).unwrap();
            event.inject_logsource_fields();
            assert_eq!(
                event.event_json["service"], service,
                "provider '{provider}' must map to '{service}'"
            );
        }
    }

    #[test]
    fn test_event_collector_constructible() {
        let _ = EventCollector::new();
    }
}
