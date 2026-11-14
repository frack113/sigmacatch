// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 sigmacatch contributors

//! Diagnostic probe for the ETW collector (feature `etw`, Windows only).
//!
//! Starts the same sessions the collector will use, prints the decoded
//! provider/event ids, and reports session loss counters. This is the M0/M1
//! validation tool: it answers "which fields does this VM actually give us"
//! without any Sigma or regression-data machinery.
//!
//! ```text
//! cargo xwin build --release --examples --features etw -p sigmacatch
//! etw_dump.exe [--seconds N] [--filter SUBSTRING] [--full]
//! ```
//!
//! Requires an elevated prompt (kernel providers).

#[cfg(not(windows))]
fn main() {
    eprintln!("etw_dump is Windows-only");
}

#[cfg(windows)]
fn main() -> anyhow::Result<()> {
    probe::main()
}

#[cfg(windows)]
mod probe {
    use std::collections::BTreeMap;
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    use anyhow::Result;
    use sigmacatch::inputs::etw::{
        self, KERNEL_LOGGER_FLAGS, MAIN_SESSION_PROVIDERS, PROCESS_SESSION_PROVIDERS, ProviderSpec,
        RunningSession, SessionConfig, TraceSession, ensure_privileges,
    };
    use sigmacatch::inputs::etw_event::{DecodedEvent, decode};
    use windows::Win32::System::Diagnostics::Etw::EVENT_RECORD;

    const PROCESS_SESSION_NAME: &str = "sigmacatch-probe-process";
    const MAIN_SESSION_NAME: &str = "sigmacatch-probe-main";
    const SAMPLES_PER_EVENT: usize = 2;

    /// (provider, event id, opcode): the classic kernel logger reports every
    /// event as id 0, so the opcode is what distinguishes them.
    type EventKey = (String, u16, u8);

    #[derive(Default)]
    struct Stats {
        events: BTreeMap<EventKey, usize>,
        raw: BTreeMap<(String, u16, u8), usize>,
        decode_failures: BTreeMap<(String, u16), usize>,
        samples: BTreeMap<EventKey, usize>,
    }

    struct Options {
        seconds: u64,
        filter: Option<String>,
        full: bool,
        /// Dump the raw payload of the first record with this opcode from the
        /// classic kernel logger (used to reverse the MOF layout).
        raw_opcode: Option<u8>,
    }

    pub fn main() -> Result<()> {
        let options = parse_args();
        if let Err(error) = ensure_privileges() {
            eprintln!("privileges: {error}");
            return Err(error);
        }
        println!("privileges: elevated");
        println!("capturing for {}s", options.seconds);

        let stats = Arc::new(Mutex::new(Stats::default()));

        let process = start(
            TraceSession::start(PROCESS_SESSION_NAME, SessionConfig::PROCESS)?,
            PROCESS_SESSION_NAME,
            PROCESS_SESSION_PROVIDERS,
            stats.clone(),
            options.full,
            options.raw_opcode,
        )?;
        let main = start(
            TraceSession::start(MAIN_SESSION_NAME, SessionConfig::MAIN)?,
            MAIN_SESSION_NAME,
            MAIN_SESSION_PROVIDERS,
            stats.clone(),
            options.full,
            options.raw_opcode,
        )?;
        // Classic kernel logger: CommandLine and UserSID only exist here.
        let kernel = start(
            TraceSession::start_kernel_logger(KERNEL_LOGGER_FLAGS, SessionConfig::PROCESS)?,
            etw::KERNEL_LOGGER_NAME,
            &[],
            stats.clone(),
            options.full,
            options.raw_opcode,
        )?;

        // Heartbeat: shows whether delivery is continuous or a single burst.
        let heartbeat = {
            let stats = Arc::clone(&stats);
            let total = options.seconds;
            std::thread::spawn(move || {
                for second in 1..=total {
                    std::thread::sleep(Duration::from_secs(1));
                    let stats = stats.lock().expect("stats lock");
                    let raw: usize = stats.raw.values().sum();
                    eprintln!("t={second}s callbacks={raw}");
                }
            })
        };
        std::thread::sleep(Duration::from_secs(options.seconds));
        let _ = heartbeat.join();

        for (label, session) in [("process", &process), ("main", &main), ("kernel", &kernel)] {
            if let Some(stats) = session.stats() {
                println!(
                    "{label} session: events_lost={} buffers={} realtime_lost={}",
                    stats.events_lost, stats.buffers_written, stats.realtime_buffers_lost
                );
            }
        }

        for (label, session) in [("process", process), ("main", main), ("kernel", kernel)] {
            let (status, ran) = session.stop();
            println!("{label} consumer: status={status} ran={ran:?}");
        }

        report(&stats, options.filter.as_deref());
        Ok(())
    }

    fn parse_args() -> Options {
        let mut options = Options {
            seconds: 10,
            filter: None,
            full: false,
            raw_opcode: None,
        };
        let mut args = std::env::args().skip(1);
        while let Some(arg) = args.next() {
            match arg.as_str() {
                "--seconds" => {
                    if let Some(value) = args.next().and_then(|v| v.parse().ok()) {
                        options.seconds = value;
                    }
                }
                "--filter" => options.filter = args.next(),
                "--full" => options.full = true,
                "--raw-opcode" => {
                    options.raw_opcode = args.next().and_then(|v| v.parse().ok());
                }
                other => eprintln!("ignoring unknown argument {other}"),
            }
        }
        options
    }

    fn start(
        session: TraceSession,
        name: &str,
        providers: &[ProviderSpec],
        stats: Arc<Mutex<Stats>>,
        full: bool,
        raw_opcode: Option<u8>,
    ) -> Result<RunningSession> {
        let sink: etw::Sink = Box::new(move |record: &EVENT_RECORD| {
            collect(record, &stats, full, raw_opcode);
        });
        RunningSession::spawn(session, name, providers, sink)
    }

    fn collect(
        record: &EVENT_RECORD,
        stats: &Arc<Mutex<Stats>>,
        full: bool,
        raw_opcode: Option<u8>,
    ) {
        {
            // Raw header census, independent of TDH decoding.
            let key = (
                guid(&record.EventHeader.ProviderId),
                record.EventHeader.EventDescriptor.Id,
                record.EventHeader.EventDescriptor.Opcode,
            );
            let mut stats = stats.lock().expect("stats lock");
            *stats.raw.entry(key).or_default() += 1;
        }
        if let Some(opcode) = raw_opcode
            && record.EventHeader.EventDescriptor.Opcode == opcode
        {
            // SAFETY: `UserDataLength` bytes are valid for the callback.
            let bytes = unsafe {
                std::slice::from_raw_parts(
                    record.UserData.cast::<u8>(),
                    record.UserDataLength as usize,
                )
            };
            let hex: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
            let ascii: String = bytes
                .iter()
                .map(|b| {
                    if b.is_ascii_graphic() {
                        *b as char
                    } else {
                        '.'
                    }
                })
                .collect();
            println!(
                "RAW opcode={opcode} provider={} id={} len={}\n{hex}\n{ascii}",
                guid(&record.EventHeader.ProviderId),
                record.EventHeader.EventDescriptor.Id,
                bytes.len()
            );
        }

        let Some(decoded) = decode(record) else {
            let key = (
                guid(&record.EventHeader.ProviderId),
                record.EventHeader.EventDescriptor.Id,
            );
            let mut stats = stats.lock().expect("stats lock");
            *stats.decode_failures.entry(key).or_default() += 1;
            return;
        };

        let key = (decoded.provider.clone(), decoded.event_id, decoded.opcode);
        let mut stats = stats.lock().expect("stats lock");
        *stats.events.entry(key.clone()).or_default() += 1;
        let sample = stats.samples.entry(key).or_default();
        if *sample >= SAMPLES_PER_EVENT {
            return;
        }
        *sample += 1;
        print_event(&decoded, full);
    }

    fn print_event(event: &DecodedEvent, full: bool) {
        println!(
            "\n[{}] {} (id={} opcode={} level={} keywords={:#x}) pid={} tid={} ts={}",
            event.provider,
            event.event_name,
            event.event_id,
            event.opcode,
            event.level,
            event.keywords,
            event.process_id,
            event.thread_id,
            event
                .utc()
                .map(|t| t.to_rfc3339())
                .unwrap_or_else(|| event.timestamp.to_string())
        );
        for property in &event.properties {
            if !full && property.name.starts_with('#') {
                continue;
            }
            let text = property.value.to_text();
            let text = if text.is_empty() {
                "<empty>"
            } else {
                text.as_str()
            };
            println!("    {} = {}", property.name, text);
        }
    }

    fn report(stats: &Arc<Mutex<Stats>>, filter: Option<&str>) {
        let stats = stats.lock().expect("stats lock");
        println!("\n=== event counts ===");
        for ((provider, event_id, opcode), count) in &stats.events {
            if let Some(filter) = filter
                && !provider.contains(filter)
            {
                continue;
            }
            println!("{provider} id={event_id} opcode={opcode}: {count}");
        }
        println!("=== raw header census (provider guid, id, opcode) ===");
        for ((provider, id, opcode), count) in &stats.raw {
            println!("{provider} id={id} opcode={opcode}: {count}");
        }
        if !stats.decode_failures.is_empty() {
            println!("=== undecoded (no TDH manifest) ===");
            for ((provider, event_id), count) in &stats.decode_failures {
                println!("{provider} {event_id}: {count}");
            }
        }
    }

    fn guid(guid: &windows::core::GUID) -> String {
        format!(
            "{:08x}-{:04x}-{:04x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
            guid.data1,
            guid.data2,
            guid.data3,
            guid.data4[0],
            guid.data4[1],
            guid.data4[2],
            guid.data4[3],
            guid.data4[4],
            guid.data4[5],
            guid.data4[6],
            guid.data4[7]
        )
    }
}
