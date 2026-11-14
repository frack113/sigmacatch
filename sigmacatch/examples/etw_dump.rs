// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 sigmacatch contributors

//! Diagnostic probe for the ETW collector (feature `etw`, Windows only).
//!
//! Starts the real sessions, prints decoded events, and reports session loss
//! counters. This is the tool the collector's coverage claims are measured
//! with: which fields a given VM actually publishes, which event ids arrive,
//! and whether the consumer keeps up.
//!
//! ```text
//! cargo xwin build --release --examples --features etw -p sigmacatch
//! etw_dump.exe [--seconds N] [--filter SUBSTRING] [--full]
//!              [--raw-opcode N] [--sessions process,main,kernel]
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
    use std::collections::{BTreeMap, HashMap, HashSet};
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    use anyhow::Result;
    use sigmacatch::inputs::etw::{
        self, KERNEL_LOGGER_FLAGS, MAIN_SESSION_PROVIDERS, PROCESS_SESSION_PROVIDERS, ProviderSpec,
        RunningSession, SessionConfig, TraceSession, ensure_privileges,
    };
    use sigmacatch::inputs::etw_event::{DecodedEvent, decode};
    use sigmacatch::inputs::etw_process::{ProcessFacts, enrich, snapshot};
    use sigmacatch::inputs::etw_sysmon::process_start_xml;
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
        /// Raw header census, before any TDH call.
        raw: BTreeMap<EventKey, usize>,
        decode_failures: BTreeMap<(String, u16), usize>,
        samples: BTreeMap<EventKey, usize>,
    }

    struct Options {
        seconds: u64,
        filter: Option<String>,
        full: bool,
        /// Dump the raw payload of the first record with this opcode.
        raw_opcode: Option<u8>,
        sessions: Vec<String>,
        /// Diagnostic: capture the process session to an ETL file instead of
        /// consuming it in realtime.
        file: Option<String>,
        /// Synthesize Sysmon EID 1 for every process first seen during the
        /// capture, from the live process.
        eid1: bool,
    }

    /// Processes seen during the capture, for the EID 1 synthesis.
    struct ProcessTracker {
        started: chrono::DateTime<chrono::Utc>,
        seen: HashSet<u32>,
        facts: HashMap<u32, ProcessFacts>,
    }

    impl ProcessTracker {
        fn new() -> Self {
            Self {
                // Tolerance for a process created just before the session.
                started: chrono::Utc::now() - chrono::Duration::seconds(2),
                seen: HashSet::new(),
                facts: HashMap::new(),
            }
        }

        /// Enrich a PID the first time it appears, and emit EID 1 when the
        /// process really started during the capture.
        fn observe(&mut self, pid: u32) {
            if pid <= 4 || !self.seen.insert(pid) {
                return;
            }
            let Some(facts) = enrich(pid) else {
                return;
            };
            let new = facts.created.is_some_and(|created| created >= self.started);
            let parent = self.facts.get(&facts.parent_pid).cloned();
            if new {
                let computer = std::env::var("COMPUTERNAME").unwrap_or_default();
                println!(
                    "\nEID1 {}",
                    process_start_xml(&computer, &facts, parent.as_ref())
                );
            }
            self.facts.insert(pid, facts);
        }
    }

    pub fn main() -> Result<()> {
        let options = parse_args();
        if let Err(error) = ensure_privileges() {
            eprintln!("privileges: {error}");
            return Err(error);
        }
        println!("privileges: elevated");
        println!("capturing for {}s", options.seconds);

        if let Some(path) = options.file.clone() {
            let session =
                TraceSession::start_file(PROCESS_SESSION_NAME, SessionConfig::PROCESS, &path)?;
            for provider in PROCESS_SESSION_PROVIDERS {
                session.enable_provider(provider)?;
            }
            std::thread::sleep(Duration::from_secs(options.seconds));
            session.stop();
            println!("wrote {path}");
            return Ok(());
        }

        let stats = Arc::new(Mutex::new(Stats::default()));
        let tracker = Arc::new(Mutex::new(ProcessTracker::new()));

        // Process-creation trigger independent of the ETW stream: realtime
        // sessions on this platform do not deliver `ProcessStart` for
        // short-lived processes, but the processes themselves are there.
        let poller = if options.eid1 {
            let tracker = Arc::clone(&tracker);
            let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
            let poll_stop = Arc::clone(&stop);
            let handle = std::thread::spawn(move || {
                while !poll_stop.load(std::sync::atomic::Ordering::Relaxed) {
                    for pid in snapshot() {
                        let mut tracker = tracker
                            .lock()
                            .unwrap_or_else(std::sync::PoisonError::into_inner);
                        tracker.observe(pid);
                    }
                    std::thread::sleep(Duration::from_millis(50));
                }
            });
            Some((handle, stop))
        } else {
            None
        };
        let mut running: Vec<(&str, RunningSession)> = Vec::new();

        if options.has("process") {
            running.push((
                "process",
                start(
                    TraceSession::start(PROCESS_SESSION_NAME, SessionConfig::PROCESS)?,
                    PROCESS_SESSION_NAME,
                    PROCESS_SESSION_PROVIDERS,
                    stats.clone(),
                    tracker.clone(),
                    &options,
                    Duration::from_millis(5),
                )?,
            ));
        }
        if options.has("main") {
            running.push((
                "main",
                start(
                    TraceSession::start(MAIN_SESSION_NAME, SessionConfig::MAIN)?,
                    MAIN_SESSION_NAME,
                    MAIN_SESSION_PROVIDERS,
                    stats.clone(),
                    tracker.clone(),
                    &options,
                    Duration::from_millis(20),
                )?,
            ));
        }
        if options.has("kernel") {
            running.push((
                "kernel",
                start(
                    TraceSession::start_kernel_logger(KERNEL_LOGGER_FLAGS, SessionConfig::PROCESS)?,
                    etw::KERNEL_LOGGER_NAME,
                    &[],
                    stats.clone(),
                    tracker.clone(),
                    &options,
                    Duration::from_millis(20),
                )?,
            ));
        }

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

        for (label, session) in running {
            if let Some(stats) = session.stats() {
                println!(
                    "{label} session: events_lost={} buffers={} realtime_lost={}",
                    stats.events_lost, stats.buffers_written, stats.realtime_buffers_lost
                );
            }
            let (status, ran) = session.stop();
            println!("{label} consumer: status={status} ran={ran:?}");
        }

        if let Some((handle, stop)) = poller {
            stop.store(true, std::sync::atomic::Ordering::Relaxed);
            let _ = handle.join();
        }
        report(&stats, options.filter.as_deref());
        Ok(())
    }

    impl Options {
        fn has(&self, session: &str) -> bool {
            self.sessions.iter().any(|s| s == session)
        }
    }

    fn parse_args() -> Options {
        let mut options = Options {
            seconds: 10,
            filter: None,
            full: false,
            raw_opcode: None,
            sessions: vec!["process".into(), "main".into(), "kernel".into()],
            file: None,
            eid1: false,
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
                "--file" => options.file = args.next(),
                "--eid1" => options.eid1 = true,
                "--sessions" => {
                    if let Some(list) = args.next() {
                        options.sessions = list.split(',').map(str::to_string).collect();
                    }
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
        tracker: Arc<Mutex<ProcessTracker>>,
        options: &Options,
        flush_interval: Duration,
    ) -> Result<RunningSession> {
        let full = options.full;
        let raw_opcode = options.raw_opcode;
        let eid1 = options.eid1;
        let sink: etw::Sink = Box::new(move |record: &EVENT_RECORD| {
            collect(record, &stats, full, raw_opcode);
            if eid1 {
                // A panic elsewhere must not turn into a poisoned-lock panic
                // here: recover the guard and keep processing records.
                let mut tracker = tracker
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                tracker.observe(record.EventHeader.ProcessId);
            }
        });
        RunningSession::spawn_with_flush(session, name, providers, sink, Some(flush_interval))
    }

    fn collect(
        record: &EVENT_RECORD,
        stats: &Arc<Mutex<Stats>>,
        full: bool,
        raw_opcode: Option<u8>,
    ) {
        let header = &record.EventHeader;
        let key = (
            guid(&header.ProviderId),
            header.EventDescriptor.Id,
            header.EventDescriptor.Opcode,
        );
        {
            let mut stats = stats.lock().expect("stats lock");
            *stats.raw.entry(key.clone()).or_default() += 1;
            if let Some(opcode) = raw_opcode
                && header.EventDescriptor.Opcode == opcode
                && stats.raw.get(&key).copied() == Some(1)
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
                    key.0,
                    header.EventDescriptor.Id,
                    bytes.len()
                );
            }
        }

        let Some(decoded) = decode(record) else {
            let mut stats = stats.lock().expect("stats lock");
            *stats
                .decode_failures
                .entry((key.0.clone(), key.1))
                .or_default() += 1;
            return;
        };

        let decoded_key = (decoded.provider.clone(), decoded.event_id, decoded.opcode);
        let mut stats = stats.lock().expect("stats lock");
        *stats.events.entry(decoded_key.clone()).or_default() += 1;
        let sample = stats.samples.entry(decoded_key).or_default();
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
