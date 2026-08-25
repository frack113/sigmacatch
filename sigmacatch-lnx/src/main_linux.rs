// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 sigmacatch contributors

//! Shared entry point of the three Linux binaries; cargo features select
//! which sysmon source (legacy tail / eBPF / none) is compiled in.

use std::collections::HashMap;

use anyhow::Result;
use async_trait::async_trait;
use sigmacatch_detection::DetectionEngine;
use sigmacatch_regression::DataFormat;
use sigmacatch_runner::{self, CollectorKind};
use sigmacatch_types::{Event, EventProducer};
use tokio::sync::{mpsc, watch};

#[cfg(feature = "sysmon")]
use sigmacatch_lnx::sysmon;
use sigmacatch_lnx::{auditd, syslog};

fn auditd_available() -> bool {
    std::path::Path::new(auditd::DEFAULT_LOG_PATH).is_file()
}

fn mode_for(auditd_ok: bool, syslog_ok: bool, ebpf_planned: bool) -> &'static str {
    match (auditd_ok, syslog_ok, ebpf_planned) {
        (true, true, true) => "linux auditd+syslog+sysmon(ebpf)",
        (true, false, true) => "linux auditd+sysmon(ebpf)",
        (false, true, true) => "linux syslog+sysmon(ebpf)",
        (false, false, true) => "linux sysmon(ebpf)",
        (true, true, false) => "linux auditd+syslog+sysmon",
        (true, false, false) => "linux auditd",
        (false, true, false) => "linux syslog+sysmon",
        (false, false, false) => "linux (no source)",
    }
}

/// Sysmon source for this binary flavour, if any:
/// - `ebpf` feature: the eBPF collector (privilege-gated at startup); a
///   failed load warns and yields `None` — no silent downgrade;
/// - `sysmon` feature: the legacy Sysmon-for-Linux syslog tail;
/// - both (dev/all-features builds): eBPF first, tail as fallback;
/// - neither: `None` — the plain binary carries no sysmon source.
#[allow(unused_variables)]
fn make_sysmon_collector(syslog_ok: bool) -> Option<(&'static str, Box<dyn EventProducer>)> {
    #[cfg(feature = "ebpf")]
    {
        match sigmacatch_lnx::ebpf::EventCollector::new() {
            Ok(collector) => return Some(("sysmon", Box::new(collector))),
            Err(e) => {
                tracing::warn!("eBPF collector unavailable ({e:#})");
                if !cfg!(feature = "sysmon") {
                    tracing::warn!("no sysmon fallback in this flavour — continuing without it");
                    return None;
                }
                tracing::warn!("falling back to the Sysmon-for-Linux syslog tail");
            }
        }
    }
    #[cfg(feature = "sysmon")]
    {
        return if syslog_ok {
            Some(("sysmon", Box::new(sysmon::EventCollector::new())))
        } else {
            None
        };
    }
    #[allow(unreachable_code)]
    None
}

fn select_collectors(
    auditd_ok: bool,
    syslog_ok: bool,
) -> Vec<(&'static str, Box<dyn EventProducer>)> {
    let mut collectors: Vec<(&'static str, Box<dyn EventProducer>)> = Vec::new();
    if auditd_ok {
        collectors.push(("auditd", Box::new(auditd::EventCollector::new())));
    }
    if syslog_ok {
        collectors.push(("syslog", Box::new(syslog::EventCollector::new())));
    }
    if let Some(sysmon) = make_sysmon_collector(syslog_ok) {
        collectors.push(sysmon);
    }
    collectors
}

struct MultiCollector(Vec<(&'static str, Box<dyn EventProducer>)>);

#[async_trait]
impl EventProducer for MultiCollector {
    async fn run(
        self: Box<Self>,
        tx: mpsc::Sender<Event>,
        stop: watch::Receiver<bool>,
    ) -> Result<()> {
        let total = self.0.len();
        if total == 0 {
            anyhow::bail!("no linux log source available");
        }
        let mut handles = Vec::with_capacity(total);
        for (name, collector) in self.0 {
            let tx = tx.clone();
            let stop = stop.clone();
            handles.push(tokio::spawn(async move {
                collector
                    .run(tx, stop)
                    .await
                    .map_err(|e| anyhow::anyhow!("{name}: {e}"))
            }));
        }
        let mut failures = Vec::new();
        for handle in handles {
            match handle.await {
                Ok(Ok(())) => {}
                Ok(Err(e)) => {
                    tracing::warn!("collector finished with error: {e}");
                    failures.push(e);
                }
                Err(e) => {
                    tracing::warn!("collector task panicked");
                    failures.push(anyhow::anyhow!("collector task panicked: {e}"));
                }
            }
        }
        if failures.len() == total {
            tracing::error!("all {total} collector(s) failed — no source active anymore");
            return Err(failures.swap_remove(0));
        }
        Ok(())
    }
}

struct LinuxCollector;

/// Whether the eBPF sysmon input is planned for this run: compiled in and
/// usable privileges-wise. Loader failure later still falls back.
#[cfg(feature = "ebpf")]
fn ebpf_planned() -> bool {
    sigmacatch_lnx::ebpf::has_required_privileges()
}

#[cfg(not(feature = "ebpf"))]
fn ebpf_planned() -> bool {
    false
}

impl CollectorKind for LinuxCollector {
    fn name(&self) -> &'static str {
        "sigmacatch-linux"
    }

    fn mode(&self) -> &'static str {
        mode_for(
            auditd_available(),
            syslog::default_log_exists(),
            ebpf_planned(),
        )
    }

    fn channels(
        &self,
        _engine: &DetectionEngine,
        _custom_map: &HashMap<String, String>,
    ) -> Option<Vec<String>> {
        None
    }

    fn build(&self, _channels: &[String]) -> Box<dyn EventProducer> {
        Box::new(MultiCollector(select_collectors(
            auditd_available(),
            syslog::default_log_exists(),
        )))
    }

    fn regression_format(&self) -> DataFormat {
        DataFormat::Log
    }
}

#[cfg(feature = "tools")]
mod cli;

#[tokio::main]
async fn main() -> Result<()> {
    // Diagnostics first: the tools subcommands must work on machines with no
    // local log source; only the collection loop requires one.
    #[cfg(feature = "tools")]
    if let Some(code) = cli::dispatch() {
        std::process::exit(code);
    }
    // Spec constraint: refuse to start without eBPF privileges rather than
    // degrade silently — the syslog fallback only covers old kernels.
    #[cfg(feature = "ebpf")]
    if !sigmacatch_lnx::ebpf::has_required_privileges() {
        anyhow::bail!(
            "insufficient privileges for the eBPF collector: run as root \
             or grant CAP_BPF+CAP_PERFMON"
        );
    }
    if !std::path::Path::new(auditd::DEFAULT_LOG_PATH).is_file()
        && !syslog::default_log_exists()
        && !cfg!(feature = "ebpf")
    {
        anyhow::bail!(
            "no linux log source found: {} (auditd) nor {:?} / {:?} / {:?} (syslog). \
             Install/configure one of them first.",
            auditd::DEFAULT_LOG_PATH,
            syslog::DEFAULT_LOG_PATHS,
            syslog::AUTH_LOG_PATHS,
            syslog::CRON_LOG_PATHS,
        );
    }
    sigmacatch_runner::run(&LinuxCollector).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value as JsonValue;

    #[test]
    fn test_mode_for() {
        assert_eq!(mode_for(true, true, false), "linux auditd+syslog+sysmon");
        assert_eq!(mode_for(true, false, false), "linux auditd");
        assert_eq!(mode_for(false, true, false), "linux syslog+sysmon");
        assert_eq!(mode_for(false, false, false), "linux (no source)");
        assert_eq!(
            mode_for(true, true, true),
            "linux auditd+syslog+sysmon(ebpf)"
        );
        assert_eq!(mode_for(true, false, true), "linux auditd+sysmon(ebpf)");
        assert_eq!(mode_for(false, true, true), "linux syslog+sysmon(ebpf)");
        assert_eq!(mode_for(false, false, true), "linux sysmon(ebpf)");
    }

    #[test]
    fn test_select_collectors_source_guards() {
        let names = |a: bool, s: bool| -> Vec<&'static str> {
            select_collectors(a, s).iter().map(|(n, _)| *n).collect()
        };
        // Source guards are honoured regardless of flavour.
        assert!(!names(false, true).contains(&"auditd"));
        assert!(!names(true, false).contains(&"syslog"));
        assert!(names(true, true).contains(&"auditd"));
        assert!(names(true, true).contains(&"syslog"));
        // Nothing to run without any source file.
        assert!(names(false, false).is_empty());
    }

    #[cfg(feature = "sysmon")]
    #[test]
    fn test_sysmon_flavour_carries_tail_only_with_syslog_file() {
        let has_sysmon = |syslog_ok| {
            select_collectors(true, syslog_ok)
                .iter()
                .any(|(n, _)| *n == "sysmon")
        };
        assert!(has_sysmon(true));
        assert!(!has_sysmon(false));
    }

    struct FakeProducer {
        events: usize,
        fail: bool,
    }

    impl FakeProducer {
        fn ok(events: usize) -> Box<Self> {
            Box::new(FakeProducer {
                events,
                fail: false,
            })
        }

        fn failing() -> Box<Self> {
            Box::new(FakeProducer {
                events: 0,
                fail: true,
            })
        }
    }

    #[async_trait]
    impl EventProducer for FakeProducer {
        async fn run(
            self: Box<Self>,
            tx: mpsc::Sender<Event>,
            stop: watch::Receiver<bool>,
        ) -> Result<()> {
            if self.fail {
                anyhow::bail!("fake source gone");
            }
            for _ in 0..self.events {
                if *stop.borrow() {
                    break;
                }
                tx.send(Event::new(JsonValue::Null, JsonValue::Null, Vec::new()))
                    .await
                    .ok();
            }
            Ok(())
        }
    }

    async fn drain(mut rx: mpsc::Receiver<Event>) -> usize {
        let mut received = 0;
        while rx.recv().await.is_some() {
            received += 1;
        }
        received
    }

    #[tokio::test]
    async fn test_multi_collector_fans_in_events() {
        let collectors: Vec<(&'static str, Box<dyn EventProducer>)> =
            vec![("a", FakeProducer::ok(2)), ("b", FakeProducer::ok(3))];
        let (tx, rx) = mpsc::channel::<Event>(16);
        let (_stop_tx, stop_rx) = watch::channel(false);

        Box::new(MultiCollector(collectors))
            .run(tx, stop_rx)
            .await
            .unwrap();

        assert_eq!(drain(rx).await, 5);
    }

    #[tokio::test]
    async fn test_multi_collector_empty_bails() {
        let (tx, _rx) = mpsc::channel::<Event>(16);
        let (_stop_tx, stop_rx) = watch::channel(false);

        let result = Box::new(MultiCollector(Vec::new())).run(tx, stop_rx).await;

        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_multi_collector_sibling_isolation() {
        let collectors: Vec<(&'static str, Box<dyn EventProducer>)> = vec![
            ("bad", FakeProducer::failing()),
            ("good", FakeProducer::ok(2)),
        ];
        let (tx, rx) = mpsc::channel::<Event>(16);
        let (_stop_tx, stop_rx) = watch::channel(false);

        Box::new(MultiCollector(collectors))
            .run(tx, stop_rx)
            .await
            .unwrap();

        assert_eq!(drain(rx).await, 2);
    }

    #[tokio::test]
    async fn test_multi_collector_all_failed_is_error() {
        let collectors: Vec<(&'static str, Box<dyn EventProducer>)> = vec![
            ("bad1", FakeProducer::failing()),
            ("bad2", FakeProducer::failing()),
        ];
        let (tx, _rx) = mpsc::channel::<Event>(16);
        let (_stop_tx, stop_rx) = watch::channel(false);

        let result = Box::new(MultiCollector(collectors)).run(tx, stop_rx).await;

        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_multi_collector_stops_promptly() {
        let collectors: Vec<(&'static str, Box<dyn EventProducer>)> = vec![
            ("a", FakeProducer::ok(usize::MAX)),
            ("b", FakeProducer::ok(usize::MAX)),
        ];
        let (tx, rx) = mpsc::channel::<Event>(16);
        let (stop_tx, stop_rx) = watch::channel(false);

        let drainer = tokio::spawn(drain(rx));
        let runner =
            tokio::spawn(
                async move { Box::new(MultiCollector(collectors)).run(tx, stop_rx).await },
            );
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        stop_tx.send(true).unwrap();

        tokio::time::timeout(std::time::Duration::from_secs(5), runner)
            .await
            .expect("multi collector must exit promptly on stop")
            .unwrap()
            .unwrap();
        drainer.await.unwrap();
    }
}
