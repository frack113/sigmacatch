// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 sigmacatch contributors

use std::collections::HashMap;

use anyhow::Result;
use async_trait::async_trait;
use sigmacatch_detection::DetectionEngine;
use sigmacatch_regression::DataFormat;
use sigmacatch_runner::{self, CollectorKind};
use sigmacatch_types::{Event, EventProducer};
use tokio::sync::{mpsc, watch};

use sigmacatch_lnx::{auditd, syslog};

fn auditd_available() -> bool {
    std::path::Path::new(auditd::DEFAULT_LOG_PATH).is_file()
}

fn mode_for(auditd_ok: bool, syslog_ok: bool) -> &'static str {
    match (auditd_ok, syslog_ok) {
        (true, true) => "linux auditd+syslog",
        (true, false) => "linux auditd",
        (false, true) => "linux syslog",
        (false, false) => "linux (no source)",
    }
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

impl CollectorKind for LinuxCollector {
    fn name(&self) -> &'static str {
        "sigmacatch-linux"
    }

    fn mode(&self) -> &'static str {
        mode_for(auditd_available(), syslog::default_log_exists())
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
    if !std::path::Path::new(auditd::DEFAULT_LOG_PATH).is_file()
        && syslog::discover_default_path().is_none()
    {
        anyhow::bail!(
            "no linux log source found: {} (auditd) nor {:?} (central syslog). \
             Install/configure one of them first.",
            auditd::DEFAULT_LOG_PATH,
            syslog::DEFAULT_LOG_PATHS,
        );
    }
    #[cfg(feature = "tools")]
    {
        let code = cli::dispatch();
        if code != 0 {
            std::process::exit(code);
        }
    }
    sigmacatch_runner::run(&LinuxCollector).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value as JsonValue;

    #[test]
    fn test_mode_for() {
        assert_eq!(mode_for(true, true), "linux auditd+syslog");
        assert_eq!(mode_for(true, false), "linux auditd");
        assert_eq!(mode_for(false, true), "linux syslog");
        assert_eq!(mode_for(false, false), "linux (no source)");
    }

    #[test]
    fn test_select_collectors() {
        assert_eq!(select_collectors(true, true).len(), 2);
        assert_eq!(select_collectors(true, false).len(), 1);
        assert_eq!(select_collectors(false, true).len(), 1);
        assert!(select_collectors(false, false).is_empty());
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
