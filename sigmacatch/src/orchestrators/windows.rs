// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 sigmacatch contributors

//! Windows orchestrator: the Event Log channels plus one process source.
//!
//! The kernel sensor is preferred for process events when it is loaded (exact
//! creation-time command lines, no live-process race); the ETW path (ETW
//! sessions + live-process facts) is the fallback when it is absent. Only one
//! of the two runs, so a process is never reported twice.
//!
//! Selected from `main.rs` on Windows when the `winevt` input is compiled in.

use std::collections::HashMap;

use crate::runner::CollectorKind;
use crate::types::{EventProducer, ProducerError};
use anyhow::Result;
use async_trait::async_trait;
use sigmacatch_core::exchange::ChannelResolver;
use tokio::sync::{mpsc, watch};

fn driver_available() -> bool {
    #[cfg(feature = "driver")]
    {
        crate::orchestrators::etw_driver::is_available()
    }
    #[cfg(not(feature = "driver"))]
    {
        false
    }
}

struct WindowsCollector;

impl CollectorKind for WindowsCollector {
    fn name(&self) -> &'static str {
        "sigmacatch"
    }

    fn mode(&self) -> String {
        let mut sources = vec!["winevt"];
        if driver_available() {
            sources.push("driver");
            // The driver owns processes and files; the ETW main session still
            // supplies the events only user mode can produce (network, DNS).
            if cfg!(feature = "etw") {
                sources.push("etw");
            }
        } else if cfg!(feature = "etw") {
            sources.push("etw");
        }
        format!("windows {}", sources.join("+"))
    }

    fn channels(
        &self,
        resolver: &dyn ChannelResolver,
        custom_map: &HashMap<String, String>,
    ) -> Option<Vec<String>> {
        Some(resolver.resolve_channels(custom_map))
    }

    fn build(&self, channels: &[String]) -> Box<dyn EventProducer> {
        Box::new(MultiCollector {
            channels: channels.to_vec(),
        })
    }
}

/// Runs the channel collector and exactly one process source.
struct MultiCollector {
    channels: Vec<String>,
}

#[async_trait]
impl EventProducer for MultiCollector {
    async fn run(
        self: Box<Self>,
        tx: mpsc::Sender<crate::types::Event>,
        stop: watch::Receiver<bool>,
    ) -> Result<(), ProducerError> {
        let mut tasks = tokio::task::JoinSet::new();

        {
            let tx = tx.clone();
            let stop = stop.clone();
            let channels = self.channels.clone();
            tasks.spawn(async move {
                Box::new(crate::orchestrators::channels::EventCollector::new(
                    channels,
                ))
                .run(tx, stop)
                .await
            });
        }

        // One pid → image map for the whole run: the kernel sensor fills it at
        // process start, the ETW mappers read it for the events that only
        // carry a pid.
        #[cfg(feature = "etw")]
        let images = crate::orchestrators::etw_process::ImageCache::new();
        let use_driver = driver_available();
        if use_driver {
            #[cfg(feature = "driver")]
            {
                let tx = tx.clone();
                let stop = stop.clone();
                let images = images.clone();
                tasks.spawn(async move {
                    Box::new(crate::orchestrators::etw_driver::EventCollector::new(
                        images,
                    ))
                    .run(tx, stop)
                    .await
                });
            }
            // The main ETW session keeps supplying the events the kernel
            // sensor cannot report (network connections, DNS queries).
            #[cfg(feature = "etw")]
            {
                let tx = tx.clone();
                let stop = stop.clone();
                let images = images.clone();
                tasks.spawn(async move {
                    Box::new(crate::orchestrators::etw::EventCollector::main_only(images))
                        .run(tx, stop)
                        .await
                });
            }
        } else {
            #[cfg(feature = "etw")]
            {
                let tx = tx.clone();
                let stop = stop.clone();
                let images = images.clone();
                tasks.spawn(async move {
                    Box::new(crate::orchestrators::etw::EventCollector::new(images))
                        .run(tx, stop)
                        .await
                });
            }
        }

        while let Some(result) = tasks.join_next().await {
            if let Err(error) = result {
                tracing::warn!("collector task failed: {error}");
            }
        }
        Ok(())
    }
}

/// Async entry — selected by `main.rs` on Windows.
pub async fn run(factory: &dyn crate::RegressionSinkFactory) -> Result<()> {
    crate::runner::run(&WindowsCollector, factory).await
}
