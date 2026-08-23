// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 sigmacatch contributors

use std::collections::HashMap;

use anyhow::Result;
use sigmacatch_detection::DetectionEngine;
use sigmacatch_runner::{self, CollectorKind};
use sigmacatch_types::EventProducer;

use sigmacatch_win::channels;

struct WinevtCollector;

impl CollectorKind for WinevtCollector {
    fn name(&self) -> &'static str {
        "sigmacatch-channel"
    }

    fn mode(&self) -> &'static str {
        "winevt multi-channel"
    }

    fn channels(
        &self,
        engine: &DetectionEngine,
        custom_map: &HashMap<String, String>,
    ) -> Option<Vec<String>> {
        Some(engine.resolve_channels(custom_map))
    }

    fn build(&self, channels: &[String]) -> Box<dyn EventProducer> {
        Box::new(channels::EventCollector::new(channels.to_vec()))
    }
}

#[cfg(feature = "tools")]
mod cli;

#[tokio::main]
async fn main() -> Result<()> {
    #[cfg(feature = "tools")]
    {
        let code = cli::dispatch();
        if code != 0 {
            std::process::exit(code);
        }
    }
    sigmacatch_runner::run(&WinevtCollector).await
}
