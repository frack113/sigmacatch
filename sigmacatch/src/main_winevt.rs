// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 sigmacatch contributors

use std::collections::HashMap;

use anyhow::Result;
use sigmacatch::runner::{self, CollectorKind};
use sigmacatch_detection::DetectionEngine;
use sigmacatch_types::EventProducer;

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
        Box::new(input_windows_channels::EventCollector::new(
            channels.to_vec(),
        ))
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    runner::run(&WinevtCollector).await
}
