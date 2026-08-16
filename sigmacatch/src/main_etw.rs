// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 sigmacatch contributors

use std::collections::HashMap;

use anyhow::Result;
use sigmacatch::runner::{self, CollectorKind};
use sigmacatch_detection::DetectionEngine;
use sigmacatch_types::EventProducer;

struct EtwCollector;

impl CollectorKind for EtwCollector {
    fn name(&self) -> &'static str {
        "sigmacatch-etw"
    }

    fn mode(&self) -> &'static str {
        "ETW direct"
    }

    fn channels(
        &self,
        _engine: &DetectionEngine,
        _custom_map: &HashMap<String, String>,
    ) -> Option<Vec<String>> {
        None
    }

    fn build(&self, _channels: &[String]) -> Box<dyn EventProducer> {
        Box::new(input_windows_etw::EventCollector::new())
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    runner::run(&EtwCollector).await
}
