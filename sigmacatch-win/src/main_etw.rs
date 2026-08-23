// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 sigmacatch contributors

use std::collections::HashMap;

use anyhow::Result;
use sigmacatch_detection::DetectionEngine;
use sigmacatch_runner::{self, CollectorKind};
use sigmacatch_types::EventProducer;

use sigmacatch_win::etw;

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
        Box::new(etw::EventCollector::new())
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    sigmacatch_runner::run(&EtwCollector).await
}
