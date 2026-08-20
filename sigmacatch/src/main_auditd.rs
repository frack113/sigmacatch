// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 sigmacatch contributors

use std::collections::HashMap;

use anyhow::Result;
use sigmacatch::runner::{self, CollectorKind};
use sigmacatch_detection::DetectionEngine;
use sigmacatch_types::EventProducer;

struct AuditdCollector;

impl CollectorKind for AuditdCollector {
    fn name(&self) -> &'static str {
        "sigmacatch-auditd"
    }

    fn mode(&self) -> &'static str {
        "auditd tail"
    }

    fn channels(
        &self,
        _engine: &DetectionEngine,
        _custom_map: &HashMap<String, String>,
    ) -> Option<Vec<String>> {
        None
    }

    fn build(&self, _channels: &[String]) -> Box<dyn EventProducer> {
        Box::new(input_linux_auditd::EventCollector::new())
    }

    fn regression_data_ext(&self) -> &'static str {
        "log"
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    runner::run(&AuditdCollector).await
}
