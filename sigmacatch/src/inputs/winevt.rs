// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 sigmacatch contributors

//! Winevt multi-channel collector (feature `winevt`).
//!
//! Selected by `main.rs` when running on Windows.

use std::collections::HashMap;

use crate::detection::DetectionEngine;
use crate::runner::CollectorKind;
use crate::types::EventProducer;
use anyhow::Result;

use crate::inputs::channels;

struct WinevtCollector;

impl CollectorKind for WinevtCollector {
    fn name(&self) -> &'static str {
        "sigmacatch"
    }

    fn mode(&self) -> String {
        "winevt multi-channel".to_string()
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

/// Async entry — selected by `main.rs` on Windows.
pub async fn run() -> Result<()> {
    let collector = WinevtCollector;
    crate::runner::run(&collector).await
}
