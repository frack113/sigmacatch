// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 sigmacatch contributors

//! Winevt multi-channel collector (feature `winevt`).
//!
//! Selected by `main.rs` when running on Windows.

pub mod channels;

use std::collections::HashMap;

use anyhow::Result;
use sigmacatch_core::exchange::ChannelResolver;
use sigmacatch_core::types::EventProducer;
use sigmacatch_runner::CollectorKind;

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
        resolver: &dyn ChannelResolver,
        custom_map: &HashMap<String, String>,
    ) -> Option<Vec<String>> {
        Some(resolver.resolve_channels(custom_map))
    }

    fn build(&self, channels: &[String]) -> Box<dyn EventProducer> {
        Box::new(channels::EventCollector::new(channels.to_vec()))
    }
}

/// Async entry — selected by `main.rs` on Windows.
pub async fn run(factory: &dyn sigmacatch_core::RegressionSinkFactory) -> Result<()> {
    let collector = WinevtCollector;
    sigmacatch_runner::run(&collector, factory).await
}
