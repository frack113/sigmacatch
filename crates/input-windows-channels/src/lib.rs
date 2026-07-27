// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 sigmacatch contributors

//! Multi-channel Windows Event Log collector that sends events into an mpsc channel.
//!
//! # API
//! - `EventCollector::new(channels)` → creates collector for specified channels
//! - Implements `EventProducer` trait — calls `run(tx)` to collect and send events

mod collector;
pub mod mapping;

pub use collector::EventCollector;
