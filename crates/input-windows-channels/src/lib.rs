// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 sigmacatch contributors

//! Multi-channel Windows Event Log collector with internal FIFO.
//!
//! Collects events from all 131 Windows channels into an internal
//! `Arc<Mutex<VecDeque<Event>>>`, exposed via `get_events()` which pops
//! all entries.
//!
//! # API
//! - `start()` → launches collection on all channels
//! - `stop()` → signals shutdown and waits for tasks
//! - `get_events()` → pops all events from FIFO

mod collector;
pub mod mapping;

pub use collector::EventCollector;
