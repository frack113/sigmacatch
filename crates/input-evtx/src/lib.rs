// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 sigmacatch contributors

//! Parse EVTX files into [`Event`] objects for the detection engine.
//!
//! Pattern: collector → convert → FIFO (Event)

mod collector;

pub use collector::{parse_evtx_file, EventCollector};
