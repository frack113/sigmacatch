// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 sigmacatch contributors

//! Parse EVTX files into [`Event`] objects for the detection engine.
//!
//! Pattern: producer → mpsc channel → detection engine

mod collector;

pub use collector::{parse_evtx_bytes, parse_evtx_file, EventCollector};
pub use sigmacatch_types::parse_winevt_xml;
