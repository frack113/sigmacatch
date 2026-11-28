// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 sigmacatch contributors

//! EVTX output for matched events.
//!
//! Live events that exist in the Windows Event Log are re-exported with
//! `EvtExportLog`; synthesized events without a record id are encoded by the
//! pure-Rust writer. The latter stays available on every target.

mod evtx;
mod evtx_writer;

pub use evtx::write_evtx;
