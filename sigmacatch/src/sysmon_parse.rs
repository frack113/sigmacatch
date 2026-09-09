// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 sigmacatch contributors

//! Parsing of Sysmon-for-Linux syslog lines (RFC3164 tag `sysmon` + winevt
//! XML body) into engine [`Event`]s. Always compiled: every binary may meet
//! this wire format — legacy tail collector AND the synthetic raw lines of
//! the eBPF input alike.

use crate::syslog::{self, Record};
use sigmacatch_types::Event;

/// Parse a single syslog line into a [`Record`] when it carries a Sysmon for
/// Linux event: RFC3164 program tag `sysmon` and an `<Event>` XML body.
pub fn parse_line(line: &[u8]) -> Option<Record> {
    let record = syslog::parse_line(line)?;
    if !is_sysmon_record(&record) {
        return None;
    }
    Some(record)
}

fn is_sysmon_record(record: &Record) -> bool {
    record.program.eq_ignore_ascii_case("sysmon") && record.message.starts_with("<Event>")
}

/// Build the [`Event`] for a Sysmon for Linux syslog line:
/// - `event_json_raw`: nested winevt JSON preserving the original XML content;
/// - `event_json` (detection): nested winevt JSON + logsource `product: linux`
///   with `service`/`category` resolved from `Linux-Sysmon/Operational`;
/// - `event_raw`: the original line bytes (regression `.log` source).
///
/// Returns `None` when the XML body cannot be parsed (truncated by the
/// syslog daemon) — callers must skip the line.
pub fn record_to_event(raw: &[u8], record: &Record) -> Option<Event> {
    let json_raw = sigmacatch_types::parse_winevt_xml_raw(&record.message).ok()?;
    let json = sigmacatch_types::parse_winevt_xml(&record.message).ok()?;
    let mut event = Event::new(json_raw, json, raw.to_vec());
    event.inject_logsource_fields_for("linux", None);
    Some(event)
}
