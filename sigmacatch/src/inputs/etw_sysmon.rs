// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 sigmacatch contributors

//! Sysmon-schema rendering of the events the ETW collector observes.
//!
//! The Windows pipeline is built around Winevt XML (`1_win_logsource.yml`,
//! `Event::from_xml_injected`), so the collector renders what it observes as
//! the Sysmon event it corresponds to instead of inventing a second shape.
//! Only fields that can be sourced exactly are written: a missing field is
//! always better than an approximated one for committed regression data.

use crate::inputs::etw_process::ProcessFacts;

/// `sigmacatch` provider id. The events are Sysmon-*schema* (same EventIDs
/// and field names) but are produced by sigmacatch, not Sysmon, so they are
/// published under our own provider and channel. `service` resolution still
/// maps the channel to `sysmon` (see `types.rs`), so the stock Sysmon Sigma
/// rules match unchanged.
const SIGMACATCH_PROVIDER: &str = "{a3e1f6c2-4b5d-4e9f-9c1a-2d7b8e0f3a6c}";
const SIGMACATCH_CHANNEL: &str = "sigmacatch/Operational";

/// Render a Sysmon **EID 1 (ProcessCreate)** event.
///
/// `parent` is the creating process's facts when they are still available (the
/// collector caches them as it sees processes); the parent fields are omitted
/// rather than guessed when it is not.
pub fn process_start_xml(
    computer: &str,
    facts: &ProcessFacts,
    parent: Option<&ProcessFacts>,
) -> String {
    let mut data = String::new();
    field(&mut data, "RuleName", "");
    field(
        &mut data,
        "UtcTime",
        &facts.created.map(sysmon_utc).unwrap_or_default(),
    );
    field(&mut data, "ProcessId", &facts.pid.to_string());
    if let Some(image) = &facts.image {
        field(&mut data, "Image", image);
    }
    if let Some(command_line) = &facts.command_line {
        field(&mut data, "CommandLine", command_line);
    }
    if let Some(user) = &facts.user {
        field(&mut data, "User", user);
    }
    if let Some(integrity) = &facts.integrity {
        field(&mut data, "IntegrityLevel", integrity);
    }
    if let Some(parent) = parent {
        field(&mut data, "ParentProcessId", &parent.pid.to_string());
        if let Some(image) = &parent.image {
            field(&mut data, "ParentImage", image);
        }
        if let Some(command_line) = &parent.command_line {
            field(&mut data, "ParentCommandLine", command_line);
        }
        if let Some(user) = &parent.user {
            field(&mut data, "ParentUser", user);
        }
    } else if facts.parent_pid != 0 {
        field(&mut data, "ParentProcessId", &facts.parent_pid.to_string());
    }

    let time = facts
        .created
        .map(|t| t.to_rfc3339_opts(chrono::SecondsFormat::Nanos, true))
        .unwrap_or_default();
    format!(
        "<Event xmlns=\"http://schemas.microsoft.com/win/2004/08/events/event\">\
         <System>\
         <Provider Name=\"sigmacatch\" Guid=\"{SIGMACATCH_PROVIDER}\"/>\
         <EventID>1</EventID><Version>5</Version><Level>4</Level><Task>1</Task><Opcode>0</Opcode>\
         <Keywords>0x8000000000000000</Keywords>\
         <TimeCreated SystemTime=\"{}\"/>\
         <EventRecordID>0</EventRecordID><Correlation/>\
         <Execution ProcessID=\"{}\" ThreadID=\"0\"/>\
         <Channel>{SIGMACATCH_CHANNEL}</Channel>\
         <Computer>{}</Computer>\
         </System>\
         <EventData>{data}</EventData>\
         </Event>",
        escape(&time),
        facts.pid,
        escape(computer)
    )
}

/// Sysmon's `UtcTime` format: `YYYY-MM-DD HH:MM:SS.mmm`.
///
/// Built by hand: a `chrono` format string round-trips through
/// `DelayedFormat::to_string`, which panics on a formatting error — inside the
/// ETW callback that would cost the whole capture.
fn sysmon_utc(time: chrono::DateTime<chrono::Utc>) -> String {
    format!(
        "{}.{:03}",
        time.format("%Y-%m-%d %H:%M:%S"),
        time.timestamp_subsec_millis()
    )
}

/// Append one `EventData` field, escaping it for XML text content.
fn field(out: &mut String, name: &str, value: &str) {
    out.push_str("<Data Name=\"");
    out.push_str(name);
    out.push_str("\">");
    out.push_str(&escape(value));
    out.push_str("</Data>");
}

fn escape(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for character in value.chars() {
        match character {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&apos;"),
            other => out.push(other),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    fn facts() -> ProcessFacts {
        ProcessFacts {
            pid: 4242,
            parent_pid: 1000,
            image: Some("C:\\Windows\\System32\\cmd.exe".into()),
            command_line: Some(r#"cmd.exe /c "echo a & b < c""#.into()),
            user: Some("MACHINE\\user".into()),
            user_sid: Some("S-1-5-21-1".into()),
            integrity: Some("High".into()),
            created: Some(
                chrono::Utc
                    .with_ymd_and_hms(2026, 11, 14, 9, 2, 12)
                    .unwrap(),
            ),
        }
    }

    #[test]
    fn renders_process_create_fields() {
        let xml = process_start_xml("VM", &facts(), None);
        assert!(xml.contains("<EventID>1</EventID>"));
        assert!(xml.contains(r#"<Data Name="ProcessId">4242</Data>"#));
        assert!(xml.contains(r#"<Data Name="UtcTime">2026-11-14 09:02:12.000</Data>"#));
        assert!(xml.contains(r#"<Data Name="ParentProcessId">1000</Data>"#));
        // No parent facts: no invented parent image.
        assert!(!xml.contains("ParentImage"));
    }

    #[test]
    fn escapes_command_lines() {
        let xml = process_start_xml("VM", &facts(), None);
        assert!(xml.contains("echo a &amp; b &lt; c"));
        assert!(!xml.contains("echo a & b"));
    }

    #[test]
    fn omits_absent_fields() {
        let bare = ProcessFacts {
            pid: 7,
            ..ProcessFacts::default()
        };
        let xml = process_start_xml("VM", &bare, None);
        assert!(!xml.contains("CommandLine"));
        assert!(!xml.contains("Image"));
    }
}
