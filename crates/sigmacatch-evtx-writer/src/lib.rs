// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 sigmacatch contributors

//! Minimal pure-Rust EVTX writer.
//!
//! `EvtExportLog` re-exports a live-log event by record id + channel. ETW
//! collector events have neither, so this crate synthesizes a valid
//! single-record EVTX directly from the Winevt XML (direct BinXML stream, no
//! templates). Round-trip testable on any platform via the `evtx` crate.

use std::collections::{HashMap, HashSet};
use std::path::Path;

use roxmltree::{Document, Node, NodeType};

const FILE_HEADER_SIZE: usize = 4096;
const CHUNK_SIZE: usize = 64 * 1024;
const CHUNK_HEADER_SIZE: usize = 512;
const RECORD_HEADER_SIZE: usize = 24;
const RECORD_START: usize = CHUNK_HEADER_SIZE;

/// `HeaderSize` field value used by Windows-produced files (evtx 0.12.2
/// fixture `security.evtx` reads 128).
const CHUNK_HEADER_FIELD_SIZE: u32 = 128;

/// Write a single-record EVTX file containing the given Winevt XML.
///
/// The record header timestamp is derived from the event's `TimeCreated`
/// element (current time when absent or malformed).
/// Errors produced while writing EVTX files.
#[derive(Debug, thiserror::Error)]
pub enum WriterError {
    /// Filesystem failure.
    #[error("filesystem error: {0}")]
    Io(#[from] std::io::Error),
    /// Input XML or parameters violate the EVTX writer contract.
    #[error("{0}")]
    Invalid(String),
}

/// Crate-local result alias over [`WriterError`].
pub type Result<T> = std::result::Result<T, WriterError>;

/// Write a single-record EVTX file from event XML, using the timestamp
/// embedded in the XML (fallback: current time).
pub fn write_evtx_from_xml(xml: &str, record_id: u64, path: &Path) -> Result<()> {
    let filetime = filetime_from_event_xml(xml).unwrap_or_else(|_| now_filetime());
    write_evtx_from_xml_with_time(xml, record_id, filetime, path)
}

/// Write a single-record EVTX file with an explicit record header timestamp
/// (100ns ticks since 1601-01-01).
pub fn write_evtx_from_xml_with_time(
    xml: &str,
    record_id: u64,
    filetime: u64,
    path: &Path,
) -> Result<()> {
    if record_id == 0 || record_id == u64::MAX {
        return Err(WriterError::Invalid(format!(
            "record_id must be in 1..=u64::MAX-1, got {record_id}"
        )));
    }
    let chunk = build_chunk(record_id, filetime, xml)?;
    let file = build_file_header(record_id);

    let mut out = Vec::with_capacity(FILE_HEADER_SIZE + CHUNK_SIZE);
    out.extend_from_slice(&file);
    out.extend_from_slice(&chunk);

    std::fs::write(path, out)
        .map_err(|e| WriterError::Invalid(format!("Failed to write EVTX {}: {e}", path.display())))
}

/// Extract a FILETIME (100ns ticks since 1601) from the event's
/// `TimeCreated SystemTime`; falls back to the current time when absent or
/// malformed so the record header always carries a parseable timestamp.
pub fn filetime_from_event_xml(xml: &str) -> Result<u64> {
    let doc = Document::parse(xml)
        .map_err(|e| WriterError::Invalid(format!("Failed to parse Winevt XML: {e}")))?;
    for node in doc.descendants() {
        if node.tag_name().name() == "TimeCreated"
            && let Some(system_time) = node.attribute("SystemTime")
        {
            return system_time_to_filetime(system_time);
        }
    }
    Err(WriterError::Invalid(
        "no TimeCreated element in Winevt XML".to_string(),
    ))
}

/// Parse `YYYY-MM-DDTHH:MM:SS[.fraction][Z|±HH:MM]` into a FILETIME.
fn system_time_to_filetime(system_time: &str) -> Result<u64> {
    let bytes = system_time.as_bytes();
    if bytes.len() < 19 {
        return Err(WriterError::Invalid(format!(
            "malformed SystemTime: {system_time}"
        )));
    }
    let read_u16 = |i: usize| -> Result<u16> {
        let hi = (bytes[i] as char)
            .to_digit(10)
            .and_then(|d| u16::try_from(d).ok());
        let lo = (bytes[i + 1] as char)
            .to_digit(10)
            .and_then(|d| u16::try_from(d).ok());
        match (hi, lo) {
            (Some(hi), Some(lo)) => Ok(hi * 10 + lo),
            _ => Err(WriterError::Invalid(format!(
                "malformed SystemTime: {system_time}"
            ))),
        }
    };
    let year = (u32::from(read_u16(0)?) * 100 + u32::from(read_u16(2)?)) as i64;
    let month = u32::from(read_u16(5)?);
    let day = u32::from(read_u16(8)?);
    let hour = u32::from(read_u16(11)?);
    let minute = u32::from(read_u16(14)?);
    let second = u32::from(read_u16(17)?);
    if !(1..=12).contains(&month) || hour > 23 || minute > 59 || second > 60 {
        return Err(WriterError::Invalid(format!(
            "malformed SystemTime: {system_time}"
        )));
    }
    let max_day = match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 => {
            if year % 4 == 0 && (year % 100 != 0 || year % 400 == 0) {
                29
            } else {
                28
            }
        }
        _ => unreachable!(),
    };
    if day == 0 || day > max_day {
        return Err(WriterError::Invalid(format!(
            "malformed SystemTime: {system_time}"
        )));
    }

    let mut fraction_ns: u32 = 0;
    let mut frac_digits: u32 = 0;
    if bytes.len() > 19 && bytes[19] == b'.' {
        for &b in bytes[20..].iter().take(9) {
            if !b.is_ascii_digit() {
                break;
            }
            fraction_ns = fraction_ns * 10 + u32::from(b - b'0');
            frac_digits += 1;
        }
        if frac_digits < 9 {
            fraction_ns *= 10u32.pow(9 - frac_digits);
        }
    }

    let mut offset_secs: i64 = 0;
    let tz_start = bytes.iter().position(|&b| b == b'T').unwrap_or(bytes.len());
    for (i, &b) in bytes[tz_start..].iter().enumerate() {
        let i = i + tz_start;
        if b == b'Z' || b == b'z' {
            break;
        }
        if b == b'+' || b == b'-' {
            if bytes.len() < i + 6 || bytes[i + 3] != b':' {
                return Err(WriterError::Invalid(format!(
                    "malformed SystemTime timezone: {system_time}"
                )));
            }
            let off_h = read_u16(i + 1)? as i64;
            let off_m = read_u16(i + 4)? as i64;
            if off_h > 23 || off_m > 59 {
                return Err(WriterError::Invalid(format!(
                    "malformed SystemTime timezone: {system_time}"
                )));
            }
            offset_secs = off_h * 3600 + off_m * 60;
            if b == b'-' {
                offset_secs = -offset_secs;
            }
            break;
        }
    }

    // Days since 1970-01-01 (Howard Hinnant's algorithm), then UNIX seconds,
    // then FILETIME epoch offset + 100ns ticks.
    let year = year - if month <= 2 { 1 } else { 0 };
    let era = year.div_euclid(400);
    let yoe = year - era * 400;
    let mp = month as i64 + if month > 2 { -3 } else { 9 };
    let doy = (153 * mp + 2) / 5 + day as i64 - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146097 + doe - 719468;

    let unix_secs = days * 86400 + hour as i64 * 3600 + minute as i64 * 60 + second as i64;
    let unix_ns = unix_secs as i128 * 1_000_000_000 + i128::from(fraction_ns)
        - offset_secs as i128 * 1_000_000_000;
    const UNIX_TO_FILETIME_NS: i128 = 116_444_736_000_000_000;
    let filetime = (unix_ns + UNIX_TO_FILETIME_NS).div_euclid(100);
    if filetime < 0 {
        return Err(WriterError::Invalid(format!(
            "SystemTime before 1601: {system_time}"
        )));
    }
    Ok(filetime as u64)
}

fn now_filetime() -> u64 {
    use chrono::Utc;
    let now = Utc::now();
    let unix_ns =
        i128::from(now.timestamp()) * 1_000_000_000 + i128::from(now.timestamp_subsec_nanos());
    const UNIX_TO_FILETIME_NS: i128 = 116_444_736_000_000_000;
    ((unix_ns + UNIX_TO_FILETIME_NS).div_euclid(100)) as u64
}

fn build_file_header(record_id: u64) -> [u8; FILE_HEADER_SIZE] {
    let mut header = [0u8; FILE_HEADER_SIZE];
    header[..8].copy_from_slice(b"ElfFile\x00");
    put_u64(&mut header, 24, record_id + 1);
    put_u32(&mut header, 32, 128);
    put_u16(&mut header, 36, 1);
    put_u16(&mut header, 38, 3);
    put_u16(&mut header, 40, 4096);
    put_u16(&mut header, 42, 1);
    let checksum = crc32fast::hash(&header[..120]);
    put_u32(&mut header, 124, checksum);
    header
}

fn build_chunk(record_id: u64, filetime: u64, xml: &str) -> Result<[u8; CHUNK_SIZE]> {
    let doc = Document::parse(xml)
        .map_err(|e| WriterError::Invalid(format!("Failed to parse Winevt XML: {e}")))?;
    let root = doc.root_element();
    if root.tag_name().name() != "Event" {
        return Err(WriterError::Invalid(format!(
            "expected <Event> root element, got <{}>",
            root.tag_name().name()
        )));
    }

    let mut encoder = Encoder::default();
    encoder.out.extend_from_slice(&[0x0f, 0x01, 0x01, 0x00]);
    encoder.encode_element(root)?;

    let binxml = &encoder.out;
    let record_size = align8(RECORD_HEADER_SIZE + 4 + binxml.len());
    let free_space_offset = RECORD_START + record_size;
    if free_space_offset > CHUNK_SIZE {
        return Err(WriterError::Invalid(format!(
            "EVTX record too large ({} bytes) for a {CHUNK_SIZE}-byte chunk",
            record_size
        )));
    }
    let string_table_offset = free_space_offset;

    let mut chunk = [0u8; CHUNK_SIZE];
    chunk[..8].copy_from_slice(b"ElfChnk\x00");
    put_u64(&mut chunk, 8, record_id);
    put_u64(&mut chunk, 16, record_id);
    put_u64(&mut chunk, 24, record_id);
    put_u64(&mut chunk, 32, record_id);
    put_u32(&mut chunk, 40, CHUNK_HEADER_FIELD_SIZE);
    put_u32(&mut chunk, 44, (RECORD_START + RECORD_HEADER_SIZE) as u32);
    put_u32(&mut chunk, 48, free_space_offset as u32);
    put_u32(&mut chunk, 52, 0);

    let record = &mut chunk[RECORD_START..free_space_offset];
    record[..4].copy_from_slice(b"\x2a\x2a\x00\x00");
    put_u32(record, 4, record_size as u32);
    put_u64(record, 8, record_id);
    put_u64(record, 16, filetime);
    record[RECORD_HEADER_SIZE..RECORD_HEADER_SIZE + binxml.len()].copy_from_slice(binxml);

    let names = build_string_table(&mut chunk, string_table_offset, &encoder.names)?;
    for (pos, name) in &encoder.refs {
        let offset = names
            .get(name)
            .ok_or_else(|| WriterError::Invalid(format!("missing string table entry {name}")))?;
        let abs = RECORD_START + RECORD_HEADER_SIZE + pos;
        put_u32(&mut chunk[..], abs, (string_table_offset + *offset) as u32);
    }

    let events_checksum = crc32fast::hash(&chunk[CHUNK_HEADER_SIZE..free_space_offset]);
    put_u32(&mut chunk, 52, events_checksum);
    let mut header_crc = crc32fast::Hasher::new();
    header_crc.update(&chunk[..120]);
    header_crc.update(&chunk[128..CHUNK_HEADER_SIZE]);
    put_u32(&mut chunk, 124, header_crc.finalize());

    Ok(chunk)
}

fn align8(n: usize) -> usize {
    (n + 7) & !7
}

/// Write the string table entries and return the name → relative-offset map.
///
/// All entries are placed in a single linked list starting at `offset`
/// (free-space area). The list head is written into bucket 0 of the
/// chunk-header hash table so the evtx crate's `StringCache` can find it.
fn build_string_table(
    chunk: &mut [u8; CHUNK_SIZE],
    offset: usize,
    names: &[String],
) -> Result<HashMap<String, usize>> {
    let mut map = HashMap::with_capacity(names.len());
    let mut cursor = offset;
    let mut entries = Vec::with_capacity(names.len());
    for name in names {
        if cursor + 10 + name.encode_utf16().count() * 2 > CHUNK_SIZE {
            return Err(WriterError::Invalid(
                "EVTX string table overflow".to_string(),
            ));
        }
        entries.push((cursor, name));
        map.insert(name.clone(), cursor - offset);
        cursor += 10 + name.encode_utf16().count() * 2;
    }
    for (i, (entry_offset, name)) in entries.iter().enumerate() {
        let next = entries.get(i + 1).map_or(0, |(o, _)| *o);
        write_string_entry(chunk, *entry_offset, name, next as u32);
    }
    // Initialize the 64-bucket string hash table in the chunk header.
    // Bucket 0 points to our linked list; the rest are zero.
    let bucket0_head = offset as u32;
    put_u32(chunk, 128, bucket0_head);
    for i in 1..64 {
        put_u32(chunk, 128 + i * 4, 0);
    }
    Ok(map)
}

fn write_string_entry(chunk: &mut [u8; CHUNK_SIZE], offset: usize, name: &str, next: u32) {
    let utf16: Vec<u16> = name.encode_utf16().collect();
    let mut entry = Vec::with_capacity(10 + utf16.len() * 2);
    entry.extend_from_slice(&next.to_le_bytes());
    entry.extend_from_slice(&hash16(&utf16).to_le_bytes());
    entry.extend_from_slice(&(utf16.len() as u16).to_le_bytes());
    for unit in &utf16 {
        entry.extend_from_slice(&unit.to_le_bytes());
    }
    entry.extend_from_slice(&0u16.to_le_bytes());
    chunk[offset..offset + entry.len()].copy_from_slice(&entry);
}

/// MS-EVEN6 §2.2.1.2 string name hash.
fn hash16(utf16: &[u16]) -> u16 {
    let mut hash: u32 = 0;
    for &unit in utf16 {
        hash = hash.wrapping_mul(65599).wrapping_add(u32::from(unit));
    }
    (hash & 0xFFFF) as u16
}

/// BinXML encoder for direct (non-template) record streams.
///
/// Token layout (MS-EVEN6 §2.2.3.1): fragment header `0f 01 01 00`, then for
/// each element `0x01`/`0x41` (open start, sizes ignored by the parser), the
/// name ref, `0x06`+value per attribute, `0x02` (close start) / `0x03`
/// (close empty), children, `0x04` (close element), and a final `0x00` EOF.
#[derive(Default)]
struct Encoder {
    out: Vec<u8>,
    names: Vec<String>,
    seen: HashSet<String>,
    refs: Vec<(usize, String)>,
}

impl Encoder {
    fn encode_element(&mut self, node: Node) -> Result<()> {
        let attrs: Vec<_> = node
            .attributes()
            .filter(|a| a.name() != "xmlns" && !a.name().starts_with("xmlns:"))
            .collect();
        let has_children = node.has_children();

        if attrs.is_empty() {
            self.out.push(0x01);
            self.out.extend_from_slice(&0u32.to_le_bytes());
        } else {
            self.out.push(0x41);
            self.out.extend_from_slice(&0u32.to_le_bytes());
        }
        self.emit_name(node.tag_name().name());
        if !attrs.is_empty() {
            self.out.extend_from_slice(&0u32.to_le_bytes());
        }

        for attr in &attrs {
            self.out.push(0x06);
            self.emit_name(attr.name());
            self.emit_value(attr.value());
        }

        if has_children {
            self.out.push(0x02);
            for child in node.children() {
                match child.node_type() {
                    NodeType::Element => self.encode_element(child)?,
                    NodeType::Text => {
                        let text = child.text().unwrap_or("");
                        if !text.trim().is_empty() {
                            self.emit_value(text);
                        }
                    }
                    other => {
                        return Err(WriterError::Invalid(format!(
                            "unsupported XML node type {other:?} in event XML"
                        )));
                    }
                }
            }
            self.out.push(0x04);
        } else {
            self.out.push(0x03);
        }
        Ok(())
    }

    fn emit_name(&mut self, name: &str) {
        if self.seen.insert(name.to_string()) {
            self.names.push(name.to_string());
        }
        self.refs.push((self.out.len(), name.to_string()));
        self.out.extend_from_slice(&0u32.to_le_bytes());
    }

    fn emit_value(&mut self, value: &str) {
        self.out.push(0x05);
        self.out.push(0x01);
        let utf16: Vec<u16> = value.encode_utf16().collect();
        self.out
            .extend_from_slice(&(utf16.len() as u16).to_le_bytes());
        for unit in &utf16 {
            self.out.extend_from_slice(&unit.to_le_bytes());
        }
    }
}

fn put_u16(buf: &mut [u8], offset: usize, value: u16) {
    buf[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}

fn put_u32(buf: &mut [u8], offset: usize, value: u32) {
    buf[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

fn put_u64(buf: &mut [u8], offset: usize, value: u64) {
    buf[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE_XML: &str = r#"<?xml version="1.0" encoding="utf-8" standalone="yes"?>
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-TaskScheduler" Guid="{de7b24ea-73c8-4a09-985d-5bdadcfa9017}"/>
    <EventID>106</EventID>
    <Version>0</Version>
    <Level>4</Level>
    <Task>106</Task>
    <Opcode>0</Opcode>
    <Keywords>0x8020000000000000</Keywords>
    <TimeCreated SystemTime="2026-01-15T10:30:45.1234567Z"/>
    <EventRecordID>1</EventRecordID>
    <Correlation/>
    <Execution ProcessID="1234" ThreadID="5678"/>
    <Channel>Microsoft-Windows-TaskScheduler/Operational</Channel>
    <Computer>WIN-TEST</Computer>
    <Security UserID="S-1-5-18"/>
  </System>
  <EventData>
    <Data Name="TaskName">\MyTask &amp; More</Data>
    <Data Name="TaskInstanceId">abc-123</Data>
  </EventData>
</Event>"#;

    #[test]
    fn filetime_parses_time_created() {
        let ft = filetime_from_event_xml(SAMPLE_XML).unwrap();
        let expected = expected_filetime(2026, 1, 15, 10, 30, 45, 123_456_700);
        assert_eq!(ft, expected);
    }

    #[test]
    fn filetime_parses_timezone_offset() {
        let ft = system_time_to_filetime("2026-01-15T12:30:45.0000000+02:00").unwrap();
        assert_eq!(
            ft,
            system_time_to_filetime("2026-01-15T10:30:45.0000000Z").unwrap()
        );
    }

    fn expected_filetime(y: i32, mo: u32, d: u32, h: u32, mi: u32, s: u32, ns: u64) -> u64 {
        let unix = chrono::TimeZone::with_ymd_and_hms(&chrono::Utc, y, mo, d, h, mi, s)
            .unwrap()
            .timestamp_nanos_opt()
            .unwrap() as i128;
        const UNIX_TO_FILETIME_NS: i128 = 116_444_736_000_000_000;
        ((unix + i128::from(ns) + UNIX_TO_FILETIME_NS).div_euclid(100)) as u64
    }

    #[test]
    fn hash16_is_stable() {
        let utf16: Vec<u16> = "Event".encode_utf16().collect();
        let mut hash: u32 = 0;
        for unit in &utf16 {
            hash = hash.wrapping_mul(65599).wrapping_add(u32::from(*unit));
        }
        assert_eq!(hash16(&utf16), (hash & 0xFFFF) as u16);
    }

    #[test]
    fn roundtrip_writer_to_parser() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("event.evtx");
        write_evtx_from_xml(SAMPLE_XML, 1, &path).unwrap();

        let mut parser = evtx::EvtxParser::from_path(&path).unwrap();
        let mut records = parser.records();
        let record = records.next().unwrap().unwrap();
        assert!(records.next().is_none());

        let xml = std::str::from_utf8(record.data.as_bytes()).unwrap();
        assert!(xml.contains("<Event>"));
        assert!(xml.contains("<EventID>106</EventID>"));
        assert!(xml.contains(r#"<Provider Name="Microsoft-Windows-TaskScheduler""#));
        assert!(xml.contains("<Data Name=\"TaskName\">\\MyTask &amp; More</Data>"));
        assert!(xml.contains("<Data Name=\"TaskInstanceId\">abc-123</Data>"));
        assert!(xml.contains(r#"<TimeCreated SystemTime="2026-01-15T10:30:45.1234567Z">"#));
    }

    #[test]
    fn roundtrip_parses_into_sigmacatch_event() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("event.evtx");
        write_evtx_from_xml(SAMPLE_XML, 1, &path).unwrap();

        let events = input_windows_evtx::parse_evtx_file(&path).unwrap();
        assert_eq!(events.len(), 1);
        let event = &events[0];
        assert_eq!(event.event_json["Event"]["System"]["EventID"], 106);
        assert_eq!(
            event.event_json["Event"]["EventData"]["TaskName"],
            r"\MyTask & More"
        );
        assert_eq!(
            event.event_json_raw["Event"]["EventData"]["TaskName"],
            r"\MyTask & More"
        );
    }

    #[test]
    fn record_binxml_starts_with_fragment_header() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("event.evtx");
        write_evtx_from_xml(SAMPLE_XML, 1, &path).unwrap();
        let data = std::fs::read(&path).unwrap();
        let binxml_start = FILE_HEADER_SIZE + RECORD_START + RECORD_HEADER_SIZE;
        assert_eq!(
            &data[binxml_start..binxml_start + 4],
            &[0x0f, 0x01, 0x01, 0x00]
        );
    }

    #[test]
    fn oversized_xml_bails_instead_of_panicking() {
        let huge_value = "x".repeat(40_000);
        let xml = format!(
            r#"<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><EventData><Data Name="Blob">{huge_value}</Data></EventData></Event>"#
        );
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("event.evtx");
        assert!(write_evtx_from_xml(&xml, 1, &path).is_err());
    }

    #[test]
    fn invalid_dates_and_timestamps_bail() {
        assert!(system_time_to_filetime("2026-02-31T00:00:00Z").is_err());
        assert!(system_time_to_filetime("2026-02-29T00:00:00Z").is_err());
        assert!(system_time_to_filetime("2024-02-30T00:00:00Z").is_err());
        assert!(system_time_to_filetime("2026-01-01T12:00:00+99:99").is_err());
        assert!(system_time_to_filetime("0001-01-01T00:00:00Z").is_err());
        assert!(system_time_to_filetime("202A-01-01T00:00:00Z").is_err());
        assert!(system_time_to_filetime("2026-13-01T00:00:00Z").is_err());
        assert!(system_time_to_filetime("2026-01-01T25:00:00Z").is_err());
    }

    #[test]
    fn leap_years_are_accepted() {
        assert!(system_time_to_filetime("2024-02-29T00:00:00Z").is_ok());
        assert!(system_time_to_filetime("2000-02-29T00:00:00Z").is_ok());
        assert!(system_time_to_filetime("1900-02-29T00:00:00Z").is_err());
    }

    #[test]
    fn zero_or_max_record_id_bails() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("event.evtx");
        assert!(write_evtx_from_xml(SAMPLE_XML, 0, &path).is_err());
        assert!(write_evtx_from_xml(SAMPLE_XML, u64::MAX, &path).is_err());
    }
}
