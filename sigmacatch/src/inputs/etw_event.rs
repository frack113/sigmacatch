// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 sigmacatch contributors

//! TDH decoding of a raw ETW record into named, typed properties.
//!
//! This is the Windows analogue of [`super::ebpf_event`]: the collector gets
//! opaque buffers from the kernel and this module turns them into the field
//! values the Sysmon-schema mapping (M2) consumes. It deliberately knows
//! nothing about Sigma or Sysmon — it only reports what the provider said.
//!
//! Everything here runs inside the ETW consumer callback, so it must not
//! block: the only allocations are the TDH information buffer and the value
//! buffers, and every failure is reported as `None` rather than a panic.

use std::net::{Ipv4Addr, Ipv6Addr};

use chrono::{DateTime, Utc};
use windows::Win32::Foundation::ERROR_SUCCESS;
use windows::Win32::System::Diagnostics::Etw::{
    EVENT_PROPERTY_INFO, EVENT_RECORD, PROPERTY_DATA_DESCRIPTOR, TDH_INTYPE_ANSISTRING,
    TDH_INTYPE_BINARY, TDH_INTYPE_BOOLEAN, TDH_INTYPE_DOUBLE, TDH_INTYPE_FILETIME,
    TDH_INTYPE_FLOAT, TDH_INTYPE_GUID, TDH_INTYPE_HEXINT32, TDH_INTYPE_HEXINT64, TDH_INTYPE_INT8,
    TDH_INTYPE_INT16, TDH_INTYPE_INT32, TDH_INTYPE_INT64, TDH_INTYPE_POINTER, TDH_INTYPE_SID,
    TDH_INTYPE_SYSTEMTIME, TDH_INTYPE_UINT8, TDH_INTYPE_UINT16, TDH_INTYPE_UINT32,
    TDH_INTYPE_UINT64, TDH_INTYPE_UNICODESTRING, TDH_OUTTYPE_IPV4, TDH_OUTTYPE_IPV6,
    TDH_OUTTYPE_PORT, TRACE_EVENT_INFO, TdhGetEventInformation, TdhGetProperty, TdhGetPropertySize,
};

/// FILETIME ticks (100 ns) between 1601-01-01 and 1970-01-01.
const FILETIME_UNIX_EPOCH: i64 = 116_444_736_000_000_000;

/// One fully decoded ETW record.
#[derive(Debug, Clone)]
pub struct DecodedEvent {
    /// Provider name from the manifest, e.g. `Microsoft-Windows-Kernel-Process`.
    pub provider: String,
    /// Event name from the manifest (`ProcessStart`), or the numeric id when
    /// the provider has no manifest.
    pub event_name: String,
    /// Numeric event id from the `EVENT_DESCRIPTOR`.
    pub event_id: u16,
    /// Numeric opcode.
    pub opcode: u8,
    /// Numeric level.
    pub level: u8,
    /// Keyword mask the provider published the event under.
    pub keywords: u64,
    /// Emitting process id (the kernel's notion, not a payload field).
    pub process_id: u32,
    /// Emitting thread id.
    pub thread_id: u32,
    /// Event timestamp as FILETIME ticks (100 ns since 1601).
    pub timestamp: i64,
    /// Payload fields in manifest order.
    pub properties: Vec<Property>,
}

impl DecodedEvent {
    /// First property with this exact name.
    pub fn get(&self, name: &str) -> Option<&Property> {
        self.properties.iter().find(|p| p.name == name)
    }

    /// String value of the named property.
    pub fn str(&self, name: &str) -> Option<&str> {
        match self.get(name).map(|p| &p.value) {
            Some(PropertyValue::Str(s)) => Some(s.as_str()),
            _ => None,
        }
    }

    /// Numeric value of the named property.
    pub fn uint(&self, name: &str) -> Option<u64> {
        match self.get(name).map(|p| &p.value) {
            Some(PropertyValue::UInt(v) | PropertyValue::Hex(v)) => Some(*v),
            _ => None,
        }
    }

    /// Timestamp as UTC.
    pub fn utc(&self) -> Option<DateTime<Utc>> {
        filetime_to_utc(self.timestamp)
    }
}

/// A single payload field.
#[derive(Debug, Clone)]
pub struct Property {
    /// Declared name, or `#<index>` when the manifest omits one.
    pub name: String,
    /// Decoded value.
    pub value: PropertyValue,
}

/// Decoded value of a TDH property.
///
/// Strings stay strings (that is what Sysmon-schema fields carry), integers
/// keep their signedness, and the Sysmon-relevant special cases (SID, GUID,
/// FILETIME, network address) are decoded here rather than at the mapping
/// layer.
#[derive(Debug, Clone)]
pub enum PropertyValue {
    /// UTF-16 or ANSI string. Arrays of strings are joined with `;`.
    Str(String),
    /// Signed integer (INT8/16/32/64, FLOAT/DOUBLE rounded).
    Int(i64),
    /// Unsigned integer (UINT8/16/32/64, PORT, POINTER).
    UInt(u64),
    /// Integer formatted as hexadecimal (HEXINT32/HEXINT64).
    Hex(u64),
    /// BOOLEAN.
    Bool(bool),
    /// GUID rendered canonically.
    Guid(String),
    /// SID rendered as `S-1-...`.
    Sid(String),
    /// FILETIME rendered as RFC 3339 UTC.
    FileTime(String),
    /// IPv4/IPv6 rendered in their canonical textual form.
    Ip(String),
    /// Opaque bytes, hex-encoded.
    Bin(String),
}

impl PropertyValue {
    /// Lossless-ish textual rendering, for logging and diagnostics.
    pub fn to_text(&self) -> String {
        match self {
            Self::Str(s) => s.clone(),
            Self::Int(v) => v.to_string(),
            Self::UInt(v) | Self::Hex(v) => v.to_string(),
            Self::Bool(b) => b.to_string(),
            Self::Guid(s) | Self::Sid(s) | Self::FileTime(s) | Self::Ip(s) | Self::Bin(s) => {
                s.clone()
            }
        }
    }
}

/// Decode one record, or `None` when TDH cannot describe it.
///
/// Failure is expected for providers without a manifest (the classic
/// `NT Kernel Logger` MOF classes decode through a different path and are not
/// handled here yet); callers count those instead of aborting the session.
pub fn decode(record: &EVENT_RECORD) -> Option<DecodedEvent> {
    // SAFETY: `record` is valid for the duration of the callback, which is the
    // contract TDH documents for `TdhGetEventInformation`.
    unsafe { decode_inner(record) }
}

unsafe fn decode_inner(record: &EVENT_RECORD) -> Option<DecodedEvent> {
    // SAFETY: every pointer below points into `info_bytes`, which is owned by
    // this function and outlives all uses.
    unsafe {
        let info_bytes = event_info(record)?;
        let base = info_bytes.as_ptr().cast::<u8>();
        let info = base.cast::<TRACE_EVENT_INFO>();

        let descriptor = &record.EventHeader.EventDescriptor;
        let provider = wide_at(base, (*info).ProviderNameOffset).unwrap_or_default();
        let event_name = wide_at(base, (*info).Anonymous1.EventNameOffset)
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| descriptor.Id.to_string());

        let mut properties = Vec::with_capacity((*info).PropertyCount as usize);
        let array =
            std::ptr::addr_of!((*info).EventPropertyInfoArray).cast::<EVENT_PROPERTY_INFO>();
        for index in 0..(*info).PropertyCount as usize {
            let prop = &*array.add(index);
            let name = wide_at(base, prop.NameOffset)
                .filter(|s| !s.is_empty())
                .unwrap_or_else(|| format!("#{index}"));
            let in_type = prop.Anonymous1.nonStructType.InType;
            let out_type = prop.Anonymous1.nonStructType.OutType;
            let Some(value) = read_value(record, base, prop, in_type, out_type) else {
                continue;
            };
            properties.push(Property { name, value });
        }

        Some(DecodedEvent {
            provider,
            event_name,
            event_id: descriptor.Id,
            opcode: descriptor.Opcode,
            level: descriptor.Level,
            keywords: descriptor.Keyword,
            process_id: record.EventHeader.ProcessId,
            thread_id: record.EventHeader.ThreadId,
            timestamp: record.EventHeader.TimeStamp,
            properties,
        })
    }
}

/// Copy the `TRACE_EVENT_INFO` blob for this record into an owned, aligned
/// buffer. TDH requires one sizing call, then one filling call.
unsafe fn event_info(record: &EVENT_RECORD) -> Option<Vec<u64>> {
    let mut size = 0u32;
    // SAFETY: null buffer + size-only call is the documented sizing probe.
    let status = unsafe { TdhGetEventInformation(record, None, None, &mut size) };
    if status != 122 || size == 0 {
        // 122 = ERROR_INSUFFICIENT_BUFFER. Anything else means no metadata.
        return None;
    }
    let words = (size as usize).div_ceil(std::mem::size_of::<u64>());
    let mut buffer: Vec<u64> = vec![0; words];
    let status = unsafe {
        TdhGetEventInformation(
            record,
            None,
            Some(buffer.as_mut_ptr().cast::<TRACE_EVENT_INFO>()),
            &mut size,
        )
    };
    if status != ERROR_SUCCESS.0 {
        return None;
    }
    Some(buffer)
}

/// Read one property value, formatting it according to its TDH input type and
/// the manifest's output type (which is what distinguishes an IPv4 address
/// stored as `UINT32` from a plain integer).
unsafe fn read_value(
    record: &EVENT_RECORD,
    info_base: *const u8,
    prop: &EVENT_PROPERTY_INFO,
    in_type: u16,
    out_type: u16,
) -> Option<PropertyValue> {
    let name_ptr = if prop.NameOffset == 0 {
        return None;
    } else {
        // SAFETY: `NameOffset` is relative to the information blob.
        unsafe { info_base.add(prop.NameOffset as usize) }.cast::<u16>()
    };
    let descriptor = PROPERTY_DATA_DESCRIPTOR {
        PropertyName: name_ptr as u64,
        ArrayIndex: 0,
        Reserved: 0,
    };

    let mut size = 0u32;
    // SAFETY: descriptor points into the live information blob.
    let status = unsafe { TdhGetPropertySize(record, None, &[descriptor], &mut size) };
    if status != ERROR_SUCCESS.0 || size == 0 {
        return None;
    }
    let mut value = vec![0u8; size as usize];
    let status =
        // SAFETY: buffer is exactly the size TDH just reported.
        unsafe { TdhGetProperty(record, None, &[descriptor], &mut value) };
    if status != ERROR_SUCCESS.0 {
        return None;
    }

    Some(format_value(&value, in_type, out_type))
}

fn format_value(bytes: &[u8], in_type: u16, out_type: u16) -> PropertyValue {
    match in_type {
        t if t == TDH_INTYPE_UNICODESTRING.0 as u16 => PropertyValue::Str(join_wide(bytes)),
        t if t == TDH_INTYPE_ANSISTRING.0 as u16 => {
            let text: Vec<&[u8]> = bytes.split(|b| *b == 0).filter(|s| !s.is_empty()).collect();
            PropertyValue::Str(
                text.iter()
                    .map(|s| String::from_utf8_lossy(s).into_owned())
                    .collect::<Vec<_>>()
                    .join(";"),
            )
        }
        t if t == TDH_INTYPE_INT8.0 as u16 => PropertyValue::Int(i64::from(bytes[0] as i8)),
        t if t == TDH_INTYPE_UINT8.0 as u16 => PropertyValue::UInt(u64::from(bytes[0])),
        t if t == TDH_INTYPE_INT16.0 as u16 => {
            PropertyValue::Int(i64::from(i16::from_le_bytes(pair(bytes))))
        }
        t if t == TDH_INTYPE_UINT16.0 as u16 => {
            let raw = u16::from_le_bytes(pair(bytes));
            if out_type == TDH_OUTTYPE_PORT.0 as u16 {
                PropertyValue::UInt(u64::from(u16::from_be(raw)))
            } else {
                PropertyValue::UInt(u64::from(raw))
            }
        }
        t if t == TDH_INTYPE_INT32.0 as u16 => {
            PropertyValue::Int(i64::from(i32::from_le_bytes(quad(bytes))))
        }
        t if t == TDH_INTYPE_UINT32.0 as u16 => {
            let raw = u32::from_le_bytes(quad(bytes));
            if out_type == TDH_OUTTYPE_IPV4.0 as u16 {
                PropertyValue::Ip(Ipv4Addr::from(raw).to_string())
            } else {
                PropertyValue::UInt(u64::from(raw))
            }
        }
        t if t == TDH_INTYPE_INT64.0 as u16 => PropertyValue::Int(i64::from_le_bytes(octet(bytes))),
        t if t == TDH_INTYPE_UINT64.0 as u16 => {
            PropertyValue::UInt(u64::from_le_bytes(octet(bytes)))
        }
        t if t == TDH_INTYPE_FLOAT.0 as u16 => {
            PropertyValue::Int(i64::from(f32::from_le_bytes(quad(bytes)) as i32))
        }
        t if t == TDH_INTYPE_DOUBLE.0 as u16 => {
            PropertyValue::Int(f64::from_le_bytes(octet(bytes)) as i64)
        }
        t if t == TDH_INTYPE_BOOLEAN.0 as u16 => PropertyValue::Bool(bytes[0] != 0),
        t if t == TDH_INTYPE_HEXINT32.0 as u16 => {
            PropertyValue::Hex(u64::from(u32::from_le_bytes(quad(bytes))))
        }
        t if t == TDH_INTYPE_HEXINT64.0 as u16 => {
            PropertyValue::Hex(u64::from_le_bytes(octet(bytes)))
        }
        t if t == TDH_INTYPE_POINTER.0 as u16 => {
            PropertyValue::Hex(u64::from_le_bytes(octet(bytes)))
        }
        t if t == TDH_INTYPE_GUID.0 as u16 => PropertyValue::Guid(guid(bytes)),
        t if t == TDH_INTYPE_SID.0 as u16 => match sid(bytes) {
            Some(s) => PropertyValue::Sid(s),
            None => PropertyValue::Bin(hex(bytes)),
        },
        t if t == TDH_INTYPE_FILETIME.0 as u16 => {
            let ticks = i64::from_le_bytes(octet(bytes));
            match filetime_to_utc(ticks) {
                Some(dt) => PropertyValue::FileTime(dt.to_rfc3339()),
                None => PropertyValue::Int(ticks),
            }
        }
        t if t == TDH_INTYPE_SYSTEMTIME.0 as u16 => match systemtime(bytes) {
            Some(dt) => PropertyValue::FileTime(dt.to_rfc3339()),
            None => PropertyValue::Bin(hex(bytes)),
        },
        t if t == TDH_INTYPE_BINARY.0 as u16 => {
            if out_type == TDH_OUTTYPE_IPV4.0 as u16 && bytes.len() >= 4 {
                PropertyValue::Ip(Ipv4Addr::new(bytes[0], bytes[1], bytes[2], bytes[3]).to_string())
            } else if out_type == TDH_OUTTYPE_IPV6.0 as u16 && bytes.len() >= 16 {
                let mut raw = [0u8; 16];
                raw.copy_from_slice(&bytes[..16]);
                PropertyValue::Ip(Ipv6Addr::from(raw).to_string())
            } else {
                PropertyValue::Bin(hex(bytes))
            }
        }
        _ => PropertyValue::Bin(hex(bytes)),
    }
}

/// Read a NUL-terminated UTF-16 string at `offset` inside the info blob.
///
/// The blob is only guaranteed for the duration of the decode, so the result
/// is copied out immediately.
unsafe fn wide_at(base: *const u8, offset: u32) -> Option<String> {
    if offset == 0 {
        return None;
    }
    let start = unsafe { base.add(offset as usize) }.cast::<u16>();
    let mut len = 0usize;
    // SAFETY: TDH names are NUL-terminated inside the blob it just handed us.
    while unsafe { *start.add(len) } != 0 {
        len += 1;
        if len > 4096 {
            return None;
        }
    }
    let slice = unsafe { std::slice::from_raw_parts(start, len) };
    Some(String::from_utf16_lossy(slice))
}

/// Join one or more NUL-terminated UTF-16 strings with `;`.
fn join_wide(bytes: &[u8]) -> String {
    let words: Vec<u16> = bytes
        .as_chunks::<2>()
        .0
        .iter()
        .map(|c| u16::from_le_bytes(*c))
        .collect();
    words
        .split(|w| *w == 0)
        .filter(|s| !s.is_empty())
        .map(String::from_utf16_lossy)
        .collect::<Vec<_>>()
        .join(";")
}

fn pair(bytes: &[u8]) -> [u8; 2] {
    let mut out = [0u8; 2];
    for (slot, byte) in out.iter_mut().zip(bytes) {
        *slot = *byte;
    }
    out
}

fn quad(bytes: &[u8]) -> [u8; 4] {
    let mut out = [0u8; 4];
    for (slot, byte) in out.iter_mut().zip(bytes) {
        *slot = *byte;
    }
    out
}

fn octet(bytes: &[u8]) -> [u8; 8] {
    let mut out = [0u8; 8];
    for (slot, byte) in out.iter_mut().zip(bytes) {
        *slot = *byte;
    }
    out
}

fn guid(bytes: &[u8]) -> String {
    if bytes.len() < 16 {
        return hex(bytes);
    }
    let d1 = u32::from_le_bytes(quad(bytes));
    let d2 = u16::from_le_bytes(pair(&bytes[4..]));
    let d3 = u16::from_le_bytes(pair(&bytes[6..]));
    format!(
        "{d1:08x}-{d2:04x}-{d3:04x}-{}-{}",
        hex(&bytes[8..10]),
        hex(&bytes[10..16])
    )
}

fn sid(bytes: &[u8]) -> Option<String> {
    let revision = *bytes.first()?;
    let count = *bytes.get(1)? as usize;
    if bytes.len() < 8 + count * 4 {
        return None;
    }
    let mut authority: u64 = 0;
    for byte in &bytes[2..8] {
        authority = (authority << 8) | u64::from(*byte);
    }
    let mut out = format!("S-{revision}");
    if authority >= 1 << 32 {
        out.push_str(&format!("-0x{authority:X}"));
    } else {
        out.push_str(&format!("-{authority}"));
    }
    for index in 0..count {
        let offset = 8 + index * 4;
        let sub = u32::from_le_bytes(quad(&bytes[offset..]));
        out.push_str(&format!("-{sub}"));
    }
    Some(out)
}

fn systemtime(bytes: &[u8]) -> Option<DateTime<Utc>> {
    if bytes.len() < 16 {
        return None;
    }
    let field = |i: usize| u16::from_le_bytes([bytes[i * 2], bytes[i * 2 + 1]]);
    let (year, month, day) = (field(0), field(1), field(3));
    let (hour, minute, second, millis) = (field(4), field(5), field(6), field(7));
    let date = chrono::NaiveDate::from_ymd_opt(i32::from(year), u32::from(month), u32::from(day))?;
    let time = chrono::NaiveTime::from_hms_milli_opt(
        u32::from(hour),
        u32::from(minute),
        u32::from(second),
        u32::from(millis),
    )?;
    Some(DateTime::<Utc>::from_naive_utc_and_offset(
        date.and_time(time),
        Utc,
    ))
}

/// FILETIME ticks → UTC.
pub fn filetime_to_utc(ticks: i64) -> Option<DateTime<Utc>> {
    let unix_100ns = ticks.checked_sub(FILETIME_UNIX_EPOCH)?;
    let nanos = unix_100ns.checked_mul(100)?;
    DateTime::from_timestamp(nanos / 1_000_000_000, (nanos % 1_000_000_000) as u32)
}

fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_well_known_sid() {
        // S-1-5-21-1-2-3-1001
        let mut bytes = vec![1, 5];
        bytes.extend_from_slice(&[0, 0, 0, 0, 0, 5]);
        for sub in [21u32, 1, 2, 3, 1001] {
            bytes.extend_from_slice(&sub.to_le_bytes());
        }
        assert_eq!(sid(&bytes).as_deref(), Some("S-1-5-21-1-2-3-1001"));
    }

    #[test]
    fn decodes_system_sid() {
        // S-1-5-18
        let mut bytes = vec![1, 1];
        bytes.extend_from_slice(&[0, 0, 0, 0, 0, 5]);
        bytes.extend_from_slice(&18u32.to_le_bytes());
        assert_eq!(sid(&bytes).as_deref(), Some("S-1-5-18"));
    }

    #[test]
    fn renders_guid_in_windows_order() {
        let bytes = [
            0x27, 0x89, 0xd0, 0xed, 0xc4, 0x9c, 0x65, 0x4e, 0xb9, 0x70, 0xc2, 0x56, 0x0f, 0xb5,
            0xc2, 0x89,
        ];
        assert_eq!(guid(&bytes), "edd08927-9cc4-4e65-b970-c2560fb5c289");
    }

    #[test]
    fn converts_filetime_to_utc() {
        // 2026-11-14T09:02:12.6007676Z
        let ticks = 134_391_205_326_007_676;
        let dt = filetime_to_utc(ticks).expect("valid");
        assert_eq!(dt.to_rfc3339(), "2026-11-14T09:02:12.600767600+00:00");
    }

    #[test]
    fn joins_utf16_arrays_on_semicolon() {
        let mut bytes = Vec::new();
        for word in "172.66.147.243".encode_utf16() {
            bytes.extend_from_slice(&word.to_le_bytes());
        }
        bytes.extend_from_slice(&0u16.to_le_bytes());
        for word in "104.20.23.154".encode_utf16() {
            bytes.extend_from_slice(&word.to_le_bytes());
        }
        bytes.extend_from_slice(&0u16.to_le_bytes());
        assert_eq!(join_wide(&bytes), "172.66.147.243;104.20.23.154");
    }

    #[test]
    fn formats_ipv4_outtype() {
        let value = format_value(
            &[172, 66, 147, 243],
            TDH_INTYPE_UINT32.0 as u16,
            TDH_OUTTYPE_IPV4.0 as u16,
        );
        assert!(matches!(value, PropertyValue::Ip(ref ip) if ip == "172.66.147.243"));
    }

    #[test]
    fn formats_network_order_port() {
        let value = format_value(
            &[0x01, 0xbb],
            TDH_INTYPE_UINT16.0 as u16,
            TDH_OUTTYPE_PORT.0 as u16,
        );
        assert!(matches!(value, PropertyValue::UInt(443)));
    }
}
