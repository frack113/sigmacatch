// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 sigmacatch contributors

//! Shared types for all sigmacatch crates and binaries.
//!
//! - [`Event`] — parsed event JSON + raw source bytes (input to the detection engine)
//! - [`Alert`] — a rule match produced by the detection engine (output)
//! - [`RegressionHeader`] — minimal rule metadata for regression data generation

use async_trait::async_trait;
use roxmltree::Node;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use std::fmt;
use std::path::PathBuf;
use tokio::sync::mpsc;
use uuid::Uuid;

/// Product identifier for rule filtering.
#[derive(Debug, Clone, PartialEq, Eq, Default, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Product {
    /// Microsoft Windows event pipelines.
    #[default]
    Windows,
    /// Linux event pipelines (auditd/syslog/eBPF).
    Linux,
    /// macOS (reserved; no collector today).
    Macos,
}

impl Product {
    /// Lowercase SigmaHQ `product` value for this platform.
    pub fn as_str(&self) -> &'static str {
        match self {
            Product::Windows => "windows",
            Product::Linux => "linux",
            Product::Macos => "macos",
        }
    }
}

impl std::str::FromStr for Product {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "windows" => Ok(Product::Windows),
            "linux" => Ok(Product::Linux),
            "macos" => Ok(Product::Macos),
            _ => Err(format!("unknown product: {s}")),
        }
    }
}

impl std::fmt::Display for Product {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// A generic event for the detection engine: parsed JSON + raw source bytes.
#[derive(Debug, Clone)]
pub struct Event {
    /// Raw JSON as collected from Winevt (preserves original EventData key names).
    /// Used for regression data generation — must match the EVTX content exactly.
    pub event_json_raw: Value,
    /// Transformed JSON for Sigma detection (EventData keys have spaces stripped).
    /// Used by the detection engine — makes field paths easier in Sigma rules.
    pub event_json: Value,
    /// Raw wire bytes as collected (XML for Winevt/sysmon paths, RFC3164 line
    /// for Linux collectors) — written verbatim to regression `.log` data.
    pub event_raw: Vec<u8>,
    /// True when this event was synthesized from ETW raw data rather than
    /// re-exported from the live Event Log. Affects EVTX generation.
    pub is_etw: bool,
}

impl Event {
    /// Build an event from its JSON views and raw bytes (non-ETW source).
    pub fn new(event_json_raw: Value, event_json: Value, event_raw: Vec<u8>) -> Self {
        Self {
            event_json_raw,
            event_json,
            event_raw,
            is_etw: false,
        }
    }

    /// Parse a Winevt XML string into an Event.
    /// Stores both raw JSON (for regression) and transformed JSON (for detection).
    pub fn from_xml(xml: &str) -> Result<Self, ParseError> {
        let json_raw = parse_winevt_xml_raw(xml)?;
        let json = parse_winevt_xml(xml)?;
        let raw = xml.as_bytes().to_vec();
        Ok(Self {
            event_json_raw: json_raw,
            event_json: json,
            event_raw: raw,
            is_etw: false,
        })
    }

    /// EventID extracted from the parsed JSON.
    fn event_id(&self) -> u32 {
        self.event_json
            .get("Event")
            .and_then(|v| v.get("System"))
            .and_then(|v| v.get("EventID"))
            .and_then(|v| v.as_u64())
            .unwrap_or(0) as u32
    }

    /// Provider extracted from the parsed JSON (System.Provider.Name).
    fn provider(&self) -> &str {
        self.event_json
            .get("Event")
            .and_then(|v| v.get("System"))
            .and_then(|v| v.get("Provider"))
            .and_then(|v| v.get("#attributes"))
            .and_then(|v| v.get("Name"))
            .and_then(|v| v.as_str())
            .unwrap_or("")
    }

    /// Channel extracted from the parsed JSON.
    ///
    /// Checks `Event.System.Channel` first (Winevt XML), then `Channel` at the
    /// top level (evtx crate output).
    fn channel(&self) -> &str {
        self.event_json
            .get("Event")
            .and_then(|v| v.get("System"))
            .and_then(|v| v.get("Channel"))
            .and_then(|v| v.as_str())
            .or_else(|| self.event_json.get("Channel").and_then(|v| v.as_str()))
            .unwrap_or("")
    }

    /// EventRecordID extracted from the parsed JSON (`Event.System.EventRecordID`).
    /// Record id from the event System section, when present.
    pub fn record_id(&self) -> Option<u64> {
        self.event_json
            .get("Event")?
            .get("System")?
            .get("EventRecordID")
            .and_then(|v| v.as_u64())
    }

    /// Inject `product`, `service`, `category` fields into `event_json`.
    ///
    /// The detection engine's `LogSourceExtractor` reads these fields to prune
    /// incompatible rules at evaluation time. Call this before sending the event
    /// to the detection engine.
    pub fn inject_logsource_fields(&mut self) {
        self.inject_logsource_fields_for("windows", None);
    }

    /// Inject `product` (mandatory) and optional `service` into `event_json`,
    /// resolving `category` from the event's channel like
    /// [`inject_logsource_fields`](Self::inject_logsource_fields).
    ///
    /// Used by non-Windows collectors (auditd) that know their logsource
    /// statically: `service` is passed explicitly and the channel/provider
    /// tables are only consulted when no service is given.
    pub fn inject_logsource_fields_for(&mut self, product: &str, service: Option<&str>) {
        let channel = self.channel().to_string();
        let provider = self.provider().to_string();
        let event_id = self.event_id();

        let service = service.map(str::to_string).or_else(|| {
            CHANNEL_TO_SERVICE
                .get(channel.as_str())
                .map(|s| s.to_string())
                .or_else(|| {
                    PROVIDER_TO_SERVICE
                        .get(provider.as_str())
                        .map(|s| s.to_string())
                })
        });

        let category = get_category(&channel, event_id)
            .map(|c| {
                // Sysmon EventID 12 is both registry add (CreateKey) and
                // delete (DeleteKey/DeleteValue); the subcategory table holds
                // one value per channel:event_id, so refine by EventType here
                // or injected `registry_add` would prune `registry_delete` rules.
                if c == "registry_add" && is_registry_delete_event_type(&self.event_json) {
                    "registry_delete"
                } else {
                    c
                }
            })
            .or_else(|| category_exclusive_sentinel(&channel))
            .map(str::to_string);

        if let Value::Object(ref mut map) = self.event_json {
            map.insert("product".into(), Value::String(product.into()));
            if let Some(s) = service {
                map.insert("service".into(), Value::String(s));
            }
            if let Some(c) = category {
                map.insert("category".into(), Value::String(c));
            }
        }
    }
}

// ─── LogSource mapping tables ───────────────────────────────────────────────

/// Channel → Sigma service name.
pub static CHANNEL_TO_SERVICE: phf::Map<&'static str, &'static str> = phf::phf_map! {
    "Application" => "application",
    "System" => "system",
    "Security" => "security",
    "Microsoft-Windows-Sysmon/Operational" => "sysmon",
    "Linux-Sysmon/Operational" => "sysmon",
    "DNS Server" => "dns-server",
    "Microsoft-Windows-DNS-Server/Analytical" => "dns-server-analytic",
    "Microsoft-Windows-DNS-Server/Audit" => "dns-server-audit",
    "Microsoft-Windows-DNS Client Events/Operational" => "dns-client",
    "Microsoft-Windows-DHCP-Server/Operational" => "dhcp",
    "Microsoft-Windows-DriverFrameworks-UserMode/Operational" => "driver-framework",
    "Microsoft-Windows-Hyper-V-Worker" => "hyper-v-worker",
    "Microsoft-IIS-Configuration/Operational" => "iis-configuration",
    "Microsoft-Windows-Kernel-EventTracing" => "kernel-event-tracing",
    "Microsoft-Windows-Kernel-ShimEngine/Operational" => "kernel-shimengine",
    "Microsoft-Windows-Kernel-ShimEngine/Diagnostic" => "kernel-shimengine",
    "Microsoft-Windows-LDAP-Client/Debug" => "ldap",
    "Microsoft-Windows-LSA/Operational" => "lsa-server",
    "Microsoft-Windows-NTLM/Operational" => "ntlm",
    "Microsoft-Windows-Ntfs/Operational" => "ntfs",
    "OpenSSH/Operational" => "openssh",
    "Microsoft-Windows-PrintService/Admin" => "printservice-admin",
    "Microsoft-Windows-PrintService/Operational" => "printservice-operational",
    "Microsoft-Windows-AppLocker/EXE and DLL" => "applocker",
    "Microsoft-Windows-AppLocker/MSI and Script" => "applocker",
    "Microsoft-Windows-AppLocker/Packaged app-Deployment" => "applocker",
    "Microsoft-Windows-AppLocker/Packaged app-Execution" => "applocker",
    "Microsoft-Windows-AppModel-Runtime/Admin" => "appmodel-runtime",
    "Microsoft-Windows-AppXDeploymentServer/Operational" => "appxdeployment-server",
    "Microsoft-Windows-AppxPackaging/Operational" => "appxpackaging-om",
    "Microsoft-Windows-Application-Experience/Program-Telemetry" => "application-experience",
    "Microsoft-Windows-Application-Experience/Program-Compatibility-Assistant" => "application-experience",
    "Microsoft-Windows-BitLocker/BitLocker Management" => "bitlocker",
    "Microsoft-Windows-Bits-Client/Operational" => "bits-client",
    "Microsoft-Windows-CAPI2/Operational" => "capi2",
    "Microsoft-Windows-CertificateServicesClient-Lifecycle-System/Operational" => "certificateservicesclient-lifecycle-system",
    "Microsoft-Windows-CodeIntegrity/Operational" => "codeintegrity-operational",
    "Microsoft-Windows-SENSE/Operational" => "sense",
    "Microsoft-ServiceBus-Client/Operational" => "servicebus-client",
    "Microsoft-ServiceBus-Client/Admin" => "servicebus-client",
    "Microsoft-Windows-Shell-Core/Operational" => "shell-core",
    "Microsoft-Windows-Security-Mitigations/Kernel Mode" => "security-mitigations",
    "Microsoft-Windows-Security-Mitigations/User Mode" => "security-mitigations",
    "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational" => "terminalservices-localsessionmanager",
    "Microsoft-Windows-VHDMP/Operational" => "vhdmp",
    "Microsoft-Windows-Windows Defender/Operational" => "windefend",
    "Microsoft-Windows-Windows Firewall With Advanced Security/Firewall" => "firewall-as",
    "Microsoft-Windows-Diagnosis-Scripted/Operational" => "diagnosis-scripted",
    "MSExchange Management" => "msexchange-management",
    "Microsoft-Windows-SmbClient/Security" => "smbclient-security",
    "Windows PowerShell" => "powershell-classic",
    "Microsoft-Windows-PowerShell/Operational" => "powershell",
    "PowerShellCore/Operational" => "powershell",
    "Microsoft-Windows-TaskScheduler/Operational" => "taskscheduler",
    "Microsoft-Windows-WMI-Activity/Operational" => "wmi",
    // Dedicated channels for unmapped ETW events of Sysmon-masquerade providers
    // (mapper::unmapped_channel_for_masquerade). Service `etw` gives them a real
    // logsource so they are never evaluated fail-open against every rule.
    "sigmacatch/etw-kernel-process" => "etw",
    "sigmacatch/etw-kernel-file" => "etw",
    "sigmacatch/etw-kernel-network" => "etw",
    "sigmacatch/etw-kernel-registry" => "etw",
    "sigmacatch/etw-dns-client" => "etw",
    "sigmacatch/etw-powershell" => "etw",
    "sigmacatch/etw-wmi-activity" => "etw",
    "sigmacatch/etw-service-control-manager" => "etw",
    "sigmacatch/etw-task-scheduler" => "etw",
    "sigmacatch/etw-unmapped" => "etw",
};

/// Channel:EventID → Sigma category.
static CHANNEL_EVENT_TO_CATEGORY: phf::Map<&'static str, &'static str> = phf::phf_map! {
    "Microsoft-Windows-Sysmon/Operational:1" => "process_creation",
    "Microsoft-Windows-Sysmon/Operational:2" => "file_change",
    "Microsoft-Windows-Sysmon/Operational:3" => "network_connection",
    "Microsoft-Windows-Sysmon/Operational:4" => "sysmon_status",
    "Microsoft-Windows-Sysmon/Operational:5" => "process_termination",
    "Microsoft-Windows-Sysmon/Operational:6" => "driver_load",
    "Microsoft-Windows-Sysmon/Operational:7" => "image_load",
    "Microsoft-Windows-Sysmon/Operational:8" => "create_remote_thread",
    "Microsoft-Windows-Sysmon/Operational:9" => "raw_access_thread",
    "Microsoft-Windows-Sysmon/Operational:10" => "process_access",
    "Microsoft-Windows-Sysmon/Operational:11" => "file_event",
    "Microsoft-Windows-Sysmon/Operational:12" => "registry_event",
    "Microsoft-Windows-Sysmon/Operational:13" => "registry_event",
    "Microsoft-Windows-Sysmon/Operational:14" => "registry_event",
    "Microsoft-Windows-Sysmon/Operational:15" => "create_stream_hash",
    "Microsoft-Windows-Sysmon/Operational:16" => "sysmon_status",
    "Microsoft-Windows-Sysmon/Operational:17" => "pipe_created",
    "Microsoft-Windows-Sysmon/Operational:18" => "pipe_created",
    "Microsoft-Windows-Sysmon/Operational:19" => "wmi_event",
    "Microsoft-Windows-Sysmon/Operational:20" => "wmi_event",
    "Microsoft-Windows-Sysmon/Operational:21" => "wmi_event",
    "Microsoft-Windows-Sysmon/Operational:22" => "dns_query",
    "Microsoft-Windows-Sysmon/Operational:23" => "file_delete",
    "Microsoft-Windows-Sysmon/Operational:24" => "clipboard_capture",
    "Microsoft-Windows-Sysmon/Operational:25" => "process_tampering",
    "Microsoft-Windows-Sysmon/Operational:26" => "file_delete_detected",
    "Microsoft-Windows-Sysmon/Operational:27" => "file_block_executable",
    "Microsoft-Windows-Sysmon/Operational:28" => "file_block_shredding",
    "Microsoft-Windows-Sysmon/Operational:29" => "file_executable_detected",
    "Microsoft-Windows-Sysmon/Operational:255" => "sysmon_error",
    "Security:4688" => "process_creation",
    "Windows PowerShell:400" => "ps_classic_start",
    "Windows PowerShell:600" => "ps_classic_provider_start",
    "Windows PowerShell:800" => "ps_classic_script",
    "Microsoft-Windows-PowerShell/Operational:4103" => "ps_module",
    "Microsoft-Windows-PowerShell/Operational:4104" => "ps_script",
    "PowerShellCore/Operational:4103" => "ps_module",
    "PowerShellCore/Operational:4104" => "ps_script",
};

/// Sub-category overrides (higher specificity than CHANNEL_EVENT_TO_CATEGORY).
static CHANNEL_EVENT_TO_SUBCATEGORY: phf::Map<&'static str, &'static str> = phf::phf_map! {
    "Microsoft-Windows-Sysmon/Operational:12" => "registry_add",
    "Microsoft-Windows-Sysmon/Operational:13" => "registry_set",
    "Microsoft-Windows-Sysmon/Operational:14" => "registry_rename",
};

/// Provider → Sigma service fallback (when channel lookup fails).
static PROVIDER_TO_SERVICE: phf::Map<&'static str, &'static str> = phf::phf_map! {
    "Microsoft-Windows-Sysmon" => "sysmon",
    "Microsoft-Windows-Security-Auditing" => "security",
    "Microsoft-Windows-PowerShell" => "powershell",
    "Microsoft-Windows-Windows Defender" => "windefend",
    "Service Control Manager" => "system",
    "Microsoft-Windows-Kernel-Process" => "process",
    "Microsoft-Windows-Kernel-Network" => "network",
    "Microsoft-Windows-Kernel-File" => "file",
    "Microsoft-Windows-Kernel-Registry" => "registry",
    "Microsoft-Windows-DNS-Client" => "dns",
    "Microsoft-Windows-SmbClient" => "smbclient",
    "Microsoft-Windows-WMI-Activity" => "wmi",
    "Microsoft-Windows-TaskScheduler" => "taskscheduler",
};

/// Resolve category from channel + event_id (subcategory overrides take precedence).
fn get_category(channel: &str, event_id: u32) -> Option<&'static str> {
    // Sysmon for Linux emits the same schema and EventIDs under its own
    // channel; reuse the Windows Sysmon mappings instead of duplicating them.
    let channel = if channel == "Linux-Sysmon/Operational" {
        "Microsoft-Windows-Sysmon/Operational"
    } else {
        channel
    };
    let key = format!("{}:{}", channel, event_id);
    CHANNEL_EVENT_TO_SUBCATEGORY
        .get(&key)
        .copied()
        .or_else(|| CHANNEL_EVENT_TO_CATEGORY.get(&key).copied())
}

/// Category-exclusive PowerShell channels: an event whose EventID is not
/// mapped (e.g. console error 4100) is never `ps_module` (4103) nor
/// `ps_script` (4104). Injecting a conflicting sentinel turns the fail-open
/// logsource pruning fail-closed, avoiding false positives (the reference
/// harness maps `ps_module` to 4103 only). `service: powershell` rules are
/// unaffected.
fn category_exclusive_sentinel(channel: &str) -> Option<&'static str> {
    match channel {
        "Microsoft-Windows-PowerShell/Operational"
        | "PowerShellCore/Operational"
        | "Windows PowerShell" => Some("ps_other"),
        _ => None,
    }
}

/// Whether the event's `EventData.EventType` marks a Sysmon registry deletion
/// (DeleteKey or DeleteValue), refining EventID 12 to the `registry_delete`
/// Sigma category instead of `registry_add`.
fn is_registry_delete_event_type(event_json: &Value) -> bool {
    matches!(
        event_json
            .pointer("/Event/EventData/EventType")
            .and_then(Value::as_str),
        Some("DeleteKey") | Some("DeleteValue")
    )
}

// ─── XML parsing ────────────────────────────────────────────────────────────

/// Maximum allowed size for a Winevt XML event (1 MB) — prevents memory
/// exhaustion from malformed or excessively large input.
const MAX_XML_SIZE: usize = 1024 * 1024;

/// Convert a decimal string to a JSON number when it parses cleanly.
fn maybe_number(s: &str) -> Option<Value> {
    if let Ok(n) = s.parse::<u64>() {
        return Some(Value::Number(n.into()));
    }
    if let Ok(n) = s.parse::<i64>() {
        return Some(Value::Number(n.into()));
    }
    None
}

/// True when the string has a GUID/UUID shape (`8-4-4-4-12`, hex with hyphens).
///
/// Shape-only check (no RFC 4122 version/variant validation) so that Sysmon
/// `ProcessGuid` values — whose middle groups encode timestamps — pass too.
fn looks_like_guid(s: &str) -> bool {
    let b = s.as_bytes();
    if b.len() != 36 {
        return false;
    }
    for (i, &c) in b.iter().enumerate() {
        if i == 8 || i == 13 || i == 18 || i == 23 {
            if c != b'-' {
                return false;
            }
        } else if !c.is_ascii_hexdigit() {
            return false;
        }
    }
    true
}

/// Normalize a scalar value for the SigmaHQ regression JSON format:
/// decimal strings → JSON numbers, GUIDs → uppercase without braces, else unchanged.
fn normalize_string(s: &str) -> Value {
    let t = s.trim();
    if let Some(n) = maybe_number(t) {
        return n;
    }
    let stripped = t
        .strip_prefix('{')
        .and_then(|inner| inner.strip_suffix('}'))
        .unwrap_or(t);
    if looks_like_guid(stripped) {
        return Value::String(stripped.to_uppercase());
    }
    Value::String(s.to_string())
}

/// EventData fields that the provider manifest types as GUIDs.
///
/// The Windows XML renderer (`EvtRender`) emits these with braces and lowercase
/// (`{5aa13a44-...}`) while SigmaHQ's committed format is uppercase without
/// braces (`5AA13A44-...`). String-typed fields that merely *look* like GUIDs
/// (e.g. registry `Details` CLSIDs, Defender `Detection ID`) keep braces in the
/// committed format, so normalization must be field-aware.
static GUID_TYPED_FIELDS: phf::Set<&'static str> = phf::phf_set! {
    "ProcessGuid",
    "ParentProcessGuid",
    "LogonGuid",
    "SourceProcessGUID",
    "TargetProcessGUID",
    "ImageGuid",
    "PipeGuid",
};

/// Normalize an EventData value: numbers to JSON numbers, GUID-typed fields to
/// uppercase without braces, all other strings verbatim.
fn normalize_eventdata_value(field: &str, value: &str) -> Value {
    let t = value.trim();
    if let Some(n) = maybe_number(t) {
        return n;
    }
    if GUID_TYPED_FIELDS.contains(field) {
        let stripped = t
            .strip_prefix('{')
            .and_then(|inner| inner.strip_suffix('}'))
            .unwrap_or(t);
        if looks_like_guid(stripped) {
            return Value::String(stripped.to_uppercase());
        }
    }
    Value::String(value.to_string())
}

/// Parse a Winevt XML string into nested JSON (raw — preserves original EventData key names).
/// Used for regression data generation where exact fidelity to the source event is required.
pub fn parse_winevt_xml_raw(xml: &str) -> Result<Value, ParseError> {
    if xml.len() > MAX_XML_SIZE {
        return Err(ParseError {
            message: format!(
                "XML input too large: {} bytes (max {} bytes)",
                xml.len(),
                MAX_XML_SIZE
            ),
        });
    }

    let doc = roxmltree::Document::parse(xml).map_err(|e| ParseError {
        message: format!("XML parse error: {}", e),
    })?;

    let root = doc.root();
    let event = root
        .descendants()
        .find(|n| n.tag_name().name() == "Event")
        .ok_or_else(|| ParseError {
            message: "no <Event> element found in XML".to_string(),
        })?;

    let mut event_map = Map::new();

    let mut event_attrs = Map::new();
    for ns in event.namespaces() {
        match ns.name() {
            None => {
                event_attrs.insert("xmlns".into(), Value::String(ns.uri().to_string()));
            }
            Some(prefix) => {
                event_attrs.insert(
                    format!("xmlns:{prefix}"),
                    Value::String(ns.uri().to_string()),
                );
            }
        }
    }
    for a in event.attributes() {
        event_attrs.insert(a.name().to_string(), Value::String(a.value().to_string()));
    }
    if !event_attrs.is_empty() {
        event_map.insert("#attributes".into(), Value::Object(event_attrs));
    }

    for child in event.children() {
        if child.is_element() {
            let name = child.tag_name().name().to_string();
            let value = node_to_value_raw(child, true);
            event_map.insert(name, value);
        }
    }

    Ok(Value::Object({
        let mut result = Map::new();
        result.insert("Event".into(), Value::Object(event_map));
        result
    }))
}

/// Parse a Winevt XML string into nested JSON.
pub fn parse_winevt_xml(xml: &str) -> Result<Value, ParseError> {
    if xml.len() > MAX_XML_SIZE {
        return Err(ParseError {
            message: format!(
                "XML input too large: {} bytes (max {} bytes)",
                xml.len(),
                MAX_XML_SIZE
            ),
        });
    }

    let doc = roxmltree::Document::parse(xml).map_err(|e| ParseError {
        message: format!("XML parse error: {}", e),
    })?;

    let root = doc.root();
    let event = root
        .descendants()
        .find(|n| n.tag_name().name() == "Event")
        .ok_or_else(|| ParseError {
            message: "no <Event> element found in XML".to_string(),
        })?;

    let mut event_map = Map::new();
    for child in event.children() {
        if child.is_element() {
            let name = child.tag_name().name().to_string();
            let value = node_to_value(child, true);
            event_map.insert(name, value);
        }
    }

    let mut result = Map::new();
    result.insert("Event".into(), Value::Object(event_map));
    result.insert("_source".into(), Value::String("winevt".to_string()));

    Ok(Value::Object(result))
}

fn node_to_value(node: Node, _is_root: bool) -> Value {
    let tag = node.tag_name().name();

    if tag == "EventData" {
        return handle_event_data(node);
    }

    let child_elements: Vec<Node> = node.children().filter(|c| c.is_element()).collect();
    let text = node
        .text()
        .map(|t| t.trim().to_string())
        .filter(|t| !t.is_empty());

    let attrs: Vec<_> = node.attributes().filter(|a| a.name() != "xmlns").collect();

    if child_elements.is_empty()
        && attrs.is_empty()
        && let Some(t) = text
    {
        if let Ok(n) = t.parse::<u64>() {
            return Value::Number(n.into());
        }
        return Value::String(t);
    }

    if child_elements.is_empty() && !attrs.is_empty() && text.is_none() {
        let mut attr_map = Map::new();
        for a in attrs {
            attr_map.insert(a.name().to_string(), Value::String(a.value().to_string()));
        }
        return Value::Object({
            let mut m = Map::new();
            m.insert("#attributes".into(), Value::Object(attr_map));
            m
        });
    }

    if child_elements.is_empty() && attrs.is_empty() && text.is_none() {
        return Value::Object(Map::new());
    }

    let mut map = Map::new();

    if !attrs.is_empty() {
        let mut attr_map = Map::new();
        for a in attrs {
            attr_map.insert(a.name().to_string(), Value::String(a.value().to_string()));
        }
        map.insert("#attributes".into(), Value::Object(attr_map));
    }

    for child in &child_elements {
        let child_name = child.tag_name().name().to_string();
        let child_value = node_to_value(*child, false);
        map.insert(child_name, child_value);
    }

    if let Some(t) = text
        && !map.contains_key("#text")
    {
        map.insert("#text".into(), Value::String(t));
    }

    Value::Object(map)
}

/// Attributes of an element for the raw format: its own namespace declaration
/// (resolved URI differs from the parent element, e.g. a `<UserData>` child that
/// switches to a provider manifest namespace) plus its regular attributes.
fn collect_element_attrs(node: Node) -> Vec<(String, String)> {
    let mut attrs = Vec::new();
    if let Some(uri) = node.tag_name().namespace() {
        let parent_ns = node
            .parent()
            .filter(|p| p.is_element())
            .and_then(|p| p.tag_name().namespace());
        if parent_ns != Some(uri) {
            attrs.push(("xmlns".to_string(), uri.to_string()));
        }
    }
    for a in node.attributes() {
        attrs.push((a.name().to_string(), a.value().to_string()));
    }
    attrs
}

fn node_to_value_raw(node: Node, _is_root: bool) -> Value {
    let tag = node.tag_name().name();

    if tag == "EventData" {
        return handle_event_data_raw(node);
    }

    let child_elements: Vec<Node> = node.children().filter(|c| c.is_element()).collect();
    let text = node
        .text()
        .map(|t| t.trim().to_string())
        .filter(|t| !t.is_empty());

    let attrs: Vec<(String, String)> = collect_element_attrs(node);

    if child_elements.is_empty()
        && attrs.is_empty()
        && let Some(t) = text
    {
        if let Some(n) = maybe_number(&t) {
            return n;
        }
        return Value::String(t);
    }

    if child_elements.is_empty() && !attrs.is_empty() && text.is_none() {
        let mut attr_map = Map::new();
        for (name, value) in &attrs {
            attr_map.insert(name.clone(), normalize_string(value));
        }
        return Value::Object({
            let mut m = Map::new();
            m.insert("#attributes".into(), Value::Object(attr_map));
            m
        });
    }

    if child_elements.is_empty() && attrs.is_empty() && text.is_none() {
        return Value::Null;
    }

    let mut map = Map::new();

    if !attrs.is_empty() {
        let mut attr_map = Map::new();
        for (name, value) in &attrs {
            attr_map.insert(name.clone(), normalize_string(value));
        }
        map.insert("#attributes".into(), Value::Object(attr_map));
    }

    for child in &child_elements {
        let child_name = child.tag_name().name().to_string();
        let child_value = node_to_value_raw(*child, false);
        map.insert(child_name, child_value);
    }

    if let Some(t) = text
        && !map.contains_key("#text")
    {
        map.insert("#text".into(), Value::String(t));
    }

    Value::Object(map)
}

fn handle_event_data(node: Node) -> Value {
    let mut map = Map::new();
    for child in node.children() {
        if child.is_element() && child.tag_name().name() == "Data" {
            let name = child.attribute("Name").unwrap_or("");
            if !name.is_empty() {
                // Strip spaces from key names so field paths like
                // `Event.EventData.SourceName` resolve without quoted notation.
                let key: String = name.chars().filter(|c| *c != ' ').collect();
                let value = child
                    .text()
                    .map(|t| t.trim().to_string())
                    .unwrap_or_default();
                map.insert(key, Value::String(value));
            }
        }
    }
    Value::Object(map)
}

fn handle_event_data_raw(node: Node) -> Value {
    let mut map = Map::new();

    let attrs = collect_element_attrs(node);
    if !attrs.is_empty() {
        let mut attr_map = Map::new();
        for (name, value) in &attrs {
            attr_map.insert(name.clone(), normalize_string(value));
        }
        map.insert("#attributes".into(), Value::Object(attr_map));
    }

    for child in node.children() {
        if child.is_element() && child.tag_name().name() == "Data" {
            let name = child.attribute("Name").unwrap_or("");
            if !name.is_empty() {
                // Preserve original key names (with spaces) for regression data.
                let value = child
                    .text()
                    .map(|t| t.trim().to_string())
                    .unwrap_or_default();
                map.insert(name.to_string(), normalize_eventdata_value(name, &value));
            }
        }
    }
    Value::Object(map)
}

/// XML parse failure surfaced by the Winevt/sysmon XML readers.
#[derive(Debug, Clone)]
pub struct ParseError {
    /// Human-readable description of what failed to parse.
    pub message: String,
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl std::error::Error for ParseError {}

// ─── Alert ─────────────────────────────────────────────────────────────────

/// An alert produced when an event matches a Sigma rule.
#[derive(Debug, Clone)]
pub struct Alert {
    /// Matched rule UUID (Sigma `id`).
    pub rule_id: Uuid,
    /// Matched rule title.
    pub rule_title: String,
    /// Matched rule description, when present.
    pub description: Option<String>,
    /// Path of the matched rule file, when known.
    pub rule_path: Option<PathBuf>,
    /// Matched rule severity (`low`/`medium`/`high`/`critical`).
    pub severity: String,
    /// Raw JSON as collected from Winevt (preserves original EventData key names).
    /// Used for regression data generation — must match the EVTX content exactly.
    pub event_json_raw: Value,
    /// Transformed JSON for Sigma detection (EventData keys have spaces stripped).
    /// Used by the detection engine.
    pub event_json: Value,
    /// Raw wire bytes as collected (see [`Event::event_raw`]).
    pub event_raw: Vec<u8>,
    /// True when this alert came from an ETW-synthesized event.
    pub is_etw: bool,
}

impl Alert {
    /// Channel extracted from the event System section (empty when absent).
    pub fn channel(&self) -> &str {
        self.event_json
            .get("Event")
            .and_then(|v| v.get("System"))
            .and_then(|v| v.get("Channel"))
            .and_then(|v| v.as_str())
            .or_else(|| self.event_json.get("Channel").and_then(|v| v.as_str()))
            .unwrap_or("")
    }

    /// Record id from the event System section, when present.
    pub fn record_id(&self) -> Option<u64> {
        self.event_json
            .get("Event")?
            .get("System")?
            .get("EventRecordID")
            .and_then(|v| v.as_u64())
    }

    /// Provider name from the event System section (empty when absent).
    pub fn provider(&self) -> &str {
        self.event_json
            .get("Event")
            .and_then(|v| v.get("System"))
            .and_then(|v| v.get("Provider"))
            .and_then(|v| v.get("#attributes"))
            .and_then(|v| v.get("Name"))
            .and_then(|v| v.as_str())
            .unwrap_or("")
    }

    /// Raw wire bytes interpreted as UTF-8 (lossy).
    pub fn raw_xml(&self) -> &str {
        std::str::from_utf8(&self.event_raw).unwrap_or("")
    }
}

// ─── RegressionHeader ──────────────────────────────────────────────────────

/// Minimal rule metadata required for regression data generation.
///
/// Decouples the regression data format from `rsigma_eval::result::RuleHeader`.
/// Evolutive — add fields here without touching rsigma internals.
#[derive(Debug, Clone)]
pub struct RegressionHeader {
    /// Rule UUID (Sigma `id`) used as the regression directory/file key.
    pub rule_id: Uuid,
    /// Human-readable rule title stored in `info.yml`.
    pub rule_title: String,
}

impl RegressionHeader {
    /// Convenience constructor.
    pub fn new(rule_id: Uuid, rule_title: String) -> Self {
        Self {
            rule_id,
            rule_title,
        }
    }
}

impl From<Alert> for RegressionHeader {
    fn from(a: Alert) -> Self {
        Self {
            rule_id: a.rule_id,
            rule_title: a.rule_title,
        }
    }
}

// ─── EventProducer ────────────────────────────────────────────────────────

/// Errors raised by an [`EventProducer`] while collecting events.
#[derive(Debug, thiserror::Error)]
pub enum ProducerError {
    /// A collection failure wrapping the underlying source error.
    #[error(transparent)]
    Collector(Box<dyn std::error::Error + Send + Sync>),
    /// A collection failure described only by a message.
    #[error("{0}")]
    Message(String),
}

/// Trait for async event producers that send events into a channel.
///
/// Implementors collect events from a source and send them into the provided
/// `mpsc::Sender<Event>`. When collection is complete, the sender is dropped
/// automatically. The producer must exit promptly when `stop` is set.
#[async_trait]
pub trait EventProducer: Send {
    /// Run the producer, sending collected events into `tx`.
    /// Stops when `stop` is set to `true` or when the receiver is dropped.
    async fn run(
        self: Box<Self>,
        tx: mpsc::Sender<Event>,
        stop: tokio::sync::watch::Receiver<bool>,
    ) -> Result<(), ProducerError>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_sysmon_process() {
        let xml = r#"<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
            <System>
                <Provider Name="Microsoft-Windows-Sysmon" Guid="{guid}"/>
                <EventID>1</EventID>
                <TimeCreated SystemTime="2024-01-01T00:00:00.0000000Z"/>
                <Channel>Microsoft-Windows-Sysmon/Operational</Channel>
                <EventRecordID>1788</EventRecordID>
            </System>
            <EventData>
                <Data Name="Image">C:\\Windows\\System32\\cmd.exe</Data>
                <Data Name="CommandLine">cmd /c whoami</Data>
                <Data Name="User">DOMAIN\\user</Data>
            </EventData>
        </Event>"#;

        let result = parse_winevt_xml(xml).unwrap();
        let event = result.as_object().unwrap();

        assert_eq!(event["_source"].as_str().unwrap(), "winevt");

        let system = event["Event"]["System"].as_object().unwrap();
        assert_eq!(system["EventID"].as_u64().unwrap(), 1);

        let provider = system["Provider"].as_object().unwrap();
        let attrs = provider["#attributes"].as_object().unwrap();
        assert_eq!(attrs["Name"].as_str().unwrap(), "Microsoft-Windows-Sysmon");

        let event_data = event["Event"]["EventData"].as_object().unwrap();
        assert_eq!(event_data["CommandLine"].as_str().unwrap(), "cmd /c whoami");
        assert_eq!(
            event_data["Image"].as_str().unwrap(),
            r"C:\\Windows\\System32\\cmd.exe"
        );
    }

    #[test]
    fn test_parse_security_event() {
        let xml = r#"<Event Channel="Security">
            <System>
                <Provider Name="Microsoft-Windows-Security-Auditing"/>
                <EventID>4624</EventID>
                <Channel>Security</Channel>
            </System>
            <EventData>
                <Data Name="TargetUserName">admin</Data>
                <Data Name="TargetDomainName">WORKGROUP</Data>
            </EventData>
        </Event>"#;

        let result = parse_winevt_xml(xml).unwrap();
        let event_data = result["Event"]["EventData"].as_object().unwrap();
        assert_eq!(event_data["TargetUserName"].as_str().unwrap(), "admin");
    }

    #[test]
    fn test_event_from_xml() {
        let xml = r#"<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
            <System>
                <Provider Name="Microsoft-Windows-Sysmon"/>
                <EventID>1</EventID>
                <Channel>Microsoft-Windows-Sysmon/Operational</Channel>
            </System>
            <EventData>
                <Data Name="Image">cmd.exe</Data>
            </EventData>
        </Event>"#;

        let event = Event::from_xml(xml).unwrap();
        assert_eq!(event.event_json["_source"].as_str().unwrap(), "winevt");
        assert_eq!(event.event_raw, xml.as_bytes());
    }

    #[test]
    fn test_parse_malformed_xml() {
        let xml = r#"<Event><System><EventID>1</EventID></System"#;
        let result = parse_winevt_xml(xml);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_no_event_element() {
        let xml = r#"<System><EventID>1</EventID></System>"#;
        let result = parse_winevt_xml(xml);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_empty_event_data() {
        let xml = r#"<Event>
            <System><EventID>1</EventID></System>
            <EventData></EventData>
        </Event>"#;
        let result = parse_winevt_xml(xml).unwrap();
        let event_data = result["Event"]["EventData"].as_object().unwrap();
        assert!(event_data.is_empty());
    }

    #[test]
    fn test_parse_event_data_no_name_attribute() {
        let xml = r#"<Event>
            <System><EventID>1</EventID></System>
            <EventData><Data>NoName</Data></EventData>
        </Event>"#;
        let result = parse_winevt_xml(xml).unwrap();
        let event_data = result["Event"]["EventData"].as_object().unwrap();
        assert!(!event_data.contains_key(""));
    }

    #[test]
    fn test_parse_unicode_event_data() {
        let xml = r#"<Event>
            <System><EventID>1</EventID></System>
            <EventData>
                <Data Name="Message">Hello world: 世界 🌍</Data>
            </EventData>
        </Event>"#;
        let result = parse_winevt_xml(xml).unwrap();
        let event_data = result["Event"]["EventData"].as_object().unwrap();
        assert_eq!(
            event_data["Message"].as_str().unwrap(),
            "Hello world: 世界 🌍"
        );
    }

    #[test]
    fn test_parse_event_id_non_numeric_string() {
        let xml = r#"<Event>
            <System><EventID>abc</EventID></System>
            <EventData></EventData>
        </Event>"#;
        let result = parse_winevt_xml(xml).unwrap();
        let system = result["Event"]["System"].as_object().unwrap();
        assert_eq!(system["EventID"].as_str().unwrap(), "abc");
    }

    #[test]
    fn test_parse_event_with_attributes_only() {
        let xml = r#"<Event>
            <System>
                <Provider Name="Test" Guid="{guid}"/>
                <EventID>1</EventID>
            </System>
        </Event>"#;
        let result = parse_winevt_xml(xml).unwrap();
        let provider = result["Event"]["System"]["Provider"].as_object().unwrap();
        assert!(provider.contains_key("#attributes"));
        let attrs = provider["#attributes"].as_object().unwrap();
        assert_eq!(attrs["Name"].as_str().unwrap(), "Test");
    }

    #[test]
    fn test_parse_event_without_eventdata() {
        let xml = r#"<Event>
            <System><EventID>1</EventID></System>
        </Event>"#;
        let result = parse_winevt_xml(xml).unwrap();
        assert!(
            !result["Event"]
                .as_object()
                .unwrap()
                .contains_key("EventData")
        );
    }

    #[test]
    fn test_parse_multiple_data_same_name() {
        let xml = r#"<Event>
            <System><EventID>1</EventID></System>
            <EventData>
                <Data Name="Image">first.exe</Data>
                <Data Name="Image">second.exe</Data>
            </EventData>
        </Event>"#;
        let result = parse_winevt_xml(xml).unwrap();
        let event_data = result["Event"]["EventData"].as_object().unwrap();
        assert_eq!(event_data["Image"].as_str().unwrap(), "second.exe");
    }

    #[test]
    fn test_parse_nested_system_elements() {
        let xml = r#"<Event>
            <System>
                <Provider Name="Test"/>
                <EventID>1</EventID>
                <Version>0</Version>
                <TimeCreated SystemTime="2024-01-01T00:00:00.0000000Z"/>
            </System>
        </Event>"#;
        let result = parse_winevt_xml(xml).unwrap();
        let system = result["Event"]["System"].as_object().unwrap();
        assert_eq!(system["EventID"].as_u64().unwrap(), 1);
        assert_eq!(system["Version"].as_u64().unwrap(), 0);
    }

    #[test]
    fn test_parse_xml_too_large() {
        let large = "A".repeat(MAX_XML_SIZE + 1);
        let xml = format!(
            "<Event><System><EventID>1</EventID></System><Data>{}</Data></Event>",
            large
        );
        let result = parse_winevt_xml(&xml);
        assert!(result.is_err());
        assert!(result.unwrap_err().message.contains("too large"));
    }

    #[test]
    fn test_parse_xml_at_max_size() {
        let at_limit = "A".repeat(MAX_XML_SIZE);
        let xml = format!(
            "<Event><System><EventID>1</EventID></System><Data>{}</Data></Event>",
            at_limit
        );
        let result = parse_winevt_xml(&xml);
        assert!(result.is_err());
    }

    #[test]
    fn test_inject_logsource_fields_sysmon() {
        let xml = r#"<Event>
            <System>
                <Provider Name="Microsoft-Windows-Sysmon"/>
                <EventID>1</EventID>
                <Channel>Microsoft-Windows-Sysmon/Operational</Channel>
            </System>
            <EventData>
                <Data Name="Image">cmd.exe</Data>
            </EventData>
        </Event>"#;
        let mut event = Event::from_xml(xml).unwrap();
        event.inject_logsource_fields();

        assert_eq!(event.event_json["product"].as_str().unwrap(), "windows");
        assert_eq!(event.event_json["service"].as_str().unwrap(), "sysmon");
        assert_eq!(
            event.event_json["category"].as_str().unwrap(),
            "process_creation"
        );
    }

    #[test]
    fn test_inject_logsource_fields_linux_sysmon() {
        let xml = r#"<Event>
            <System>
                <Provider Name="Linux-Sysmon"/>
                <EventID>1</EventID>
                <Channel>Linux-Sysmon/Operational</Channel>
                <Computer>debian</Computer>
            </System>
            <EventData>
                <Data Name="Image">/usr/bin/id</Data>
            </EventData>
        </Event>"#;
        let mut event = Event::from_xml(xml).unwrap();
        event.inject_logsource_fields_for("linux", None);

        assert_eq!(event.event_json["product"].as_str().unwrap(), "linux");
        assert_eq!(event.event_json["service"].as_str().unwrap(), "sysmon");
        assert_eq!(
            event.event_json["category"].as_str().unwrap(),
            "process_creation"
        );
    }

    #[test]
    fn test_inject_logsource_fields_linux_sysmon_categories() {
        for (eid, category) in [
            (3u32, "network_connection"),
            (5, "process_termination"),
            (10, "process_access"),
            (11, "file_event"),
            (22, "dns_query"),
            (23, "file_delete"),
        ] {
            let json = serde_json::json!({
                "Event": {
                    "System": {
                        "Provider": { "#attributes": { "Name": "Linux-Sysmon" } },
                        "EventID": eid,
                        "Channel": "Linux-Sysmon/Operational"
                    }
                }
            });
            let mut event = Event::new(json.clone(), json, Vec::new());
            event.inject_logsource_fields_for("linux", None);

            assert_eq!(
                event.event_json["category"].as_str().unwrap(),
                category,
                "EID {eid}"
            );
        }
    }

    #[test]
    fn test_inject_logsource_fields_security() {
        let json = serde_json::json!({
            "Event": {
                "System": {
                    "Provider": { "#attributes": { "Name": "Microsoft-Windows-Security-Auditing" } },
                    "EventID": 4688,
                    "Channel": "Security"
                }
            }
        });
        let mut event = Event::new(json.clone(), json, Vec::new());
        event.inject_logsource_fields();

        assert_eq!(event.event_json["product"].as_str().unwrap(), "windows");
        assert_eq!(event.event_json["service"].as_str().unwrap(), "security");
        assert_eq!(
            event.event_json["category"].as_str().unwrap(),
            "process_creation"
        );
    }

    #[test]
    fn test_inject_logsource_fields_unknown_channel() {
        let json = serde_json::json!({
            "Event": {
                "System": {
                    "Provider": { "#attributes": { "Name": "UnknownProvider" } },
                    "EventID": 1,
                    "Channel": "UnknownChannel"
                }
            }
        });
        let mut event = Event::new(json.clone(), json, Vec::new());
        event.inject_logsource_fields();

        assert_eq!(event.event_json["product"].as_str().unwrap(), "windows");
        assert!(event.event_json.get("service").is_none());
        assert!(event.event_json.get("category").is_none());
    }

    #[test]
    fn test_inject_logsource_fields_registry_subcategory() {
        let json = serde_json::json!({
            "Event": {
                "System": {
                    "Provider": { "#attributes": { "Name": "Microsoft-Windows-Sysmon" } },
                    "EventID": 13,
                    "Channel": "Microsoft-Windows-Sysmon/Operational"
                }
            }
        });
        let mut event = Event::new(json.clone(), json, Vec::new());
        event.inject_logsource_fields();

        assert_eq!(event.event_json["service"].as_str().unwrap(), "sysmon");
        // EID 13 → registry_set (subcategory override, not registry_event)
        assert_eq!(
            event.event_json["category"].as_str().unwrap(),
            "registry_set"
        );
    }

    #[test]
    fn test_inject_logsource_fields_registry_eventid12_eventtype() {
        let mk = |event_type: Option<&str>| {
            let mut data = serde_json::Map::new();
            if let Some(et) = event_type {
                data.insert("EventType".into(), Value::String(et.into()));
            }
            serde_json::json!({
                "Event": {
                    "System": {
                        "Provider": { "#attributes": { "Name": "Microsoft-Windows-Sysmon" } },
                        "EventID": 12,
                        "Channel": "Microsoft-Windows-Sysmon/Operational"
                    },
                    "EventData": Value::Object(data)
                }
            })
        };

        // CreateKey → registry_add
        let json = mk(Some("CreateKey"));
        let mut event = Event::new(json.clone(), json, Vec::new());
        event.inject_logsource_fields();
        assert_eq!(
            event.event_json["category"].as_str().unwrap(),
            "registry_add"
        );

        // DeleteKey → registry_delete
        let json = mk(Some("DeleteKey"));
        let mut event = Event::new(json.clone(), json, Vec::new());
        event.inject_logsource_fields();
        assert_eq!(
            event.event_json["category"].as_str().unwrap(),
            "registry_delete"
        );

        // DeleteValue → registry_delete
        let json = mk(Some("DeleteValue"));
        let mut event = Event::new(json.clone(), json, Vec::new());
        event.inject_logsource_fields();
        assert_eq!(
            event.event_json["category"].as_str().unwrap(),
            "registry_delete"
        );

        // Missing EventType → fall back to registry_add
        let json = mk(None);
        let mut event = Event::new(json.clone(), json, Vec::new());
        event.inject_logsource_fields();
        assert_eq!(
            event.event_json["category"].as_str().unwrap(),
            "registry_add"
        );

        // Non-registry events keep their own category
        let json = serde_json::json!({
            "Event": {
                "System": {
                    "Provider": { "#attributes": { "Name": "Microsoft-Windows-Sysmon" } },
                    "EventID": 1,
                    "Channel": "Microsoft-Windows-Sysmon/Operational"
                },
                "EventData": { "EventType": "DeleteValue" }
            }
        });
        let mut event = Event::new(json.clone(), json, Vec::new());
        event.inject_logsource_fields();
        assert_eq!(
            event.event_json["category"].as_str().unwrap(),
            "process_creation"
        );
    }

    #[test]
    fn test_inject_logsource_fields_provider_fallback() {
        let json = serde_json::json!({
            "Event": {
                "System": {
                    "Provider": { "#attributes": { "Name": "Microsoft-Windows-Sysmon" } },
                    "EventID": 1,
                    "Channel": "ForwardedEvents"
                }
            }
        });
        let mut event = Event::new(json.clone(), json, Vec::new());
        event.inject_logsource_fields();

        assert_eq!(event.event_json["product"].as_str().unwrap(), "windows");
        // Channel unknown → provider fallback resolves service
        assert_eq!(event.event_json["service"].as_str().unwrap(), "sysmon");
        // Category absent because get_category uses unknown channel
        assert!(event.event_json.get("category").is_none());
    }

    #[test]
    fn test_inject_logsource_fields_ps_module_eventid() {
        // EventID 4103 is module logging → ps_module
        let json = serde_json::json!({
            "Event": {
                "System": {
                    "Provider": { "#attributes": { "Name": "Microsoft-Windows-PowerShell" } },
                    "EventID": 4103,
                    "Channel": "Microsoft-Windows-PowerShell/Operational"
                }
            }
        });
        let mut event = Event::new(json.clone(), json, Vec::new());
        event.inject_logsource_fields();

        assert_eq!(event.event_json["service"].as_str().unwrap(), "powershell");
        assert_eq!(event.event_json["category"].as_str().unwrap(), "ps_module");
    }

    #[test]
    fn test_inject_logsource_fields_ps_script_eventid() {
        // EventID 4104 is script block logging → ps_script
        let json = serde_json::json!({
            "Event": {
                "System": {
                    "Provider": { "#attributes": { "Name": "Microsoft-Windows-PowerShell" } },
                    "EventID": 4104,
                    "Channel": "PowerShellCore/Operational"
                }
            }
        });
        let mut event = Event::new(json.clone(), json, Vec::new());
        event.inject_logsource_fields();

        assert_eq!(event.event_json["category"].as_str().unwrap(), "ps_script");
    }

    #[test]
    fn test_inject_logsource_fields_ps_unmapped_eventid_sentinel() {
        // EventID 4100 (console error) is neither ps_module nor ps_script:
        // inject a conflicting sentinel so ps_* rules are pruned.
        let json = serde_json::json!({
            "Event": {
                "System": {
                    "Provider": { "#attributes": { "Name": "Microsoft-Windows-PowerShell" } },
                    "EventID": 4100,
                    "Channel": "Microsoft-Windows-PowerShell/Operational"
                }
            }
        });
        let mut event = Event::new(json.clone(), json, Vec::new());
        event.inject_logsource_fields();

        assert_eq!(event.event_json["service"].as_str().unwrap(), "powershell");
        assert_eq!(event.event_json["category"].as_str().unwrap(), "ps_other");
    }

    #[test]
    fn test_inject_logsource_fields_ps_classic_script() {
        // Classic channel EventID 800 → ps_classic_script
        let json = serde_json::json!({
            "Event": {
                "System": {
                    "Provider": { "#attributes": { "Name": "PowerShell" } },
                    "EventID": 800,
                    "Channel": "Windows PowerShell"
                }
            }
        });
        let mut event = Event::new(json.clone(), json, Vec::new());
        event.inject_logsource_fields();

        assert_eq!(
            event.event_json["category"].as_str().unwrap(),
            "ps_classic_script"
        );
    }

    #[test]
    fn test_inject_logsource_fields_ps_classic_unmapped_sentinel() {
        // Classic channel unmapped EventID → sentinel
        let json = serde_json::json!({
            "Event": {
                "System": {
                    "Provider": { "#attributes": { "Name": "PowerShell" } },
                    "EventID": 401,
                    "Channel": "Windows PowerShell"
                }
            }
        });
        let mut event = Event::new(json.clone(), json, Vec::new());
        event.inject_logsource_fields();

        assert_eq!(event.event_json["category"].as_str().unwrap(), "ps_other");
    }

    #[test]
    fn test_parse_winevt_xml_raw_preserves_spaces() {
        let xml = r#"<Event>
            <System>
                <Provider Name="Microsoft-Windows-Sysmon"/>
                <EventID>1</EventID>
                <Channel>Microsoft-Windows-Sysmon/Operational</Channel>
            </System>
            <EventData>
                <Data Name="Image">C:\\Windows\\System32\\cmd.exe</Data>
                <Data Name="CommandLine">cmd /c whoami</Data>
                <Data Name="User">DOMAIN\\user</Data>
            </EventData>
        </Event>"#;

        let result = parse_winevt_xml_raw(xml).unwrap();
        let event_data = result["Event"]["EventData"].as_object().unwrap();
        assert_eq!(
            event_data["Image"].as_str().unwrap(),
            "C:\\\\Windows\\\\System32\\\\cmd.exe"
        );
        assert_eq!(event_data["CommandLine"].as_str().unwrap(), "cmd /c whoami");
        assert_eq!(event_data["User"].as_str().unwrap(), "DOMAIN\\\\user");
    }

    #[test]
    fn test_parse_winevt_xml_raw_diverges_from_transformed() {
        let xml = r#"<Event>
            <System>
                <Provider Name="Microsoft-Windows-Sysmon"/>
                <EventID>1</EventID>
                <Channel>Microsoft-Windows-Sysmon/Operational</Channel>
            </System>
            <EventData>
                <Data Name="Command Line">cmd /c whoami</Data>
                <Data Name="Target Image">C:\\Windows\\System32\\calc.exe</Data>
            </EventData>
        </Event>"#;

        let raw = parse_winevt_xml_raw(xml).unwrap();
        let transformed = parse_winevt_xml(xml).unwrap();

        let raw_data = raw["Event"]["EventData"].as_object().unwrap();
        let transformed_data = transformed["Event"]["EventData"].as_object().unwrap();

        assert!(
            raw_data.contains_key("Command Line"),
            "raw should preserve 'Command Line' with space"
        );
        assert!(
            transformed_data.contains_key("CommandLine"),
            "transformed should have 'CommandLine' without space"
        );
        assert!(
            !raw_data.contains_key("CommandLine"),
            "raw should NOT have 'CommandLine'"
        );
        assert!(
            !transformed_data.contains_key("Command Line"),
            "transformed should NOT have 'Command Line'"
        );

        assert!(
            raw_data.contains_key("Target Image"),
            "raw should preserve 'Target Image' with space"
        );
        assert!(
            transformed_data.contains_key("TargetImage"),
            "transformed should have 'TargetImage' without space"
        );
    }

    #[test]
    fn test_event_from_xml_raw_preserved_after_inject() {
        let xml = r#"<Event>
            <System>
                <Provider Name="Microsoft-Windows-Sysmon"/>
                <EventID>1</EventID>
                <Channel>Microsoft-Windows-Sysmon/Operational</Channel>
            </System>
            <EventData>
                <Data Name="Command Line">cmd.exe</Data>
            </EventData>
        </Event>"#;

        let mut event = Event::from_xml(xml).unwrap();

        let raw_before = event.event_json_raw.clone();
        let raw_has_space = raw_before["Event"]["EventData"]["Command Line"]
            .as_str()
            .is_some();
        assert!(
            raw_has_space,
            "event_json_raw should have 'Command Line' before inject"
        );

        event.inject_logsource_fields();

        let raw_after = &event.event_json_raw;
        assert_eq!(
            raw_after["Event"]["EventData"]["Command Line"]
                .as_str()
                .unwrap(),
            "cmd.exe"
        );
        assert!(
            !raw_after["Event"]["EventData"]
                .as_object()
                .unwrap()
                .contains_key("CommandLine"),
            "event_json_raw should NOT have 'CommandLine' after inject"
        );
        assert!(
            raw_after["Event"]["System"]["Provider"]["#attributes"]["Name"]
                .as_str()
                .is_some(),
            "event_json_raw should preserve Provider attributes"
        );

        assert_eq!(
            event.event_json.get("product").map(|v| v.as_str().unwrap()),
            Some("windows")
        );
        assert_eq!(
            event.event_json.get("service").map(|v| v.as_str().unwrap()),
            Some("sysmon")
        );
    }

    #[test]
    fn test_handle_event_data_raw_empty_name() {
        let xml = r#"<Event>
            <System><EventID>1</EventID></System>
            <EventData>
                <Data Name="">empty_name</Data>
                <Data Name="ValidName">valid_value</Data>
            </EventData>
        </Event>"#;

        let result = parse_winevt_xml_raw(xml).unwrap();
        let event_data = result["Event"]["EventData"].as_object().unwrap();
        assert!(
            !event_data.contains_key(""),
            "empty Name attribute should be skipped"
        );
        assert_eq!(event_data["ValidName"].as_str().unwrap(), "valid_value");
    }

    #[test]
    fn test_parse_winevt_xml_raw_unicode() {
        let xml = r#"<Event>
            <System><EventID>1</EventID></System>
            <EventData>
                <Data Name="Message">Hello world: 世界 🌍</Data>
                <Data Name="Command Line">cmd /c echo 你好</Data>
            </EventData>
        </Event>"#;

        let result = parse_winevt_xml_raw(xml).unwrap();
        let event_data = result["Event"]["EventData"].as_object().unwrap();
        assert_eq!(
            event_data["Message"].as_str().unwrap(),
            "Hello world: 世界 🌍"
        );
        assert_eq!(
            event_data["Command Line"].as_str().unwrap(),
            "cmd /c echo 你好"
        );
    }

    #[test]
    fn test_parse_winevt_xml_raw_empty_eventdata() {
        let xml = r#"<Event>
            <System><EventID>1</EventID></System>
            <EventData></EventData>
        </Event>"#;

        let result = parse_winevt_xml_raw(xml).unwrap();
        let event_data = result["Event"]["EventData"].as_object().unwrap();
        assert!(event_data.is_empty());
    }

    #[test]
    fn test_parse_winevt_xml_raw_no_eventdata() {
        let xml = r#"<Event>
            <System><EventID>1</EventID></System>
        </Event>"#;

        let result = parse_winevt_xml_raw(xml).unwrap();
        assert!(
            !result["Event"]
                .as_object()
                .unwrap()
                .contains_key("EventData")
        );
    }

    #[test]
    fn test_parse_winevt_xml_raw_too_large() {
        let large = "A".repeat(MAX_XML_SIZE + 1);
        let xml = format!(
            "<Event><System><EventID>1</EventID></System><Data>{}</Data></Event>",
            large
        );
        let result = parse_winevt_xml_raw(&xml);
        assert!(result.is_err());
        assert!(result.unwrap_err().message.contains("too large"));
    }

    #[test]
    fn test_alert_event_json_raw_populated() {
        let xml = r#"<Event>
            <System>
                <Provider Name="Microsoft-Windows-Sysmon"/>
                <EventID>1</EventID>
                <Channel>Microsoft-Windows-Sysmon/Operational</Channel>
            </System>
            <EventData>
                <Data Name="Command Line">cmd.exe</Data>
            </EventData>
        </Event>"#;

        let event = Event::from_xml(xml).unwrap();
        let alert = Alert {
            rule_id: Uuid::nil(),
            rule_title: "Test Rule".to_string(),
            description: None,
            rule_path: None,
            severity: "medium".to_string(),
            event_json_raw: event.event_json_raw.clone(),
            event_json: event.event_json.clone(),
            event_raw: event.event_raw.clone(),
            is_etw: false,
        };

        assert!(
            alert.event_json_raw["Event"]["EventData"]["Command Line"]
                .as_str()
                .is_some()
        );
        assert!(
            alert.event_json["Event"]["EventData"]["CommandLine"]
                .as_str()
                .is_some()
        );
    }

    #[test]
    fn test_parse_winevt_xml_raw_sigmahq_format() {
        let xml = r#"<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
            <System>
                <Provider Name="Microsoft-Windows-Sysmon" Guid="{5770385f-c22a-43e0-bf4c-06f5698ffbd9}"/>
                <EventID>1</EventID>
                <TimeCreated SystemTime="2025-10-25T16:56:16.019794Z"/>
                <Correlation/>
                <Execution ProcessID="3308" ThreadID="4008"/>
                <Channel>Microsoft-Windows-Sysmon/Operational</Channel>
                <EventRecordID>11418519</EventRecordID>
            </System>
            <EventData>
                <Data Name="ProcessId">5112</Data>
                <Data Name="ProcessGuid">{5aa13a44-0130-68fd-4e35-000000004002}</Data>
                <Data Name="Image">C:\\Windows\\System32\\certutil.exe</Data>
                <Data Name="LogonId">0x529ae3</Data>
            </EventData>
        </Event>"#;

        let result = parse_winevt_xml_raw(xml).unwrap();
        let event = result["Event"].as_object().unwrap();

        assert!(
            !result.as_object().unwrap().contains_key("_source"),
            "raw JSON should not carry _source (SigmaHQ format has none)"
        );

        let event_attrs = event["#attributes"].as_object().unwrap();
        assert_eq!(
            event_attrs["xmlns"].as_str().unwrap(),
            "http://schemas.microsoft.com/win/2004/08/events/event"
        );

        let system = event["System"].as_object().unwrap();
        assert_eq!(system["EventID"].as_u64().unwrap(), 1);
        assert_eq!(system["EventRecordID"].as_u64().unwrap(), 11418519);
        assert!(system["Correlation"].is_null());

        let provider_attrs = system["Provider"]["#attributes"].as_object().unwrap();
        assert_eq!(
            provider_attrs["Guid"].as_str().unwrap(),
            "5770385F-C22A-43E0-BF4C-06F5698FFBD9",
            "GUID should be uppercase without braces"
        );

        let execution_attrs = system["Execution"]["#attributes"].as_object().unwrap();
        assert_eq!(execution_attrs["ProcessID"].as_u64().unwrap(), 3308);
        assert_eq!(execution_attrs["ThreadID"].as_u64().unwrap(), 4008);

        let event_data = event["EventData"].as_object().unwrap();
        assert_eq!(event_data["ProcessId"].as_u64().unwrap(), 5112);
        assert_eq!(
            event_data["ProcessGuid"].as_str().unwrap(),
            "5AA13A44-0130-68FD-4E35-000000004002",
            "ProcessGuid should be uppercase without braces"
        );
        assert_eq!(
            event_data["LogonId"].as_str().unwrap(),
            "0x529ae3",
            "hex values stay strings"
        );
        assert_eq!(
            event_data["Image"].as_str().unwrap(),
            "C:\\\\Windows\\\\System32\\\\certutil.exe"
        );
    }

    #[test]
    fn test_parse_winevt_xml_raw_string_guids_and_attrs() {
        let xml = r#"<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
            <System>
                <Provider Name="Microsoft-Windows-Sysmon" Guid="{5770385f-c22a-43e0-bf4c-06f5698ffbd9}"/>
                <EventID>13</EventID>
            </System>
            <EventData Name="SetValue">
                <Data Name="ProcessGuid">{5aa13a44-62e7-68fd-c13e-000000004002}</Data>
                <Data Name="Details">{00000001-0000-0000-0000-0000FEEDACDC}</Data>
            </EventData>
            <UserData>
                <Operation_ClientFailure xmlns="http://manifests.microsoft.com/win/2006/windows/WMI">
                    <Id>{00000000-0000-0000-0000-000000000000}</Id>
                </Operation_ClientFailure>
            </UserData>
        </Event>"#;

        let result = parse_winevt_xml_raw(xml).unwrap();
        let event = result["Event"].as_object().unwrap();

        let event_data = event["EventData"].as_object().unwrap();
        assert_eq!(
            event_data["#attributes"]["Name"].as_str().unwrap(),
            "SetValue",
            "EventData attributes must be preserved"
        );
        assert_eq!(
            event_data["ProcessGuid"].as_str().unwrap(),
            "5AA13A44-62E7-68FD-C13E-000000004002",
            "GUID-typed field: braces stripped + uppercase"
        );
        assert_eq!(
            event_data["Details"].as_str().unwrap(),
            "{00000001-0000-0000-0000-0000FEEDACDC}",
            "string-typed GUID: braces kept verbatim"
        );

        let failure = event["UserData"]["Operation_ClientFailure"]
            .as_object()
            .unwrap();
        assert_eq!(
            failure["#attributes"]["xmlns"].as_str().unwrap(),
            "http://manifests.microsoft.com/win/2006/windows/WMI",
            "own namespace declaration preserved"
        );
        assert_eq!(
            failure["Id"].as_str().unwrap(),
            "{00000000-0000-0000-0000-000000000000}",
            "non-GUID-typed Id kept verbatim"
        );

        let system = event["System"].as_object().unwrap();
        assert!(
            !system.contains_key("#attributes"),
            "inherited namespace must not be re-emitted on children"
        );
    }
}
