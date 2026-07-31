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

/// Product identifier for rule filtering.
#[derive(Debug, Clone, PartialEq, Eq, Default, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Product {
    #[default]
    Windows,
    Linux,
    Macos,
}

impl Product {
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
    pub event_json: Value,
    pub event_raw: Vec<u8>,
}

impl Event {
    pub fn new(event_json: Value, event_raw: Vec<u8>) -> Self {
        Self {
            event_json,
            event_raw,
        }
    }

    /// Parse a Winevt XML string into an Event.
    pub fn from_xml(xml: &str) -> Result<Self, ParseError> {
        let json = parse_winevt_xml(xml)?;
        let raw = xml.as_bytes().to_vec();
        Ok(Self {
            event_json: json,
            event_raw: raw,
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
        let channel = self.channel().to_string();
        let provider = self.provider().to_string();
        let event_id = self.event_id();

        let service = CHANNEL_TO_SERVICE
            .get(channel.as_str())
            .map(|s| s.to_string())
            .or_else(|| {
                PROVIDER_TO_SERVICE
                    .get(provider.as_str())
                    .map(|s| s.to_string())
            });

        let category = get_category(&channel, event_id).map(|s| s.to_string());

        if let Value::Object(ref mut map) = self.event_json {
            map.insert("product".into(), Value::String("windows".into()));
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
static CHANNEL_TO_SERVICE: phf::Map<&'static str, &'static str> = phf::phf_map! {
    "Application" => "application",
    "System" => "system",
    "Security" => "security",
    "Microsoft-Windows-Sysmon/Operational" => "sysmon",
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
    "Security:4672" => "privilege_use",
    "Security:4625" => "login_failure",
    "Security:4624" => "login",
    "Security:4634" => "logoff",
    "Security:4647" => "logoff",
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
};

/// Resolve category from channel + event_id (subcategory overrides take precedence).
fn get_category(channel: &str, event_id: u32) -> Option<&'static str> {
    let key = format!("{}:{}", channel, event_id);
    CHANNEL_EVENT_TO_SUBCATEGORY
        .get(&key)
        .copied()
        .or_else(|| CHANNEL_EVENT_TO_CATEGORY.get(&key).copied())
}

// ─── XML parsing ────────────────────────────────────────────────────────────

/// Maximum allowed size for a Winevt XML event (1 MB).
///
/// Winevt events are typically well under this limit. This prevents
/// memory exhaustion from malformed or excessively large input.
const MAX_XML_SIZE: usize = 1024 * 1024;

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

    if child_elements.is_empty() && attrs.is_empty() {
        if let Some(t) = text {
            if let Ok(n) = t.parse::<u64>() {
                return Value::Number(n.into());
            }
            return Value::String(t);
        }
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

    if let Some(t) = text {
        if !map.contains_key("#text") {
            map.insert("#text".into(), Value::String(t));
        }
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

#[derive(Debug, Clone)]
pub struct ParseError {
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
    pub rule_id: String,
    pub rule_title: String,
    pub description: Option<String>,
    pub rule_path: Option<PathBuf>,
    pub severity: String,
    pub event_json: Value,
    pub event_raw: Vec<u8>,
}

impl Alert {
    pub fn channel(&self) -> &str {
        self.event_json
            .get("Event")
            .and_then(|v| v.get("System"))
            .and_then(|v| v.get("Channel"))
            .and_then(|v| v.as_str())
            .or_else(|| self.event_json.get("Channel").and_then(|v| v.as_str()))
            .unwrap_or("")
    }

    pub fn record_id(&self) -> Option<u64> {
        self.event_json
            .get("Event")?
            .get("System")?
            .get("EventRecordID")
            .and_then(|v| v.as_u64())
    }

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
    pub rule_id: String,
    pub rule_title: String,
}

impl RegressionHeader {
    pub fn new(rule_id: String, rule_title: String) -> Self {
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
        self,
        tx: mpsc::Sender<Event>,
        stop: tokio::sync::watch::Receiver<bool>,
    ) -> anyhow::Result<()>;
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
        assert!(!result["Event"]
            .as_object()
            .unwrap()
            .contains_key("EventData"));
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
        // Last value wins when duplicate names exist
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
        let mut event = Event::new(json, Vec::new());
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
        let mut event = Event::new(json, Vec::new());
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
        let mut event = Event::new(json, Vec::new());
        event.inject_logsource_fields();

        assert_eq!(event.event_json["service"].as_str().unwrap(), "sysmon");
        // EID 13 → registry_set (subcategory override, not registry_event)
        assert_eq!(
            event.event_json["category"].as_str().unwrap(),
            "registry_set"
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
        let mut event = Event::new(json, Vec::new());
        event.inject_logsource_fields();

        assert_eq!(event.event_json["product"].as_str().unwrap(), "windows");
        // Channel unknown → provider fallback resolves service
        assert_eq!(event.event_json["service"].as_str().unwrap(), "sysmon");
        // Category absent because get_category uses unknown channel
        assert!(event.event_json.get("category").is_none());
    }
}
