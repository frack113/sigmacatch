// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 sigmacatch contributors

//! validate-motor: batch validation of the Sigma detection engine against SigmaHQ regression data.
//!
//! Parses .evtx files using the evtx crate, normalizes the nested JSON output
//! to match the Winevt XmlParser format (flattened EventID, Channel, CommandLine, etc.),
//! then evaluates events against loaded Sigma rules.
//!
//! Usage:
//!   cargo run --release --bin validate_motor <sigmahq_dir>
//!
//! Pipeline:
//!   1. Scan <sigmahq_dir>/regression_data for info.yml files
//!   2. For each triplet: rule.yml + .evtx + info.yml
//!   3. Parse EVTX binary -> nested JSON -> flattened JSON (Winevt-compatible format)
//!   4. Evaluate event against the Sigma rule using rsigma-eval
//!   5. Validate: rule MUST match (positive detection test)
//!   6. Report per-rule pass/fail + summary

use anyhow::{anyhow, Result};
use evtx::EvtxParser;
use rsigma_eval::event::JsonEvent;
use rsigma_eval::Engine;
use rsigma_parser::parse_sigma_yaml;
use rsigma_parser::LogSource;
use serde_json::Value;
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

// ─── Regression Data Scanner ──────────────────────────────────────────────────

struct RegressionTriplet {
    evtx_path: PathBuf,
    info_path: PathBuf,
}

fn scan_regression_data(base: &Path) -> Result<Vec<RegressionTriplet>> {
    let mut triplets = Vec::new();

    if !base.exists() {
        return Err(anyhow!("Directory does not exist: {}", base.display()));
    }

    let walk = fs::read_dir(base)?;
    for entry in walk.flatten() {
        let sub = entry.path();
        if !sub.is_dir() {
            continue;
        }
        scan_dir_recursive(&sub, base, &mut triplets)?;
    }

    triplets.sort_by(|a, b| a.info_path.cmp(&b.info_path));
    Ok(triplets)
}

#[allow(clippy::only_used_in_recursion)]
fn scan_dir_recursive(
    dir: &Path,
    base: &Path,
    triplets: &mut Vec<RegressionTriplet>,
) -> Result<()> {
    let entries = match fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return Ok(()),
    };

    let mut has_info = false;
    let mut has_evtx = false;
    let mut has_json = false;
    let mut info_path = None;
    let mut evtx_path = None;

    for entry in entries.flatten() {
        let ep = entry.path();
        if ep.is_file() {
            match ep.extension().and_then(|e| e.to_str()) {
                Some("yml") | Some("yaml") => {
                    if ep.file_name().map(|n| n == "info.yml").unwrap_or(false) {
                        has_info = true;
                        info_path = Some(ep);
                    }
                }
                Some("evtx") => {
                    has_evtx = true;
                    evtx_path = Some(ep);
                }
                Some("json") => {
                    has_json = true;
                }
                _ => {}
            }
        } else if ep.is_dir() {
            scan_dir_recursive(&ep, base, triplets)?;
        }
    }

    if has_info && has_evtx && has_json {
        if let (Some(info), Some(evtx)) = (info_path, evtx_path) {
            triplets.push(RegressionTriplet {
                evtx_path: evtx,
                info_path: info,
            });
        }
    }

    Ok(())
}

// ─── Rule Resolution ──────────────────────────────────────────────────────────

fn find_rule_file(info_path: &Path, sigma_dir: &Path) -> Result<PathBuf> {
    let content =
        fs::read_to_string(info_path).map_err(|e| anyhow!("Failed to read info.yml: {}", e))?;

    let mut rule_id = None;
    let mut in_rule_metadata = false;

    for line in content.lines() {
        let trimmed = line.trim();

        if trimmed == "rule_metadata:" {
            in_rule_metadata = true;
            continue;
        }

        if in_rule_metadata && trimmed.starts_with("- id:") {
            rule_id = trimmed.strip_prefix("- id:").map(|s| s.trim());
        }

        if in_rule_metadata
            && !line.starts_with(' ')
            && !trimmed.is_empty()
            && trimmed != "rule_metadata:"
            && !trimmed.starts_with("- id:")
        {
            in_rule_metadata = false;
        }
    }

    let rule_id = rule_id.ok_or_else(|| anyhow!("No rule_id found in info.yml"))?;

    for rules_subdir in [
        "rules",
        "rules-dfir",
        "rules-emerging-threats",
        "rules-threat-hunting",
    ] {
        let rules_dir = sigma_dir.join(rules_subdir);
        if !rules_dir.exists() {
            continue;
        }
        if let Ok(found) = find_rule_by_id(&rules_dir, rule_id) {
            return Ok(found);
        }
    }

    Err(anyhow!(
        "Rule file not found for ID {} in {}",
        rule_id,
        sigma_dir.display()
    ))
}

fn find_rule_by_id(dir: &Path, rule_id: &str) -> Result<PathBuf> {
    let entries = fs::read_dir(dir)?;
    for entry in entries.flatten() {
        let ep = entry.path();
        if ep.is_file() {
            if let Some(name) = ep.file_name().and_then(|n| n.to_str()) {
                if name == "index.yml" {
                    continue;
                }
                if let Ok(content) = fs::read_to_string(&ep) {
                    for line in content.lines() {
                        if line.trim() == format!("id: {}", rule_id) {
                            return Ok(ep);
                        }
                    }
                }
            }
        } else if ep.is_dir() {
            if let Ok(found) = find_rule_by_id(&ep, rule_id) {
                return Ok(found);
            }
        }
    }
    Err(anyhow!("Not found"))
}

// ─── LogSource Resolution (copy of src/sigma/mapping/mod.rs) ───────────────

static CHANNEL_TO_SERVICE: phf::Map<&'static str, &'static str> = phf::phf_map! {
    "Microsoft-Windows-Sysmon/Operational" => "sysmon",
    "Security" => "security",
    "System" => "system",
    "Application" => "application",
    "Windows PowerShell" => "powershell-classic",
    "Microsoft-Windows-PowerShell/Operational" => "powershell",
    "PowerShellCore/Operational" => "powershell",
    "Microsoft-Windows-Windows Defender/Operational" => "windefend",
    "Microsoft-Windows-TaskScheduler/Operational" => "taskscheduler",
    "Microsoft-Windows-WMI-Activity/Operational" => "wmi",
    "Microsoft-Windows-DNS Client Events/Operational" => "dns-client",
    "Microsoft-Windows-DNS-Client/Operational" => "dns-client",
    "DNS Server" => "dns-server",
    "Microsoft-Windows-DNS-Server/Analytical" => "dns-server-analytic",
    "Microsoft-Windows-DNS-Server/Audit" => "dns-server-audit",
    "Microsoft-Windows-AppLocker/EXE and DLL" => "applocker",
    "Microsoft-Windows-AppLocker/MSI and Script" => "applocker",
    "Microsoft-Windows-AppLocker/Packaged app-Deployment" => "applocker",
    "Microsoft-Windows-AppLocker/Packaged app-Execution" => "applocker",
    "Microsoft-Windows-Bits-Client/Operational" => "bits-client",
    "Microsoft-Windows-DHCP-Server/Operational" => "dhcp",
    "Microsoft-Windows-Diagnosis-Scripted/Operational" => "diagnosis-scripted",
    "Microsoft-Windows-DriverFrameworks-UserMode/Operational" => "driver-framework",
    "Microsoft-Windows-BitLocker/BitLocker Management" => "bitlocker",
    "Microsoft-Windows-CAPI2/Operational" => "capi2",
    "Microsoft-Windows-CertificateServicesClient-Lifecycle-System/Operational" => "certificateservicesclient-lifecycle-system",
    "Microsoft-Windows-CodeIntegrity/Operational" => "codeintegrity-operational",
    "Microsoft-Windows-Windows Firewall With Advanced Security/Firewall" => "firewall-as",
    "Microsoft-Windows-Hyper-V-Worker" => "hyper-v-worker",
    "Microsoft-IIS-Configuration/Operational" => "iis-configuration",
    "Microsoft-Windows-Kernel-EventTracing" => "kernel-event-tracing",
    "Microsoft-Windows-Kernel-ShimEngine/Operational" => "kernel-shimengine",
    "Microsoft-Windows-Kernel-ShimEngine/Diagnostic" => "kernel-shimengine",
    "Microsoft-Windows-LDAP-Client/Debug" => "ldap",
    "Microsoft-Windows-LSA/Operational" => "lsa-server",
    "MSExchange Management" => "msexchange-management",
    "Microsoft-Windows-Ntfs/Operational" => "ntfs",
    "Microsoft-Windows-NTLM/Operational" => "ntlm",
    "OpenSSH/Operational" => "openssh",
    "Microsoft-Windows-PrintService/Admin" => "printservice-admin",
    "Microsoft-Windows-PrintService/Operational" => "printservice-operational",
    "Microsoft-Windows-Security-Mitigations/Kernel Mode" => "security-mitigations",
    "Microsoft-Windows-Security-Mitigations/User Mode" => "security-mitigations",
    "Microsoft-Windows-SENSE/Operational" => "sense",
    "Microsoft-ServiceBus-Client/Operational" => "servicebus-client",
    "Microsoft-ServiceBus-Client/Admin" => "servicebus-client",
    "Microsoft-Windows-Shell-Core/Operational" => "shell-core",
    "Microsoft-Windows-SmbClient/Security" => "smbclient-security",
    "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational" => "terminalservices-localsessionmanager",
    "Microsoft-Windows-VHDMP/Operational" => "vhdmp",
    "Microsoft-Windows-Application-Experience/Program-Telemetry" => "application-experience",
    "Microsoft-Windows-Application-Experience/Program-Compatibility-Assistant" => "application-experience",
    "Microsoft-Windows-AppModel-Runtime/Admin" => "appmodel-runtime",
    "Microsoft-Windows-AppXDeploymentServer/Operational" => "appxdeployment-server",
    "Microsoft-Windows-AppxPackaging/Operational" => "appxpackaging-om",
    "Microsoft-Windows-Kernel-PnP/Device Configuration" => "pnp",
};

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
};

static CHANNEL_EVENT_TO_SUBCATEGORY: phf::Map<&'static str, &'static str> = phf::phf_map! {
    "Microsoft-Windows-Sysmon/Operational:13" => "registry_set",
    "Microsoft-Windows-Sysmon/Operational:14" => "registry_rename",
};

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

fn resolve_logsource(
    channel: &str,
    provider: &str,
    event_id: u32,
    _custom_map: &HashMap<String, String>,
    _event_data: Option<&Value>,
) -> LogSource {
    let lookup_service =
        |ch: &str| -> Option<String> { CHANNEL_TO_SERVICE.get(ch).map(|s| (*s).to_string()) };

    if let Some(service) = lookup_service(channel) {
        let composite_key = format!("{}:{}", channel, event_id);

        // For registry EventIDs (12, 13, 14), use broader category (registry_event)
        // for Sigma compatibility. Many SigmaHQ rules use the broader category.
        let category = if matches!(event_id, 12..=14) {
            // Use the base category (registry_event) for Sigma compatibility
            CHANNEL_EVENT_TO_CATEGORY
                .get(&composite_key)
                .copied()
                .map(|s| s.to_string())
                .or_else(|| {
                    CHANNEL_EVENT_TO_SUBCATEGORY
                        .get(&composite_key)
                        .copied()
                        .map(|s| s.to_string())
                })
        } else {
            CHANNEL_EVENT_TO_SUBCATEGORY
                .get(&composite_key)
                .copied()
                .map(|s| s.to_string())
                .or_else(|| {
                    CHANNEL_EVENT_TO_CATEGORY
                        .get(&composite_key)
                        .copied()
                        .map(|s| s.to_string())
                })
        };

        return LogSource {
            product: Some("windows".into()),
            service: Some(service),
            category,
            ..LogSource::default()
        };
    }

    if let Some(service) = PROVIDER_TO_SERVICE.get(provider) {
        return LogSource {
            product: Some("windows".into()),
            service: Some((*service).to_string()),
            category: None,
            ..LogSource::default()
        };
    }

    LogSource {
        product: Some("windows".into()),
        service: None,
        category: None,
        ..LogSource::default()
    }
}

// ─── EVTX JSON Normalizer ───────────────────────────────────────────────────

fn normalize_evtx_json(json: &Value) -> Value {
    let event = json
        .get("Event")
        .and_then(|v| v.as_object())
        .cloned()
        .unwrap_or_default();
    let mut result: serde_json::Map<String, Value> = serde_json::Map::new();

    // System fields
    let system = event
        .get("System")
        .and_then(|v| v.as_object())
        .cloned()
        .unwrap_or_default();

    // ProviderName
    if let Some(provider) = system.get("Provider") {
        if let Some(attrs) = provider.get("#attributes").and_then(|v| v.as_object()) {
            if let Some(name) = attrs.get("Name") {
                result.insert("ProviderName".into(), name.clone());
            }
        }
    }

    // EventID, Channel, TimeCreated, EventRecordID
    if let Some(event_id) = system.get("EventID") {
        result.insert("EventID".into(), Value::String(event_id.to_string()));
    }
    if let Some(channel) = system.get("Channel") {
        result.insert("Channel".into(), channel.clone());
    }
    if let Some(time_created) = system.get("TimeCreated") {
        if let Some(attrs) = time_created.get("#attributes").and_then(|v| v.as_object()) {
            if let Some(system_time) = attrs.get("SystemTime") {
                result.insert("TimeCreated".into(), system_time.clone());
            }
        }
    }
    if let Some(event_record_id) = system.get("EventRecordID") {
        result.insert(
            "EventRecordID".into(),
            Value::String(event_record_id.to_string()),
        );
    }

    // Execution info
    if let Some(execution) = system.get("Execution") {
        if let Some(attrs) = execution.get("#attributes").and_then(|v| v.as_object()) {
            if let Some(process_id) = attrs.get("ProcessID") {
                result.insert("ProcessID".into(), process_id.clone());
            }
            if let Some(thread_id) = attrs.get("ThreadID") {
                result.insert("ThreadID".into(), thread_id.clone());
            }
        }
    }

    // Computer, Security
    if let Some(computer) = system.get("Computer") {
        result.insert("Computer".into(), computer.clone());
    }
    if let Some(security) = system.get("Security") {
        if let Some(attrs) = security.get("#attributes").and_then(|v| v.as_object()) {
            if let Some(user_id) = attrs.get("UserID") {
                result.insert("UserID".into(), user_id.clone());
            }
        }
    }

    // Other System fields (Version, Level, Task, Opcode, Keywords)
    for key in &["Version", "Level", "Task", "Opcode", "Keywords"] {
        if let Some(val) = system.get(*key) {
            result.insert(key.to_string(), Value::String(val.to_string()));
        }
    }

    // EventData fields (flattened into top-level)
    if let Some(event_data) = event.get("EventData").and_then(|v| v.as_object()) {
        for (key, value) in event_data {
            if key != "#attributes" && !key.starts_with('#') {
                result.insert(key.clone(), value.clone());
            }
        }
    }

    // UserData fields (flattened into top-level for XML-based event logs)
    if let Some(user_data) = event.get("UserData").and_then(|v| v.as_object()) {
        for (key, value) in user_data {
            if key != "#attributes" && !key.starts_with('#') {
                match value {
                    Value::String(s) => {
                        result.insert(key.clone(), Value::String(s.clone()));
                    }
                    Value::Object(m) => {
                        // For nested objects like Operation_ClientFailure, flatten one more level
                        for (nested_key, nested_val) in m {
                            if nested_key != "#attributes" && !nested_key.starts_with('#') {
                                let full_key = format!("{}.{}", key, nested_key);
                                result.insert(full_key, nested_val.clone());
                            }
                        }
                    }
                    _ => {
                        result.insert(key.clone(), value.clone());
                    }
                }
            }
        }
    }

    result.insert("_source".into(), Value::String("winevt".to_string()));

    Value::Object(result)
}

// ─── Validation ───────────────────────────────────────────────────────────────

struct ValidationStats {
    total: usize,
    passed: usize,
    failed: Vec<(String, String)>,
}

impl ValidationStats {
    fn new() -> Self {
        Self {
            total: 0,
            passed: 0,
            failed: Vec::new(),
        }
    }

    fn add_pass(&mut self) {
        self.passed += 1;
    }

    fn add_fail(&mut self, rule_name: String, error: String) {
        self.failed.push((rule_name, error));
    }

    fn print_summary(&self) {
        println!("\n{}", "=".repeat(60));
        println!("  VALIDATION SUMMARY");
        println!("{}", "=".repeat(60));
        println!("  Total rules:     {}", self.total);
        println!("  Passed:          {}", self.passed);
        println!("  Failed:          {}", self.failed.len());
        println!(
            "  Pass rate:       {:.1}%",
            if self.total > 0 {
                (self.passed as f64 / self.total as f64) * 100.0
            } else {
                0.0
            }
        );
        println!("{}", "=".repeat(60));

        if !self.failed.is_empty() {
            println!("\nFailed rules:");
            for (name, error) in &self.failed {
                println!("  FAIL {} — {}", name, error);
            }
        }
    }
}

fn validate_triplet(
    triplet: &RegressionTriplet,
    sigma_dir: &Path,
) -> Result<(String, bool, String)> {
    let rule_path = find_rule_file(&triplet.info_path, sigma_dir).map_err(|e| anyhow!("{}", e))?;

    let rule_name = triplet
        .info_path
        .parent()
        .and_then(|p| p.file_name())
        .and_then(|n| n.to_str())
        .unwrap_or("unknown");

    let rule_content =
        fs::read_to_string(&rule_path).map_err(|e| anyhow!("Failed to read rule: {}", e))?;

    let collection =
        parse_sigma_yaml(&rule_content).map_err(|e| anyhow!("Failed to parse rule YAML: {}", e))?;

    if collection.rules.is_empty() {
        return Err(anyhow!("No rules found in {}", rule_path.display()));
    }

    let rule = &collection.rules[0];
    let rule_id = rule.id.as_deref().unwrap_or("unknown");

    // Parse EVTX using the evtx crate and normalize JSON to match Winevt XmlParser output.
    // The evtx crate returns nested JSON (Event.System.EventID, Event.EventData.CommandLine)
    // but our Winevt parser flattens it to top-level keys (EventID, Channel, CommandLine, etc.).
    let mut parser = EvtxParser::from_path(&triplet.evtx_path)
        .map_err(|e| anyhow!("Failed to open EVTX file: {}", e))?;

    let mut events: Vec<Value> = Vec::new();
    for json_record in parser.records_json_value().flatten() {
        // json_record.data is the nested JSON from the evtx crate.
        // Normalize to flattened Winevt-style format.
        let normalized = normalize_evtx_json(&json_record.data);
        events.push(normalized);
    }

    if events.is_empty() {
        return Err(anyhow!(
            "No events extracted from EVTX: {}",
            triplet.evtx_path.display()
        ));
    }

    let first_event = events[0].clone();

    // Derive the event's logsource from its Channel, ProviderName, and EventID
    // (same as the WinevtCollector does via resolve_logsource).
    let channel = first_event
        .get("Channel")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let provider = first_event
        .get("ProviderName")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let event_id_str = first_event
        .get("EventID")
        .and_then(|v| v.as_str())
        .unwrap_or("0");
    let event_id: u32 = event_id_str.parse().unwrap_or(0);

    let event_logsource = resolve_logsource(
        channel,
        provider,
        event_id,
        &HashMap::new(),
        Some(&first_event),
    );

    let mut engine = Engine::new();

    engine
        .add_collection(&collection)
        .map_err(|e| anyhow!("Engine add_collection failed: {}", e))?;

    let json_event = JsonEvent::borrow(&first_event);
    let matches = engine.evaluate_with_logsource(&json_event, &event_logsource);

    let result = if matches.is_empty() {
        Err(anyhow!(
            "FALSE NEGATIVE — no matches (EventID={}, Channel={:?}, provider={:?})",
            first_event
                .get("EventID")
                .and_then(|v| v.as_str())
                .unwrap_or("0"),
            first_event.get("Channel").and_then(|v| v.as_str()),
            first_event.get("ProviderName").and_then(|v| v.as_str()),
        ))
    } else {
        Ok(format!("{} match(es)", matches.len()))
    };

    let is_pass = result.is_ok();
    let detail = result.unwrap_or_else(|e| e.to_string());

    Ok((format!("{} ({})", rule_name, rule_id), is_pass, detail))
}

// ─── Main ─────────────────────────────────────────────────────────────────────

fn main() {
    let args: Vec<String> = std::env::args().collect();

    if args.len() < 2 {
        eprintln!("Usage: validate_motor <sigmahq_dir>");
        eprintln!();
        eprintln!("Scans <sigmahq_dir>/regression_data/ for info.yml triplets");
        eprintln!("and validates the detection engine against each one.");
        eprintln!();
        eprintln!("Example:");
        eprintln!("  cargo run --release --example validate_motor ./sigma");
        std::process::exit(1);
    }

    let sigma_dir = PathBuf::from(&args[1]);
    let regression_dir = sigma_dir.join("regression_data");

    println!("SigmaHQ directory: {}", sigma_dir.display());
    println!("Scanning regression data: {}", regression_dir.display());
    println!();

    let triplets = match scan_regression_data(&regression_dir) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("Failed to scan regression data: {}", e);
            std::process::exit(1);
        }
    };

    if triplets.is_empty() {
        eprintln!(
            "No regression triplets found in {}",
            regression_dir.display()
        );
        std::process::exit(1);
    }

    println!("Found {} regression triplet(s)", triplets.len());
    println!();
    println!("Running validation...");
    println!();

    let mut stats = ValidationStats::new();
    let mut skipped: Vec<(String, String)> = Vec::new();

    for triplet in &triplets {
        stats.total += 1;
        let name = triplet
            .info_path
            .parent()
            .and_then(|p| p.file_name())
            .and_then(|n| n.to_str())
            .unwrap_or("unknown")
            .to_string();

        let evtx_exists = triplet.evtx_path.exists();
        let evtx_size = if evtx_exists {
            fs::metadata(&triplet.evtx_path)
                .map(|m| m.len())
                .unwrap_or(0)
        } else {
            0
        };

        print!(
            "  [{:>4}/{:<4}] {:<50} ... ",
            stats.passed + stats.failed.len(),
            stats.total,
            name
        );

        if !evtx_exists {
            skipped.push((name.clone(), "evtx file missing".to_string()));
            println!("[SKIP] evtx file missing");
            continue;
        }

        if evtx_size < 0x1000 {
            skipped.push((
                name.clone(),
                format!("evtx too small ({} bytes)", evtx_size),
            ));
            println!("[SKIP] evtx too small ({} bytes)", evtx_size);
            continue;
        }

        match validate_triplet(triplet, &sigma_dir) {
            Ok((display_name, is_pass, detail)) => {
                if is_pass {
                    stats.add_pass();
                    println!("[PASS] {}", detail);
                } else {
                    let msg = detail.clone();
                    stats.add_fail(display_name.clone(), msg);
                    println!("[FAIL] {}", detail);
                }
            }
            Err(e) => {
                let msg = e.to_string();
                stats.add_fail(name.clone(), msg);
                println!("[FAIL] {}", e);
            }
        }
    }

    if !skipped.is_empty() {
        println!("\n[SKIPPED] {} triplet(s) (missing data):", skipped.len());
        for (name, reason) in &skipped {
            println!("  - {} — {}", name, reason);
        }
    }

    stats.print_summary();

    if !stats.failed.is_empty() {
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_find_rule_by_id() {
        let dir = tempfile::tempdir().unwrap();
        let yml_path = dir.path().join("test_rule.yml");
        fs::write(&yml_path, "id: abc123\ntitle: Test\n").unwrap();

        let found = find_rule_by_id(dir.path(), "abc123");
        assert!(found.is_ok());
        assert_eq!(found.unwrap(), yml_path);
    }

    #[test]
    fn test_find_rule_by_id_not_found() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("other.yml"), "id: xyz789\n").unwrap();

        let found = find_rule_by_id(dir.path(), "abc123");
        assert!(found.is_err());
    }
}
