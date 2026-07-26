// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 sigmacatch contributors

pub mod channel_list;

use rsigma_parser::LogSource;
use std::collections::HashMap;

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

// ─── Channel:EventID → Category (composite key "channel:eid") ───────────────
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

// ─── Sub-category overrides (higher specificity) ────────────────────────────
static CHANNEL_EVENT_TO_SUBCATEGORY: phf::Map<&'static str, &'static str> = phf::phf_map! {
    "Microsoft-Windows-Sysmon/Operational:12" => "registry_add",
    "Microsoft-Windows-Sysmon/Operational:13" => "registry_set",
    "Microsoft-Windows-Sysmon/Operational:14" => "registry_rename",
};

// ─── Provider → Service (fallback when channel unknown) ────────────────────
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

fn get_category(channel: &str, event_id: u32) -> Option<&'static str> {
    let composite_key = format!("{}:{}", channel, event_id);
    CHANNEL_EVENT_TO_SUBCATEGORY
        .get(&composite_key)
        .copied()
        .or_else(|| CHANNEL_EVENT_TO_CATEGORY.get(&composite_key).copied())
}

/// Resolve LogSource from channel, provider, and event_id.
///
/// INVARIANT: channel > provider > default
/// Priority order MUST NOT be changed:
///   1. Channel → service (CHANNEL_TO_SERVICE_MAP + custom_map override)
///   2. Provider → service (PROVIDER_TO_SERVICE) fallback
///   3. Default: product=windows, service=None, category=None
pub fn resolve_logsource(
    channel: &str,
    provider: &str,
    event_id: u32,
    custom_map: &HashMap<String, String>,
) -> LogSource {
    if let Some(service) = custom_map.get(channel) {
        tracing::debug!(
            "LogSource resolved via custom_map: service={}, category={:?}",
            service,
            get_category(channel, event_id)
        );
        return LogSource {
            product: Some("windows".into()),
            service: Some(service.clone()),
            category: get_category(channel, event_id).map(|s| s.to_string()),
            ..LogSource::default()
        };
    }

    if let Some(service) = CHANNEL_TO_SERVICE.get(channel) {
        let category = get_category(channel, event_id);
        tracing::debug!(
            "LogSource resolved via channel: service={}, category={:?}",
            service,
            category
        );
        return LogSource {
            product: Some("windows".into()),
            service: Some(service.to_string()),
            category: category.map(|s| s.to_string()),
            ..LogSource::default()
        };
    }

    if let Some(service) = PROVIDER_TO_SERVICE.get(provider) {
        tracing::debug!(
            "LogSource resolved via provider fallback: service={}",
            service
        );
        return LogSource {
            product: Some("windows".into()),
            service: Some(service.to_string()),
            category: None,
            ..LogSource::default()
        };
    }

    tracing::debug!("LogSource resolved via default: product=windows");
    LogSource {
        product: Some("windows".into()),
        service: None,
        category: None,
        ..LogSource::default()
    }
}

/// Build a reverse map: service (or service:category) → Vec<ChannelTarget>.
#[derive(Debug, Clone)]
pub struct ChannelTarget {
    pub channel: String,
    pub event_ids: Option<Vec<u32>>,
}

pub fn build_logsource_to_channels(
    custom_map: &HashMap<String, String>,
) -> HashMap<String, Vec<ChannelTarget>> {
    let mut service_targets: HashMap<String, Vec<String>> = HashMap::new();
    let mut category_targets: HashMap<String, Vec<(String, Vec<u32>)>> = HashMap::new();

    for (channel, service) in &CHANNEL_TO_SERVICE {
        service_targets
            .entry(service.to_string())
            .or_default()
            .push(channel.to_string());
    }

    for (channel, service) in custom_map {
        service_targets
            .entry(service.clone())
            .or_default()
            .push(channel.clone());
    }

    for (key, category) in &CHANNEL_EVENT_TO_CATEGORY {
        if let Some(colon_pos) = key.rfind(':') {
            let channel = &key[..colon_pos];
            let eid_str = &key[colon_pos + 1..];
            if let Ok(eid) = eid_str.parse::<u32>() {
                if let Some(service) = CHANNEL_TO_SERVICE.get(channel) {
                    let cat_key = format!("{}:{}", service, category);
                    category_targets
                        .entry(cat_key)
                        .or_default()
                        .push((channel.to_string(), vec![eid]));
                }
            }
        }
    }

    for (key, subcat) in &CHANNEL_EVENT_TO_SUBCATEGORY {
        if let Some(colon_pos) = key.rfind(':') {
            let channel = &key[..colon_pos];
            let eid_str = &key[colon_pos + 1..];
            if let Ok(eid) = eid_str.parse::<u32>() {
                if let Some(service) = CHANNEL_TO_SERVICE.get(channel) {
                    let subcat_key = format!("{}:{}", service, subcat);
                    let parent_key = format!(
                        "{}:{}",
                        service,
                        CHANNEL_EVENT_TO_CATEGORY
                            .get(key)
                            .copied()
                            .unwrap_or_default()
                    );
                    category_targets
                        .entry(subcat_key)
                        .or_default()
                        .push((channel.to_string(), vec![eid]));
                    if let Some(parent_targets) = category_targets.get_mut(&parent_key) {
                        parent_targets.push((channel.to_string(), vec![eid]));
                    }
                }
            }
        }
    }

    let mut merged: HashMap<String, Vec<ChannelTarget>> = HashMap::new();

    for (service, channels) in service_targets {
        let mut targets: Vec<ChannelTarget> = channels
            .into_iter()
            .map(|channel| ChannelTarget {
                channel,
                event_ids: None,
            })
            .collect();
        targets.sort_by(|a, b| a.channel.cmp(&b.channel));
        merged.insert(service, targets);
    }

    for (cat_key, targets) in category_targets {
        let existing: Vec<ChannelTarget> = merged.remove(&cat_key).unwrap_or_default();
        let mut by_channel: HashMap<String, Vec<u32>> = HashMap::new();
        for (channel, eids) in targets {
            by_channel.entry(channel).or_default().extend(eids);
        }
        let mut merged_targets: Vec<ChannelTarget> = by_channel
            .into_iter()
            .map(|(channel, mut eids)| {
                eids.sort();
                eids.dedup();
                ChannelTarget {
                    channel,
                    event_ids: Some(eids),
                }
            })
            .collect();
        merged_targets.extend(existing);
        merged_targets.sort_by(|a, b| a.channel.cmp(&b.channel));
        merged.insert(cat_key, merged_targets);
    }

    merged
}
