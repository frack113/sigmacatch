// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 sigmacatch contributors

use crate::SigmaCollection;
use sigmacatch_types::{
    CHANNEL_EVENT_TO_CATEGORY, CHANNEL_EVENT_TO_SUBCATEGORY, CHANNEL_TO_SERVICE,
};
use std::collections::{HashMap, HashSet};

/// All channels to collect from via Winevt API.
pub const ALL_CHANNELS: &[&str] = &[
    // 95 channels
    // Standard Windows logs
    "Application",
    "System",
    "Security",
    // Sysmon
    "Microsoft-Windows-Sysmon/Operational",
    // DNS
    "DNS Server",
    "Microsoft-Windows-DNS-Server/Analytical",
    "Microsoft-Windows-DNS-Server/Audit",
    "Microsoft-Windows-DNS Client Events/Operational",
    // DHCP
    "Microsoft-Windows-DHCP-Server/Operational",
    // Driver Frameworks
    "Microsoft-Windows-DriverFrameworks-UserMode/Operational",
    // Hyper-V
    "Microsoft-Windows-Hyper-V-Worker",
    // IIS
    "Microsoft-IIS-Configuration/Operational",
    // Kernel
    "Microsoft-Windows-Kernel-EventTracing",
    "Microsoft-Windows-Kernel-ShimEngine/Operational",
    "Microsoft-Windows-Kernel-ShimEngine/Diagnostic",
    // LDAP
    "Microsoft-Windows-LDAP-Client/Debug",
    // LSA
    "Microsoft-Windows-LSA/Operational",
    // NTLM
    "Microsoft-Windows-NTLM/Operational",
    // NTFS
    "Microsoft-Windows-Ntfs/Operational",
    // OpenSSH
    "OpenSSH/Operational",
    // Print Service
    "Microsoft-Windows-PrintService/Admin",
    "Microsoft-Windows-PrintService/Operational",
    // AppLocker
    "Microsoft-Windows-AppLocker/EXE and DLL",
    "Microsoft-Windows-AppLocker/MSI and Script",
    "Microsoft-Windows-AppLocker/Packaged app-Deployment",
    "Microsoft-Windows-AppLocker/Packaged app-Execution",
    // AppModel Runtime
    "Microsoft-Windows-AppModel-Runtime/Admin",
    // AppX
    "Microsoft-Windows-AppXDeploymentServer/Operational",
    "Microsoft-Windows-AppxPackaging/Operational",
    // Application Experience
    "Microsoft-Windows-Application-Experience/Program-Telemetry",
    "Microsoft-Windows-Application-Experience/Program-Compatibility-Assistant",
    // BitLocker
    "Microsoft-Windows-BitLocker/BitLocker Management",
    // BITS
    "Microsoft-Windows-Bits-Client/Operational",
    // CAPI2
    "Microsoft-Windows-CAPI2/Operational",
    // Certificate Services Client
    "Microsoft-Windows-CertificateServicesClient-Lifecycle-System/Operational",
    // Code Integrity
    "Microsoft-Windows-CodeIntegrity/Operational",
    // SENSE
    "Microsoft-Windows-SENSE/Operational",
    // Service Bus
    "Microsoft-ServiceBus-Client/Operational",
    "Microsoft-ServiceBus-Client/Admin",
    // Shell Core
    "Microsoft-Windows-Shell-Core/Operational",
    // Security Mitigations
    "Microsoft-Windows-Security-Mitigations/Kernel Mode",
    "Microsoft-Windows-Security-Mitigations/User Mode",
    // Terminal Services
    "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational",
    // VHDMP
    "Microsoft-Windows-VHDMP/Operational",
    // Windows Defender
    "Microsoft-Windows-Windows Defender/Operational",
    // Windows Firewall
    "Microsoft-Windows-Windows Firewall With Advanced Security/Firewall",
    // Diagnosis
    "Microsoft-Windows-Diagnosis-Scripted/Operational",
    // MSExchange
    "MSExchange Management",
    // SMB Client
    "Microsoft-Windows-SmbClient/Security",
    // PowerShell
    "Windows PowerShell",
    "Microsoft-Windows-PowerShell/Operational",
    "PowerShellCore/Operational",
    // Task Scheduler
    "Microsoft-Windows-TaskScheduler/Operational",
    // WMI
    "Microsoft-Windows-WMI-Activity/Operational",
];

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

/// Resolve channels from a Sigma collection by extracting service/category pairs.
///
/// For each rule in the collection, extracts `logsource.service` and
/// `logsource.category` to determine which Windows Event Log channels
/// are needed. Rules without a service trigger all channels (conservative
/// fallback). Rules whose service/category cannot be mapped to any channel
/// also trigger all channels (fail-open): the mapping tables are never
/// complete, and silently dropping such rules would produce no regression
/// data for them.
pub fn resolve_channels_from_collection(
    collection: &SigmaCollection,
    custom_map: &HashMap<String, String>,
) -> Vec<String> {
    if collection.rules.is_empty() {
        tracing::info!("No rules loaded — cannot resolve channels");
        return Vec::new();
    }

    let map = build_logsource_to_channels(custom_map);
    let mut channels_set: HashSet<String> = HashSet::new();
    let mut any_without_service = false;
    let mut any_unresolved = false;
    let mut unresolved_rules: usize = 0;
    let mut unresolved_logsources: HashSet<String> = HashSet::new();

    for rule in &collection.rules {
        if !rule
            .logsource
            .product
            .as_deref()
            .map(|p| p.eq_ignore_ascii_case("windows"))
            .unwrap_or(false)
        {
            continue;
        }

        match (&rule.logsource.service, &rule.logsource.category) {
            (Some(service), Some(category)) => {
                let key = format!("{}:{}", service, category);
                if let Some(targets) = map.get(&key) {
                    for t in targets {
                        channels_set.insert(t.channel.clone());
                    }
                } else {
                    any_unresolved = true;
                    unresolved_rules += 1;
                    unresolved_logsources.insert(key);
                }
            }
            (Some(service), None) => {
                if let Some(targets) = map.get(service) {
                    for t in targets {
                        channels_set.insert(t.channel.clone());
                    }
                } else {
                    any_unresolved = true;
                    unresolved_rules += 1;
                    unresolved_logsources.insert(service.clone());
                }
            }
            (None, Some(category)) => {
                // Category-only: find channels whose category matches
                let mut found = false;
                for (key, cat) in &CHANNEL_EVENT_TO_CATEGORY {
                    if cat == category {
                        if let Some(colon_pos) = key.rfind(':') {
                            let channel = &key[..colon_pos];
                            channels_set.insert(channel.to_string());
                            found = true;
                        }
                    }
                }
                for (key, subcat) in &CHANNEL_EVENT_TO_SUBCATEGORY {
                    if subcat == category {
                        if let Some(colon_pos) = key.rfind(':') {
                            let channel = &key[..colon_pos];
                            channels_set.insert(channel.to_string());
                            found = true;
                        }
                    }
                }
                if !found {
                    any_unresolved = true;
                    unresolved_rules += 1;
                    unresolved_logsources.insert(category.clone());
                }
            }
            (None, None) => {
                any_without_service = true;
            }
        }
    }

    if any_without_service || any_unresolved {
        if any_unresolved {
            let mut sorted: Vec<String> = unresolved_logsources.into_iter().collect();
            sorted.sort();
            tracing::warn!(
                "{unresolved_rules} rules with unmapped logsource (service/category) — failing open to all channels: {sorted:?}"
            );
        }
        for targets in map.values() {
            for t in targets {
                channels_set.insert(t.channel.clone());
            }
        }
    }

    let mut channels: Vec<String> = channels_set.into_iter().collect();
    channels.sort();

    tracing::info!("Channels to collect: {:?}", channels);

    channels
}
