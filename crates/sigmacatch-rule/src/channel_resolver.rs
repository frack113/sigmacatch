// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 sigmacatch contributors

use crate::SigmaRule;
use std::collections::{HashMap, HashSet};

/// Channel lookup key: (product, service, category) — the three fields of a Sigma LogSource.
static LOGSOURCE_CHANNELS: phf::Map<
    (&'static str, &'static str, &'static str),
    &'static [&'static str],
> = phf::phf_map! {
    ("windows", "application", "") => &["Application"],
    ("windows", "application-experience", "") => &[
        "Microsoft-Windows-Application-Experience/Program-Telemetry",
        "Microsoft-Windows-Application-Experience/Program-Compatibility-Assistant",
    ],
    ("windows", "applocker", "") => &[
        "Microsoft-Windows-AppLocker/EXE and DLL",
        "Microsoft-Windows-AppLocker/MSI and Script",
        "Microsoft-Windows-AppLocker/Packaged app-Deployment",
        "Microsoft-Windows-AppLocker/Packaged app-Execution",
    ],
    ("windows", "appmodel-runtime", "") => &["Microsoft-Windows-AppModel-Runtime/Admin"],
    ("windows", "appxdeployment-server", "") => &["Microsoft-Windows-AppXDeploymentServer/Operational"],
    ("windows", "appxpackaging-om", "") => &["Microsoft-Windows-AppxPackaging/Operational"],
    ("windows", "bitlocker", "") => &["Microsoft-Windows-BitLocker/BitLocker Management"],
    ("windows", "bits-client", "") => &["Microsoft-Windows-Bits-Client/Operational"],
    ("windows", "capi2", "") => &["Microsoft-Windows-CAPI2/Operational"],
    ("windows", "certificateservicesclient-lifecycle-system", "") => &[
        "Microsoft-Windows-CertificateServicesClient-Lifecycle-System/Operational",
    ],
    ("windows", "codeintegrity-operational", "") => &["Microsoft-Windows-CodeIntegrity/Operational"],
    ("windows", "dhcp", "") => &["Microsoft-Windows-DHCP-Server/Operational"],
    ("windows", "diagnosis-scripted", "") => &["Microsoft-Windows-Diagnosis-Scripted/Operational"],
    ("windows", "dns-client", "") => &["Microsoft-Windows-DNS Client Events/Operational"],
    ("windows", "dns-server", "") => &["DNS Server"],
    ("windows", "dns-server-analytic", "") => &["Microsoft-Windows-DNS-Server/Analytical"],
    ("windows", "dns-server-audit", "") => &["Microsoft-Windows-DNS-Server/Audit"],
    ("windows", "driver-framework", "") => &["Microsoft-Windows-DriverFrameworks-UserMode/Operational"],
    ("windows", "firewall-as", "") => &[
        "Microsoft-Windows-Windows Firewall With Advanced Security/Firewall",
    ],
    ("windows", "hyper-v-worker", "") => &["Microsoft-Windows-Hyper-V-Worker"],
    ("windows", "iis-configuration", "") => &["Microsoft-IIS-Configuration/Operational"],
    ("windows", "kernel-event-tracing", "") => &["Microsoft-Windows-Kernel-EventTracing"],
    ("windows", "kernel-shimengine", "") => &[
        "Microsoft-Windows-Kernel-ShimEngine/Operational",
        "Microsoft-Windows-Kernel-ShimEngine/Diagnostic",
    ],
    ("windows", "ldap", "") => &["Microsoft-Windows-LDAP-Client/Debug"],
    ("windows", "lsa-server", "") => &["Microsoft-Windows-LSA/Operational"],
    ("windows", "msexchange-management", "") => &["MSExchange Management"],
    ("windows", "ntfs", "") => &["Microsoft-Windows-Ntfs/Operational"],
    ("windows", "ntlm", "") => &["Microsoft-Windows-NTLM/Operational"],
    ("windows", "openssh", "") => &["OpenSSH/Operational"],
    ("windows", "powershell", "") => &[
        "Microsoft-Windows-PowerShell/Operational",
        "PowerShellCore/Operational",
    ],
    ("windows", "powershell-classic", "") => &["Windows PowerShell"],
    ("windows", "printservice-admin", "") => &["Microsoft-Windows-PrintService/Admin"],
    ("windows", "printservice-operational", "") => &["Microsoft-Windows-PrintService/Operational"],
    ("windows", "security", "") => &["Security"],
    ("windows", "security-mitigations", "") => &[
        "Microsoft-Windows-Security-Mitigations/Kernel Mode",
        "Microsoft-Windows-Security-Mitigations/User Mode",
    ],
    ("windows", "sense", "") => &["Microsoft-Windows-SENSE/Operational"],
    ("windows", "servicebus-client", "") => &[
        "Microsoft-ServiceBus-Client/Operational",
        "Microsoft-ServiceBus-Client/Admin",
    ],
    ("windows", "shell-core", "") => &["Microsoft-Windows-Shell-Core/Operational"],
    ("windows", "smbclient-security", "") => &["Microsoft-Windows-SmbClient/Security"],
    ("windows", "sysmon", "") => &["Microsoft-Windows-Sysmon/Operational"],
    ("windows", "system", "") => &["System"],
    ("windows", "taskscheduler", "") => &["Microsoft-Windows-TaskScheduler/Operational"],
    ("windows", "terminalservices-localsessionmanager", "") => &[
        "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational",
    ],
    ("windows", "vhdmp", "") => &["Microsoft-Windows-VHDMP/Operational"],
    ("windows", "windefend", "") => &["Microsoft-Windows-Windows Defender/Operational"],
    ("windows", "wmi", "") => &["Microsoft-Windows-WMI-Activity/Operational"],

    ("windows", "", "clipboard_capture") => &["Microsoft-Windows-Sysmon/Operational"],
    ("windows", "", "create_remote_thread") => &["Microsoft-Windows-Sysmon/Operational"],
    ("windows", "", "create_stream_hash") => &["Microsoft-Windows-Sysmon/Operational"],
    ("windows", "", "dns_query") => &["Microsoft-Windows-Sysmon/Operational"],
    ("windows", "", "driver_load") => &["Microsoft-Windows-Sysmon/Operational"],
    ("windows", "", "file_block_executable") => &["Microsoft-Windows-Sysmon/Operational"],
    ("windows", "", "file_block_shredding") => &["Microsoft-Windows-Sysmon/Operational"],
    ("windows", "", "file_change") => &["Microsoft-Windows-Sysmon/Operational"],
    ("windows", "", "file_delete") => &["Microsoft-Windows-Sysmon/Operational"],
    ("windows", "", "file_delete_detected") => &["Microsoft-Windows-Sysmon/Operational"],
    ("windows", "", "file_event") => &["Microsoft-Windows-Sysmon/Operational"],
    ("windows", "", "file_executable_detected") => &["Microsoft-Windows-Sysmon/Operational"],
    ("windows", "", "image_load") => &["Microsoft-Windows-Sysmon/Operational"],
    ("windows", "", "login") => &["Security"],
    ("windows", "", "login_failure") => &["Security"],
    ("windows", "", "logoff") => &["Security"],
    ("windows", "", "network_connection") => &["Microsoft-Windows-Sysmon/Operational"],
    ("windows", "", "pipe_created") => &["Microsoft-Windows-Sysmon/Operational"],
    ("windows", "", "privilege_use") => &["Security"],
    ("windows", "", "process_access") => &["Microsoft-Windows-Sysmon/Operational"],
    ("windows", "", "process_creation") => &[
        "Microsoft-Windows-Sysmon/Operational",
        "Security",
    ],
    ("windows", "", "process_tampering") => &["Microsoft-Windows-Sysmon/Operational"],
    ("windows", "", "process_termination") => &["Microsoft-Windows-Sysmon/Operational"],
    ("windows", "", "ps_classic_provider_start") => &["Windows PowerShell"],
    ("windows", "", "ps_classic_script") => &["Windows PowerShell"],
    ("windows", "", "ps_classic_start") => &["Windows PowerShell"],
    ("windows", "", "ps_module") => &[
        "Microsoft-Windows-PowerShell/Operational",
        "PowerShellCore/Operational",
    ],
    ("windows", "", "ps_script") => &[
        "Microsoft-Windows-PowerShell/Operational",
        "PowerShellCore/Operational",
    ],
    ("windows", "", "raw_access_thread") => &["Microsoft-Windows-Sysmon/Operational"],
    ("windows", "", "registry_add") => &["Microsoft-Windows-Sysmon/Operational"],
    ("windows", "", "registry_delete") => &["Microsoft-Windows-Sysmon/Operational"],
    ("windows", "", "registry_event") => &["Microsoft-Windows-Sysmon/Operational"],
    ("windows", "", "registry_rename") => &["Microsoft-Windows-Sysmon/Operational"],
    ("windows", "", "registry_set") => &["Microsoft-Windows-Sysmon/Operational"],
    ("windows", "", "sysmon_error") => &["Microsoft-Windows-Sysmon/Operational"],
    ("windows", "", "sysmon_status") => &["Microsoft-Windows-Sysmon/Operational"],
    ("windows", "", "wmi_event") => &["Microsoft-Windows-Sysmon/Operational"],

    ("windows", "powershell", "ps_module") => &[
        "Microsoft-Windows-PowerShell/Operational",
        "PowerShellCore/Operational",
    ],
    ("windows", "powershell", "ps_script") => &[
        "Microsoft-Windows-PowerShell/Operational",
        "PowerShellCore/Operational",
    ],
    ("windows", "powershell-classic", "ps_classic_provider_start") => &["Windows PowerShell"],
    ("windows", "powershell-classic", "ps_classic_script") => &["Windows PowerShell"],
    ("windows", "powershell-classic", "ps_classic_start") => &["Windows PowerShell"],
    ("windows", "security", "login") => &["Security"],
    ("windows", "security", "login_failure") => &["Security"],
    ("windows", "security", "logoff") => &["Security"],
    ("windows", "security", "privilege_use") => &["Security"],
    ("windows", "security", "process_creation") => &["Security"],
    ("windows", "sysmon", "clipboard_capture") => &["Microsoft-Windows-Sysmon/Operational"],
    ("windows", "sysmon", "create_remote_thread") => &["Microsoft-Windows-Sysmon/Operational"],
    ("windows", "sysmon", "create_stream_hash") => &["Microsoft-Windows-Sysmon/Operational"],
    ("windows", "sysmon", "dns_query") => &["Microsoft-Windows-Sysmon/Operational"],
    ("windows", "sysmon", "driver_load") => &["Microsoft-Windows-Sysmon/Operational"],
    ("windows", "sysmon", "file_block_executable") => &["Microsoft-Windows-Sysmon/Operational"],
    ("windows", "sysmon", "file_block_shredding") => &["Microsoft-Windows-Sysmon/Operational"],
    ("windows", "sysmon", "file_change") => &["Microsoft-Windows-Sysmon/Operational"],
    ("windows", "sysmon", "file_delete") => &["Microsoft-Windows-Sysmon/Operational"],
    ("windows", "sysmon", "file_delete_detected") => &["Microsoft-Windows-Sysmon/Operational"],
    ("windows", "sysmon", "file_event") => &["Microsoft-Windows-Sysmon/Operational"],
    ("windows", "sysmon", "file_executable_detected") => &["Microsoft-Windows-Sysmon/Operational"],
    ("windows", "sysmon", "image_load") => &["Microsoft-Windows-Sysmon/Operational"],
    ("windows", "sysmon", "network_connection") => &["Microsoft-Windows-Sysmon/Operational"],
    ("windows", "sysmon", "pipe_created") => &["Microsoft-Windows-Sysmon/Operational"],
    ("windows", "sysmon", "process_access") => &["Microsoft-Windows-Sysmon/Operational"],
    ("windows", "sysmon", "process_creation") => &["Microsoft-Windows-Sysmon/Operational"],
    ("windows", "sysmon", "process_tampering") => &["Microsoft-Windows-Sysmon/Operational"],
    ("windows", "sysmon", "process_termination") => &["Microsoft-Windows-Sysmon/Operational"],
    ("windows", "sysmon", "raw_access_thread") => &["Microsoft-Windows-Sysmon/Operational"],
    ("windows", "sysmon", "registry_add") => &["Microsoft-Windows-Sysmon/Operational"],
    ("windows", "sysmon", "registry_delete") => &["Microsoft-Windows-Sysmon/Operational"],
    ("windows", "sysmon", "registry_event") => &["Microsoft-Windows-Sysmon/Operational"],
    ("windows", "sysmon", "registry_rename") => &["Microsoft-Windows-Sysmon/Operational"],
    ("windows", "sysmon", "registry_set") => &["Microsoft-Windows-Sysmon/Operational"],
    ("windows", "sysmon", "sysmon_error") => &["Microsoft-Windows-Sysmon/Operational"],
    ("windows", "sysmon", "sysmon_status") => &["Microsoft-Windows-Sysmon/Operational"],
    ("windows", "sysmon", "wmi_event") => &["Microsoft-Windows-Sysmon/Operational"],
};

pub(crate) fn resolve_channels(
    rules: &[SigmaRule],
    custom_map: &HashMap<String, String>,
) -> Vec<String> {
    if rules.is_empty() {
        tracing::info!("No rules loaded — cannot resolve channels");
        return Vec::new();
    }

    let mut channels_set: HashSet<String> = HashSet::new();
    let mut unresolved_rules: usize = 0;
    let mut unresolved_logsources: HashSet<String> = HashSet::new();
    let mut rules_without_logsource: usize = 0;

    for rule in rules {
        if !rule
            .logsource
            .product
            .as_deref()
            .map(|p| p.eq_ignore_ascii_case("windows"))
            .unwrap_or(false)
        {
            continue;
        }

        let service = rule.logsource.service.as_deref();
        let category = rule.logsource.category.as_deref();

        // Priority lookup: (product, service, category) → (product, service, "") → (product, "", category)
        let mut targets: Vec<&str> = Vec::new();

        if let (Some(s), Some(c)) = (service, category) {
            if let Some(static_targets) = LOGSOURCE_CHANNELS.get(&("windows", s, c)) {
                targets.extend(static_targets.iter().copied());
            }
        } else if let Some(s) = service {
            if let Some(static_targets) = LOGSOURCE_CHANNELS.get(&("windows", s, "")) {
                targets.extend(static_targets.iter().copied());
            }
            for (channel, custom_service) in custom_map {
                if custom_service == s {
                    targets.push(channel);
                }
            }
        } else if let Some(c) = category {
            if let Some(static_targets) = LOGSOURCE_CHANNELS.get(&("windows", "", c)) {
                targets.extend(static_targets.iter().copied());
            }
        }

        if targets.is_empty() {
            let has_service = rule.logsource.service.is_some();
            let has_category = rule.logsource.category.is_some();
            if !has_service && !has_category {
                rules_without_logsource += 1;
            } else {
                unresolved_rules += 1;
                unresolved_logsources.insert(format!(
                    "{}:{}",
                    rule.logsource.service.as_deref().unwrap_or("*"),
                    rule.logsource.category.as_deref().unwrap_or("*")
                ));
            }
        } else {
            channels_set.extend(targets.into_iter().map(str::to_string));
        }
    }

    if rules_without_logsource > 0 {
        tracing::warn!(
            "{rules_without_logsource} rules have no logsource (service/category) — no channels resolved from them"
        );
    }
    if unresolved_rules > 0 {
        let mut sorted: Vec<String> = unresolved_logsources.into_iter().collect();
        sorted.sort();
        tracing::warn!(
            "{unresolved_rules} rules with unmapped logsource (service/category) — no channels resolved from them: {sorted:?}"
        );
    }

    let mut channels: Vec<String> = channels_set.into_iter().collect();
    channels.sort();

    tracing::info!("Channels to collect: {:?}", channels);

    channels
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parse_sigma_yaml;
    use crate::SigmaCollection;

    fn parse_rule(logsource: &str) -> SigmaCollection {
        let yaml = format!(
            "title: test rule\nid: test-rule\nlogsource:\n{logsource}\ndetection:\n  sel:\n    EventID: 1\n  condition: sel\n"
        );
        parse_sigma_yaml(&yaml).expect("rule must parse")
    }

    fn resolve(logsource: &str) -> Vec<String> {
        resolve_channels(&parse_rule(logsource).rules, &HashMap::new())
    }

    fn resolve_multi(logsources: &[&str]) -> Vec<String> {
        let mut collection = SigmaCollection::default();
        for ls in logsources {
            let parsed = parse_rule(ls);
            collection.rules.extend(parsed.rules);
        }
        resolve_channels(&collection.rules, &HashMap::new())
    }

    #[test]
    fn test_resolve_service_only() {
        let channels = resolve("  product: windows\n  service: sysmon\n");
        assert_eq!(channels, vec!["Microsoft-Windows-Sysmon/Operational"]);
    }

    #[test]
    fn test_resolve_service_category() {
        let channels =
            resolve("  product: windows\n  service: sysmon\n  category: process_creation\n");
        assert_eq!(channels, vec!["Microsoft-Windows-Sysmon/Operational"]);
    }

    #[test]
    fn test_resolve_category_only_spans_services() {
        let channels = resolve("  product: windows\n  category: process_creation\n");
        assert_eq!(
            channels,
            vec![
                "Microsoft-Windows-Sysmon/Operational".to_string(),
                "Security".to_string()
            ]
        );
    }

    #[test]
    fn test_resolve_subcategory() {
        let channels = resolve("  product: windows\n  service: sysmon\n  category: registry_add\n");
        assert_eq!(channels, vec!["Microsoft-Windows-Sysmon/Operational"]);
    }

    #[test]
    fn test_resolve_registry_delete() {
        // (service, category) lookup path
        let channels =
            resolve("  product: windows\n  service: sysmon\n  category: registry_delete\n");
        assert_eq!(channels, vec!["Microsoft-Windows-Sysmon/Operational"]);
        // category-only lookup path (no service)
        let channels = resolve("  product: windows\n  category: registry_delete\n");
        assert_eq!(channels, vec!["Microsoft-Windows-Sysmon/Operational"]);
    }

    #[test]
    fn test_resolve_parent_category() {
        let channels = resolve("  product: windows\n  category: registry_event\n");
        assert_eq!(channels, vec!["Microsoft-Windows-Sysmon/Operational"]);
    }

    #[test]
    fn test_resolve_unknown_service_strict_no_fallback() {
        let channels =
            resolve("  product: windows\n  service: sysmon\n  category: bogus_category\n");
        assert!(channels.is_empty());
    }

    #[test]
    fn test_resolve_unknown_service() {
        let channels = resolve("  product: windows\n  service: nonexistent\n");
        assert!(channels.is_empty());
    }

    #[test]
    fn test_resolve_unknown_category() {
        let channels = resolve("  product: windows\n  category: nonexistent\n");
        assert!(channels.is_empty());
    }

    #[test]
    fn test_resolve_no_logsource() {
        let channels = resolve("  product: windows\n");
        assert!(channels.is_empty());
    }

    #[test]
    fn test_resolve_ignores_non_windows() {
        let channels = resolve("  product: linux\n  category: process_creation\n");
        assert!(channels.is_empty());
    }

    #[test]
    fn test_resolve_union_across_rules() {
        let channels = resolve_multi(&[
            "  product: windows\n  service: sysmon\n  category: process_creation\n",
            "  product: windows\n  service: security\n  category: login\n",
        ]);
        assert_eq!(
            channels,
            vec![
                "Microsoft-Windows-Sysmon/Operational".to_string(),
                "Security".to_string()
            ]
        );
    }

    #[test]
    fn test_resolve_custom_map() {
        let mut custom_map = HashMap::new();
        custom_map.insert(
            "Custom-Channel/Operational".to_string(),
            "sysmon".to_string(),
        );
        let collection = parse_rule("  product: windows\n  service: sysmon\n");
        let channels = resolve_channels(&collection.rules, &custom_map);
        assert_eq!(
            channels,
            vec![
                "Custom-Channel/Operational".to_string(),
                "Microsoft-Windows-Sysmon/Operational".to_string()
            ]
        );
    }

    #[test]
    fn test_resolve_custom_map_service_category_untouched() {
        let mut custom_map = HashMap::new();
        custom_map.insert(
            "Custom-Channel/Operational".to_string(),
            "sysmon".to_string(),
        );
        let collection =
            parse_rule("  product: windows\n  service: sysmon\n  category: process_creation\n");
        let channels = resolve_channels(&collection.rules, &custom_map);
        assert_eq!(channels, vec!["Microsoft-Windows-Sysmon/Operational"]);
    }

    #[test]
    fn test_empty_collection() {
        let collection = SigmaCollection::default();
        let channels = resolve_channels(&collection.rules, &HashMap::new());
        assert!(channels.is_empty());
    }
}
